"""Kernel-authenticated internal CLI admission and serial campaign queue.

It schedules frozen production routes; it neither expands public RPC methods
nor treats unavailable stage providers as acceptance.
"""
from datetime import datetime,timezone
import errno,fcntl,os,signal,socket,stat,struct,threading
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import canonical_json_line,decode_json,digest_jcs
from skillloop.runtime.operation_store import OperatorOperationStore,STORAGE_POLICY,WIRE_LIMIT


class OperatorService:
    def __init__(self,*,deployment_path,dispatcher):
        if os.geteuid()!=21001:raise PermissionError('operator_service_actual_controller')
        self.config=read_owned(deployment_path,uid=21010,gid=21001,limit=2097152)
        cfg=self.config
        if (set(cfg)!={'kind','deployment_epoch','campaign_digest','storage_policy','socket','socket_gid','operator_uids','store','deadline','routes','digest'}
                or cfg['kind']!='OperatorServiceDeployment' or type(cfg['operator_uids']) is not list
                or any(type(uid) is not int or uid<1 or uid in set(range(21002,21010))|{21011} for uid in cfg['operator_uids'])):
            raise ValueError('operator_service_frozen_deployment')
        self.dispatcher=dispatcher;self.stop=threading.Event();self.inflight_preserved=False
        self.admission_lock=threading.Lock()
        whole=self.dispatcher.phase.round_manifest
        if (cfg['storage_policy']!=STORAGE_POLICY or cfg['deployment_epoch']!=whole['deployment_epoch']
                or cfg['campaign_digest'] not in {c['campaign_digest'] for c in whole['campaigns']}):
            raise ValueError('operator_actual_storage_whole_round_binding')
        deadline=datetime.fromisoformat(cfg['deadline'].replace('Z','+00:00'))
        if (deadline.tzinfo is None or self.dispatcher.ledger.campaign_started_at is None
                or deadline.timestamp()!=self.dispatcher.ledger.campaign_started_at+28800
                or type(cfg['routes']) is not list or not 1<=len(cfg['routes'])<=2048):
            raise ValueError('operator_single_campaign_original_clock_and_routes')
        from skillloop.runtime.operator_routes import validate_operator_routes
        routes=[read_owned(path,uid=21010,gid=21001,limit=WIRE_LIMIT) for path in cfg['routes']]
        self.routes=validate_operator_routes(routes,campaign_digest=cfg['campaign_digest'],deadline=cfg['deadline'])
        key='operator-storage-'+cfg['digest'][7:]
        ledger=self.dispatcher.ledger;state=ledger.read()
        prior=[e for e in state.get('auxiliary_executions',[]) if e['operation_key']==key]
        requested={'seconds':60,'input_tokens':0,'output_tokens':0,'disk_bytes':33554432}
        if prior:
            if (len(prior)!=1 or prior[0]['stage']!='approval_deployment' or prior[0]['requested_cost']!=requested
                    or state.get('whole_round_binding')!={'manifest_digest':whole['digest'],'campaign':cfg['campaign_digest']}
                    or state.get('campaign_started_at')!=ledger.campaign_started_at):
                raise ValueError('operator_storage_original_spending_required')
        else:
            ledger.consume_auxiliary(manifest=whole,campaign=cfg['campaign_digest'],stage='approval_deployment',
                operation_key=key,**requested)
        self.store=OperatorOperationStore(cfg['store'],cfg['deployment_epoch'])
        self.dispatcher.operation_store=self.store
    def recover_original_operations(self):
        for ref,request,route in self.store.running():
            try:self.store.complete(ref,self.dispatcher.recover_final(request,route))
            except Exception as recovery_error:
                try:
                    self.dispatcher.reconcile_original_retirements(request,route)
                    proof=self.dispatcher.recover_unstarted_tail(request,route)
                    self.store.requeue_unstarted_tail(ref,proof)
                except Exception as custody_error:
                    # A started operation may already have dispatched a model,
                    # committed a business effect or lost its response. Retain
                    # available diagnostics before exposing a stable unknown;
                    # an existing immutable original failure stays unchanged.
                    if hasattr(custody_error,'add_note'):
                        custody_error.add_note('original_recovery_error:'+type(recovery_error).__name__)
                    try:self.dispatcher.preserve_failure(request,route,custody_error)
                    except Exception:pass
                    self.store.fail(ref,'unknown_requires_recovery')

    def stop_admission(self):
        # Signal handlers only fence admission. The original worker owns its
        # runtime, lease, cancellation and evidence journals until it drains.
        self.stop.set()

    def request(self,uid,value):
        if value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):raise ValueError('operator_request_seal')
        if uid not in self.config['operator_uids']:raise PermissionError('operator_peer_not_admitted')
        if value.get('kind')=='InternalOperatorQuery':
            if set(value)!={'kind','operation_ref','digest'}:raise ValueError('operator_query_shape')
            return self.store.status(uid,value['operation_ref'])
        if (set(value)!={'kind','command','parameters','operation_id','digest'}
                or value.get('kind')!='InternalOperatorRequest' or type(value['parameters']) is not dict
                or type(value['operation_id']) is not str or not 1<=len(value['operation_id'])<=256):
            raise ValueError('operator_request_shape')
        if value['command'].startswith('admin ') and uid!=21010:raise PermissionError('operator_admin_actual_peer')
        route=self.routes.get((value['command'],digest_jcs(value['parameters'])))
        if route is None:raise TimeoutError('operator_unadmitted_required_route')
        with self.admission_lock:
            if self.stop.is_set():raise TimeoutError('operator_admission_stopping')
            return self.store.accept(uid,value,route)
    def worker(self,*,control_only=False):
        while not self.stop.is_set():
            with self.admission_lock:
                if self.stop.is_set():break
                item=self.store.claim(control_only=control_only)
            if item is None:self.stop.wait(0.25);continue
            ref,request,route=item
            try:self.store.complete(ref,self.dispatcher.execute(request,route))
            except BaseException as error:
                # Detailed production journals remain private. Public status
                # does not contain private paths, case errors or traceback.
                try:self.dispatcher.preserve_failure(request,route,error)
                except BaseException as custody_error:
                    if hasattr(error,'add_note'):
                        error.add_note('controller_failure_custody_unavailable:'+type(custody_error).__name__)
                # The dispatcher can fail after a task was delivered or a
                # publication committed. A generic failure would hide that
                # uncertainty and invite a fresh attempt with the same work.
                self.store.fail(ref,'unknown_requires_recovery')
    def serve(self):
        # One controller owns admission and recovery at a time. Keep the lock
        # inode across restarts; deleting a lock could admit a second service.
        endpoint=Path(self.config['socket'])
        parent=endpoint.parent.lstat()
        if (endpoint.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid!=21001 or stat.S_IMODE(parent.st_mode)!=0o750):
            raise PermissionError('operator_controller_socket_directory')
        fd=os.open(str(endpoint)+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=21001
                    or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600):
                raise PermissionError('operator_service_lock_custody')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if endpoint.exists() or endpoint.is_symlink():
                original=endpoint.lstat()
                os.lseek(fd,0,os.SEEK_SET);raw=os.read(fd,4097)
                if not raw or len(raw)>4096:raise RuntimeError('operator_socket_identity_missing')
                identity=decode_json(raw)
                if (identity!={'socket':str(endpoint),'device':original.st_dev,'inode':original.st_ino}
                        or not stat.S_ISSOCK(original.st_mode) or original.st_uid!=21001):
                    raise PermissionError('operator_socket_original_identity_required')
                # Even a matching inode cannot be removed while listening.
                with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as probe:
                    probe.settimeout(1)
                    try:probe.connect(str(endpoint))
                    except OSError as error:
                        if error.errno!=errno.ECONNREFUSED:raise
                    else:raise RuntimeError('operator_original_service_still_listening')
                current=endpoint.lstat()
                if (current.st_dev,current.st_ino)!=(original.st_dev,original.st_ino):
                    raise RuntimeError('operator_socket_changed_during_recovery')
                endpoint.unlink()
            self._serve_locked(fd)
        finally:
            if self.inflight_preserved:
                # Keep the ownership fence until the process and its original
                # non-daemon worker exit. Closing it here would permit a second
                # service while the original Runtime still has custody.
                self._custody_lock_fd=fd
            else:os.close(fd)

    def _serve_locked(self,lock_fd):
        endpoint=Path(self.config['socket']);parent=endpoint.parent.lstat()
        if endpoint.exists() or endpoint.is_symlink() or parent.st_uid!=21001 or stat.S_IMODE(parent.st_mode)!=0o750:
            raise PermissionError('operator_fresh_controller_socket_directory')
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as server:
            server.bind(str(endpoint));os.chown(endpoint,-1,self.config['socket_gid']);os.chmod(endpoint,0o660)
            bound=endpoint.lstat()
            identity=canonical_json_line({'socket':str(endpoint),'device':bound.st_dev,'inode':bound.st_ino})
            os.lseek(lock_fd,0,os.SEEK_SET);os.ftruncate(lock_fd,0)
            if os.write(lock_fd,identity)!=len(identity):raise OSError('operator_socket_identity_short_write')
            os.fsync(lock_fd)
            directory=os.open(endpoint.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(directory)
            finally:os.close(directory)
            server.listen(16);server.settimeout(0.5)
            self.recover_original_operations()
            workers=[threading.Thread(target=self.worker,kwargs={'control_only':lane},daemon=False)
                for lane in (False,True)]
            for worker in workers:worker.start()
            try:
                while not self.stop.is_set() and datetime.now(timezone.utc)<datetime.fromisoformat(self.config['deadline'].replace('Z','+00:00')):
                    try:connection,_=server.accept()
                    except socket.timeout:continue
                    with connection:
                        connection.settimeout(9)
                        uid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
                        try:
                            raw,_,flags,_=connection.recvmsg(WIRE_LIMIT+1)
                            if not raw or len(raw)>WIRE_LIMIT or flags&socket.MSG_TRUNC:raise ValueError('operator_message_bound')
                            result=self.request(uid,decode_json(raw));reply={'ok':True,'result':result,'error_code':None}
                        except PermissionError:reply={'ok':False,'result':None,'error_code':'permission_denied'}
                        except ValueError:reply={'ok':False,'result':None,'error_code':'invalid_args'}
                        except Exception:reply={'ok':False,'result':None,'error_code':'unavailable'}
                        if len(canonical_json_line(reply))>WIRE_LIMIT:
                            reply={'ok':False,'result':None,'error_code':'unavailable'}
                        try:connection.sendall(canonical_json_line(reply))
                        except OSError:pass  # Accepted original operation remains queryable after response loss.
            finally:
                self.stop.set()
                for worker in workers:worker.join(timeout=15)
                # A live worker keeps its process/evidence; do not unlink and
                # replace the endpoint as if this service drained successfully.
                if any(worker.is_alive() for worker in workers):
                    self.inflight_preserved=True
                    raise RuntimeError('operator_inflight_custody_preserved')
                current=endpoint.lstat()
                if (current.st_dev,current.st_ino)!=(bound.st_dev,bound.st_ino):
                    raise RuntimeError('operator_socket_changed_before_cleanup')
                endpoint.unlink()


def main():
    os.umask(0o077)
    from skillloop.runtime.task_controller import FormalTaskController
    from skillloop.ci.campaign_registry import CampaignRegistry
    from skillloop.repair.budget import SpendingLedger
    from skillloop.runtime.docker_api import DockerEngine
    from skillloop.runtime.gateway import ExactLocalTokenizer
    from skillloop.runtime.campaign_dispatcher import CampaignDispatcher
    cfg=read_owned('/deployment/controller.json',uid=21010,gid=21001,limit=2097152)
    if cfg.get('kind')!='ControllerCampaignDeployment':raise ValueError('controller_campaign_deployment')
    if (cfg.get('engine_socket')!='/engine.sock' or type(cfg.get('engine_socket_gid')) is not int
            or cfg['engine_socket_gid'] not in os.getgroups()):
        raise PermissionError('controller_engine_socket_explicit_group')
    engine_socket=Path(cfg['engine_socket']).lstat()
    if (not stat.S_ISSOCK(engine_socket.st_mode) or engine_socket.st_gid!=cfg['engine_socket_gid']
            or stat.S_IMODE(engine_socket.st_mode)&0o007 or engine_socket.st_mode&0o060!=0o060):
        raise PermissionError('controller_actual_engine_socket_custody')
    controller=FormalTaskController(**cfg['task_controller'])
    tokenizer=ExactLocalTokenizer('/model',expected_hashes=cfg['tokenizer_hashes'])
    service=None;previous_signals={}
    try:
        dispatcher=CampaignDispatcher(controller=controller,registry=CampaignRegistry(cfg['registry']),
            ledger=SpendingLedger(Path(cfg['ledger']),victim_seconds=cfg['victim_seconds'],campaign_started_at=cfg['campaign_started_at']),
            engine=DockerEngine(cfg['engine_socket']),tokenizer=tokenizer,
            whole_round_manifest_path=cfg['whole_round_manifest_path'],phase_journal=cfg['phase_journal'])
        service=OperatorService(deployment_path='/deployment/operator-service.json',dispatcher=dispatcher)
        for number in (signal.SIGTERM,signal.SIGINT):
            previous_signals[number]=signal.getsignal(number)
            signal.signal(number,lambda signum,frame: service.stop_admission())
        service.serve()
    finally:
        for number,handler in previous_signals.items():signal.signal(number,handler)
        # A non-daemon worker may still be committing or preserving original
        # evidence. Closing its shared tokenizer during that work is unsafe.
        if service is None or not service.inflight_preserved:tokenizer.close()


if __name__=='__main__':main()
