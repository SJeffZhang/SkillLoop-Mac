"""Controller publishes immutable task intents and starts the real Proxy lease.

No model is launched here. A complete campaign dispatcher must journal spending
and reserve business/evidence capacity before invoking its isolated Runtime.
Transport loss is an unknown state requiring recovery, never automatic replay.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import os
from pathlib import Path
import stat

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs, validate_envelope
from skillloop.runtime.client import ProxyClient, ProxyRPCError


def _read(path, uid, gid, mode, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != mode or info.st_size > limit):
            raise PermissionError('task_transport_file_custody')
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('task_transport_size')
    return raw


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class FormalTaskController:
    def __init__(self, *, epoch, inbox, receipts, journal, sockets):
        if os.geteuid() != 21001:
            raise PermissionError('task_transport_controller_uid')
        self.epoch = epoch
        self.inbox, self.receipts, self.journal = map(Path, (inbox, receipts, journal))
        for path, uid, gid, mode in ((self.inbox,21001,21003,0o750),
                                     (self.receipts,21003,21001,0o750),
                                     (self.journal,21001,21001,0o700)):
            info = path.lstat()
            if (not path.is_absolute() or path.is_symlink() or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode):
                raise PermissionError('task_transport_directory_custody')
        if 21003 not in set(os.getgroups()) | {os.getegid()}:
            raise PermissionError('task_transport_proxy_read_group')
        self.client = ProxyClient(Path(sockets), expected_server_uid=21003)

    def publish(self, intent):
        if (type(intent) is not dict or intent.get('kind') != 'ControllerImportedTask'
                or intent.get('deployment_epoch') != self.epoch
                or intent.get('digest') != digest_jcs({k:v for k,v in intent.items() if k!='digest'})):
            raise ValueError('task_transport_intent_identity')
        if intent['plan']['body']['phase']!='dev' or intent['suite']['body']['visibility']=='private_evaluation':
            raise PermissionError('controller_cannot_publish_private_plan')
        raw = canonical_json_line(intent)
        if len(raw)>2097152:
            raise ValueError('task_transport_intent_capacity')
        target = self.inbox / (intent['digest'][7:]+'.json')
        if os.path.lexists(target):
            if _read(target,21001,21003,0o640,2097152)!=raw:
                raise ValueError('task_transport_immutable_conflict')
            return target
        temporary = self.inbox / (intent['digest'][7:]+'.pending')
        # The Proxy enumerates only final *.json entries. A pending intent is
        # written in the Controller-private journal before its atomic handoff.
        temporary = self.journal / temporary.name
        if os.path.lexists(temporary):
            if _read(temporary,21001,21003,0o640,2097152)!=raw:
                raise RuntimeError('task_transport_pending_unknown')
        else:
            fd = os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
            with os.fdopen(fd,'wb') as stream:
                os.fchown(stream.fileno(),-1,21003);os.fchmod(stream.fileno(),0o640)
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
        # Mount setup must place journal and inbox on the same evidence volume.
        # EXDEV is a real setup failure; do not use copy/unlink as a fallback.
        os.rename(temporary,target);_sync(self.inbox);_sync(self.journal)
        return target

    def admission(self, intent):
        if intent.get('digest')!=digest_jcs({k:v for k,v in intent.items() if k!='digest'}) or intent.get('deployment_epoch')!=self.epoch:
            raise ValueError('task_transport_intent_changed')
        path = self.receipts / (intent['digest'][7:]+'.json')
        if not os.path.lexists(path):
            return None  # Caller resumes the same intent; no busy waiting here.
        receipt = decode_json(_read(path,21003,21001,0o640,262144))
        if (type(receipt) is not dict or receipt.get('kind')!='TaskAdmissionTransportReceipt'
                or receipt.get('digest')!=digest_jcs({k:v for k,v in receipt.items() if k!='digest'})
                or receipt.get('intent_digest')!=intent['digest']
                or receipt.get('deployment_epoch')!=self.epoch or type(receipt.get('ok')) is not bool):
            raise ValueError('task_transport_receipt_binding')
        if not receipt['ok']:
            if set(receipt)!={'kind','intent_digest','deployment_epoch','ok','error_code','digest'}:
                raise ValueError('task_transport_rejection_shape')
            raise ProxyRPCError(receipt['error_code'])
        if set(receipt)!={'kind','intent_digest','deployment_epoch','ok','result','digest'}:
            raise ValueError('task_transport_acceptance_shape')
        result = receipt['result']
        if (result['digest']!=digest_jcs({k:v for k,v in result.items() if k!='digest'})
                or result['intent_digest']!=intent['digest'] or result['producer_uid']!=21003
                or result['run_request_digest']!=intent['run_request']['digest']
                or result['task_binding_digest']!=intent['binding']['digest']
                or result['campaign_id']!=intent['campaign_id'] or result['qualification_issued'] is not False):
            raise ValueError('task_transport_admission_binding')
        return result

    def reserve_campaign(self, campaign, plan):
        from skillloop.proxy.wire import make_control, validate_control
        identity={'epoch':self.epoch,'campaign':campaign,'plan':plan}
        key=digest_jcs(identity)[7:]
        sent=self.journal/(key+'.reservation-request.json')
        completed=self.journal/(key+'.reservation-result.json')
        if os.path.lexists(completed):
            result=decode_json(_read(completed,21001,os.getegid(),0o600,262144))
            if (result.get('identity')!=identity or result.get('digest')!=digest_jcs({k:v for k,v in result.items() if k!='digest'})):
                raise ValueError('campaign_reservation_journal_binding')
            validate_control(result['result'])
            return result['result']
        if os.path.lexists(sent):
            raise RuntimeError('campaign_reservation_unknown_requires_operation_recovery')
        request=make_control('ControlRequest',{'operation_id':'reserve-'+key,
            'deadline':(datetime.now(timezone.utc)+timedelta(seconds=9)).isoformat().replace('+00:00','Z'),
            'method':'reserve_campaign','params':{'campaign_digest':campaign,'plan_digest':plan}})
        fd=os.open(sent,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(request));stream.flush();os.fsync(stream.fileno())
        _sync(self.journal)
        result=self.client._send('control.sock',request)['result'];validate_control(result)
        if (result['kind']!='CampaignInspection' or result['body']['campaign_public_ref']!=campaign
                or result['body']['state']!='reserved' or result['body']['qualification']!='none'):
            raise ValueError('campaign_reservation_proxy_binding')
        receipt={'identity':identity,'result':result};receipt['digest']=digest_jcs(receipt)
        fd=os.open(completed,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(receipt));stream.flush();os.fsync(stream.fileno())
        _sync(self.journal)
        return result

    def campaign_cancellation_params(self,campaign):
        """Use only original opaque Lease/closure receipts, never private plans.

        A missing/unknown original Lease cannot be invented to satisfy the
        frozen CancellationResult contract. A concurrent fence change is an
        explicit CAS failure, never an automatic second cancellation.
        """
        if os.geteuid()!=21001:raise PermissionError('campaign_cancel_controller')
        receipts=list(self.journal.iterdir())
        if len(receipts)>4096:raise ValueError('campaign_cancel_original_journal_capacity')
        leases={};fences={}
        for path in receipts:
            if not path.name.endswith(('.lease.json','.lease-observed.json','.closed.json','.cancelled-before-runtime.json','.pre-dispatch-cancelled.json')):
                continue
            value=decode_json(_read(path,21001,21001,0o600,262144))
            if value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):
                raise ValueError('campaign_cancel_original_receipt_seal')
            lease=value if value.get('kind')=='Lease' else value.get('lease')
            if lease is not None:
                validate_envelope(lease)
                if lease['kind']!='Lease':raise ValueError('campaign_cancel_original_lease_kind')
                body=lease['body']
                if body['campaign_id']==campaign:
                    run=body['run_id'];leases[run]=body
                    fences[run]=max(fences.get(run,0),body['fencing_token'])
            cancellation=value if value.get('kind')=='CancellationResult' else value.get('cancellation',value.get('result'))
            if type(cancellation) is dict and cancellation.get('kind')=='CancellationResult':
                from skillloop.proxy.wire import validate_control
                validate_control(cancellation);body=cancellation['body']
                if body['campaign_public_ref']==campaign:
                    run=body['run_id'];fences[run]=max(fences.get(run,0),body['effective_fence'])
        if not leases:raise RuntimeError('campaign_cancel_original_lease_unavailable')
        run=max(leases,key=lambda key:(leases[key]['expires_at'],key))
        return {'run_id':run,'expected_fence':fences[run],
                'reason':'admin campaign cancellation:'+campaign}

    def start(self, intent, *, operation_id):
        admission = self.admission(intent)
        if admission is None:
            return None
        logical = {'epoch':self.epoch,'intent':intent['digest'],'operation_id':operation_id,
                   'run_request_digest':intent['run_request']['digest'],
                   'task_binding_digest':intent['binding']['digest']}
        from skillloop.proxy.wire import make_control
        request=make_control('ControlRequest',{'operation_id':operation_id,
            'deadline':(datetime.now(timezone.utc)+timedelta(seconds=9)).isoformat().replace('+00:00','Z'),
            'method':'start_run','params':{k:logical[k] for k in ('run_request_digest','task_binding_digest')}})
        logical['request']=request
        key = digest_jcs({"epoch":self.epoch,"intent":intent["digest"]})
        path = self.journal / (key[7:]+'.start.json')
        if os.path.lexists(path):
            raise RuntimeError('task_start_previously_sent_requires_operation_recovery')
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(logical));stream.flush();os.fsync(stream.fileno())
        _sync(self.journal)
        lease = self.client._send('control.sock',request)['result']
        validate_envelope(lease)
        expires = datetime.fromisoformat(lease['body']['expires_at'].replace('Z','+00:00'))
        if (lease['kind']!='Lease' or lease['body']['state']!='active'
                or lease['body']['campaign_id']!=intent['campaign_id']
                or lease['body']['run_id']!=intent['binding']['body']['run_id']
                or lease['body']['fencing_token']!=1
                or expires>datetime.fromisoformat(intent['run_deadline'].replace('Z','+00:00'))
                or expires<=datetime.now(timezone.utc)):
            raise ValueError('task_start_lease_binding')
        result = {'lease':lease,'trust_revision':admission['trust_revision'],
                  'approval_digest':admission['approval_digest'],'intent_digest':intent['digest']}
        result['digest']=digest_jcs(result)
        result_path = self.journal / (key[7:]+'.lease.json')
        fd=os.open(result_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(result));stream.flush();os.fsync(stream.fileno())
        _sync(self.journal)
        return result

    def start_private_reference(self, reference_path, *, minimum_remaining_seconds):
        """Start an already admitted private task without reading its assignment.

        Only Evaluator issues the opaque reference. Unknown sends require the
        original operation's recovery; a replay never renews an issued Lease.
        """
        import re
        from skillloop.discovery.formal_task_gate import read_owned
        from skillloop.proxy.wire import make_control
        if (os.geteuid() != 21001 or type(minimum_remaining_seconds) is not int
                or not 1 <= minimum_remaining_seconds <= 300):
            raise PermissionError('private_start_controller_window')
        value = read_owned(reference_path, uid=21004, gid=21001, limit=262144)
        fields = {'kind', 'opaque_ref', 'campaign_id', 'deployment_epoch', 'run_id',
            'run_request_digest', 'task_binding_digest', 'run_deadline', 'approval_digest',
            'trust_revision', 'digest'}
        if (set(value) != fields or value['kind'] != 'EvaluatorOpaqueRunReference'
                or value['deployment_epoch'] != self.epoch
                or not re.fullmatch(r'private-run-[0-9a-f]{32}', value['opaque_ref'])
                or any(not re.fullmatch(r'sha256:[0-9a-f]{64}', value[k]) for k in
                       ('campaign_id', 'run_request_digest', 'task_binding_digest', 'approval_digest'))
                or type(value['trust_revision']) is not int or value['trust_revision'] < 1):
            raise ValueError('private_start_opaque_reference')
        key = value['opaque_ref']
        sent = self.journal / (key + '.start.json')
        completed = self.journal / (key + '.lease.json')
        if os.path.lexists(completed):
            original = decode_json(_read(completed, 21001, os.getegid(), 0o600, 262144))
            if (original.get('reference_digest') != value['digest']
                    or original.get('digest') != digest_jcs({k:v for k,v in original.items() if k!='digest'})):
                raise ValueError('private_start_original_lease_conflict')
            validate_envelope(original['lease'])
            return original
        if os.path.lexists(sent):
            raise RuntimeError('private_start_unknown_original_operation_recovery_required')
        expiry = datetime.fromisoformat(value['run_deadline'].replace('Z', '+00:00'))
        if expiry.tzinfo is None or (expiry - datetime.now(timezone.utc)).total_seconds() <= minimum_remaining_seconds + 9:
            raise TimeoutError('private_start_original_task_window')
        request = make_control('ControlRequest', {'operation_id': key,
            'deadline': (datetime.now(timezone.utc) + timedelta(seconds=9)).isoformat().replace('+00:00', 'Z'),
            'method': 'start_run', 'params': {k:value[k] for k in ('run_request_digest', 'task_binding_digest')}})
        logical = {'kind': 'OpaquePrivateStartIntent', 'reference': value, 'request': request,
                   'automatic_reexecution_allowed': False}
        logical['digest'] = digest_jcs(logical)
        fd = os.open(sent, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical_json_line(logical)); stream.flush(); os.fsync(stream.fileno())
        _sync(self.journal)
        lease = self.client._send('control.sock', request)['result']
        observed = {'kind': 'OpaquePrivateLeaseObserved', 'reference_digest': value['digest'], 'lease': lease}
        observed['digest'] = digest_jcs(observed)
        fd = os.open(self.journal / (key + '.lease-observed.json'),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical_json_line(observed)); stream.flush(); os.fsync(stream.fileno())
        _sync(self.journal)
        validate_envelope(lease)
        actual_expiry = datetime.fromisoformat(lease['body']['expires_at'].replace('Z', '+00:00'))
        if (lease['kind'] != 'Lease' or lease['body']['state'] != 'active'
                or lease['body']['campaign_id'] != value['campaign_id']
                or lease['body']['run_id'] != value['run_id'] or lease['body']['fencing_token'] != 1
                or actual_expiry.tzinfo is None or actual_expiry > expiry):
            raise ValueError('private_start_actual_lease_binding_or_window')
        if (actual_expiry - datetime.now(timezone.utc)).total_seconds() <= minimum_remaining_seconds:
            # This method has not dispatched a Runtime. Fence the known Lease
            # before reporting that startup can no longer fit its original TTL.
            from skillloop.proxy.wire import validate_control
            cancel = make_control('ControlRequest', {'operation_id': key + '-cancel-before-runtime',
                'deadline': (datetime.now(timezone.utc) + timedelta(seconds=9)).isoformat().replace('+00:00', 'Z'),
                'method': 'cancel_run', 'params': {'run_id': value['run_id'],
                    'expected_fence': lease['body']['fencing_token'],
                    'reason': 'private task lease cannot fit runtime; no runtime dispatched'}})
            fd = os.open(self.journal / (key + '.cancel-before-runtime.json'),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(canonical_json_line(cancel)); stream.flush(); os.fsync(stream.fileno())
            _sync(self.journal)
            cancelled = self.client._send('control.sock', cancel)['result']; validate_control(cancelled)
            if (cancelled['kind'] != 'CancellationResult' or cancelled['body']['run_id'] != value['run_id']
                    or cancelled['body']['campaign_public_ref'] != value['campaign_id']
                    or cancelled['body']['effective_fence'] != lease['body']['fencing_token'] + 1):
                raise ValueError('private_start_cancellation_binding')
            fd = os.open(self.journal / (key + '.cancelled-before-runtime.json'),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(canonical_json_line(cancelled)); stream.flush(); os.fsync(stream.fileno())
            _sync(self.journal)
            raise TimeoutError('private_start_original_window_fenced_without_runtime')
        receipt = {'kind': 'OpaquePrivateRunStarted', 'reference_digest': value['digest'],
            'opaque_ref': key, 'campaign_id': value['campaign_id'], 'deployment_epoch': self.epoch,
            'lease': lease, 'approval_digest': value['approval_digest'],
            'trust_revision': value['trust_revision'], 'automatic_reexecution_allowed': False}
        receipt['digest'] = digest_jcs(receipt)
        fd = os.open(completed, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical_json_line(receipt)); stream.flush(); os.fsync(stream.fileno())
        _sync(self.journal)
        return receipt

    def publish_private_start(self, reference_path, *, evaluator_directory):
        """Publish the already durable Lease; this method cannot issue/start one."""
        import re
        from skillloop.discovery.formal_task_gate import read_owned
        if os.geteuid() != 21001 or 21004 not in set(os.getgroups()) | {os.getegid()}:
            raise PermissionError('private_start_evaluator_read_group')
        reference = read_owned(reference_path, uid=21004, gid=21001, limit=262144)
        key = reference.get('opaque_ref', '')
        if (reference.get('kind') != 'EvaluatorOpaqueRunReference'
                or reference.get('deployment_epoch') != self.epoch
                or not re.fullmatch(r'private-run-[0-9a-f]{32}', key)):
            raise ValueError('private_start_publication_reference')
        receipt = decode_json(_read(self.journal / (key + '.lease.json'), 21001, os.getegid(), 0o600, 262144))
        lease = validate_envelope(receipt['lease'])
        if (receipt.get('kind') != 'OpaquePrivateRunStarted'
                or receipt.get('digest') != digest_jcs({k:v for k,v in receipt.items() if k!='digest'})
                or receipt.get('reference_digest') != reference['digest']
                or any(receipt.get(k) != reference[k] for k in
                       ('opaque_ref','campaign_id','deployment_epoch','approval_digest','trust_revision'))
                or receipt.get('automatic_reexecution_allowed') is not False
                or lease['kind'] != 'Lease' or lease['body']['run_id'] != reference['run_id']
                or lease['body']['campaign_id'] != reference['campaign_id']):
            raise ValueError('private_start_publication_original_lease')
        root = Path(evaluator_directory); info = root.lstat()
        if (not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)) != (21001,21004,0o750)):
            raise PermissionError('private_start_publication_directory')
        target = root / (key + '.json')
        if os.path.lexists(target):
            original = read_owned(target, uid=21001, gid=21004, limit=262144)
            if original != receipt:
                raise ValueError('private_start_publication_conflict')
            return original
        # Exclusive pending record: an interrupted publication is recoverable,
        # never permission to send start_run again or renew its original expiry.
        pending = root / (key + '.pending')
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), -1, 21004); os.fchmod(stream.fileno(), 0o640)
            stream.write(canonical_json_line(receipt)); stream.flush(); os.fsync(stream.fileno())
        if os.path.lexists(target):
            raise FileExistsError('private_start_publication_race')
        os.rename(pending, target); _sync(root)
        return receipt

    def finish_private_reference(self, reference, started, *, runtime_image, runtime_container_id,
                                 keeper_id, run_volume, engine):
        """Fence the actual stopped worker without disclosing its private intent.

        Reuse the same actual Engine/keeper/cancellation checks as development;
        the derived binding contains only fields already held by Controller.
        """
        import re
        if (os.geteuid()!=21001 or reference.get('kind')!='EvaluatorOpaqueRunReference'
                or reference.get('deployment_epoch')!=self.epoch
                or reference.get('digest')!=digest_jcs({k:v for k,v in reference.items() if k!='digest'})
                or started.get('kind')!='OpaquePrivateRunStarted'
                or started.get('digest')!=digest_jcs({k:v for k,v in started.items() if k!='digest'})
                or started.get('reference_digest')!=reference['digest']
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',runtime_image)
                or any(started.get(k)!=reference[k] for k in
                       ('opaque_ref','campaign_id','deployment_epoch','approval_digest','trust_revision'))):
            raise ValueError('private_finish_original_reference_and_lease')
        bound={'kind':'ControllerOpaqueClosureBinding','reference_digest':reference['digest'],
            'deployment_epoch':self.epoch,'campaign_id':reference['campaign_id'],
            'config':{'mac_runtime_image':runtime_image},
            'binding':{'body':{'run_id':reference['run_id']}},
            'run_request':{'digest':reference['run_request_digest']}}
        bound['digest']=digest_jcs(bound)
        closure_start={**started,'intent_digest':bound['digest']}
        closure_start['digest']=digest_jcs({k:v for k,v in closure_start.items() if k!='digest'})
        closure=self.finish(bound,closure_start,runtime_container_id=runtime_container_id,
            keeper_id=keeper_id,run_volume=run_volume,
            operation_id=reference['opaque_ref']+'-finish',engine=engine)
        value={'kind':'OpaquePrivateBusinessClosure','reference_digest':reference['digest'],
            'started_digest':started['digest'],'binding':bound,'closure':closure,
            'evidence_released':False,'private_result_verified':False,'qualification_issued':False}
        value['digest']=digest_jcs(value)
        return value

    def finish(self, intent, started, *, runtime_container_id, keeper_id, run_volume, operation_id, engine):
        """Persist actual stopped worker identity before the Controller cancel RPC.

        This fences later business effects and permits the Proxy's consistent
        snapshot export. It does not release evidence custody, clear unknown
        model execution, or claim independent review/qualification completed.
        """
        import re
        from skillloop.runtime.docker_api import DockerEngine
        if (not isinstance(engine,DockerEngine) or type(runtime_container_id) is not str
                or type(keeper_id) is not str or type(run_volume) is not str
                or not re.fullmatch(r'[0-9a-f]{64}',runtime_container_id)
                or not re.fullmatch(r'[0-9a-f]{64}',keeper_id)):
            raise ValueError('formal_finish_actual_engine_required')
        if (intent.get('digest')!=digest_jcs({k:v for k,v in intent.items() if k!='digest'})
                or started.get('digest')!=digest_jcs({k:v for k,v in started.items() if k!='digest'})
                or started['intent_digest']!=intent['digest'] or intent['deployment_epoch']!=self.epoch):
            raise ValueError('formal_finish_intent')
        observed=engine.inspect(runtime_container_id)
        config=intent['config'];lease=started['lease']
        validate_envelope(lease)
        if (lease['kind']!='Lease' or lease['body']['run_id']!=intent['binding']['body']['run_id']
                or lease['body']['campaign_id']!=intent['campaign_id']):
            raise ValueError('formal_finish_lease_binding')
        labels=observed['Config'].get('Labels',{})
        if (observed['Id']!=runtime_container_id or observed['State']['Running']
                or observed['Image']!=config['mac_runtime_image']
                or observed['Config']['User']!='21002:21002'
                or labels.get('skillloop.run_request')!=intent['run_request']['digest']
                or observed['HostConfig']['NetworkMode']!='none'
                or observed['HostConfig']['ReadonlyRootfs'] is not True):
            raise ValueError('formal_finish_runtime_not_stopped_or_wrong_owner')
        mounts=observed.get('Mounts',[])
        if not any(m.get('Name')==run_volume and m.get('Destination')=='/evidence' and m.get('RW') is True for m in mounts):
            raise ValueError('formal_finish_runtime_evidence_volume')
        keeper=engine.inspect(keeper_id)
        keeper_mounts=keeper.get('Mounts',[])
        if (keeper.get('Id')!=keeper_id or keeper.get('Image')!=config['mac_runtime_image']
                or keeper['State']['Running'] is not True or keeper['Config']['User']!='21001:21001'
                or keeper['Config'].get('Labels',{}).get('skillloop.run_request')!=intent['run_request']['digest']
                or len(keeper_mounts)!=1 or keeper_mounts[0].get('Name')!=run_volume
                or keeper_mounts[0].get('RW') is not False):
            raise ValueError('formal_finish_actual_keeper_required')
        logical={'intent_digest':intent['digest'],'operation_id':operation_id,'deployment_epoch':self.epoch,
                 'run_id':lease['body']['run_id'],'expected_fence':lease['body']['fencing_token'],
                 'stopped_container_id':runtime_container_id,'actual_exit_code':observed['State']['ExitCode']}
        logical.update(keeper_id=keeper_id,run_volume=run_volume,keeper_inspection_digest=digest_jcs(keeper))
        from skillloop.proxy.wire import make_control,validate_control
        request=make_control('ControlRequest',{'operation_id':operation_id,
            'deadline':(datetime.now(timezone.utc)+timedelta(seconds=9)).isoformat().replace('+00:00','Z'),
            'method':'cancel_run','params':{'run_id':logical['run_id'],
                'expected_fence':logical['expected_fence'],
                'reason':'actual isolated worker stopped; preserve custody for evaluator and Gate'}})
        logical['request']=request
        key=digest_jcs({'epoch':self.epoch,'intent':intent['digest']})
        path=self.journal/(key[7:]+'.cancel.json')
        if os.path.lexists(path):
            raise RuntimeError('formal_finish_previously_sent_requires_operation_recovery')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(logical));stream.flush();os.fsync(stream.fileno())
        _sync(self.journal)
        result=self.client._send('control.sock',request)['result'];validate_control(result)
        if (result['kind']!='CancellationResult' or result['body']['run_id']!=logical['run_id']
                or result['body']['campaign_public_ref']!=intent['campaign_id']
                or result['body']['effective_fence']!=logical['expected_fence']+1):
            raise ValueError('formal_finish_cancellation_binding')
        record={'kind':'FormalTaskBusinessClosure','intent_digest':intent['digest'],'cancellation':result,
                'stopped_container_id':runtime_container_id,'actual_exit_code':logical['actual_exit_code'],
                'keeper_id':keeper_id,'run_volume':run_volume,'keeper_inspection_digest':logical['keeper_inspection_digest'],
                'evidence_released':False,'independent_gate_complete':False}
        record['digest']=digest_jcs(record)
        fd=os.open(self.journal/(key[7:]+'.closed.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(record));stream.flush();os.fsync(stream.fileno())
        _sync(self.journal)
        return record

    def cancel_before_runtime(self,intent,started):
        """Fence an admitted Lease before this dispatcher creates its worker.

        This cancellation grants no resource retirement permission and makes
        no claim that an unknown model or container stopped. Transport loss
        stays unknown; the original request is never resent automatically.
        """
        from skillloop.proxy.wire import make_control,validate_control
        if (os.geteuid()!=21001 or intent.get('deployment_epoch')!=self.epoch
                or intent.get('digest')!=digest_jcs({k:v for k,v in intent.items() if k!='digest'})
                or started.get('digest')!=digest_jcs({k:v for k,v in started.items() if k!='digest'})
                or started['intent_digest']!=intent['digest']):
            raise ValueError('formal_pre_dispatch_cancellation_binding')
        lease=validate_envelope(started['lease'])
        if (lease['kind']!='Lease' or lease['body']['run_id']!=intent['binding']['body']['run_id']
                or lease['body']['campaign_id']!=intent['campaign_id']):
            raise ValueError('formal_pre_dispatch_lease_binding')
        key=intent['digest'][7:]
        request=make_control('ControlRequest',{'operation_id':'pre-dispatch-cancel-'+key,
            'deadline':(datetime.now(timezone.utc)+timedelta(seconds=9)).isoformat().replace('+00:00','Z'),
            'method':'cancel_run','params':{'run_id':lease['body']['run_id'],
                'expected_fence':lease['body']['fencing_token'],
                'reason':'actual lease cannot fit the frozen worker; dispatcher has not created the runtime'}})
        sent=self.journal/(key+'.pre-dispatch-cancel.json')
        fd=os.open(sent,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(request));stream.flush();os.fsync(stream.fileno())
        _sync(self.journal)
        result=self.client._send('control.sock',request)['result'];validate_control(result)
        if (result['kind']!='CancellationResult' or result['body']['run_id']!=lease['body']['run_id']
                or result['body']['campaign_public_ref']!=intent['campaign_id']
                or result['body']['effective_fence']!=lease['body']['fencing_token']+1):
            raise ValueError('formal_pre_dispatch_cancellation_result')
        record={'kind':'FormalPreDispatchCancellation','intent_digest':intent['digest'],
                'request_digest':request['digest'],'cancellation':result,
                'runtime_dispatch_attempted':False,'model_stop_verified':False,
                'evidence_released':False,'qualification_issued':False}
        record['digest']=digest_jcs(record)
        fd=os.open(self.journal/(key+'.pre-dispatch-cancelled.json'),
                   os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(record));stream.flush();os.fsync(stream.fileno())
        _sync(self.journal)
        return record


def imported_task_intent(entry, *, domain, policy, inputs, run_deadline):
    """Produce the immutable task handoff from a frozen whole-campaign entry.

    This does not register a campaign, approve a source, or reserve an attempt.
    It uses actual control-plane domain/policy and exact imported package pins;
    the receiving Proxy resolves the administrator-issued approval independently.
    """
    if entry.get('kind')=='protected' and os.geteuid()!=21004:
        raise PermissionError('private_task_intent_actual_evaluator_required')
    import base64
    from scripts.spec_v22_core import canonical_policy
    from skillloop.loader import ApprovedPackageLoader, validate_source_admission
    from skillloop.families.registry import FamilyRegistry
    from skillloop.families.builders import build_artifact
    from skillloop.families.oracle import validate_artifact
    from skillloop.families.task_world import formal_task
    from skillloop.protocol import digest_bytes
    from skillloop.runtime.mac_entry import verify_formal_entry, verify_protected_entry
    config, compiled = entry['config'], entry['compiled']
    if config.get('whole_flow_required') is not True:
        raise ValueError('formal_whole_campaign_config_required')
    # The campaign's original eight-hour wall clock is not a task Lease.
    # Admit a fresh task just before dispatch, within the frozen Proxy TTL;
    # shortening the task deadline never replenishes campaign spending.
    campaign_deadline=datetime.fromisoformat(run_deadline.replace('Z','+00:00'))
    now=datetime.now(timezone.utc)
    task_seconds=config.get('proxy_deadline_seconds')
    if (campaign_deadline.tzinfo is None or type(task_seconds) is not int
            or not 1<=task_seconds<=300
            or not 0<(campaign_deadline-now).total_seconds()<=28800):
        raise ValueError('formal_task_original_campaign_and_proxy_clock')
    # The business authority's frozen timestamp grammar is UTC seconds.
    # Round down, never up: formatting cannot extend the actual task TTL or
    # reset the original fractional campaign clock.
    task_deadline=min(campaign_deadline,now+timedelta(seconds=task_seconds)).replace(microsecond=0)
    verifier=verify_protected_entry if entry.get('kind')=='protected' else verify_formal_entry
    verifier(entry,image=config['mac_runtime_image'],source_digest=entry['source_index_digest'],
             model_port=config['model_service_port'])
    admission=entry['source_admission']
    validate_source_admission(admission,config,compiled['subject_digest'])
    encoded=admission['package_files']
    if type(encoded) is not dict or not 1<=len(encoded)<=32 or any(type(v) is not str or len(v)>5464 for v in encoded.values()):
        raise ValueError('formal_package_capacity')
    package={k:base64.b64decode(v,validate=True) for k,v in encoded.items()}
    loader=ApprovedPackageLoader(approved_sources=admission['approved_sources'],
        reference_resource_ids=admission['reference_resource_ids'],approved_subjects=admission.get('approved_subjects'))
    selection=loader.select(admission['source_snapshot'],package,admission['manifest'],
        profile_id=entry['profile'],family_id=FamilyRegistry().profile(entry['profile'])['family_id'])
    if selection.subject_digest!=compiled['subject_digest'] or digest_bytes(package['SKILL.md'])!=compiled['skill_digest']:
        raise ValueError('formal_compiled_package_binding')
    candidate=loader.approved_subjects.get(selection.source_snapshot_digest)
    if candidate is None or candidate['body']['policy_digest']!=canonical_policy(policy)['digest']:
        raise ValueError('formal_candidate_policy_required')
    expected=build_artifact(entry['profile'],inputs)
    validate_artifact(entry['profile'],inputs,expected)
    case=compiled['cases'][entry['case_id']]
    binding,request,raw=formal_task(domain=domain,policy=policy,profile_id=entry['profile'],
        subject_digest=selection.subject_digest,case_digest=case['digest'],suite_digest=compiled['suite']['digest'],
        plan_digest=entry['plan']['digest'],repetition_index=entry['repetition'],
        run_id='run-'+entry['digest'][7:],task_instance_id='task-'+entry['digest'][7:],config_digest=digest_jcs(config),
        initial_world_digest=digest_jcs({'profile_id':entry['profile'],
            'inputs':{k:digest_bytes(v) for k,v in inputs.items()},'expected_digest':digest_bytes(expected)}),
        inputs=inputs,package_resources=selection.resource_bytes())
    selection.check_binding(binding)
    value={'kind':'EvaluatorPrivateTask' if entry.get('kind')=='protected' else 'ControllerImportedTask',
        'deployment_epoch':config['deployment_epoch'],
        'campaign_id':entry['campaign_id'],'profile_id':entry['profile'],'domain':domain,'policy':policy,
        'binding':binding,'run_request':request,'plan':entry['plan'],'suite':compiled['suite'],
        'run_deadline':task_deadline.strftime('%Y-%m-%dT%H:%M:%SZ'),'config':config,'source_admission':admission,
        'input_resources':{k:base64.b64encode(v).decode('ascii') for k,v in raw.items()}}
    value['digest']=digest_jcs(value)
    return value
