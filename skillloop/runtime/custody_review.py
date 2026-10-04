"""Gate-role raw review before controller retirement; never issues qualification."""
import argparse
import os
from pathlib import Path
import stat
import subprocess
import time
import re
from pathlib import PurePosixPath

from skillloop.protocol import canonical_json_line, decode_json, digest_bytes, digest_jcs
from skillloop.ci.qualification_store import GATE_UID, CONTROLLER_UID, _path
from skillloop.runtime.evidence_quota import EvidenceQuotaKeeper
from skillloop.runtime.gateway import ExactLocalTokenizer
from scripts.mac_m6_gate import sealed, load, rebuild_entry, result_path
from scripts.dgx_m6_repair import source_index


class GateReviewDispatcher:
    """Dispatch the frozen Gate role automatically after each durable export.

    The deployment must pregrant the review directory. The Gate receives only
    readonly source/tokenizer/evidence and its own output directory, no sockets,
    Docker socket or writable authority database.
    """
    def __init__(self,*,plan,manifest,source,tokenizer,review_directory):
        if os.geteuid()!=CONTROLLER_UID:raise PermissionError('controller_dispatch_uid_required')
        if (plan.get('digest')!=digest_jcs({k:v for k,v in plan.items() if k!='digest'}) or
                plan.get('manifest_digest')!=manifest['digest']):raise ValueError('custody_dispatch_plan')
        policy=plan.get('policy',{})
        required={'image','source_index_digest','deployment_epoch','timeout_seconds',
                  'reserved_reviews','auxiliary_seconds','review_module_digest','scratch_bytes'}
        if (set(policy) not in (required,required|{'volume_mounts'}) or
                digest_jcs(policy)!=manifest['config'].get('custody_gate_policy_digest') or
                policy['image']!=manifest['config']['mac_runtime_image'] or
                policy['source_index_digest']!=digest_jcs(manifest['source_index']) or
                policy['deployment_epoch']!=manifest['config']['deployment_epoch'] or
                policy['review_module_digest']!=digest_bytes(Path(__file__).read_bytes()) or
                type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=300 or
                type(policy['reserved_reviews']) is not int or policy['reserved_reviews']!=len(manifest['entries']) or
                type(policy['scratch_bytes']) is not int or not 1048576<=policy['scratch_bytes']<=536870912 or
                type(policy['auxiliary_seconds']) is not int or
                policy['auxiliary_seconds']<policy['reserved_reviews']*(policy['timeout_seconds']+60)):
            raise ValueError('custody_dispatch_frozen_policy')
        if manifest['config'].get('whole_flow_required') is True and 'volume_mounts' not in policy:
            raise ValueError('custody_controller_mount_namespace_requires_volume_pins')
        if 'volume_mounts' in policy:
            pins=policy['volume_mounts']
            if type(pins) is not dict or set(pins)!={'campaign','source','tokenizer','reviews'}:
                raise ValueError('custody_dispatch_volume_pins')
            for pin in pins.values():
                if (type(pin) is not dict or set(pin)!={'volume','subpath'}
                        or type(pin['volume']) is not str or type(pin['subpath']) is not str
                        or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',pin['volume'])
                        or not PurePosixPath(pin['subpath']).parts or PurePosixPath(pin['subpath']).is_absolute()
                        or '..' in PurePosixPath(pin['subpath']).parts
                        or str(PurePosixPath(pin['subpath']))!=pin['subpath']):
                    raise ValueError('custody_dispatch_volume_pins')
        self.plan,self.policy,self.manifest=plan,policy,manifest
        self.source,self.tokenizer,self.directory=map(lambda p:Path(p).absolute(),(source,tokenizer,review_directory))
        parent=self.directory.lstat()
        if (self.directory.is_symlink() or parent.st_uid!=GATE_UID or parent.st_gid!=CONTROLLER_UID
                or stat.S_IMODE(parent.st_mode)!=0o750):raise PermissionError('custody_dispatch_output_grant')
        if source_index(self.source)!=manifest['source_index']:raise ValueError('custody_dispatch_source_changed')

    def review(self,*,root,entry,receipt_path,campaign_started_at):
        root=Path(root).absolute();output=self.directory/(entry['digest'][7:]+'.json')
        if output.exists() and 'volume_mounts' not in self.policy:return output
        if (sealed(load(root/'manifest.json'))['digest']!=self.manifest['digest'] or
                entry['source_index_digest']!=self.policy['source_index_digest'] or
                type(campaign_started_at) not in (int,float) or campaign_started_at>time.time()):
            raise ValueError('custody_dispatch_entry_clock')
        relative=next((p for p in self.manifest['entries'] if sealed(load(root/p))==entry),None)
        if relative is None:raise ValueError('custody_dispatch_entry_not_in_manifest')
        # Exported files belong to this controller; grant readonly group access
        # only after verify_export has completed, never to another role's DB.
        grant=[root/'manifest.json',Path(receipt_path)]
        grant.extend(root/p for p in self.manifest['entries'])
        target=result_path(root,entry).parent
        receipt=sealed(load(receipt_path))
        if sum(item['bytes'] for item in receipt['files'])+1048576>self.policy['scratch_bytes']:
            raise ValueError('custody_dispatch_scratch_budget')
        grant.extend(path for path in target.rglob('*'))
        grant.append(target)
        for path in list(grant):
            parent=path.parent
            while parent!=root and root in parent.parents:
                grant.append(parent);parent=parent.parent
        grant.append(root)
        for path in set(grant):
            info=path.lstat()
            if (info.st_uid!=CONTROLLER_UID or stat.S_ISLNK(info.st_mode) or
                    not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))):
                raise PermissionError('custody_dispatch_read_grant_owner')
            os.chown(path,-1,CONTROLLER_UID)
            os.chmod(path,0o750 if stat.S_ISDIR(info.st_mode) else 0o640)
        # Never borrow a new clock when retiring a previous execution.
        left=campaign_started_at+28800-time.time()
        if left<self.policy['timeout_seconds']+60:raise TimeoutError('custody_dispatch_terminal_reserve')
        name='skillloop-entry-gate-'+entry['digest'][7:27]
        command=['docker','run','--name',name,'--pull=never','--user','21005:21005',
            '--group-add','21001','--network','none','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--memory','2g','--cpus','2','--pids-limit','64',
            '--ulimit','nofile=128:128','--tmpfs','/tmp:rw,nosuid,nodev,size='+str(self.policy['scratch_bytes']),
            '--label','skillloop.entry='+entry['digest'],'--label','skillloop.custody-plan='+self.plan['digest'],
            '--mount','type=bind,src='+str(root)+',dst=/campaign,readonly',
            '--mount','type=bind,src='+str(self.source)+',dst=/code,readonly',
            '--mount','type=bind,src='+str(self.tokenizer)+',dst=/model,readonly',
            '--mount','type=bind,src='+str(self.directory)+',dst=/reviews',
            '--entrypoint','python',self.policy['image'],'-m','skillloop.runtime.custody_review',
            '--root','/campaign','--entry','/campaign/'+relative,'--source','/code',
            '--tokenizer','/model','--receipt','/campaign/'+Path(receipt_path).relative_to(root).as_posix(),
            '--output','/reviews/'+output.name]
        if 'volume_mounts' in self.policy:
            return self._review_engine(root=root,entry=entry,output=output,name=name,
                arguments=command[command.index(self.policy['image'])+1:])
        # A named retained container fences replay after lost launch/response.
        # Recovery inspects its actual exit and exported review; no model is run.
        probe=subprocess.run(['docker','inspect',name],capture_output=True,timeout=20)
        if probe.returncode==0:
            values=decode_json(probe.stdout)
            if (len(values)!=1 or values[0]['Image']!=self.policy['image'] or
                    values[0]['Config']['Labels'].get('skillloop.entry')!=entry['digest'] or
                    values[0]['Config']['Labels'].get('skillloop.custody-plan')!=self.plan['digest']):
                raise ValueError('custody_dispatch_existing_identity')
            if values[0]['State']['Running']:raise TimeoutError('custody_dispatch_existing_running')
            if values[0]['State']['ExitCode']!=0 or not output.exists():raise ValueError('custody_dispatch_existing_failed')
            return output
        try:
            result=subprocess.run(command,capture_output=True,timeout=self.policy['timeout_seconds'])
        except subprocess.TimeoutExpired:
            # The retained named identity is inspected before stopping. Its
            # cleanup is charged to the already reserved auxiliary minute.
            probe=subprocess.run(['docker','inspect',name],capture_output=True,timeout=20)
            if probe.returncode==0:
                values=decode_json(probe.stdout)
                if (len(values)==1 and values[0]['Image']==self.policy['image'] and
                        values[0]['Config']['Labels'].get('skillloop.custody-plan')==self.plan['digest']):
                    subprocess.run(['docker','stop','-t','1',values[0]['Id']],capture_output=True,timeout=20)
            raise
        logs=root/'custody-dispatch';logs.mkdir(mode=0o700,exist_ok=True)
        from skillloop.discovery.scan_service import durable_save
        for suffix,raw in (('stdout',result.stdout),('stderr',result.stderr)):
            path=logs/(entry['digest'][7:]+'.'+suffix)
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        inspected=subprocess.run(['docker','inspect',name],capture_output=True,timeout=20)
        if inspected.returncode:raise ValueError('custody_dispatch_terminal_inspect')
        values=decode_json(inspected.stdout)
        if (len(values)!=1 or values[0]['Image']!=self.policy['image'] or values[0]['State']['Running'] or
                values[0]['Config']['User']!='21005:21005' or
                values[0]['Config']['Labels'].get('skillloop.custody-plan')!=self.plan['digest']):
            raise ValueError('custody_dispatch_terminal_identity')
        durable_save(logs/(entry['digest'][7:]+'.json'),{'kind':'CustodyGateDispatch',
            'entry_digest':entry['digest'],'plan_digest':self.plan['digest'],'returncode':result.returncode,
            'inspect':values[0],'stdout_digest':digest_bytes(result.stdout),'stderr_digest':digest_bytes(result.stderr)})
        if result.returncode or not output.exists():raise ValueError('custody_dispatch_gate_failed')
        return output

    def _review_engine(self,*,root,entry,output,name,arguments):
        from skillloop.runtime.docker_api import DockerEngine
        from skillloop.discovery.scan_service import durable_save
        engine=DockerEngine(self.manifest['config'].get('docker_engine_socket','/var/run/docker.sock'))
        mounts=[]
        for field,target in (('campaign','/campaign'),('source','/code'),
                             ('tokenizer','/model'),('reviews','/reviews')):
            pin=self.policy['volume_mounts'][field]
            mounts.append({'Type':'volume','Source':pin['volume'],'Target':target,
                'ReadOnly':field!='reviews','VolumeOptions':{'Subpath':pin['subpath']}})
        config={'Image':self.policy['image'],'User':'21005:21005','Entrypoint':['python'],
            'Cmd':arguments,'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code'],
            'Labels':{'skillloop.entry':entry['digest'],'skillloop.custody-plan':self.plan['digest']},
            'HostConfig':{'GroupAdd':['21001'],'NetworkMode':'none','ReadonlyRootfs':True,
                'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':2147483648,
                'NanoCpus':2000000000,'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
                'Tmpfs':{'/tmp':'rw,nosuid,nodev,size='+str(self.policy['scratch_bytes'])},'Mounts':mounts}}
        logs=root/'custody-dispatch';logs.mkdir(mode=0o700,exist_ok=True)
        prefix=entry['digest'][7:]
        def identity(observed):
            if (observed['Image']!=self.policy['image'] or observed['Config']['User']!='21005:21005'
                    or observed['Config'].get('Labels')!=config['Labels']
                    or observed['HostConfig']['NetworkMode']!='none'
                    or observed['HostConfig']['ReadonlyRootfs'] is not True):
                raise ValueError('custody_dispatch_actual_identity')
            actual={m['Destination']:m for m in observed['Mounts']}
            if set(actual)!={m['Target'] for m in mounts}:
                raise ValueError('custody_dispatch_actual_mounts')
            for mount in mounts:
                value=actual[mount['Target']]
                if (value['Type']!='volume' or value['Name']!=mount['Source']
                        or value['RW'] is mount['ReadOnly']):
                    raise ValueError('custody_dispatch_actual_mounts')
        try:
            observed=engine.inspect(name)
        except RuntimeError as error:
            if not str(error).startswith('docker_engine_404:'):raise
            observed=None
        journal=logs/(prefix+'.intent.json')
        if observed is not None:
            identity(observed)
            if not journal.exists():raise ValueError('custody_dispatch_unjournaled_identity')
            saved=sealed(load(journal))
            if saved['configuration_digest']!=digest_jcs(config):raise ValueError('custody_dispatch_intent_changed')
            if observed['State']['Running']:raise TimeoutError('custody_dispatch_existing_running')
            if observed['State']['ExitCode']!=0 or not output.exists():raise ValueError('custody_dispatch_existing_failed')
            review=sealed(load(_path(output)))
            if review['entry_digest']!=entry['digest'] or review['manifest_digest']!=self.manifest['digest']:
                raise ValueError('custody_dispatch_existing_review_binding')
            return output
        if journal.exists() or output.exists():
            raise RuntimeError('custody_dispatch_unknown_creation_preserve_evidence')
        intent={'kind':'CustodyGateDispatchIntent','entry_digest':entry['digest'],
            'plan_digest':self.plan['digest'],'configuration_digest':digest_jcs(config)}
        intent['digest']=digest_jcs(intent);durable_save(journal,intent)
        identifier=engine.create(name,config)
        durable_save(logs/(prefix+'.created.json'),{'kind':'CustodyGateCreated',
            'container_id':identifier,'configuration_digest':digest_jcs(config)})
        try:
            engine.start(identifier)
            state=engine.wait(identifier,self.policy['timeout_seconds'])
            observed=engine.inspect(identifier);identity(observed)
            if observed['Id']!=identifier or observed['State']['Running']:
                raise ValueError('custody_dispatch_terminal_identity')
            raw=engine.logs(identifier)
            fd=os.open(logs/(prefix+'.engine-log'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            durable_save(logs/(prefix+'.json'),{'kind':'CustodyGateDispatch',
                'entry_digest':entry['digest'],'plan_digest':self.plan['digest'],
                'returncode':state['StatusCode'],'inspect':observed,'log_digest':digest_bytes(raw)})
            if state['StatusCode'] or observed['State']['ExitCode'] or not output.exists():
                raise ValueError('custody_dispatch_gate_failed')
            review=sealed(load(_path(output)))
            if review['entry_digest']!=entry['digest'] or review['manifest_digest']!=self.manifest['digest']:
                raise ValueError('custody_dispatch_review_binding')
            return output
        except BaseException as error:
            try:
                observed=engine.inspect(identifier);identity(observed)
                if observed['Id']!=identifier:raise ValueError('custody_dispatch_stop_identity')
                if observed['State']['Running']:
                    engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
            except BaseException as secondary:
                error.add_note('custody_dispatch_stop_requires_recovery:'+type(secondary).__name__)
            raise


def review_scan(*, export_root, source_snapshot, deployment_digest, scanner_profile_digest, output):
    """Reconstruct scanner output for custody, including incomplete coverage.

    Expected source/deployment come from the Gate's admitted round manifest.
    Evidence preservation is independent of the scanner's acceptance verdict.
    """
    if os.geteuid()!=GATE_UID:raise PermissionError('independent_gate_uid_required')
    from skillloop.discovery.scan_service import read_sealed, export_inventory
    from skillloop.discovery.scanner import reduce_scan, ANALYZERS
    from skillloop.protocol import validate_envelope
    validate_envelope(source_snapshot)
    if source_snapshot['kind']!='SourceSnapshot':raise ValueError('scan_review_source_kind')
    root=Path(export_root)
    if root.is_symlink() or not root.is_dir():raise ValueError('scan_review_export_directory')
    receipt=read_sealed(root/'scan-evidence.json')
    snapshot=read_sealed(root/'source-snapshot.json')
    normalized=read_sealed(root/'normalized-report.json')
    terminal=decode_json((root/'container-terminal.json').read_bytes())
    if (receipt.get('kind')!='FormalScanEvidence' or snapshot!=source_snapshot or
            receipt['source_snapshot_digest']!=source_snapshot['digest'] or
            receipt['deployment_digest']!=deployment_digest or
            receipt['scanner_profile_digest']!=scanner_profile_digest or
            digest_bytes(ANALYZERS.read_bytes())!=scanner_profile_digest or
            terminal['Id']!=receipt['container_id'] or terminal['Image']!=receipt['image'] or
            terminal['State']['Running'] or terminal['State']['ExitCode']!=receipt['upstream_exit_code'] or
            terminal['Config']['User']!='21008:21008'):
        raise ValueError('scan_review_export_identity')
    files=export_inventory(root)
    raw=(root/'raw-report.json').read_bytes()
    report,findings,dispositions=reduce_scan(receipt['profile_id'],raw,receipt['upstream_exit_code'],
        subject_digest=source_snapshot['body']['skill_digest'],require_llm=False,allow_risk_exit=True)
    stored=decode_json((root/'findings.json').read_bytes())
    if (report!=normalized or report['digest']!=receipt['scanner_report_digest'] or
            digest_bytes(raw)!=receipt['raw_report_digest'] or
            stored!={'findings':findings,'dispositions':dispositions}):
        raise ValueError('scan_review_reconstruction_mismatch')
    package={item['path']:item for item in source_snapshot['body']['files']}
    actual={item['path'].removeprefix('subject/'):item for item in files if item['path'].startswith('subject/')}
    if (set(package)!=set(actual) or any(actual[name]['digest']!=value['bytes_digest'] or
            actual[name]['bytes']!=value['size_bytes'] for name,value in package.items())):
        raise ValueError('scan_review_package_changed')
    review={'kind':'ScanEvidenceReview','operation_id':receipt['operation_id'],
            'deployment_digest':deployment_digest,'export_receipt_digest':receipt['digest'],
            'raw_report_digest':receipt['raw_report_digest'],'scanner_report_digest':report['digest'],
            'raw_inventory_digest':digest_jcs(files),'evidence_complete':True,
            'coverage_complete':report['body']['status']=='complete','qualification_issued':False}
    review['digest']=digest_jcs(review)
    output=Path(output)
    parent=output.parent.lstat()
    if (output.parent.is_symlink() or parent.st_uid!=GATE_UID or parent.st_gid!=CONTROLLER_UID
            or stat.S_IMODE(parent.st_mode)!=0o750):raise PermissionError('scan_review_output_grant')
    try:fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    except FileExistsError:
        if decode_json(_path(output).read_bytes())!=review:raise ValueError('scan_review_immutable')
        return review
    with os.fdopen(fd,'wb') as stream:
        os.fchmod(stream.fileno(),0o640);os.fchown(stream.fileno(),-1,CONTROLLER_UID)
        stream.write(canonical_json_line(review));stream.flush();os.fsync(stream.fileno())
    directory=os.open(output.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)
    return review


def review_entry(*, root, entry_path, source, tokenizer_path, receipt_path, output):
    if os.geteuid() != GATE_UID:
        raise PermissionError('independent_gate_uid_required')
    root, source, tokenizer_path = map(Path, (root, source, tokenizer_path))
    manifest = sealed(load(root / 'manifest.json'))
    entry = sealed(load(entry_path))
    if (entry['digest'] not in [sealed(load(root / p))['digest'] for p in manifest['entries']]
            or source_index(source) != manifest['source_index']
            or entry['source_index_digest'] != digest_jcs(manifest['source_index'])):
        raise ValueError('custody_source_or_entry_identity')
    if digest_bytes((source / 'specs/mac/runtime-profile.json').read_bytes()) != manifest['runtime_profile_digest']:
        raise ValueError('custody_runtime_profile_identity')
    for name, expected in manifest['tokenizer_hashes'].items():
        if digest_bytes((tokenizer_path / name).read_bytes()) != expected:
            raise ValueError('custody_tokenizer_identity')
    receipt = sealed(load(receipt_path))
    if receipt.get('kind') != 'VerifiedQuotaExport' or receipt['entry_digest'] != entry['digest']:
        raise ValueError('custody_export_receipt_identity')
    target = result_path(root, entry).parent
    files = []
    total = 0
    for path in sorted(target.rglob('*')):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError('custody_unsafe_export')
        if not stat.S_ISREG(info.st_mode):
            continue
        total += info.st_size
        if len(files) >= 1024 or total > 536870912:
            raise ValueError('custody_export_bound')
        files.append({'path': path.relative_to(target).as_posix(), 'bytes': info.st_size,
                      'digest': digest_bytes(path.read_bytes())})
    if files != receipt['files'] or not {'result.json', 'authority.db', 'authority.backup.db'} <= {f['path'] for f in files}:
        raise ValueError('custody_raw_inventory_changed')
    if EvidenceQuotaKeeper._tables(target / 'authority.db') != EvidenceQuotaKeeper._tables(target / 'authority.backup.db'):
        raise ValueError('custody_authority_backup_changed')
    tokenizer = ExactLocalTokenizer(str(tokenizer_path))
    try:
        result = rebuild_entry(root, entry, tokenizer, set(), set())
    finally:
        tokenizer.close()
    body = result['body']
    verdict = ('fail' if body['utility_status'] == 'fail' or body['security_violation'] else
               'pass' if body['coverage_complete'] and body['utility_status'] == 'pass' else 'inconclusive')
    review = {'kind': 'EntryEvidenceReview', 'entry_digest': entry['digest'],
              'export_receipt_digest': receipt['digest'], 'manifest_digest': manifest['digest'],
              'source_index_digest': entry['source_index_digest'], 'raw_inventory_digest': digest_jcs(files),
              'reconstructed_result_digest': result['digest'], 'evidence_complete': True,
              'verdict': verdict, 'qualification_issued': False}
    review['digest'] = digest_jcs(review)
    output = Path(output).absolute()
    parent = output.parent.stat()
    if (output.parent.is_symlink() or parent.st_uid != GATE_UID or parent.st_gid != CONTROLLER_UID
            or stat.S_IMODE(parent.st_mode) != 0o750):
        raise PermissionError('custody_review_directory_grant')
    # Exclusive durable publication; changed raw cannot replace an earlier review.
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    except FileExistsError:
        if decode_json(_path(output).read_bytes()) != review:
            raise ValueError('custody_review_immutable')
        return review
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o640)
        os.fchown(stream.fileno(), -1, CONTROLLER_UID)
        stream.write(canonical_json_line(review))
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return review


def main():
    parser = argparse.ArgumentParser()
    for name in ('root', 'entry', 'source', 'tokenizer', 'receipt', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    review_entry(root=args.root, entry_path=args.entry, source=args.source,
                 tokenizer_path=args.tokenizer, receipt_path=args.receipt, output=args.output)


if __name__ == '__main__':
    main()
