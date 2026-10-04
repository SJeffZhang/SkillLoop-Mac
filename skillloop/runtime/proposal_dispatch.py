"""Controller dispatch of isolated native proposals in the original campaign.

No model response, candidate, or stopped process grants qualification. Complete
role evidence and the gateway stay available for independent whole-round review.
"""
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

from skillloop.protocol import canonical_json_line, digest_jcs
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.repair.budget import SpendingLedger
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.evaluation_dispatch import _preserve_logs, _verify_role_process
from skillloop.runtime.round_manifest import read_round_manifest


def _save(directory, name, value):
    value=dict(value);value['digest']=digest_jcs(value)
    raw=canonical_json_line(value)
    if len(raw)>8388608:raise ValueError('native_dispatch_journal_capacity')
    fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return value


def dispatch_model_bridge(*, policy, gateway_policy_directory, bridge_directory,
                          journal_directory, whole_round_manifest_path, ledger, engine):
    """Start one actual gateway and return only after sealed identity + UDS.

    Long-lived model calls are charged by their respective worker reservations;
    this slot reserves startup, identity inspection, logs, and shutdown costs.
    This does not start, reset, or certify the host backend's private lifecycle.
    """
    if os.geteuid()!=21001 or type(engine) is not DockerEngine or type(ledger) is not SpendingLedger:
        raise PermissionError('native_gateway_dispatch_controller')
    required={'kind','campaign_digest','gateway_policy_digest','image','whole_round_manifest_digest',
              'campaign_deadline','startup_seconds','closure_seconds','maximum_evidence_bytes','mounts','digest'}
    if (type(policy) is not dict or set(policy)!=required or policy['kind']!='FrozenNativeGatewayDispatch'
            or policy['digest']!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
            or type(policy['startup_seconds']) is not int or not 1<=policy['startup_seconds']<=300
            or type(policy['closure_seconds']) is not int or not 60<=policy['closure_seconds']<=300
            or type(policy['maximum_evidence_bytes']) is not int or not 1<=policy['maximum_evidence_bytes']<=33554432):
        raise ValueError('native_gateway_frozen_dispatch_policy')
    whole=read_round_manifest(whole_round_manifest_path)
    scope=next((c for c in whole['campaigns'] if c['campaign_digest']==policy['campaign_digest']),None)
    gateway_policy=read_owned(Path(gateway_policy_directory)/'policy.json',uid=21010,gid=21011,limit=262144)
    deadline=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
    protected=gateway_policy.get('kind')=='ProtectedNativeModelBridgePolicy'
    if (protected and (gateway_policy.get('allowed_client_uid')!=21002
            or gateway_policy.get('campaign_id')!=policy['campaign_digest']
            or gateway_policy.get('deployment_epoch')!=whole['deployment_epoch'])):
        raise ValueError('protected_gateway_dispatch_campaign_identity')
    if (scope is None or whole['digest']!=policy['whole_round_manifest_digest'] or policy['image']!=whole['image']
            or gateway_policy['digest']!=policy['gateway_policy_digest']
            or gateway_policy.get('kind') not in {'NativeModelBridgePolicy','ProtectedNativeModelBridgePolicy'}
            or gateway_policy.get('whole_round_manifest_digest')!=whole['digest']
            or gateway_policy.get('source_digest')!=whole['source_digest']
            or gateway_policy.get('campaign_deadline')!=policy['campaign_deadline']
            or gateway_policy.get('allowed_client_uid') not in {21002,21006,21007}
            or gateway_policy.get('model_host')!='host.docker.internal'
            or deadline.tzinfo is None or ledger.campaign_started_at is None
            or deadline.timestamp()!=ledger.campaign_started_at+28800
            or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['startup_seconds']+policy['closure_seconds']):
        raise ValueError('native_gateway_original_round_policy_binding')
    uid=gateway_policy['allowed_client_uid']
    bridge=Path(bridge_directory);info=bridge.lstat()
    if (not bridge.is_absolute() or bridge.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21011 or info.st_gid!=uid or stat.S_IMODE(info.st_mode)!=0o750
            or os.path.lexists(bridge/'model.sock') or os.path.lexists(bridge/'backend-identity.json')):
        raise PermissionError('native_gateway_fresh_bridge_required')
    directory=Path(journal_directory);info=directory.lstat()
    if (not directory.is_absolute() or directory.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21001 or stat.S_IMODE(info.st_mode)!=0o700):
        raise PermissionError('native_gateway_private_journal')
    mounts=[]
    targets={'gateway_policy':'/gateway-policy','whole_round':'/whole-round',
             'tokenizer':'/model','model_bridge':'/model-bridge'}
    if protected:targets['lifecycle_review']='/lifecycle-review'
    if type(policy['mounts']) is not dict or set(policy['mounts'])!=set(targets):
        raise ValueError('native_gateway_mount_set')
    for key,target in targets.items():
        pin=policy['mounts'][key]
        if type(pin) is not dict or set(pin)!={'volume','subpath'}:
            raise ValueError('native_gateway_volume_pin')
        path=PurePosixPath(pin['subpath'])
        if (type(pin['volume']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',pin['volume'])
                or not path.parts or path.is_absolute() or '..' in path.parts or str(path)!=pin['subpath']):
            raise ValueError('native_gateway_volume_subpath')
        mounts.append({'Type':'volume','Source':pin['volume'],'Target':target,'ReadOnly':key!='model_bridge',
                       'VolumeOptions':{'Subpath':pin['subpath']}})
    config={'Image':whole['image'],'User':'21011:21011','Entrypoint':['python'],
        'Cmd':['-m','skillloop.runtime.model_bridge_service'],
        'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code'],
        'Labels':{'skillloop.role':'model_gateway','skillloop.dispatch_policy':gateway_policy['digest'],
                  'skillloop.whole_round':whole['digest']},
        'HostConfig':{'GroupAdd':['21001',str(uid)],'NetworkMode':'bridge','ReadonlyRootfs':True,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,'NanoCpus':2000000000,
            'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
    if protected:config['HostConfig']['LogConfig']={'Type':'none','Config':{}}
    _save(directory,'dispatch-intent.json',{'kind':'FormalNativeGatewayDispatchIntent',
        'dispatch_digest':policy['digest'],'gateway_policy_digest':gateway_policy['digest'],'configuration':config})
    spending=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_digest'],stage='private_factory_lifecycle' if protected else 'import_scan',
        operation_key='gateway-'+policy['digest'][7:],seconds=policy['startup_seconds']+policy['closure_seconds'],
        input_tokens=0,output_tokens=0,disk_bytes=policy['maximum_evidence_bytes'])
    _save(directory,'spending.json',{'kind':'FormalNativeGatewaySpending','spending':spending})
    identifier=engine.create('skillloop-gateway-'+policy['digest'][7:39],config)
    _save(directory,'created.json',{'kind':'FormalNativeGatewayCreated','container_id':identifier,
                                   'dispatch_digest':policy['digest'],'gateway_policy_digest':gateway_policy['digest']})
    def identity(observed):
        if (observed.get('Id')!=identifier or observed.get('Image')!=whole['image']
                or observed.get('Config',{}).get('User')!='21011:21011'
                or observed.get('Config',{}).get('Labels')!=config['Labels']):
            raise ValueError('native_gateway_actual_identity')
        hc=observed['HostConfig']
        if any(hc.get(k)!=config['HostConfig'][k] for k in ('NetworkMode','ReadonlyRootfs','Memory','NanoCpus','PidsLimit')):
            raise ValueError('native_gateway_actual_limits')
        if (hc.get('CapAdd') or 'ALL' not in hc.get('CapDrop',[])
                or 'no-new-privileges' not in hc.get('SecurityOpt',[]) or set(hc.get('GroupAdd',[]))!={'21001',str(uid)}):
            raise ValueError('native_gateway_actual_privilege')
        if protected and hc.get('LogConfig',{}).get('Type')!='none':
            raise PermissionError('protected_gateway_logs_private_custody')
        actual=hc.get('Mounts',[])
        if len(actual)!=len(mounts):raise ValueError('native_gateway_actual_mount_set')
        for wanted in mounts:
            matches=[m for m in actual if m.get('Target')==wanted['Target']]
            if (len(matches)!=1 or any(matches[0].get(k)!=wanted[k] for k in ('Type','Source','ReadOnly'))
                    or matches[0].get('VolumeOptions',{}).get('Subpath')!=wanted['VolumeOptions']['Subpath']):
                raise ValueError('native_gateway_actual_mount_binding')
    try:
        identity(engine.inspect(identifier));engine.start(identifier)
        started=time.monotonic()
        while True:
            observed=engine.inspect(identifier);identity(observed)
            if not observed['State']['Running']:raise RuntimeError('native_gateway_start_failed_preserve_evidence')
            if os.path.lexists(bridge/'backend-identity.json') and os.path.lexists(bridge/'model.sock'):break
            if time.monotonic()-started>=policy['startup_seconds']:raise TimeoutError('native_gateway_start_unknown')
            time.sleep(0.1)
        backend=read_owned(bridge/'backend-identity.json',uid=21011,gid=uid,limit=262144)
        socket_info=(bridge/'model.sock').lstat()
        if (backend.get('kind')!='NativeModelBackendIdentity' or backend.get('gateway_uid')!=21011
                or backend.get('policy_digest')!=gateway_policy['digest']
                or backend.get('tokenizer_hashes')!=gateway_policy['tokenizer_hashes']
                or backend.get('observed')!={'backend_version':gateway_policy['backend_version'],
                    'model_id':gateway_policy['model_id'],'model_manifest_digest':gateway_policy['model_manifest_digest']}
                or backend.get('fresh_backend_lifecycle_verified') is not protected
                or (protected and backend.get('lifecycle_grant_digest')!=gateway_policy['lifecycle_grant_digest'])
                or not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid!=21011
                or socket_info.st_gid!=uid or stat.S_IMODE(socket_info.st_mode)!=0o660):
            raise ValueError('native_gateway_actual_backend_or_socket_changed')
        return _save(directory,'ready.json',{'kind':'FormalNativeGatewayReady','container_id':identifier,
            'dispatch_digest':policy['digest'],'gateway_policy_digest':gateway_policy['digest'],
            'backend_identity_digest':backend['digest'],'inspection':observed,
            'fresh_backend_lifecycle_verified':protected,'evidence_released':False})
    except BaseException as error:
        try:
            observed=engine.inspect(identifier);identity(observed)
            if observed['State']['Running']:engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
            logs_digest=_preserve_logs(engine,identifier,directory,'failure-process.log')
            _save(directory,'failure.json',{'kind':'FormalNativeGatewayFailure','container_id':identifier,
                'reason':str(error),'error_type':type(error).__name__,'logs_digest':logs_digest,
                'spent':True,'automatic_replay_allowed':False,'evidence_released':False})
        except BaseException as secondary:error.add_note('native_gateway_preservation_requires_recovery:'+type(secondary).__name__)
        raise


def dispatch_proposal(*, assignment_directory, evidence_directory, policy,
                      journal_directory,whole_round_manifest_path,ledger,engine,registry):
    from skillloop.ci.campaign_registry import CampaignRegistry
    if type(registry) is not CampaignRegistry:
        raise ValueError('native_proposal_current_campaign_registry_required')
    with registry.development_scope(campaign=policy['campaign_digest']) as admitted:
        if admitted['deadline']!=policy['campaign_deadline']:
            raise ValueError('native_proposal_original_registry_clock_changed')
        return _dispatch_proposal_open(assignment_directory=assignment_directory,
            evidence_directory=evidence_directory,policy=policy,journal_directory=journal_directory,
            whole_round_manifest_path=whole_round_manifest_path,ledger=ledger,engine=engine)


def dispatch_application_gate(*, assignment_directory, reviews_directory, policy,
                              journal_directory, whole_round_manifest_path,
                              ledger, engine, registry):
    """Run the independent Gate before any bounded candidate source grant.

    The original development lock remains held until the Gate has exited and its
    sealed review has been read. Neither process success nor this review closes
    the development pairing or creates a qualification.
    """
    from skillloop.ci.campaign_registry import CampaignRegistry
    if (os.geteuid()!=21001 or type(engine) is not DockerEngine
            or type(ledger) is not SpendingLedger or type(registry) is not CampaignRegistry):
        raise PermissionError('application_gate_dispatch_actual_controller')
    fields={'kind','campaign_digest','image','whole_round_manifest_digest','assignment_digest',
            'campaign_deadline','timeout_seconds','maximum_evidence_bytes','mounts','digest'}
    if (type(policy) is not dict or set(policy)!=fields
            or policy['kind']!='FrozenCandidateApplicationGateDispatch'
            or policy['digest']!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=600
            or type(policy['maximum_evidence_bytes']) is not int
            or not 1<=policy['maximum_evidence_bytes']<=33554432):
        raise ValueError('application_gate_frozen_dispatch')
    whole=read_round_manifest(whole_round_manifest_path)
    job=read_owned(Path(assignment_directory)/'job.json',uid=21001,gid=21005,limit=8388608)
    directory=Path(journal_directory);info=directory.lstat()
    if (not directory.is_absolute() or directory.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21001 or stat.S_IMODE(info.st_mode)!=0o700):
        raise PermissionError('application_gate_private_dispatch_journal')
    reviews=Path(reviews_directory);info=reviews.lstat()
    if (not reviews.is_absolute() or reviews.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21005 or info.st_gid!=21001 or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('application_gate_actual_review_directory')
    mounts=[]
    if type(policy['mounts']) is not dict or set(policy['mounts'])!={'assignment','patcher','tokenizer','whole_round','reviews'}:
        raise ValueError('application_gate_mount_set')
    for key,target in (('assignment','/assignment'),('patcher','/patcher'),('tokenizer','/model'),
                       ('whole_round','/whole-round'),('reviews','/reviews')):
        pin=policy['mounts'][key]
        if type(pin) is not dict or set(pin)!={'volume','subpath'}:
            raise ValueError('application_gate_volume_pin')
        path=PurePosixPath(pin['subpath'])
        if (type(pin['volume']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',pin['volume'])
                or not path.parts or path.is_absolute() or '..' in path.parts or str(path)!=pin['subpath']):
            raise ValueError('application_gate_volume_subpath')
        mounts.append({'Type':'volume','Source':pin['volume'],'Target':target,'ReadOnly':key!='reviews',
                       'VolumeOptions':{'Subpath':pin['subpath']}})
    config={'Image':policy['image'],'User':'21005:21005','Entrypoint':['python'],
        'Cmd':['-m','skillloop.repair.formal_application_gate'],
        'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code',
               'SKILLLOOP_RAW_HISTORY_MAX_BYTES='+str(policy['maximum_evidence_bytes'])],
        'Labels':{'skillloop.role':'candidate_application_gate','skillloop.dispatch_policy':policy['digest'],
                  'skillloop.whole_round':whole['digest']},
        'HostConfig':{'GroupAdd':['21001'],'NetworkMode':'none','ReadonlyRootfs':True,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,
            'NanoCpus':2000000000,'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
    with registry.development_scope(campaign=policy['campaign_digest']) as admitted:
        deadline=datetime.fromisoformat(admitted['deadline'].replace('Z','+00:00'))
        if (policy['campaign_deadline']!=admitted['deadline'] or job.get('deadline')!=admitted['deadline']
                or job.get('campaign_id')!=policy['campaign_digest']
                or job.get('config_digest')!=admitted['bindings']['config_digest']
                or job.get('digest')!=policy['assignment_digest']
                or job.get('whole_round_manifest_digest')!=whole['digest']
                or policy['whole_round_manifest_digest']!=whole['digest'] or policy['image']!=whole['image']
                or ledger.campaign_started_at is None or deadline.timestamp()!=ledger.campaign_started_at+28800
                or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+120):
            raise ValueError('application_gate_original_campaign_binding')
        _save(directory,'dispatch-intent.json',{'kind':'FormalCandidateApplicationGateIntent',
            'policy_digest':policy['digest'],'configuration':config,'assignment_digest':job['digest']})
        spending=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_digest'],stage='repair_pairing',
            operation_key='application-gate-'+policy['digest'][7:],seconds=policy['timeout_seconds']+60,
            input_tokens=0,output_tokens=0,disk_bytes=policy['maximum_evidence_bytes'])
        _save(directory,'spending.json',{'kind':'FormalCandidateApplicationGateSpending','spending':spending})
        identifier=engine.create('skillloop-application-gate-'+policy['digest'][7:39],config)
        _save(directory,'created.json',{'kind':'FormalCandidateApplicationGateCreated','container_id':identifier})
        try:
            _verify_role_process(engine.inspect(identifier),identifier,config,mounts)
            engine.start(identifier);state=engine.wait(identifier,policy['timeout_seconds'])
            observed=engine.inspect(identifier)
            _verify_role_process(observed,identifier,config,mounts)
            logs_digest=_preserve_logs(engine,identifier,directory,'process.log')
            _save(directory,'completion.json',{'kind':'FormalCandidateApplicationGateCompletion',
                'inspection':observed,'wait_result':state,'logs_digest':logs_digest,'evidence_released':False})
            if observed['State']['Running'] or state['StatusCode'] or observed['State']['ExitCode']:
                raise RuntimeError('application_gate_failed_preserve_evidence')
            review=read_owned(reviews/(job['digest'][7:]+'.json'),uid=21005,gid=21001,limit=262144)
            if (review.get('kind')!='GateBoundedCandidateApplication'
                    or review.get('campaign_id')!=policy['campaign_digest']
                    or review.get('assignment_digest')!=job['digest']
                    or review.get('config_digest')!=admitted['bindings']['config_digest']
                    or review.get('deployment_epoch')!=whole['deployment_epoch']
                    or review.get('application_verified') is not True
                    or review.get('qualification_issued') is not False):
                raise ValueError('application_gate_actual_review_binding')
            return {'review':review,'container_id':identifier,'inspection':observed,'evidence_released':False}
        except BaseException as error:
            try:
                observed=engine.inspect(identifier)
                _verify_role_process(observed,identifier,config,mounts)
                if observed['State']['Running']:engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
                _save(directory,'failure.json',{'kind':'FormalCandidateApplicationGateFailure',
                    'container_id':identifier,'reason':str(error),'error_type':type(error).__name__,
                    'automatic_replay_allowed':False,'evidence_released':False})
            except BaseException as secondary:error.add_note('application_gate_preservation_requires_recovery:'+type(secondary).__name__)
            raise


def _dispatch_proposal_open(*, assignment_directory, evidence_directory, policy,
                      journal_directory, whole_round_manifest_path, ledger, engine):
    if (os.geteuid()!=21001 or type(engine) is not DockerEngine
            or type(ledger) is not SpendingLedger):
        raise PermissionError('native_dispatch_actual_controller_required')
    required={'kind','campaign_digest','role_uid','assignment_digest','proposal_policy_digest',
              'image','whole_round_manifest_digest','campaign_deadline','timeout_seconds',
              'maximum_evidence_bytes','gateway_container_id','gateway_policy_digest','mounts','digest'}
    if (type(policy) is not dict or set(policy)!=required
            or policy['kind']!='FrozenNativeProposalDispatch'
            or policy['digest']!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
            or policy['role_uid'] not in {21006,21007}
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=600
            or type(policy['maximum_evidence_bytes']) is not int
            or not 1<=policy['maximum_evidence_bytes']<=33554432
            or not re.fullmatch(r'[0-9a-f]{64}',policy['gateway_container_id'])):
        raise ValueError('native_dispatch_frozen_policy')
    whole=read_round_manifest(whole_round_manifest_path)
    scope=next((c for c in whole['campaigns'] if c['campaign_digest']==policy['campaign_digest']),None)
    deadline=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
    if (scope is None or whole['digest']!=policy['whole_round_manifest_digest']
            or whole['image']!=policy['image'] or deadline.tzinfo is None
            or ledger.campaign_started_at is None or deadline.timestamp()!=ledger.campaign_started_at+28800
            or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+120):
        raise ValueError('native_dispatch_original_whole_round_binding')
    uid=policy['role_uid']
    assignment=Path(assignment_directory)
    job=read_owned(assignment/'job.json',uid=21001,gid=uid,limit=2097152)
    proposal_policy=read_owned(assignment/'policy.json',uid=21001,gid=uid,limit=262144)
    if (job['digest']!=policy['assignment_digest'] or job.get('role_uid')!=uid
            or job.get('profile')!=scope['profile']
            or job.get('policy_digest')!=proposal_policy['digest']
            or proposal_policy['digest']!=policy['proposal_policy_digest']
            or proposal_policy.get('role_uid')!=uid
            or proposal_policy.get('whole_round_manifest_digest')!=whole['digest']
            or proposal_policy.get('source_digest')!=whole['source_digest']
            or proposal_policy.get('campaign_deadline')!=policy['campaign_deadline']
            or proposal_policy.get('max_requests')!=1
            or type(proposal_policy.get('request_timeout_seconds')) is not int
            or not 1<=proposal_policy['request_timeout_seconds']<=180
            or policy['timeout_seconds']<proposal_policy['request_timeout_seconds']+60):
        raise ValueError('native_dispatch_assignment_or_single_reserved_request')
    directory=Path(journal_directory);info=directory.lstat()
    if (not directory.is_absolute() or directory.is_symlink() or info.st_uid!=21001
            or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700):
        raise PermissionError('native_dispatch_private_journal')
    evidence=Path(evidence_directory);info=evidence.lstat()
    if (not evidence.is_absolute() or evidence.is_symlink() or info.st_uid!=uid
            or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700):
        raise PermissionError('native_dispatch_fresh_role_evidence')
    # The Controller has no write grant to this directory. Freshness is enforced
    # by a unique volume/subpath and the role's exclusive session writes.
    mounts=[]
    if type(policy['mounts']) is not dict or set(policy['mounts'])!={'assignment','evidence','tokenizer','whole_round','model_bridge'}:
        raise ValueError('native_dispatch_role_mount_set')
    for key,target in (('assignment','/assignment'),('evidence','/evidence'),
                       ('tokenizer','/model'),('whole_round','/whole-round'),('model_bridge','/model-bridge')):
        pin=policy['mounts'][key]
        if type(pin) is not dict or set(pin)!={'volume','subpath'}:
            raise ValueError('native_dispatch_volume_pin')
        path=PurePosixPath(pin['subpath'])
        if (type(pin['volume']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',pin['volume'])
                or not path.parts or path.is_absolute() or '..' in path.parts or str(path)!=pin['subpath']):
            raise ValueError('native_dispatch_volume_subpath')
        mounts.append({'Type':'volume','Source':pin['volume'],'Target':target,'ReadOnly':key!='evidence',
                       'VolumeOptions':{'Subpath':pin['subpath']}})
    gateway=engine.inspect(policy['gateway_container_id'])
    labels=gateway.get('Config',{}).get('Labels',{})
    bridge_pin=policy['mounts']['model_bridge']
    gateway_mounts=[m for m in gateway.get('HostConfig',{}).get('Mounts',[]) if m.get('Target')=='/model-bridge']
    if (gateway.get('Id')!=policy['gateway_container_id'] or gateway.get('Image')!=policy['image']
            or gateway.get('Config',{}).get('User')!='21011:21011'
            or gateway.get('State',{}).get('Running') is not True
            or labels.get('skillloop.role')!='model_gateway'
            or labels.get('skillloop.dispatch_policy')!=policy['gateway_policy_digest']
            or labels.get('skillloop.whole_round')!=whole['digest']
            or len(gateway_mounts)!=1 or gateway_mounts[0].get('Type')!='volume'
            or gateway_mounts[0].get('Source')!=bridge_pin['volume']
            or gateway_mounts[0].get('VolumeOptions',{}).get('Subpath')!=bridge_pin['subpath']):
        raise ValueError('native_dispatch_actual_gateway_binding')
    model=proposal_policy['model_config']
    maximum=512 if uid==21006 else 1024
    if (model.get('max_context_tokens')!=16384 or model.get('max_output_tokens')!=maximum
            or model.get('temperature')!=(0.7 if uid==21006 else 0.2) or model.get('top_p')!=0.9
            or model.get('thinking') is not False or model.get('gateway_uid')!=21011):
        raise ValueError('native_dispatch_role_model_bounds')
    config={'Image':policy['image'],'User':str(uid)+':'+str(uid),'Entrypoint':['python'],
        'Cmd':['-m','skillloop.runtime.proposal_worker'],
        'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code'],
        'Labels':{'skillloop.role':'generator' if uid==21006 else 'patcher',
                  'skillloop.dispatch_policy':policy['digest'],'skillloop.whole_round':whole['digest']},
        'HostConfig':{'GroupAdd':['21001'],'NetworkMode':'none','ReadonlyRootfs':True,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,
            'NanoCpus':2000000000,'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
    _save(directory,'dispatch-intent.json',{'kind':'FormalNativeProposalDispatchIntent',
        'policy_digest':policy['digest'],'assignment_digest':job['digest'],'configuration':config})
    spending=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_digest'],
        stage='development' if uid==21006 else 'repair_pairing',operation_key='proposal-'+policy['digest'][7:],
        seconds=policy['timeout_seconds']+60,input_tokens=16384-maximum,output_tokens=maximum,
        disk_bytes=policy['maximum_evidence_bytes'])
    _save(directory,'spending.json',{'kind':'FormalNativeProposalSpending','policy_digest':policy['digest'],'spending':spending})
    identifier=engine.create('skillloop-proposal-'+policy['digest'][7:39],config)
    _save(directory,'created.json',{'kind':'FormalNativeProposalCreated','container_id':identifier,'policy_digest':policy['digest']})
    def identity(observed):
        if (observed.get('Id')!=identifier or observed.get('Image')!=policy['image']
                or observed.get('Config',{}).get('User')!=config['User']
                or observed.get('Config',{}).get('Labels')!=config['Labels']):
            raise ValueError('native_dispatch_actual_worker_identity')
        hc=observed['HostConfig']
        for key in ('NetworkMode','ReadonlyRootfs','Memory','NanoCpus','PidsLimit'):
            if hc.get(key)!=config['HostConfig'][key]:raise ValueError('native_dispatch_actual_isolation')
        if ('ALL' not in hc.get('CapDrop',[]) or hc.get('CapAdd')
                or 'no-new-privileges' not in hc.get('SecurityOpt',[])
                or set(hc.get('GroupAdd',[]))!={'21001'}):
            raise ValueError('native_dispatch_actual_privilege')
        actual=hc.get('Mounts',[])
        if len(actual)!=len(mounts):raise ValueError('native_dispatch_actual_mount_set')
        for expected in mounts:
            matches=[m for m in actual if m.get('Target')==expected['Target']]
            if (len(matches)!=1 or any(matches[0].get(k)!=expected[k] for k in ('Type','Source','ReadOnly'))
                    or matches[0].get('VolumeOptions',{}).get('Subpath')!=expected['VolumeOptions']['Subpath']):
                raise ValueError('native_dispatch_actual_mount_binding')
    try:
        identity(engine.inspect(identifier));engine.start(identifier)
        state=engine.wait(identifier,policy['timeout_seconds'])
        observed=engine.inspect(identifier);identity(observed)
        logs_digest=_preserve_logs(engine,identifier,directory,'process.log')
        _save(directory,'completion.json',{'kind':'FormalNativeProposalProcessCompletion',
            'policy_digest':policy['digest'],'inspection':observed,'wait_result':state,'logs_digest':logs_digest,
            'evidence_released':False,'qualification_issued':False})
        if observed['State']['Running'] or state['StatusCode'] or observed['State']['ExitCode']:
            raise RuntimeError('native_proposal_failed_preserve_spent_evidence')
        proposal=read_owned(evidence/'proposal.json',uid=uid,gid=21001,limit=8388608)
        if (proposal.get('kind')!=('FormalNativeAttackProposal' if uid==21006 else 'FormalNativePatchProposal')
                or proposal.get('assignment_digest')!=job['digest'] or proposal.get('producer_uid')!=uid
                or proposal.get('policy_digest')!=proposal_policy['digest']
                or proposal.get('whole_round_manifest_digest')!=whole['digest']
                or proposal.get('qualification_issued') is not False):
            raise ValueError('native_dispatch_role_output_binding')
        return {'proposal':proposal,'container_id':identifier,'inspection':observed,
                'evidence_released':False,'independent_review_complete':False}
    except BaseException as error:
        try:
            observed=engine.inspect(identifier);identity(observed)
            if observed['State']['Running']:engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
            _save(directory,'failure.json',{'kind':'FormalNativeProposalFailure','policy_digest':policy['digest'],
                'reason':str(error),'error_type':type(error).__name__,'spent':True,'automatic_replay_allowed':False,
                'inspection':engine.inspect(identifier),'evidence_released':False})
        except BaseException as secondary:error.add_note('native_proposal_preservation_requires_recovery:'+type(secondary).__name__)
        raise
