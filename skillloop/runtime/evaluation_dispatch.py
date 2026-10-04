"""Controller launches the actual independent Evaluator from frozen volume pins.

All sources are named Docker volumes/subpaths. Container-local paths must never
be passed as host bind sources: the Docker daemon has a different mount namespace.
This dispatch produces an evaluation, not a Gate verdict or qualification.
"""
from datetime import datetime,timezone
import os
from pathlib import Path,PurePosixPath
import re
import stat

from skillloop.protocol import canonical_json_line,digest_jcs,digest_bytes
from skillloop.runtime.docker_api import DockerEngine


def _preserve_logs(engine, identifier, directory, name):
    raw=engine.logs(identifier,maximum_bytes=1048576,timeout=5)
    fd=os.open(Path(directory)/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    return digest_bytes(raw)


def _verify_role_process(observed,identifier,config,mounts,*,controller_engine_bind=False):
    """Inspect actual Engine settings before executing a privileged role.

    This establishes configured bounds, not observed seccomp enforcement or
    capacity exhaustion. Keep both claims distinct in the round evidence.
    """
    expected=config['HostConfig'];actual=observed['HostConfig']
    if (observed['Id']!=identifier or observed['Image']!=config['Image']
            or observed['Config']['User']!=config['User']
            or observed['Config'].get('Labels')!=config['Labels']
            or observed['Config'].get('Entrypoint')!=config['Entrypoint']
            or observed['Config'].get('Cmd')!=config['Cmd']):
        raise ValueError('formal_review_actual_role_identity')
    environment=observed['Config'].get('Env',[])
    if type(environment) is not list or any(type(v) is not str or '=' not in v for v in environment):
        raise ValueError('formal_review_actual_environment_shape')
    keys=[v.split('=',1)[0] for v in environment]
    if len(keys)!=len(set(keys)) or not set(config['Env']).issubset(set(environment)):
        raise ValueError('formal_review_actual_environment_binding')
    for field in ('NetworkMode','ReadonlyRootfs','Memory','NanoCpus','PidsLimit','Tmpfs'):
        if actual.get(field)!=expected[field]:
            raise ValueError('formal_review_actual_resource_bound:'+field)
    if (set(actual.get('GroupAdd') or [])!=set(expected.get('GroupAdd',[]))
            or set(actual.get('CapDrop') or []) not in ({'ALL'},{'CAP_ALL'})
            or actual.get('CapAdd')
            or set(actual.get('SecurityOpt') or [])!={'no-new-privileges'}
            or actual.get('Privileged') is not False
            or actual.get('Ulimits')!=expected['Ulimits']):
        raise ValueError('formal_review_actual_privilege_or_fd_bound')
    mounted=actual.get('Mounts',[])
    if len(mounted)!=len(mounts) or observed.get('Mounts') is None:
        raise ValueError('formal_review_actual_mount_set')
    for pin in mounts:
        selected=[m for m in mounted if m.get('Target')==pin['Target']]
        resolved=[m for m in observed['Mounts'] if m.get('Destination')==pin['Target']]
        if pin['Type']=='bind':
            if (controller_engine_bind is not True or config['User']!='21001:21001'
                    or pin['Target']!='/engine.sock' or pin['Source']!='/var/run/docker.sock'
                    or pin['ReadOnly'] is not False or len(selected)!=1 or len(resolved)!=1
                    or any(selected[0].get(k)!=pin[k] for k in ('Type','Source','ReadOnly'))
                    or resolved[0].get('Type')!='bind' or resolved[0].get('Source')!=pin['Source']
                    or resolved[0].get('RW') is not True):
                raise ValueError('formal_controller_exact_engine_socket_binding')
            continue
        if (len(selected)!=1 or any(selected[0].get(k)!=pin[k] for k in ('Type','Source','ReadOnly'))
                or selected[0].get('VolumeOptions',{}).get('Subpath')!=pin.get('VolumeOptions',{}).get('Subpath')
                or len(resolved)!=1 or resolved[0].get('Type')!='volume'
                or resolved[0].get('Name')!=pin['Source']
                or resolved[0].get('RW') is not (not pin['ReadOnly'])):
            raise ValueError('formal_review_actual_evidence_volume_binding')


def dispatch_task_gate(*,entry,intent,policy,journal_directory,engine,archive_mode=False,lifecycle_mode=False):
    """Launch the real Gate on the same assignment/raw and Evaluator output.

    Gate is read-only on every producer artifact. The separate policy and
    auxiliary timeout must be frozen before the original victim is admitted.
    """
    if entry.get('kind')=='protected':raise PermissionError('private_gate_requires_opaque_evaluator_assignment')
    if os.geteuid()!=21001 or not isinstance(engine,DockerEngine) or type(archive_mode) is not bool or type(lifecycle_mode) is not bool or (archive_mode and lifecycle_mode):
        raise PermissionError('formal_gate_dispatch_controller')
    if (policy.get('digest')!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
            or policy['entry_digest']!=entry['digest']
            or policy['image']!=entry['config']['mac_runtime_image']
            or policy['deployment_epoch']!=intent['deployment_epoch']
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=1200
            or set(policy['mounts'])!=({'lifecycle','private_authority','reviews','gateway_review'} if lifecycle_mode else
                {'archive','original_reviews','reviews'} if archive_mode
                else {'assignment','runtime','snapshot','evaluation','reviews','tokenizer'})):
        raise ValueError('formal_gate_frozen_dispatch_policy')
    deadline=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
    if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+60:
        raise TimeoutError('formal_gate_original_terminal_budget')
    if archive_mode and (policy.get('kind')!='FrozenArchiveGateDispatch'
            or type(policy.get('maximum_bytes')) is not int or not 1<=policy['maximum_bytes']<=2147483648
            or type(policy.get('maximum_files')) is not int or not 1<=policy['maximum_files']<=4096
            or not 1<=policy['timeout_seconds']<=120):
        raise ValueError('formal_archive_gate_frozen_policy')
    if lifecycle_mode and (policy.get('kind')!='FrozenModelLifecycleGateDispatch'
            or not 1<=policy['timeout_seconds']<=120):
        raise ValueError('formal_lifecycle_gate_frozen_policy')
    mounts=[]
    targets=(('lifecycle','/lifecycle'),('private_authority','/private-authority'),
             ('reviews','/reviews'),('gateway_review','/gateway-review')) if lifecycle_mode else (('archive','/archive'),('original_reviews','/original-reviews'),('reviews','/reviews')) if archive_mode else (
        ('assignment','/assignment'),('runtime','/raw'),('snapshot','/authority'),
        ('evaluation','/evaluation'),('reviews','/reviews'),('tokenizer','/model'))
    for field,target in targets:
        pin=policy['mounts'][field]
        subpath=PurePosixPath(pin['subpath'])
        volume_root=archive_mode and field=='archive' and pin.get('subpath')=='.'
        if (set(pin)!={'volume','subpath'}
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',pin['volume'])
                or (not volume_root and (not subpath.parts or subpath.is_absolute() or '..' in subpath.parts
                    or str(subpath)!=pin['subpath']))):
            raise ValueError('formal_gate_volume_pins')
        mounts.append({'Type':'volume','Source':pin['volume'],'Target':target,
            'ReadOnly':field not in {'reviews','gateway_review'},'VolumeOptions':{} if volume_root else {'Subpath':pin['subpath']}})
    directory=Path(journal_directory);info=directory.lstat()
    if (not directory.is_absolute() or directory.is_symlink() or info.st_uid!=21001
            or stat.S_IMODE(info.st_mode)!=0o700):
        raise PermissionError('formal_gate_dispatch_journal')
    config={'Image':policy['image'],'User':'21005:21005','Entrypoint':['python'],
        'Cmd':['-m','skillloop.discovery.formal_task_gate'],
        'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code'],
        'Labels':{'skillloop.role':'gate','skillloop.intent':intent['digest'],
                  'skillloop.dispatch_policy':policy['digest']},
        'HostConfig':{'GroupAdd':['21004','21001'],'NetworkMode':'none','ReadonlyRootfs':True,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,
            'NanoCpus':2000000000,'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
    if archive_mode:
        config['Cmd'].append('--archive')
        config['Labels']['skillloop.role']='archive_gate'
        config['Env'] += ['SKILLLOOP_ARCHIVE_INTENT='+intent['digest'],
            'SKILLLOOP_ARCHIVE_DEADLINE='+policy['campaign_deadline'],
            'SKILLLOOP_ARCHIVE_MAX_BYTES='+str(policy['maximum_bytes']),
            'SKILLLOOP_ARCHIVE_MAX_FILES='+str(policy['maximum_files'])]
    if lifecycle_mode:
        config['Cmd']=['-m','skillloop.protection.model_lifecycle_gate']
        config['Labels']['skillloop.role']='model_lifecycle_gate'
        config['HostConfig']['GroupAdd'].append('21011')
        config['HostConfig']['LogConfig']={'Type':'none','Config':{}}
    def save(name,value):
        value['digest']=digest_jcs(value)
        fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(value));stream.flush();os.fsync(stream.fileno())
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    save('gate-dispatch.json',{'kind':'FormalTaskGateDispatchIntent',
        'policy_digest':policy['digest'],'configuration_digest':digest_jcs(config),'intent_digest':intent['digest']})
    identifier=engine.create(('skillloop-archive-gate-' if archive_mode else 'skillloop-task-gate-')+intent['digest'][7:39],config)
    save('gate-created.json',{'kind':'FormalTaskGateCreated','container_id':identifier,'policy_digest':policy['digest']})
    def identity(observed):
        if (observed['Id']!=identifier or observed['Image']!=policy['image']
                or observed['Config']['User']!='21005:21005' or observed['Config'].get('Labels')!=config['Labels']
                or observed['HostConfig']['NetworkMode']!='none' or observed['HostConfig']['ReadonlyRootfs'] is not True):
            raise ValueError('formal_gate_actual_process_identity')
        actual=observed['HostConfig'].get('Mounts',[])
        if len(actual)!=len(mounts):raise ValueError('formal_gate_actual_mount_set')
        for wanted in mounts:
            matches=[m for m in actual if m.get('Target')==wanted['Target']]
            if (len(matches)!=1 or any(matches[0].get(k)!=wanted[k] for k in ('Type','Source','ReadOnly'))
                    or matches[0].get('VolumeOptions',{}).get('Subpath')!=wanted.get('VolumeOptions',{}).get('Subpath')):
                raise ValueError('formal_gate_actual_volume_binding')
    try:
        _verify_role_process(engine.inspect(identifier),identifier,config,mounts)
        engine.start(identifier);state=engine.wait(identifier,policy['timeout_seconds'])
        observed=engine.inspect(identifier);identity(observed)
        _verify_role_process(observed,identifier,config,mounts)
        if lifecycle_mode:
            if observed['HostConfig'].get('LogConfig',{}).get('Type')!='none':
                raise ValueError('formal_lifecycle_private_log_custody')
            logs_digest=None
        else:
            logs_digest=_preserve_logs(engine,identifier,directory,'gate-process.log')
        save('gate-completion.json',{'logs_digest':logs_digest,'kind':'FormalTaskGateProcessCompletion','container_id':identifier,
            'policy_digest':policy['digest'],'inspection':observed,'wait_result':state,'evidence_released':False})
        if observed['State']['Running'] or state['StatusCode'] or observed['State']['ExitCode']:
            raise RuntimeError('formal_task_gate_failed_preserve_evidence')
        return observed
    except BaseException as error:
        try:
            observed=engine.inspect(identifier);identity(observed)
            if observed['State']['Running']:engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
        except BaseException as secondary:error.add_note('formal_gate_stop_requires_recovery:'+type(secondary).__name__)
        raise


def dispatch_evaluation(*,entry,intent,capture,assignment_directory,policy,engine):
    if entry.get('kind')=='protected':raise PermissionError('private_evaluation_requires_opaque_evaluator_assignment')
    if os.geteuid()!=21001 or not isinstance(engine,DockerEngine):
        raise PermissionError('formal_evaluation_dispatch_controller')
    if policy.get('digest')!=digest_jcs({k:v for k,v in policy.items() if k!='digest'}):
        raise ValueError('formal_evaluation_dispatch_policy')
    if (policy['entry_digest']!=entry['digest'] or policy['image']!=entry['config']['mac_runtime_image']
            or policy['deployment_epoch']!=intent['deployment_epoch']
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=1200):
        raise ValueError('formal_evaluation_dispatch_frozen_binding')
    if (type(policy.get('maximum_database_bytes')) is not int
            or not 1<=policy['maximum_database_bytes']<=2147483648
            or type(policy.get('snapshot_wait_seconds')) is not int
            or not 1<=policy['snapshot_wait_seconds']<=60
            or policy['timeout_seconds']<=policy['snapshot_wait_seconds']
            or set(policy['mounts'])!={'assignment','runtime','snapshot','evaluation','tokenizer'}):
        raise ValueError('formal_evaluation_dispatch_capacity')
    deadline=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
    if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+60:
        raise ValueError('formal_evaluation_original_budget_exhausted')
    mounts=[]
    for field,target,readonly in (('assignment','/assignment',True),('runtime','/raw',True),
                                 ('snapshot','/authority',True),('evaluation','/evaluation',False),('tokenizer','/model',True)):
        pin=policy['mounts'][field]
        subpath=PurePosixPath(pin['subpath'])
        if (set(pin)!={'volume','subpath'}
                or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}',pin['volume'])
                or not subpath.parts or subpath.is_absolute() or '..' in subpath.parts
                or str(subpath)!=pin['subpath']):
            raise ValueError('formal_evaluation_volume_subpath')
        mounts.append({'Type':'volume','Source':pin['volume'],'Target':target,'ReadOnly':readonly,
                       'VolumeOptions':{'Subpath':pin['subpath']}})
    directory=Path(assignment_directory);info=directory.lstat()
    if (not directory.is_absolute() or directory.is_symlink() or info.st_uid!=21001
            or info.st_gid!=21004 or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('formal_evaluation_assignment_grant')
    assignment={'kind':'FormalEvaluatorAssignment','entry':entry,'intent':intent,'capture':capture,
                'maximum_database_bytes':policy['maximum_database_bytes'],
                'snapshot_wait_seconds':policy['snapshot_wait_seconds'],'campaign_deadline':policy['campaign_deadline']}
    assignment['digest']=digest_jcs(assignment);raw=canonical_json_line(assignment)
    if len(raw)>8388608:raise ValueError('formal_evaluation_assignment_capacity')
    fd=os.open(directory/'job.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'wb') as stream:
        os.fchown(stream.fileno(),-1,21004);os.fchmod(stream.fileno(),0o640)
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    config={'Image':policy['image'],'User':'21004:21004','Entrypoint':['python'],
        'Cmd':['-m','skillloop.discovery.formal_evaluator'],
        'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code',
               'SKILLLOOP_EVALUATOR_ASSIGNMENT=/assignment/job.json'],
        'Labels':{'skillloop.role':'protected_evaluator','skillloop.intent':intent['digest'],
                  'skillloop.dispatch_policy':policy['digest']},
        'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
            'SecurityOpt':['no-new-privileges'],'Memory':1073741824,'NanoCpus':2000000000,
            'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
    # Persist the complete intent before Engine create. Existing intent cannot
    # be replayed automatically after an unknown create/start/wait response.
    journal={'kind':'FormalEvaluationDispatchIntent','policy_digest':policy['digest'],
             'assignment_digest':assignment['digest'],'configuration_digest':digest_jcs(config)}
    journal['digest']=digest_jcs(journal)
    fd=os.open(directory/'dispatch.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(canonical_json_line(journal));stream.flush();os.fsync(stream.fileno())
    identifier=engine.create('skillloop-evaluate-'+assignment['digest'][7:39],config)
    fd=os.open(directory/'container-id',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:stream.write(identifier+'\n');stream.flush();os.fsync(stream.fileno())
    try:
        _verify_role_process(engine.inspect(identifier),identifier,config,mounts)
        engine.start(identifier)
        state=engine.wait(identifier,policy['timeout_seconds'])
        observed=engine.inspect(identifier)
        _verify_role_process(observed,identifier,config,mounts)
        if (observed['Id']!=identifier or observed['Image']!=policy['image'] or observed['State']['Running']
                or observed['Config']['User']!='21004:21004'
                or observed['Config'].get('Labels')!=config['Labels']
                or observed['HostConfig']['NetworkMode']!='none'
                or observed['HostConfig']['ReadonlyRootfs'] is not True):
            raise RuntimeError('formal_evaluation_actual_process_identity')
        actual=observed['HostConfig'].get('Mounts',[])
        if len(actual)!=len(mounts):raise ValueError('formal_evaluation_actual_mount_count')
        for wanted in mounts:
            matches=[m for m in actual if m.get('Target')==wanted['Target']]
            if (len(matches)!=1 or any(matches[0].get(k)!=wanted[k] for k in ('Type','Source','ReadOnly'))
                    or matches[0].get('VolumeOptions',{}).get('Subpath')!=wanted.get('VolumeOptions',{}).get('Subpath')):
                raise ValueError('formal_evaluation_actual_mount_binding')
        logs_digest=_preserve_logs(engine,identifier,directory,'evaluation-process.log')
        record={'logs_digest':logs_digest,'kind':'FormalEvaluationProcessCompletion','container_id':identifier,
                'policy_digest':policy['digest'],'assignment_digest':assignment['digest'],
                'inspection':observed,'wait_result':state,'evidence_released':False}
        record['digest']=digest_jcs(record)
        fd=os.open(directory/'process-completion.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical_json_line(record));stream.flush();os.fsync(stream.fileno())
        if state['StatusCode']!=0 or observed['State']['ExitCode']!=0:raise RuntimeError('formal_independent_evaluation_failed_preserve_evidence')
    except BaseException as error:
        try:
            actual=engine.inspect(identifier)
            if (actual['Id']!=identifier or actual['Image']!=policy['image']
                    or actual['Config'].get('Labels')!=config['Labels']):
                raise RuntimeError('formal_evaluation_unknown_container_preserve_custody')
            if actual['State']['Running']:
                engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
        except BaseException as secondary:
            error.add_note('formal_evaluation_stop_requires_recovery:'+type(secondary).__name__)
        raise
    # Retain process and output for Gate review; Controller cannot manufacture
    # an Evaluator-owned result or release the Runtime's evidence Keeper here.
    return {'container_id':identifier,'assignment_digest':assignment['digest'],
            'inspection':observed,'independent_gate_complete':False,'evidence_released':False}
