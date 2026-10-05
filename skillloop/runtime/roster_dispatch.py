"""Controller dispatches the real roster Gate and consumes its freeze once."""
from datetime import datetime,timezone
import os
from pathlib import Path,PurePosixPath
import re
import stat

from skillloop.ci.campaign_registry import CampaignRegistry
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.proxy.qualification_authority import current_authority
from skillloop.repair.budget import SpendingLedger
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.evaluation_dispatch import _preserve_logs,_verify_role_process
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.round_manifest import read_round_manifest


def dispatch_roster_gate(*,policy,assignment_directory,roster_directory,journal_directory,
                         authority_directory,whole_round_manifest_path,registry,ledger,engine,harden_only=False):
    if type(harden_only) is not bool:raise ValueError('roster_dispatch_mode')
    if (os.geteuid()!=21001 or type(engine) is not DockerEngine
            or type(registry) is not CampaignRegistry or type(ledger) is not SpendingLedger):
        raise PermissionError('roster_dispatch_actual_controller')
    fields={'kind','campaign_digest','image','assignment_digest','whole_round_manifest_digest',
            'campaign_deadline','timeout_seconds','maximum_evidence_bytes','mounts','digest'}
    if (type(policy) is not dict or set(policy)!=fields or policy['kind']!=
            ('FrozenDevelopmentHardenDispatch' if harden_only else 'FrozenDevelopmentRosterDispatch')
            or policy['digest']!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
            or type(policy['timeout_seconds']) is not int or not 1<=policy['timeout_seconds']<=120
            or type(policy['maximum_evidence_bytes']) is not int
            or not 1<=policy['maximum_evidence_bytes']<=268435456):
        raise ValueError('roster_dispatch_original_frozen_policy')
    whole=read_round_manifest(whole_round_manifest_path)
    job=read_owned(Path(assignment_directory)/'job.json',uid=21001,gid=21005,limit=8388608)
    directory=Path(journal_directory);info=directory.lstat()
    if (not directory.is_absolute() or directory.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21001 or stat.S_IMODE(info.st_mode)!=0o700):
        raise PermissionError('roster_dispatch_private_journal')
    output=Path(roster_directory);info=output.lstat()
    if (not output.is_absolute() or output.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21005 or info.st_gid!=21001 or stat.S_IMODE(info.st_mode)!=0o750
            or any(output.iterdir()) or any(directory.iterdir())):
        raise PermissionError('roster_dispatch_fresh_output_or_recovery_required')
    targets={'assignment':'/assignment','whole_round':'/whole-round','evaluation':'/evaluation',
        'task_reviews':'/task-reviews','applications':'/applications','scans':'/scans',
        'scan_reviews':'/scan-reviews','authority':'/authority-projection','roster':'/roster'}
    semantic_mounts=set(targets)|{'semantic','tokenizer'}
    if type(policy['mounts']) is dict and set(policy['mounts'])==semantic_mounts:
        targets.update(semantic='/semantic',tokenizer='/model')
    if type(policy['mounts']) is not dict or set(policy['mounts'])!=set(targets):
        raise ValueError('roster_dispatch_complete_readonly_evidence_mounts')
    mounts=[]
    for key,target in targets.items():
        pin=policy['mounts'][key]
        if type(pin) is not dict or set(pin)!={'volume','subpath'}:
            raise ValueError('roster_dispatch_mount_pin')
        path=PurePosixPath(pin['subpath'])
        if (type(pin['volume']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',pin['volume'])
                or not path.parts or path.is_absolute() or '..' in path.parts or str(path)!=pin['subpath']):
            raise ValueError('roster_dispatch_volume_subpath')
        mounts.append({'Type':'volume','Source':pin['volume'],'Target':target,'ReadOnly':key!='roster',
            'VolumeOptions':{'Subpath':pin['subpath']}})
    config={'Image':policy['image'],'User':'21005:21005','Entrypoint':['python'],
        'Cmd':['-m','skillloop.discovery.formal_harden_gate' if harden_only else 'skillloop.discovery.formal_roster_gate'],
        'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code',
               'SKILLLOOP_RAW_HISTORY_MAX_BYTES='+str(policy['maximum_evidence_bytes'])],
        'Labels':{'skillloop.role':'roster_gate','skillloop.whole_round':whole['digest'],
                  'skillloop.dispatch_policy':policy['digest']},
        'HostConfig':{'GroupAdd':['21001','21004'],'NetworkMode':'none','ReadonlyRootfs':True,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Memory':1073741824,
            'NanoCpus':2000000000,'PidsLimit':64,'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
            'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':mounts}}
    with registry.development_scope(campaign=policy['campaign_digest']) as state:
        deadline=datetime.fromisoformat(state['deadline'].replace('Z','+00:00'))
        spending=ledger.read()
        if (job.get('kind')!='FormalDevelopmentRosterAssignment' or job.get('digest')!=policy['assignment_digest']
                or job.get('bindings')!=state['bindings'] or job.get('deadline')!=state['deadline']
                or policy['campaign_deadline']!=state['deadline']
                or job.get('whole_round_manifest_digest')!=whole['digest']
                or whole['digest']!=policy['whole_round_manifest_digest'] or policy['image']!=whole['image']
                or digest_jcs(job['config'])!=state['bindings']['config_digest']
                or ledger.campaign_started_at is None or deadline.timestamp()!=ledger.campaign_started_at+28800
                or spending.get('campaign_started_at')!=ledger.campaign_started_at
                or spending.get('executions')!=job.get('spent_entries')
                or (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+120):
            raise ValueError('roster_dispatch_original_registry_and_complete_spending')
        cost=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_digest'],stage='repair_pairing',
            operation_key='roster-'+policy['digest'][7:],seconds=policy['timeout_seconds']+60,
            input_tokens=0,output_tokens=0,disk_bytes=policy['maximum_evidence_bytes'])
        _save(directory,'dispatch-intent.json',{'kind':'FormalDevelopmentRosterDispatchIntent',
            'configuration':config,'assignment_digest':job['digest'],'spending':cost})
        identifier=engine.create('skillloop-roster-'+policy['digest'][7:39],config)
        _save(directory,'created.json',{'kind':'FormalDevelopmentRosterCreated','container_id':identifier})
        try:
            _verify_role_process(engine.inspect(identifier),identifier,config,mounts)
            engine.start(identifier);wait=engine.wait(identifier,policy['timeout_seconds'])
            observed=engine.inspect(identifier);_verify_role_process(observed,identifier,config,mounts)
            logs_digest=_preserve_logs(engine,identifier,directory,'process.log')
            _save(directory,'completion.json',{'kind':'FormalDevelopmentRosterProcessCompletion',
                'inspection':observed,'wait_result':wait,'logs_digest':logs_digest})
            if observed['State']['Running'] or wait['StatusCode'] or observed['State']['ExitCode']:
                raise RuntimeError('roster_gate_failed_no_private_epoch_release')
            evidence=read_owned(output/'development-evidence.json',uid=21005,gid=21001,limit=16777216)
            if harden_only:
                from skillloop.proxy.wire import validate_control
                result=read_owned(output/'harden-result.json',uid=21005,gid=21001,limit=262144)
                review=read_owned(output/'harden-review.json',uid=21005,gid=21001,limit=262144)
                validate_control(result)
                applications=evidence['applications']
                if (result['kind']!='HardenResult' or not applications
                        or review.get('kind')!='FormalDevelopmentHardenReview'
                        or review.get('assignment_digest')!=job['digest']
                        or review.get('development_evidence_digest')!=evidence['digest']
                        or review.get('result_digest')!=result['digest']
                        or review.get('roster_frozen') is not False or review.get('qualification_issued') is not False
                        or review.get('repair_round')!=applications[-1]['repair_round']
                        or result['body']['campaign_public_ref']!=policy['campaign_digest']
                        or result['body']['parent_subject_digest']!=applications[-1]['parent_subject_digest']
                        or result['body']['candidate_subject_digest']!=applications[-1]['candidate_bundle_digest']
                        or result['body']['patch_application_digest']!=applications[-1]['application_digest']
                        or os.path.lexists(output/'freeze.json')):
                    raise ValueError('harden_dispatch_actual_current_review_chain')
            else:
                freeze=read_owned(output/'freeze.json',uid=21005,gid=21001,limit=262144)
            if not harden_only and (freeze.get('kind')!='FrozenCampaignSubjectRoster'
                    or freeze.get('development_evidence_digest')!=evidence['digest']
                    or evidence.get('assignment_digest')!=job['digest']
                    or freeze.get('development_plan_digest')!=job['plan']['digest']
                    or freeze.get('subjects')!=evidence.get('subjects')):
                raise ValueError('roster_dispatch_actual_gate_freeze_chain')
        except BaseException as error:
            try:
                observed=engine.inspect(identifier);_verify_role_process(observed,identifier,config,mounts)
                if observed['State']['Running']:engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
                _save(directory,'failure.json',{'kind':'FormalDevelopmentRosterFailure','container_id':identifier,
                    'reason':str(error),'error_type':type(error).__name__,'automatic_replay_allowed':False})
            except BaseException as secondary:error.add_note('roster_custody_requires_recovery:'+type(secondary).__name__)
            raise
    if harden_only:
        _save(directory,'consumed.json',{'kind':'FormalDevelopmentHardenConsumed',
            'review_digest':review['digest'],'result_digest':result['digest'],
            'container_id':identifier,'roster_frozen':False,'qualification_issued':False})
        return result
    # The Gate review ran under the registry read transaction. Now serialize
    # consuming its result with live Proxy approval/plan-head publication too.
    with current_authority(authority_directory,epoch=state['bindings']['deployment_epoch'],
            config_digest=state['bindings']['config_digest'],trust_revision=state['bindings']['trust_revision'],
            approval_digests=job['approval_digests'],campaign=policy['campaign_digest']) as authority:
        heads=[h for h in authority.get('plan_heads',[]) if h['campaign_id']==policy['campaign_digest']]
        if len(heads)!=1 or heads[0]['plan_digest']!=job['plan']['digest']:
            raise ValueError('roster_dispatch_proxy_plan_changed_before_consumption')
        final=registry.freeze_subjects(campaign=policy['campaign_digest'],gate_freeze_path=output/'freeze.json')
    _save(directory,'consumed.json',{'kind':'FormalDevelopmentRosterConsumed',
        'freeze_digest':freeze['digest'],'final_bindings':final,'container_id':identifier,'qualification_issued':False})
    return {'freeze':freeze,'bindings':final,'inspection':observed,'container_id':identifier}
