"""Create the current Runtime's bounded evidence volume and original Keeper.

This is per-task custody, not a proof of the full campaign's physical quota.
Creation and start intents precede Engine calls; unknown calls are never repeated.
"""
from datetime import datetime,timezone
import os,re
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.protection.current_task import _directory
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.protected_flow import _controller_record
from skillloop.runtime.docker_api import DockerEngine,DockerEngineError
from skillloop.runtime.evaluation_dispatch import _verify_role_process
from skillloop.runtime.round_manifest import read_round_manifest
from skillloop.repair.budget import SpendingLedger
from skillloop.ci.campaign_registry import CampaignRegistry


def prepare_private_resources(*,policy_path,reference_path,journal_directory,whole_round_manifest_path,engine,ledger,registry):
    if (os.geteuid()!=21001 or type(engine) is not DockerEngine
            or type(ledger) is not SpendingLedger or type(registry) is not CampaignRegistry):
        raise PermissionError('private_resources_actual_controller')
    policy=read_owned(policy_path,uid=21010,gid=21001,limit=262144)
    fields={'kind','campaign_id','deployment_epoch','image','whole_round_manifest_digest','campaign_deadline',
        'maximum_bytes','timeout_seconds','digest'}
    if (set(policy)!=fields or policy['kind']!='FrozenPrivateRuntimeResources'
            or type(policy['maximum_bytes']) is not int or not 1048576<=policy['maximum_bytes']<=20971520
            or policy['maximum_bytes']%4096 or type(policy['timeout_seconds']) is not int
            or not 1<=policy['timeout_seconds']<=120):
        raise ValueError('private_resources_original_policy')
    whole=read_round_manifest(whole_round_manifest_path)
    reference=read_owned(reference_path,uid=21004,gid=21001,limit=262144)
    if (whole['digest']!=policy['whole_round_manifest_digest'] or whole['image']!=policy['image']
            or whole['deployment_epoch']!=policy['deployment_epoch']
            or reference.get('kind')!='EvaluatorOpaqueRunReference'
            or any(reference.get(k)!=policy[k] for k in ('campaign_id','deployment_epoch'))
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',reference.get('run_request_digest',''))):
        raise ValueError('private_resources_current_reference')
    root=_directory(journal_directory,21001,21001,0o700)
    identity=digest_jcs({'policy_digest':policy['digest'],'reference_digest':reference['digest']})
    labels={'skillloop.deployment_epoch':policy['deployment_epoch'],'skillloop.run_request':reference['run_request_digest'],
        'skillloop.private_resource':identity}
    volume_name='skillloop-private-'+identity[7:47];name='skillloop-private-keeper-'+identity[7:39]
    options={'type':'tmpfs','device':'tmpfs',
        'o':'size='+str(policy['maximum_bytes'])+',uid=21002,gid=21002,mode=0700'}
    deadline=datetime.fromisoformat(policy['campaign_deadline'].replace('Z','+00:00'))
    if deadline.tzinfo is None or ledger.campaign_started_at is None or deadline.timestamp()!=ledger.campaign_started_at+28800:
        raise ValueError('private_resources_original_clock')
    def volume_identity(value):
        if (value.get('Name')!=volume_name or value.get('Driver')!='local' or value.get('Options')!=options
                or value.get('Labels')!=labels):raise ValueError('private_resources_original_volume_identity')
    def keeper_identity(value,config):
        _verify_role_process(value,value['Id'],config,config['HostConfig']['Mounts'])
        if value.get('Name')!='/'+name:raise ValueError('private_resources_original_keeper_name')
        actual=[m for m in value.get('Mounts',[]) if m.get('Type')=='volume' and m.get('Name')==volume_name
            and m.get('Destination')=='/held' and m.get('RW') is False]
        if len(actual)!=1:raise ValueError('private_resources_original_keeper_mount')
    with registry.private_scope(campaign=policy['campaign_id']) as state:
        if state['gate_freeze']['deadline']!=policy['campaign_deadline']:
            raise ValueError('private_resources_original_registry')
        if (root/'completion.json').exists():
            result=_controller_record(root/'completion.json')
            if (result.get('kind')!='PrivateRuntimeResourcesReady' or result.get('resource_identity')!=identity
                    or result.get('budget_closure')!='within_original_budget'):
                raise ValueError('private_resources_changed_original_completion')
            volume_identity(engine.inspect_volume(volume_name))
            actual=engine.inspect(result['keeper']['Id']);keeper_identity(actual,result['configuration'])
            if actual['State']['Running'] is not True:raise RuntimeError('private_resources_original_keeper_no_longer_alive')
            return result
        if not (root/'intent.json').exists():
            if any(root.iterdir()):raise RuntimeError('private_resources_unrecognized_partial_journal')
            remaining=(deadline-datetime.now(timezone.utc)).total_seconds()
            if remaining<=policy['timeout_seconds']+120:raise TimeoutError('private_resources_full_original_budget')
            # The deadline closes authorization, not the only live mount of
            # this tmpfs. A failed or delayed archive must retain its original
            # bytes until the independently reviewed retirement stops Keeper.
            config={'Image':policy['image'],'User':'21001:21001','Entrypoint':['python'],
                'Cmd':['-c','import time; time.sleep(2147483647)'],'Env':['PYTHONDONTWRITEBYTECODE=1'],
                'Labels':{**labels,'skillloop.role':'private_evidence_keeper'},
                'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
                    'SecurityOpt':['no-new-privileges'],'Memory':67108864,'NanoCpus':1000000000,'PidsLimit':16,
                    'Ulimits':[{'Name':'nofile','Soft':64,'Hard':64}],'LogConfig':{'Type':'none','Config':{}},
                    'Mounts':[{'Type':'volume','Source':volume_name,'Target':'/held','ReadOnly':True}]}}
            _save(root,'intent.json',{'kind':'PrivateRuntimeResourcesIntent','resource_identity':identity,
                'policy_digest':policy['digest'],'reference_digest':reference['digest'],'configuration':config,
                'volume_name':volume_name,'container_name':name,'started_at':datetime.now(timezone.utc).isoformat(),
                'automatic_replacement_allowed':False})
        intent=_controller_record(root/'intent.json')
        if (intent.get('resource_identity')!=identity or intent.get('policy_digest')!=policy['digest']
                or intent.get('reference_digest')!=reference['digest']):raise ValueError('private_resources_changed_intent')
        config=intent['configuration'];started=datetime.fromisoformat(intent['started_at'])
        def budget():
            if (datetime.now(timezone.utc)-started).total_seconds()>policy['timeout_seconds'] or datetime.now(timezone.utc)>=deadline:
                raise TimeoutError('private_resources_original_startup_budget_expired')
        if not (root/'spending.json').exists():
            cost=ledger.consume_auxiliary(manifest=whole,campaign=policy['campaign_id'],stage='protected',
                operation_key='private-resources-'+identity[7:],seconds=policy['timeout_seconds'],
                input_tokens=0,output_tokens=0,disk_bytes=policy['maximum_bytes']+1048576)
            _save(root,'spending.json',{'kind':'PrivateRuntimeResourcesSpending','spending':cost})
        cost=_controller_record(root/'spending.json')['spending']
        if (cost.get('operation_key')!='private-resources-'+identity[7:]
                or cost.get('requested_cost')!={'seconds':policy['timeout_seconds'],'input_tokens':0,
                    'output_tokens':0,'disk_bytes':policy['maximum_bytes']+1048576}
                or cost not in ledger.read().get('auxiliary_executions',[])):
            raise ValueError('private_resources_original_spending')
        try:
            budget()
            if (root/'volume-create-intent.json').exists():
                volume=engine.inspect_volume(volume_name)
            else:
                try:engine.inspect_volume(volume_name)
                except DockerEngineError as error:
                    if error.status!=404:raise
                else:raise ValueError('private_resources_existing_foreign_volume')
                _save(root,'volume-create-intent.json',{'kind':'PrivateVolumeCreationIntent','resource_identity':identity})
                volume=engine.create_volume(volume_name,driver_options=options,labels=labels)
            volume_identity(volume)
            if not (root/'volume.json').exists():_save(root,'volume.json',{'kind':'PrivateVolumeCreated','volume':volume})
            budget()
            if (root/'keeper-create-intent.json').exists():
                keeper=engine.request('GET','/containers/'+name+'/json')
                keeper_identity(keeper,config);identifier=keeper['Id']
                created=datetime.fromisoformat(keeper['Created'].replace('Z','+00:00'))
                creation=_controller_record(root/'keeper-create-intent.json')
                if not datetime.fromisoformat(creation['at'])<=created<=datetime.now(timezone.utc):
                    raise ValueError('private_resources_original_keeper_creation_time')
            else:
                _save(root,'keeper-create-intent.json',{'kind':'PrivateKeeperCreationIntent','at':datetime.now(timezone.utc).isoformat(),
                    'resource_identity':identity})
                identifier=engine.create(name,config);keeper=engine.inspect(identifier);keeper_identity(keeper,config)
            if not (root/'keeper-created.json').exists():_save(root,'keeper-created.json',{'kind':'PrivateKeeperCreated','inspection':keeper})
            elif _controller_record(root/'keeper-created.json')['inspection']['Id']!=identifier:
                raise ValueError('private_resources_changed_original_keeper_id')
            budget()
            if (root/'keeper-start-intent.json').exists():
                keeper=engine.inspect(identifier);keeper_identity(keeper,config)
                if keeper['State']['Running'] is not True:raise RuntimeError('private_resources_original_start_unknown_no_restart')
            else:
                _save(root,'keeper-start-intent.json',{'kind':'PrivateKeeperStartIntent','at':datetime.now(timezone.utc).isoformat(),
                    'container_id':identifier})
                engine.start(identifier);keeper=engine.inspect(identifier);keeper_identity(keeper,config)
            start=_controller_record(root/'keeper-start-intent.json')
            if (keeper['State']['Running'] is not True or start['container_id']!=keeper['Id']
                    or datetime.fromisoformat(keeper['State']['StartedAt'].replace('Z','+00:00'))<datetime.fromisoformat(start['at'])):
                raise ValueError('private_resources_original_keeper_start_proof')
            budget()
            return _save(root,'completion.json',{'kind':'PrivateRuntimeResourcesReady','resource_identity':identity,
                'policy_digest':policy['digest'],'reference_digest':reference['digest'],'volume':volume,
                'keeper':keeper,'configuration':config,'evidence_pin':{'volume':volume_name,'subpath':None},
                'maximum_bytes':policy['maximum_bytes'],'spending':cost,'budget_closure':'within_original_budget',
                'keeper_alive_before_runtime_write':True,'full_campaign_physical_quota_verified':False,'qualification_issued':False})
        except BaseException as error:
            try:
                if not (root/'failure.json').exists():
                    _save(root,'failure.json',{'kind':'PrivateRuntimeResourcesFailure','resource_identity':identity,
                        'error_type':type(error).__name__,'automatic_replacement_allowed':False,'volumes_removed':False})
            except BaseException as custody_error:
                error.add_note('private_resources_failure_custody:'+type(custody_error).__name__)
            raise
