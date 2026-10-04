"""All eleven frozen role templates and actual bounded directory provisioning.

Worker roles are launched on demand, not as idle placeholder services. Every
role config comes from the same Admin manifest and actual Engine identity.
"""
from datetime import datetime,timezone
import os,re
from pathlib import Path,PurePosixPath
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.evaluation_dispatch import _verify_role_process
from skillloop.runtime.protected_flow import _controller_record
from skillloop.protocol import digest_jcs

ROLES={'controller':21001,'runtime':21002,'proxy':21003,'protected_evaluator':21004,'gate':21005,
       'generator':21006,'patcher':21007,'scanner':21008,'report':21009,'admin':21010,'model_gateway':21011}
MODULES={'controller':{'skillloop.runtime.operator_service'},'runtime':{'scripts.mac_agent_runtime'},
    'proxy':{'skillloop.proxy.service'},'protected_evaluator':{'skillloop.protection.formal_factory','skillloop.protection.formal_session'},
    'gate':{'skillloop.ci.campaign_gate','skillloop.discovery.formal_task_gate','skillloop.runtime.private_retirement','skillloop.discovery.formal_roster_gate','skillloop.repair.formal_application_gate','skillloop.protection.model_lifecycle_gate'},
    'generator':{'skillloop.runtime.proposal_worker'},'patcher':{'skillloop.runtime.proposal_worker'},
    'report':{'skillloop.runtime.role_command_worker'},'admin':{'skillloop.runtime.role_command_worker'},
    'model_gateway':{'skillloop.runtime.model_bridge_service','skillloop.discovery.semantic_worker'}}


class WholeRoleDeployment:
    def __init__(self,*,manifest_path,journal_directory,engine,ledger,whole_round_manifest_path):
        if os.geteuid()!=21001 or type(engine) is not DockerEngine:raise PermissionError('whole_deployment_actual_controller')
        from skillloop.repair.budget import SpendingLedger
        from skillloop.runtime.round_manifest import read_round_manifest
        if type(ledger) is not SpendingLedger:raise PermissionError('whole_deployment_original_spending_required')
        self.ledger=ledger;self.whole=read_round_manifest(whole_round_manifest_path)
        self.plan=read_owned(manifest_path,uid=21010,gid=21001,limit=2097152);self.manifest_path=str(manifest_path);self.engine=engine
        from skillloop.protection.current_task import _directory
        self.root=_directory(journal_directory,21001,21001,0o700)
        p=self.plan
        if (set(p)!={'kind','campaign_digest','whole_round_manifest_digest','deployment_epoch','deadline','image','source_digest','bootstrap_mount','volume',
            'volume_bytes','operator_uids','directories','documents','external_volumes','roles','bootstrap_seconds','digest'} or p['kind']!='FrozenWholeRoleDeployment'
                or set(p['roles'])!=set(ROLES) or not re.fullmatch(r'sha256:[0-9a-f]{64}',p['image'])
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',p['source_digest'])
                or type(p['volume_bytes']) is not int or not 1048576<=p['volume_bytes']<=2147483648
                or type(p['bootstrap_seconds']) is not int or not 1<=p['bootstrap_seconds']<=120):
            raise ValueError('whole_deployment_complete_frozen_roles')
        if type(p['operator_uids']) is not list or any(type(uid) is not int or uid<1 or uid in range(21002,21010) or uid==21011 for uid in p['operator_uids']):
            raise ValueError('whole_deployment_operator_identity_boundary')
        self.deadline=datetime.fromisoformat(p['deadline'].replace('Z','+00:00'))
        if (p['whole_round_manifest_digest']!=self.whole['digest'] or p['deployment_epoch']!=self.whole['deployment_epoch']
                or p['image']!=self.whole['image'] or p['source_digest']!=self.whole['source_digest']
                or ledger.campaign_started_at is None or self.deadline.timestamp()!=ledger.campaign_started_at+28800):
            raise ValueError('whole_deployment_original_source_clock_budget')
        self.validate_roles()
    def validate_roles(self):
        directories={d['path']:d for d in self.plan['directories']}
        if any(d['privacy'] not in {'configuration','public','development','opaque','protected','current_private','control'} for d in directories.values()):
            raise ValueError('whole_deployment_declared_privacy')
        for d in directories.values():
            if d['privacy']=='protected' and d['uid'] not in {21004,21005}:
                raise PermissionError('whole_deployment_private_custodian_required')
            if d['privacy']=='current_private' and d['uid'] not in {21002,21004,21005}:
                raise PermissionError('whole_deployment_current_task_custody')
        if len(directories)!=len(self.plan['directories']):raise ValueError('whole_deployment_duplicate_directory')
        for role,uid in ROLES.items():
            template=self.plan['roles'][role];config=template['config']
            if set(template)!={'config','private_read_scope'}:raise ValueError('whole_role_template_shape')
            hc=config['HostConfig'];cmd=config['Cmd']
            groups=hc.get('GroupAdd',[])
            if (type(groups) is not list or any(type(g) is not str or not g.isdecimal() for g in groups)
                    or len(groups)!=len(set(groups))):
                raise ValueError('whole_role_supplementary_groups')
            permitted={str(uid),'21001'}
            for declared in self.plan['directories']:
                if (declared['privacy'] not in {'protected','current_private'}
                        or role in {'protected_evaluator','gate'}
                        or declared['privacy']=='current_private' and role=='runtime'):
                    permitted.add(str(declared['gid']))
            if not set(groups)<=permitted or role in {'admin','report'} and '21001' not in groups:
                raise PermissionError('whole_role_evidence_group_boundary')
            if type(config.get('Env')) is not list:
                raise ValueError('whole_role_explicit_environment_required')
            valid_entry=(cmd[:1]==['-m'] and len(cmd)==2 and cmd[1] in MODULES.get(role,set()))
            if role=='scanner':valid_entry=cmd==['/opt/skillloop-scanner/offline_osv.py','scan','/subject/SKILL.md','--no-llm','--format','json','--output','/report/report.json']
            if (not valid_entry or config.get('Entrypoint')!=['python'] or config.get('User')!=str(uid)+':'+str(uid)
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}',config.get('Image',''))
                    or config.get('Labels',{}).get('skillloop.deployment_epoch')!=self.plan['deployment_epoch']
                    or hc.get('ReadonlyRootfs') is not True or hc.get('CapDrop')!=['ALL']
                    or 'no-new-privileges' not in hc.get('SecurityOpt',[])
                    or hc.get('NetworkMode')!=('bridge' if role=='model_gateway' else 'none')
                    or hc.get('LogConfig',{}).get('Type')!='none'
                    or hc.get('Privileged',False) is not False or hc.get('CapAdd')
                    or type(hc.get('Memory')) is not int or not 134217728<=hc['Memory']<=4294967296
                    or hc.get('NanoCpus')!=2000000000 or hc.get('PidsLimit')!=64
                    or hc.get('Ulimits')!=[{'Name':'nofile','Soft':128,'Hard':128}]
                    or hc.get('RestartPolicy',{}).get('Name','no')!='no'
                    or hc.get('PidMode','') or hc.get('IpcMode','private') not in {'','private'}
                    or hc.get('Tmpfs')!={'/tmp':'rw,nosuid,nodev,size=64m'}):
                raise ValueError('whole_role_actual_identity_and_isolation:'+role)
            for mount in hc['Mounts']:
                if mount['Type']=='bind':
                    if role!='controller' or mount.get('Source')!='/var/run/docker.sock' or mount.get('Target')!='/engine.sock' or mount.get('ReadOnly') is not False:
                        raise PermissionError('whole_role_host_mount_forbidden')
                    continue
                if mount['Type']!='volume':raise PermissionError('whole_role_only_pinned_volumes')
                if mount['Source']!=self.plan['volume']:
                    external=self.plan['external_volumes'].get(mount['Source'])
                    if (not mount.get('ReadOnly') or external is None or role not in external['allowed_roles']
                            or external['privacy'] not in {'configuration','public','model'}):
                        raise PermissionError('whole_role_external_volume_provenance')
                    continue
                sub=mount.get('VolumeOptions',{}).get('Subpath');directory=directories.get(sub)
                if directory is None:raise ValueError('whole_role_declared_subpath_required')
                privacy=directory['privacy']
                if privacy=='protected' and role not in {'protected_evaluator','gate'}:
                    raise PermissionError('whole_role_full_private_mount_forbidden')
                if privacy=='current_private' and role not in {'protected_evaluator','gate','runtime'}:
                    raise PermissionError('whole_role_current_private_mount_forbidden')
                if role=='report' and privacy not in {'public','configuration'}:raise PermissionError('report_only_public_mount')
                if not mount['ReadOnly'] and directory['uid']!=uid:raise PermissionError('whole_role_cross_owner_write')
    def provision(self):
        p=self.plan
        if (self.root/'provisioned.json').exists():return _controller_record(self.root/'provisioned.json')
        if any(self.root.iterdir()):raise RuntimeError('whole_deployment_original_bootstrap_recovery_required')
        if self.deadline.tzinfo is None or (self.deadline-datetime.now(timezone.utc)).total_seconds()<=p['bootstrap_seconds']+120:
            raise TimeoutError('whole_deployment_original_clock')
        _save(self.root,'provision-intent.json',{'kind':'WholeRoleProvisionIntent','manifest_digest':p['digest']})
        spending=self.ledger.consume_auxiliary(manifest=self.whole,campaign=p['campaign_digest'],
            stage='approval_deployment',operation_key='deploy-'+p['digest'][7:],seconds=p['bootstrap_seconds']+120,
            input_tokens=0,output_tokens=0,disk_bytes=p['volume_bytes']+2097152)
        _save(self.root,'spending.json',{'kind':'WholeRoleProvisionSpending','spending':spending})
        volume=self.engine.create_volume(p['volume'],driver_options={'type':'tmpfs','device':'tmpfs',
            'o':'size='+str(p['volume_bytes'])+',mode=0700'},labels={'skillloop.deployment_epoch':p['deployment_epoch']})
        _save(self.root,'volume.json',{'kind':'WholeRoleDeploymentVolume','inspection':volume})
        # The readonly Keeper starts before the first directory/config write.
        keeper_config={'Image':p['image'],'User':'21001:21001','Entrypoint':['python'],
            'Cmd':['-c','import time;time.sleep('+str(max(1,int((self.deadline-datetime.now(timezone.utc)).total_seconds())))+')'],
            'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
                'Memory':134217728,'PidsLimit':16,'LogConfig':{'Type':'none','Config':{}},
                'Mounts':[{'Type':'volume','Source':p['volume'],'Target':'/deployment-data','ReadOnly':True}]},
            'Labels':{'skillloop.deployment_epoch':p['deployment_epoch'],'skillloop.role':'deployment_keeper'}}
        keeper=self.engine.create('skillloop-keeper-'+p['digest'][7:31],keeper_config)
        _save(self.root,'keeper-created.json',{'kind':'WholeRoleKeeperCreated','id':keeper,'configuration':keeper_config})
        self.engine.start(keeper);live=self.engine.inspect(keeper)
        if live['State']['Running'] is not True or live['Image']!=p['image']:raise RuntimeError('whole_role_keeper_not_live')
        mounts=[{'Type':'volume','Source':p['volume'],'Target':'/deployment-data','ReadOnly':False},
                {'Type':'volume','Source':p['bootstrap_mount']['volume'],'Target':'/bootstrap','ReadOnly':True,
                 'VolumeOptions':{'Subpath':p['bootstrap_mount']['subpath']}}]
        config={'Image':p['image'],'User':'0:0','Entrypoint':['python'],'Cmd':['-m','skillloop.runtime.deployment_bootstrap'],
            'Env':['PYTHONDONTWRITEBYTECODE=1','PYTHONPATH=/code/scripts/vendor:/code',
                   'SKILLLOOP_DEPLOYMENT_DIGEST='+p['digest']],
            'Labels':{'skillloop.deployment_epoch':p['deployment_epoch'],'skillloop.role':'trusted_directory_bootstrap'},
            'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
                'CapAdd':['CHOWN','FOWNER','DAC_OVERRIDE'],'SecurityOpt':['no-new-privileges'],
                'Memory':134217728,'NanoCpus':1000000000,'PidsLimit':16,
                'LogConfig':{'Type':'none','Config':{}},'Mounts':mounts}}
        identifier=self.engine.create('skillloop-bootstrap-'+p['digest'][7:31],config)
        _save(self.root,'bootstrap-created.json',{'kind':'WholeRoleBootstrapCreated','id':identifier,'configuration':config})
        self.engine.start(identifier);wait=self.engine.wait(identifier,p['bootstrap_seconds']);actual=self.engine.inspect(identifier)
        if wait['StatusCode'] or actual['State']['ExitCode'] or actual['State']['Running']:
            raise RuntimeError('whole_role_bootstrap_failed_volume_preserved')
        return _save(self.root,'provisioned.json',{'kind':'WholeRoleProvisionCompletion','manifest_digest':p['digest'],
            'keeper':self.engine.inspect(keeper),'bootstrap':actual,'role_uids':ROLES,
            'runtime_acceptance_complete':False,'qualification_issued':False})
    def create_role(self,role,operation_id):
        if role not in ROLES or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',operation_id):raise ValueError('whole_role_operation')
        provisioned=self.provision();live=self.engine.inspect(provisioned['keeper']['Id'])
        if live['State']['Running'] is not True:raise RuntimeError('whole_role_keeper_expired')
        filename='role-'+digest_jcs({'role':role,'operation':operation_id})[7:]+'.json'
        if (self.root/(filename+'.created')).exists():
            original=_controller_record(self.root/(filename+'.created'))
            actual=self.engine.inspect(original['id'])
            if actual.get('Config')!=original['inspection'].get('Config') or actual.get('Image')!=original['inspection'].get('Image'):
                raise ValueError('whole_role_original_created_identity_changed')
            return original
        if (self.root/filename).exists():raise RuntimeError('whole_role_original_create_requires_recovery')
        config=self.plan['roles'][role]['config']
        _save(self.root,filename,{'kind':'WholeRoleCreateIntent','role':role,'operation':operation_id,'configuration':config})
        spending=self.ledger.consume_auxiliary(manifest=self.whole,campaign=self.plan['campaign_digest'],
            stage='approval_deployment',operation_key='role-create-'+digest_jcs({'role':role,'operation':operation_id})[7:],
            seconds=60,input_tokens=0,output_tokens=0,disk_bytes=2097152)
        _save(self.root,filename+'.cost',{'kind':'WholeRoleCreateSpending','spending':spending})
        identifier=self.engine.create('skillloop-'+role+'-'+digest_jcs(operation_id)[7:31],config)
        actual=self.engine.inspect(identifier);_verify_role_process(actual,identifier,config,config['HostConfig']['Mounts'],controller_engine_bind=role=='controller')
        return _save(self.root,filename+'.created',{'kind':'WholeRoleCreated','role':role,'id':identifier,'inspection':actual})

    def start_role(self,role,operation_id):
        created=self.create_role(role,operation_id);identifier=created['id']
        token=digest_jcs({'role':role,'operation':operation_id})[7:]
        completed=self.root/('start-'+token+'.complete.json')
        intent=self.root/('start-'+token+'.intent.json')
        if completed.exists():return _controller_record(completed)
        if intent.exists():
            actual=self.engine.inspect(identifier)
            original=created['inspection']
            if (actual.get('Config')!=original.get('Config') or actual.get('Image')!=original.get('Image')
                    or actual.get('State',{}).get('StartedAt') in {None,'0001-01-01T00:00:00Z'}):
                raise RuntimeError('whole_role_unknown_original_start_no_replay')
            # Inspection proves this same container started. Never start a
            # stopped worker again, even when its original response was lost.
        else:
            _save(self.root,intent.name,{'kind':'WholeRoleStartIntent','created_digest':created['digest'],'id':identifier})
            self.engine.start(identifier);actual=self.engine.inspect(identifier)
        return _save(self.root,completed.name,{'kind':'WholeRoleStartObserved','created_digest':created['digest'],
            'inspection':actual,'qualification_issued':False})
