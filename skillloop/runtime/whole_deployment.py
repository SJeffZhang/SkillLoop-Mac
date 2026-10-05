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
MODULES={'controller':{'skillloop.runtime.operator_service'},'runtime':{'scripts.mac_agent_runtime','skillloop.runtime.private_evidence_handoff'},
    'proxy':{'skillloop.proxy.service'},'protected_evaluator':{'skillloop.protection.formal_factory','skillloop.protection.formal_session','skillloop.discovery.formal_evaluator'},
    'gate':{'skillloop.ci.qualification_withdrawal','skillloop.ci.campaign_gate','skillloop.discovery.formal_task_gate','skillloop.runtime.private_retirement','skillloop.discovery.formal_roster_gate','skillloop.repair.formal_application_gate','skillloop.protection.model_lifecycle_gate','skillloop.runtime.encrypted_archive','skillloop.runtime.encrypted_restore'},
    'generator':{'skillloop.runtime.proposal_worker'},'patcher':{'skillloop.runtime.proposal_worker'},
    'report':{'skillloop.runtime.role_command_worker'},'admin':{'skillloop.runtime.role_command_worker','skillloop.runtime.archive_key_service'},
    'model_gateway':{'skillloop.runtime.model_bridge_service','skillloop.discovery.semantic_worker'}}
MODULES['gate'].add('skillloop.discovery.formal_harden_gate')


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
            'storage_backend','provisioning_bytes','engine_socket_gid','operator_uids','directories','documents','external_volumes','roles','bootstrap_seconds','digest'} or p['kind']!='FrozenWholeRoleDeployment'
                or set(p['roles'])!=set(ROLES) or not re.fullmatch(r'sha256:[0-9a-f]{64}',p['image'])
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',p['source_digest'])
                or p['storage_backend']!='local_persistent'
                or type(p['engine_socket_gid']) is not int or not 0<=p['engine_socket_gid']<=4294967294
                or type(p['provisioning_bytes']) is not int or not 1048576<=p['provisioning_bytes']<=16777216
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
        return self.validate_roles_manifest(self.plan)

    @staticmethod
    def validate_roles_manifest(plan):
        # A role keeps one UID/authority boundary while using separately frozen
        # entries for lifecycle review, task Gate and campaign Gate. Changing
        # templates after bootstrap previously required reprovisioning the same
        # volume, which correctly refused to overwrite existing directories.
        variants=[]
        for role,template in plan['roles'].items():
            if 'entry_variants' not in template:continue
            declared=template['entry_variants']
            if (set(template)!={'config','private_read_scope','entry_variants'}
                    or type(declared) is not dict or len(declared)>len(MODULES.get(role,set()))):
                raise ValueError('whole_role_frozen_entry_variants')
            for module,entry in declared.items():
                if (module not in MODULES.get(role,set()) or type(entry) is not dict
                        or set(entry)!={'config','private_read_scope'}
                        or entry['config'].get('Cmd')!=['-m',module]
                        or entry['config']['Cmd']==template['config'].get('Cmd')):
                    raise ValueError('whole_role_exact_frozen_entry_variant')
                variants.append((role,entry))
        if any('entry_variants' in t for t in plan['roles'].values()):
            base={**plan,'roles':{role:{k:v for k,v in entry.items() if k!='entry_variants'}
                                for role,entry in plan['roles'].items()}}
            WholeRoleDeployment.validate_roles_manifest(base)
            for role,entry in variants:
                WholeRoleDeployment.validate_roles_manifest({**base,'roles':{**base['roles'],role:entry}})
            return
        from skillloop.runtime.deployment_bootstrap import validate_directory_manifest
        validate_directory_manifest(plan)
        directories={d['path']:d for d in plan['directories']}
        if any(d['privacy'] not in {'configuration','public','development','opaque','protected','current_private','control'} for d in directories.values()):
            raise ValueError('whole_deployment_declared_privacy')
        for d in directories.values():
            if d['privacy']=='protected' and d['uid'] not in {21004,21005}:
                raise PermissionError('whole_deployment_private_custodian_required')
            if d['privacy']=='current_private' and d['uid'] not in {21002,21004,21005}:
                raise PermissionError('whole_deployment_current_task_custody')
        if len(directories)!=len(plan['directories']):raise ValueError('whole_deployment_duplicate_directory')
        for role,uid in ROLES.items():
            template=plan['roles'][role];config=template['config']
            if set(template)!={'config','private_read_scope'}:raise ValueError('whole_role_template_shape')
            hc=config['HostConfig'];cmd=config['Cmd']
            groups=hc.get('GroupAdd',[])
            if (type(groups) is not list or any(type(g) is not str or not g.isdecimal() for g in groups)
                    or len(groups)!=len(set(groups))):
                raise ValueError('whole_role_supplementary_groups')
            permitted={str(uid),'21001'}
            if role=='controller':
                if type(plan.get('engine_socket_gid')) is not int or not 0<=plan['engine_socket_gid']<=4294967294:
                    raise ValueError('whole_controller_engine_socket_gid')
                permitted.add(str(plan['engine_socket_gid']))
                if str(plan['engine_socket_gid']) not in groups:
                    raise PermissionError('whole_controller_engine_socket_group_required')
            for declared in plan['directories']:
                if (declared['privacy'] not in {'protected','current_private'}
                        or role in {'protected_evaluator','gate'}
                        or declared['privacy']=='current_private' and role=='runtime'):
                    permitted.add(str(declared['gid']))
            if not set(groups)<=permitted or role in {'admin','report'} and '21001' not in groups:
                raise PermissionError('whole_role_evidence_group_boundary')
            if type(config.get('Env')) is not list:
                raise ValueError('whole_role_explicit_environment_required')
            environment=config['Env']
            if (any(type(item) is not str or '=' not in item or '\x00' in item for item in environment)
                    or len({item.split('=',1)[0] for item in environment})!=len(environment)):
                raise ValueError('whole_role_unique_explicit_environment')
            valid_entry=(cmd[:1]==['-m'] and len(cmd)==2 and cmd[1] in MODULES.get(role,set()))
            if role=='scanner':valid_entry=cmd==['/opt/skillloop-scanner/offline_osv.py','scan','/subject/SKILL.md','--no-llm','--format','json','--output','/report/report.json']
            if (not valid_entry or config.get('Entrypoint')!=['python'] or config.get('User')!=str(uid)+':'+str(uid)
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}',config.get('Image',''))
                    or role!='scanner' and config.get('Image')!=plan['image']
                    or config.get('Labels',{}).get('skillloop.deployment_epoch')!=plan['deployment_epoch']
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
            mounts=hc.get('Mounts')
            scope=template['private_read_scope']
            if (type(scope) is not list or any(type(path) is not str or path not in directories for path in scope)
                    or scope!=sorted(set(scope))):
                raise ValueError('whole_role_exact_private_read_scope')
            observed_private=set()
            if (type(mounts) is not list or not mounts
                    or any(type(m) is not dict or type(m.get('Target')) is not str
                        or not PurePosixPath(m['Target']).is_absolute()
                        or '..' in PurePosixPath(m['Target']).parts
                        or str(PurePosixPath(m['Target']))!=m['Target']
                        or type(m.get('ReadOnly')) is not bool for m in mounts)
                    or len({m['Target'] for m in mounts})!=len(mounts)):
                raise ValueError('whole_role_unique_canonical_mount_targets')
            if role=='controller' and not any(m.get('Type')=='bind' and m.get('Target')=='/engine.sock' for m in mounts):
                raise PermissionError('whole_controller_actual_engine_mount_required')
            for mount in mounts:
                if mount['Type']=='bind':
                    if role!='controller' or mount.get('Source')!='/var/run/docker.sock' or mount.get('Target')!='/engine.sock' or mount.get('ReadOnly') is not False:
                        raise PermissionError('whole_role_host_mount_forbidden')
                    continue
                if mount['Type']!='volume':raise PermissionError('whole_role_only_pinned_volumes')
                if mount['Source']!=plan['volume']:
                    external=plan['external_volumes'].get(mount['Source'])
                    if (not mount.get('ReadOnly') or external is None or role not in external['allowed_roles']
                            or external['privacy'] not in {'configuration','public','model'}):
                        raise PermissionError('whole_role_external_volume_provenance')
                    continue
                sub=mount.get('VolumeOptions',{}).get('Subpath');directory=directories.get(sub)
                if directory is None:raise ValueError('whole_role_declared_subpath_required')
                # A volume subpath exposes its entire subtree, regardless of
                # the label on its root or a read-only flag. Never rely on DAC
                # alone to conceal private descendants inside a public parent.
                exposed=[d for path,d in directories.items()
                    if PurePosixPath(path).is_relative_to(PurePosixPath(sub))]
                for actual_directory in exposed:
                    privacy=actual_directory['privacy']
                    if privacy in {'protected','current_private'}:
                        observed_private.add(actual_directory['path'])
                    # A read-only mount still exposes authority rows and keys.
                    # These worker roles use separately provisioned UDS/current
                    # input handoffs, never another role's control store.
                    if (privacy=='control' and actual_directory['uid']!=uid
                            and role in {'runtime','generator','patcher','scanner','model_gateway'}):
                        raise PermissionError('whole_worker_foreign_control_store_mount_forbidden')
                    if privacy=='protected' and role not in {'protected_evaluator','gate'}:
                        raise PermissionError('whole_role_full_private_mount_forbidden')
                    if privacy=='current_private' and role not in {'protected_evaluator','gate','runtime'}:
                        raise PermissionError('whole_role_current_private_mount_forbidden')
                    if role=='report' and privacy not in {'public','configuration'}:
                        raise PermissionError('report_only_public_mount')
                    if not mount['ReadOnly'] and actual_directory['uid']!=uid:
                        raise PermissionError('whole_role_cross_owner_write')
            if set(scope)!=observed_private:
                raise PermissionError('whole_role_private_scope_actual_mount_mismatch')
    def bootstrap_config(self):
        p=self.plan
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
        return config

    def provision(self):
        p=self.plan
        if (self.root/'provisioned.json').exists():
            original=_controller_record(self.root/'provisioned.json')
            if (original.get('kind')!='WholeRoleProvisionCompletion' or original.get('manifest_digest')!=p['digest']
                    or original.get('role_uids')!=ROLES or original.get('storage_backend')!='local_persistent'):
                raise ValueError('whole_deployment_original_provision_identity')
            keeper=self.engine.inspect(original['keeper']['Id'],timeout=5)
            if (any(keeper.get(k)!=original['keeper'].get(k) for k in ('Id','Image','Config','HostConfig','Mounts'))
                    or keeper.get('State',{}).get('Running') is not True):
                raise RuntimeError('whole_deployment_original_keeper_unavailable')
            return original
        if any(self.root.iterdir()):return self.recover_provision()
        if self.deadline.tzinfo is None or (self.deadline-datetime.now(timezone.utc)).total_seconds()<=p['bootstrap_seconds']+120:
            raise TimeoutError('whole_deployment_original_clock')
        _save(self.root,'provision-intent.json',{'kind':'WholeRoleProvisionIntent','manifest_digest':p['digest']})
        spending=self.ledger.consume_auxiliary(manifest=self.whole,campaign=p['campaign_digest'],
            stage='approval_deployment',operation_key='deploy-'+p['digest'][7:],seconds=p['bootstrap_seconds']+120,
            input_tokens=0,output_tokens=0,disk_bytes=p['provisioning_bytes'])
        _save(self.root,'spending.json',{'kind':'WholeRoleProvisionSpending','spending':spending})
        # Long-lived authority stores must share the actual persistent disk's
        # free floor. A <=2GiB tmpfs can never admit a 2GiB floor plus DB/WAL.
        # Per-task bounded tmpfs and its original Keeper are separate callers.
        volume=self.engine.create_volume(p['volume'],driver_options={},labels={'skillloop.deployment_epoch':p['deployment_epoch']},timeout=5)
        if (volume.get('Name')!=p['volume'] or volume.get('Driver')!='local'
                or volume.get('Options') not in (None,{})
                or volume.get('Labels',{}).get('skillloop.deployment_epoch')!=p['deployment_epoch']):
            raise ValueError('whole_deployment_actual_persistent_volume_required')
        _save(self.root,'volume.json',{'kind':'WholeRoleDeploymentVolume','inspection':volume})
        # The readonly Keeper starts before the first directory/config write.
        keeper_config={'Image':p['image'],'User':'21001:21001','Entrypoint':['python'],
            'Cmd':['-c','import time;time.sleep('+str(max(1,int((self.deadline-datetime.now(timezone.utc)).total_seconds())))+')'],
            'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
                'Memory':134217728,'PidsLimit':16,'LogConfig':{'Type':'none','Config':{}},
                'Mounts':[{'Type':'volume','Source':p['volume'],'Target':'/deployment-data','ReadOnly':True}]},
            'Labels':{'skillloop.deployment_epoch':p['deployment_epoch'],'skillloop.role':'deployment_keeper'}}
        keeper=self.engine.create('skillloop-keeper-'+p['digest'][7:31],keeper_config,timeout=5)
        _save(self.root,'keeper-created.json',{'kind':'WholeRoleKeeperCreated','id':keeper,'configuration':keeper_config})
        self.engine.start(keeper,timeout=5);live=self.engine.inspect(keeper,timeout=5)
        if live['State']['Running'] is not True or live['Image']!=p['image']:raise RuntimeError('whole_role_keeper_not_live')
        config=self.bootstrap_config()
        identifier=self.engine.create('skillloop-bootstrap-'+p['digest'][7:31],config,timeout=5)
        _save(self.root,'bootstrap-created.json',{'kind':'WholeRoleBootstrapCreated','id':identifier,'configuration':config})
        self.engine.start(identifier,timeout=5);wait=self.engine.wait(identifier,p['bootstrap_seconds']);actual=self.engine.inspect(identifier,timeout=5)
        if wait['StatusCode'] or actual['State']['ExitCode'] or actual['State']['Running']:
            raise RuntimeError('whole_role_bootstrap_failed_volume_preserved')
        return self.recover_provision()

    def recover_provision(self):
        """GET and attest the original completed bootstrap; never recreate/start."""
        p=self.plan
        if (self.deadline-datetime.now(timezone.utc)).total_seconds()<=120:
            raise TimeoutError('whole_deployment_original_closure_clock')
        names={'provision-intent.json','spending.json','volume.json','keeper-created.json','bootstrap-created.json'}
        if {path.name for path in self.root.iterdir()}!=names:
            raise RuntimeError('whole_deployment_partial_or_unknown_bootstrap_preserved')
        original={name:_controller_record(self.root/name) for name in names}
        if original['provision-intent.json'].get('manifest_digest')!=p['digest']:
            raise ValueError('whole_deployment_original_provision_intent')
        spent=original['spending.json'].get('spending')
        state=self.ledger.read()
        if (spent not in state.get('auxiliary_executions',[])
                or spent.get('operation_key')!='deploy-'+p['digest'][7:]
                or spent.get('stage')!='approval_deployment'
                or state.get('whole_round_binding')!={'manifest_digest':self.whole['digest'],
                                                     'campaign':p['campaign_digest']}):
            raise ValueError('whole_deployment_original_spending_required')
        volume=self.engine.inspect_volume(p['volume'],timeout=5)
        old_volume=original['volume.json'].get('inspection')
        if (type(old_volume) is not dict
                or any(volume.get(k)!=old_volume.get(k) for k in
                       ('Name','Driver','Mountpoint','CreatedAt','Options','Labels','Scope'))
                or volume.get('Name')!=p['volume'] or volume.get('Driver')!='local'
                or volume.get('Options') not in (None,{})
                or volume.get('Labels',{}).get('skillloop.deployment_epoch')!=p['deployment_epoch']):
            raise ValueError('whole_deployment_original_volume_changed')
        keeper_record=original['keeper-created.json'];bootstrap_record=original['bootstrap-created.json']
        if (keeper_record.get('kind')!='WholeRoleKeeperCreated'
                or bootstrap_record.get('kind')!='WholeRoleBootstrapCreated'
                or bootstrap_record.get('configuration')!=self.bootstrap_config()):
            raise ValueError('whole_deployment_original_configuration_changed')
        keeper_config=keeper_record['configuration']
        keeper=self.engine.inspect(keeper_record['id'],timeout=5)
        bootstrap=self.engine.inspect(bootstrap_record['id'],timeout=5)
        def inspect_original(value,record):
            config=record['configuration']
            if (value.get('Id')!=record['id'] or value.get('Image')!=p['image']
                    or any(value.get('Config',{}).get(k)!=config[k] for k in
                           ('User','Entrypoint','Cmd','Labels'))
                    or not set(config.get('Env',[])).issubset(value['Config'].get('Env',[]))):
                raise ValueError('whole_deployment_original_container_changed')
            hc=value.get('HostConfig',{});expected=config['HostConfig']
            for field,setting in expected.items():
                if field in {'CapDrop','CapAdd'}:
                    if {c.removeprefix('CAP_') for c in hc.get(field) or []}!=set(setting):
                        raise ValueError('whole_deployment_original_privileges_changed')
                elif hc.get(field)!=setting:
                    raise ValueError('whole_deployment_original_host_configuration_changed:'+field)
            if hc.get('Privileged') is not False or hc.get('Binds') or hc.get('Devices'):
                raise ValueError('whole_deployment_original_unapproved_mount_or_privilege')
            if ('CapAdd' not in expected and hc.get('CapAdd')
                    or 'GroupAdd' not in expected and hc.get('GroupAdd')):
                raise ValueError('whole_deployment_original_unapproved_group_or_capability')
            actual_mounts=value.get('Mounts',[])
            if len(actual_mounts)!=len(expected['Mounts']):
                raise ValueError('whole_deployment_original_mount_inventory')
            for mount in expected['Mounts']:
                actual=[m for m in actual_mounts if m.get('Destination')==mount['Target']]
                if (len(actual)!=1 or actual[0].get('Type')!='volume'
                        or actual[0].get('Name')!=mount['Source']
                        or actual[0].get('RW') is not (not mount['ReadOnly'])):
                    raise ValueError('whole_deployment_original_physical_volume_mount')
        inspect_original(keeper,keeper_record);inspect_original(bootstrap,bootstrap_record)
        if (keeper_config.get('Image')!=p['image'] or keeper_config.get('User')!='21001:21001'
                or keeper_config.get('Labels')!={'skillloop.deployment_epoch':p['deployment_epoch'],
                                                'skillloop.role':'deployment_keeper'}
                or keeper.get('State',{}).get('Running') is not True):
            raise RuntimeError('whole_deployment_original_keeper_unavailable')
        status=bootstrap.get('State',{})
        if (status.get('Status')!='exited' or status.get('Running') is not False
                or status.get('ExitCode')!=0 or status.get('OOMKilled') is not False
                or status.get('Error') or not status.get('StartedAt')
                or status['StartedAt'].startswith('0001-')):
            raise RuntimeError('whole_deployment_original_bootstrap_not_complete')
        finished=datetime.fromisoformat(status['FinishedAt'].replace('Z','+00:00'))
        began=datetime.fromisoformat(status['StartedAt'].replace('Z','+00:00'))
        if (finished.tzinfo is None or began.tzinfo is None or began.timestamp()<self.ledger.campaign_started_at
                or finished<began or finished>self.deadline or finished>datetime.now(timezone.utc)
                or (finished-began).total_seconds()>p['bootstrap_seconds']):
            raise ValueError('whole_deployment_original_bootstrap_finish_clock')
        return _save(self.root,'provisioned.json',{'kind':'WholeRoleProvisionCompletion','manifest_digest':p['digest'],
            'keeper':keeper,'bootstrap':bootstrap,'role_uids':ROLES,
            'storage_backend':'local_persistent','campaign_capacity_verified':False,
            'runtime_acceptance_complete':False,'qualification_issued':False})
    def role_config(self,role,module=None):
        if role not in ROLES:raise ValueError('whole_role_identity_required')
        template=self.plan['roles'][role]
        if module is None or template['config']['Cmd']==['-m',module]:return template['config']
        variant=template.get('entry_variants',{}).get(module)
        if variant is None:raise ValueError('whole_role_entry_variant_not_frozen')
        return variant['config']

    def create_role(self,role,operation_id,*,module=None):
        if role not in ROLES or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',operation_id):raise ValueError('whole_role_operation')
        config=self.role_config(role,module)
        provisioned=self.provision();live=self.engine.inspect(provisioned['keeper']['Id'])
        if live['State']['Running'] is not True:raise RuntimeError('whole_role_keeper_expired')
        filename='role-'+digest_jcs({'role':role,'operation':operation_id})[7:]+'.json'
        if (self.root/(filename+'.created')).exists():
            original=_controller_record(self.root/(filename+'.created'))
            intent=_controller_record(self.root/filename)
            if (intent.get('kind')!='WholeRoleCreateIntent' or intent.get('operation')!=operation_id
                    or intent.get('configuration')!=config or intent.get('role')!=role
                    or original.get('kind')!='WholeRoleCreated' or original.get('role')!=role
                    or original.get('id')!=original.get('inspection',{}).get('Id')):
                raise ValueError('whole_role_original_entry_variant_changed')
            actual=self.engine.inspect(original['id'])
            _verify_role_process(actual,original['id'],config,config['HostConfig']['Mounts'],controller_engine_bind=role=='controller')
            if actual.get('Config')!=original['inspection'].get('Config') or actual.get('Image')!=original['inspection'].get('Image'):
                raise ValueError('whole_role_original_created_identity_changed')
            return original
        name='skillloop-'+role+'-'+digest_jcs(operation_id)[7:31]
        if (self.root/filename).exists():
            intent=_controller_record(self.root/filename)
            cost=_controller_record(self.root/(filename+'.cost'))
            if (intent.get('kind')!='WholeRoleCreateIntent' or intent.get('role')!=role
                    or intent.get('operation')!=operation_id or intent.get('configuration')!=config
                    or intent.get('container_name')!=name or intent.get('manifest_digest')!=self.plan['digest']
                    or cost.get('kind')!='WholeRoleCreateSpending'):
                raise ValueError('whole_role_original_create_identity_required')
            state=self.ledger.read();spent=cost['spending']
            if (state.get('whole_round_binding')!={'manifest_digest':self.whole['digest'],'campaign':self.plan['campaign_digest']}
                    or state.get('campaign_started_at')!=self.ledger.campaign_started_at
                    or spent not in state.get('auxiliary_executions',[])
                    or spent.get('stage')!='approval_deployment'
                    or spent.get('operation_key')!='role-create-'+digest_jcs({'role':role,'operation':operation_id})[7:]
                    or spent.get('requested_cost')!={'seconds':60,'input_tokens':0,'output_tokens':0,'disk_bytes':2097152}):
                raise ValueError('whole_role_original_creation_spending_required')
            # A GET is the only recovery request. Missing/ambiguous creation
            # stays unknown; this branch never sends a replacement POST.
            actual=self.engine.inspect(name)
            _verify_role_process(actual,actual['Id'],config,config['HostConfig']['Mounts'],controller_engine_bind=role=='controller')
            began=datetime.fromisoformat(intent['recorded_at'])
            created_at=datetime.fromisoformat(actual['Created'].replace('Z','+00:00'))
            if (actual.get('Name')!='/'+name or began.tzinfo is None or created_at.tzinfo is None
                    or not began<=created_at<=datetime.now(timezone.utc) or created_at>=self.deadline):
                raise ValueError('whole_role_original_named_creation_clock')
            return _save(self.root,filename+'.created',{'kind':'WholeRoleCreated','role':role,
                'id':actual['Id'],'inspection':actual})
        _save(self.root,filename,{'kind':'WholeRoleCreateIntent','role':role,'operation':operation_id,
            'configuration':config,'container_name':name,'manifest_digest':self.plan['digest'],
            'recorded_at':datetime.now(timezone.utc).isoformat()})
        spending=self.ledger.consume_auxiliary(manifest=self.whole,campaign=self.plan['campaign_digest'],
            stage='approval_deployment',operation_key='role-create-'+digest_jcs({'role':role,'operation':operation_id})[7:],
            seconds=60,input_tokens=0,output_tokens=0,disk_bytes=2097152)
        _save(self.root,filename+'.cost',{'kind':'WholeRoleCreateSpending','spending':spending})
        identifier=self.engine.create(name,config)
        actual=self.engine.inspect(identifier);_verify_role_process(actual,identifier,config,config['HostConfig']['Mounts'],controller_engine_bind=role=='controller')
        return _save(self.root,filename+'.created',{'kind':'WholeRoleCreated','role':role,'id':identifier,'inspection':actual})

    def start_role(self,role,operation_id,*,module=None):
        created=self.create_role(role,operation_id,module=module);identifier=created['id']
        token=digest_jcs({'role':role,'operation':operation_id})[7:]
        completed=self.root/('start-'+token+'.complete.json')
        intent=self.root/('start-'+token+'.intent.json')
        if completed.exists():
            observed=_controller_record(completed)
            if (observed.get('kind')!='WholeRoleStartObserved' or observed.get('created_digest')!=created['digest']
                    or observed['inspection']['Id']!=identifier
                    or observed['inspection']['Config']!=created['inspection']['Config']
                    or observed['inspection']['Image']!=created['inspection']['Image']):
                raise ValueError('whole_role_original_start_completion_identity')
            return observed
        if intent.exists():
            original_intent=_controller_record(intent)
            if (original_intent.get('kind')!='WholeRoleStartIntent'
                    or original_intent.get('created_digest')!=created['digest']
                    or original_intent.get('id')!=identifier):
                raise ValueError('whole_role_original_start_intent_identity')
            actual=self.engine.inspect(identifier)
            original=created['inspection']
            if (actual.get('Config')!=original.get('Config') or actual.get('Image')!=original.get('Image')
                    or actual.get('State',{}).get('StartedAt') in {None,'0001-01-01T00:00:00Z'}):
                raise RuntimeError('whole_role_unknown_original_start_no_replay')
            # Inspection proves this same container started. Never start a
            # stopped worker again, even when its original response was lost.
        else:
            actual=self.engine.inspect(identifier)
            _verify_role_process(actual,identifier,self.role_config(role,module),
                self.role_config(role,module)['HostConfig']['Mounts'],controller_engine_bind=role=='controller')
            if (actual.get('State',{}).get('Running') is not False
                    or actual.get('State',{}).get('StartedAt') not in {None,'0001-01-01T00:00:00Z'}
                    or actual.get('State',{}).get('Status')!='created'):
                raise RuntimeError('whole_role_previously_started_without_original_intent')
            _save(self.root,intent.name,{'kind':'WholeRoleStartIntent','created_digest':created['digest'],'id':identifier})
            self.engine.start(identifier);actual=self.engine.inspect(identifier)
        return _save(self.root,completed.name,{'kind':'WholeRoleStartObserved','created_digest':created['digest'],
            'inspection':actual,'qualification_issued':False})
