"""Admin production of all role configurations from one frozen declaration.

This creates configuration, never approvals, lifecycle proofs or task results.
The Controller consumes the resulting manifest through WholeRoleDeployment.
"""
import os
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.protection.current_task import _directory,_publish
from skillloop.runtime.whole_deployment import ROLES,MODULES,WholeRoleDeployment

MANIFEST_FIELDS={'campaign_digest','whole_round_manifest_digest','deployment_epoch','deadline',
    'image','source_digest','bootstrap_mount','volume','storage_backend','provisioning_bytes',
    'engine_socket_gid','operator_uids','directories','documents','external_volumes','bootstrap_seconds'}


def produce_deployment(policy_path):
    if os.geteuid()!=21010:raise PermissionError('whole_role_actual_admin_producer')
    policy=read_owned(policy_path,uid=21010,gid=21001,limit=2097152)
    if (set(policy)!=MANIFEST_FIELDS|{'kind','role_requests','output_directory','digest'}
            or policy['kind']!='FrozenWholeRoleProductionPolicy'
            or type(policy['role_requests']) is not dict or set(policy['role_requests'])!=set(ROLES)):
        raise ValueError('whole_role_complete_production_policy')
    roles={}
    for role,uid in ROLES.items():
        request=policy['role_requests'][role]
        if (type(request) is not dict or set(request)!=
                {'module','environment','mounts','groups','memory_bytes','private_read_scope','image'}):
            raise ValueError('whole_role_production_declaration')
        module=request['module']
        if role=='scanner':
            if module!='offline_static_scan':raise ValueError('whole_scanner_frozen_entry')
            command=['/opt/skillloop-scanner/offline_osv.py','scan','/subject/SKILL.md',
                '--no-llm','--format','json','--output','/report/report.json']
        else:
            if module not in MODULES[role]:raise ValueError('whole_role_production_entry')
            command=['-m',module]
        if type(request['environment']) is not dict or any(type(k) is not str or type(v) is not str
                or not k or '=' in k or '\x00' in k+v for k,v in request['environment'].items()):
            raise ValueError('whole_role_production_environment')
        environment={'PYTHONDONTWRITEBYTECODE':'1','PYTHONPATH':'/code/scripts/vendor:/code:/opt/archive-crypto'}
        if set(environment)&set(request['environment']):
            raise ValueError('whole_role_production_runtime_environment_fixed')
        environment.update(request['environment'])
        groups=request['groups']
        if type(groups) is not list or len(groups)!=len(set(groups)):
            raise ValueError('whole_role_production_unique_groups')
        config={'Image':request['image'],'User':str(uid)+':'+str(uid),'Entrypoint':['python'],
            'Cmd':command,'Env':[k+'='+v for k,v in sorted(environment.items())],
            'Labels':{'skillloop.deployment_epoch':policy['deployment_epoch'],'skillloop.role':role},
            'HostConfig':{'GroupAdd':groups,'NetworkMode':'bridge' if role=='model_gateway' else 'none',
                'ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
                'Memory':request['memory_bytes'],'NanoCpus':2000000000,'PidsLimit':64,
                'Ulimits':[{'Name':'nofile','Soft':128,'Hard':128}],
                'RestartPolicy':{'Name':'no'},'LogConfig':{'Type':'none','Config':{}},
                'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=64m'},'Mounts':request['mounts']}}
        roles[role]={'config':config,'private_read_scope':request['private_read_scope']}
    value={'kind':'FrozenWholeRoleDeployment',**{k:policy[k] for k in MANIFEST_FIELDS},'roles':roles}
    value['digest']=digest_jcs(value)
    WholeRoleDeployment.validate_roles_manifest(value)
    # The controller document and actual Docker mount must describe the same
    # explicitly authorized socket group, rather than an inherited root group.
    controller_documents=[d['value'] for d in value['documents']
        if d['value'].get('kind')=='ControllerCampaignDeployment']
    if len(controller_documents)!=1 or (controller_documents[0].get('engine_socket'),
            controller_documents[0].get('engine_socket_gid'))!=('/engine.sock',value['engine_socket_gid']):
        raise ValueError('whole_controller_production_socket_binding')
    output=_directory(policy['output_directory'],21010,21001,0o750)
    path=output/'deployment.json'
    if os.path.lexists(path):
        if read_owned(path,uid=21010,gid=21001,limit=2097152)!=value:
            raise ValueError('whole_deployment_original_production_conflict')
    else:_publish(path,value,21001)
    return value
