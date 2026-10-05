"""Admin production of all role configurations from one frozen declaration.

This creates configuration, never approvals, lifecycle proofs or task results.
The Controller consumes the resulting manifest through WholeRoleDeployment.
"""
import os
from pathlib import Path,PurePosixPath
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
    def template(role,request):
        uid=ROLES[role]
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
        return {'config':config,'private_read_scope':request['private_read_scope']}
    for role in ROLES:
        request=policy['role_requests'][role]
        if type(request) is not dict:raise ValueError('whole_role_production_declaration')
        variants=request.get('entry_variants',{})
        if type(variants) is not dict or len(variants)>len(MODULES.get(role,set())):
            raise ValueError('whole_role_production_entry_variants')
        base={k:v for k,v in request.items() if k!='entry_variants'}
        roles[role]=template(role,base)
        entries={}
        for module,variant in variants.items():
            if (module not in MODULES.get(role,set()) or type(variant) is not dict
                    or variant.get('module')!=module or module==base['module']):
                raise ValueError('whole_role_production_exact_entry_variant')
            entries[module]=template(role,variant)
        if entries:roles[role]['entry_variants']=entries
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
    operator_documents=[d['value'] for d in value['documents']
        if d['value'].get('kind')=='OperatorServiceDeployment']
    from skillloop.runtime.operation_store import STORAGE_POLICY
    if (len(operator_documents)!=1 or operator_documents[0].get('storage_policy')!=STORAGE_POLICY
            or operator_documents[0].get('campaign_digest')!=value['campaign_digest']
            or operator_documents[0].get('deployment_epoch')!=value['deployment_epoch']
            or operator_documents[0].get('deadline')!=value['deadline']):
        raise ValueError('whole_operator_original_physical_storage_and_clock')
    # All approved routes are checked before producing a bootstrap package.
    # Actual operator startup repeats this check on the mounted documents.
    documents={}
    directories={d['path']:d for d in value['directories']}
    mounts=value['roles']['controller']['config']['HostConfig']['Mounts']
    for document in value['documents']:
        original=PurePosixPath(document['directory'])/document['name']
        for mount in mounts:
            if mount.get('Type')!='volume' or mount.get('Source')!=value['volume']:
                continue
            subpath=PurePosixPath(mount['VolumeOptions']['Subpath'])
            try:relative=original.relative_to(subpath)
            except ValueError:continue
            target=str(PurePosixPath(mount['Target'])/relative)
            # Use the most specific actual mount at the target path. A nested
            # overlay must not make a hidden bootstrap document look readable.
            overlay=max((m for m in mounts if PurePosixPath(target).is_relative_to(PurePosixPath(m['Target']))),
                        key=lambda m:len(PurePosixPath(m['Target']).parts))
            if overlay is not mount:continue
            directory=directories[document['directory']]
            if directory['uid']!=21010 or directory['gid']!=21001:
                continue
            if target in documents and documents[target]!=document['value']:
                raise ValueError('whole_operator_route_mount_alias_conflict')
            documents[target]=document['value']
    operator=operator_documents[0]
    if type(operator.get('routes')) is not list or not 1<=len(operator['routes'])<=2048:
        raise ValueError('whole_operator_complete_route_documents_required')
    routes=[]
    for path in operator['routes']:
        route=documents.get(path)
        if route is None:
            raise ValueError('whole_operator_route_document_missing')
        routes.append(route)
    from skillloop.runtime.operator_routes import validate_operator_routes
    validate_operator_routes(routes,campaign_digest=value['campaign_digest'],deadline=value['deadline'])
    output=_directory(policy['output_directory'],21010,21001,0o750)
    path=output/'deployment.json'
    if os.path.lexists(path):
        if read_owned(path,uid=21010,gid=21001,limit=2097152)!=value:
            raise ValueError('whole_deployment_original_production_conflict')
    else:_publish(path,value,21001)
    return value
