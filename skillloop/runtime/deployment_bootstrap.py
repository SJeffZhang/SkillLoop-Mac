"""Trusted one-shot directory provisioning; no model or business execution."""
import os,stat
from pathlib import Path,PurePosixPath
from skillloop.protocol import decode_json,digest_jcs



def validate_directory_manifest(value):
    """Preflight the exact provisioning input before any volume write."""
    import re
    from skillloop.protocol import canonical_json_line
    operators=value.get('operator_uids')
    if (type(operators) is not list or len(operators)!=len(set(operators))
            or any(type(uid) is not int or uid<1 for uid in operators)):
        raise ValueError('bootstrap_operator_identity_shape')
    directories=value.get('directories');documents=value.get('documents')
    if (type(directories) is not list or not 1<=len(directories)<=512
            or type(documents) is not list or len(documents)>512):
        raise ValueError('bootstrap_bounded_configuration')
    seen={}
    for item in sorted(directories,key=lambda r:(len(PurePosixPath(r['path']).parts),r['path'])):
        if type(item) is not dict or set(item)!={'path','uid','gid','mode','privacy'}:
            raise ValueError('bootstrap_directory_shape')
        path=PurePosixPath(item['path'])
        if (path.is_absolute() or not path.parts or '..' in path.parts or str(path)!=item['path']
                or type(item['uid']) is not int or item['uid'] not in range(21001,21012)
                or type(item['gid']) is not int or item['gid'] not in set(range(21001,21012))|set(operators)
                or type(item['mode']) is not int or item['mode'] not in {448,488}
                or item['path'] in seen or len(path.parts)>1 and str(path.parent) not in seen
                or item['privacy'] not in {'configuration','public','development','opaque','protected','current_private','control'}):
            raise ValueError('bootstrap_directory_bound')
        if item['privacy']=='protected' and item['uid'] not in {21004,21005}:
            raise PermissionError('bootstrap_private_custodian')
        if item['privacy']=='current_private' and item['uid'] not in {21002,21004,21005}:
            raise PermissionError('bootstrap_current_task_custodian')
        seen[item['path']]=item
    names=set();total=0
    for document in documents:
        if (type(document) is not dict or set(document)!={'directory','name','value'}
                or document['directory'] not in seen or type(document['name']) is not str
                or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}\.json',document['name'])
                or type(document['value']) is not dict):
            raise ValueError('bootstrap_config_document_shape')
        policy=seen[document['directory']];identity=(document['directory'],document['name'])
        if identity in names:raise ValueError('bootstrap_duplicate_document')
        names.add(identity)
        if policy['uid']!=21010 or policy['privacy']!='configuration':
            raise PermissionError('bootstrap_admin_configuration_only')
        kind=document['value'].get('kind')
        if (type(kind) is not str or not (kind.endswith('Deployment') or kind.startswith('Frozen') or kind.endswith('Policy'))
                or document['value'].get('digest')!=digest_jcs({k:v for k,v in document['value'].items() if k!='digest'})):
            raise ValueError('bootstrap_sealed_configuration_only')
        total+=len(canonical_json_line(document['value']))
        if total>2097152:raise ValueError('bootstrap_original_total_document_budget')
    return seen


def main():
    if os.geteuid()!=0:raise PermissionError('deployment_bootstrap_trusted_root')
    fd=os.open('/bootstrap/manifest.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=21010 or info.st_size>2097152:
            raise PermissionError('bootstrap_actual_admin_manifest')
        value=decode_json(stream.read(2097153))
    if value.get('digest')!=os.environ.get('SKILLLOOP_DEPLOYMENT_DIGEST') or value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):raise ValueError('bootstrap_manifest_seal')
    validate_directory_manifest(value)
    root=Path('/deployment-data')
    if any(root.iterdir()):raise ValueError('bootstrap_new_volume_required')
    directories=value['directories'];seen=set()
    # Sort parents before children; every parent is declared, never inferred
    # with permissive ownership or a world-readable default.
    for item in sorted(directories,key=lambda r:(len(PurePosixPath(r['path']).parts),r['path'])):
        if set(item)!={'path','uid','gid','mode','privacy'}:raise ValueError('bootstrap_directory_shape')
        path=PurePosixPath(item['path'])
        if (path.is_absolute() or not path.parts or '..' in path.parts or str(path)!=item['path']
                or item['uid'] not in range(21001,21012) or item['gid'] not in set(range(21001,21012))|set(value['operator_uids'])
                or item['mode'] not in {448,488} or item['path'] in seen
                or len(path.parts)>1 and str(path.parent) not in seen):
            raise ValueError('bootstrap_directory_bound')
        target=root/str(path);target.mkdir(mode=0o700);os.chown(target,item['uid'],item['gid']);os.chmod(target,item['mode'])
        seen.add(item['path'])
    for document in value['documents']:
        if set(document)!={'directory','name','value'} or document['directory'] not in seen:
            raise ValueError('bootstrap_config_document_shape')
        import re
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}\.json',document['name']):
            raise ValueError('bootstrap_document_relative_json')
        policy=next(d for d in directories if d['path']==document['directory'])
        if policy['uid']!=21010 or policy['privacy']!='configuration':
            raise PermissionError('bootstrap_admin_configuration_only')
        # This directory producer cannot fabricate a private plan, task,
        # evaluation, qualification, model lifecycle proof or public result.
        kind=document['value'].get('kind','')
        if not (kind.endswith('Deployment') or kind.startswith('Frozen') or kind.endswith('Policy')):
            raise PermissionError('bootstrap_only_configuration_documents')
        from skillloop.protocol import canonical_json_line
        raw=canonical_json_line(document['value'])
        if len(raw)>2097152:raise ValueError('bootstrap_document_capacity')
        target=root/document['directory']/document['name']
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            os.fchown(stream.fileno(),21010,policy['gid']);os.fchmod(stream.fileno(),0o640)
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
    for parent,_,_ in os.walk(root,topdown=False):
        fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)


if __name__=='__main__':main()
