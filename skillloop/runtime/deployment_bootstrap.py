"""Trusted one-shot directory provisioning; no model or business execution."""
import os,stat
from pathlib import Path,PurePosixPath
from skillloop.protocol import decode_json,digest_jcs


def main():
    if os.geteuid()!=0:raise PermissionError('deployment_bootstrap_trusted_root')
    fd=os.open('/bootstrap/manifest.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=21010 or info.st_size>2097152:
            raise PermissionError('bootstrap_actual_admin_manifest')
        value=decode_json(stream.read(2097153))
    if value.get('digest')!=os.environ.get('SKILLLOOP_DEPLOYMENT_DIGEST') or value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):raise ValueError('bootstrap_manifest_seal')
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
