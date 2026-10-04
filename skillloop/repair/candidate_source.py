"""Admin writes Gate-rebuilt candidates as Git objects and immutable source grants.

No checkout, hook, filter, ref update or shell process is involved. Partial
object writes remain unreachable until the immutable grant is published.
"""
from datetime import datetime,timezone
import base64,hashlib,os,stat,zlib
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.loader import validate_source_admission
from skillloop.protocol import digest_jcs,validate_envelope
from skillloop.source import GitObjectReader,import_git_package,_path
from skillloop.protection.current_task import _directory,_publish


def _object(reader,kind,raw):
    framed=kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw
    oid=hashlib.sha1(framed).hexdigest()
    created=False
    try:os.mkdir(oid[:2],0o750,dir_fd=reader.fd);created=True
    except FileExistsError:pass
    fd=os.open(oid[:2],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=reader.fd)
    try:
        if created:os.fchown(fd,-1,21003);os.fchmod(fd,0o750);os.fsync(reader.fd)
        info=os.fstat(fd)
        if info.st_uid!=21010 or info.st_gid!=21003 or stat.S_IMODE(info.st_mode)!=0o750:
            raise PermissionError('candidate_git_object_directory_custody')
        try:out=os.open(oid[2:],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640,dir_fd=fd)
        except FileExistsError:
            if reader.object(oid,kind,len(raw))!=raw:raise ValueError('candidate_existing_object_mismatch')
            return oid
        with os.fdopen(out,'wb') as stream:
            os.fchown(stream.fileno(),-1,21003);os.fchmod(stream.fileno(),0o640)
            stream.write(zlib.compress(framed));stream.flush();os.fsync(stream.fileno())
        os.fsync(fd)
    finally:os.close(fd)
    return oid


def _tree(reader,entries):
    ordered=sorted(entries,key=lambda row:row[3].encode()+ (b'/' if row[1]=='tree' else b''))
    if len({e[3] for e in ordered})!=len(ordered):raise ValueError('candidate_duplicate_tree_entry')
    return _object(reader,'tree',b''.join(mode.lstrip('0').encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid)
        for mode,kind,oid,name in ordered))


def produce_candidate(assignment_path):
    if os.geteuid()!=21010 or 21003 not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('candidate_source_actual_admin')
    job=read_owned(assignment_path,uid=21001,gid=21010,limit=2097152)
    fields={'kind','campaign_id','deployment_digest','deployment_epoch','config','repository','parent_commit',
        'skill_path','parent_subject_digest','gate_review_path','gate_application_path','parent_manifest',
        'reference_resource_ids','inbox_directory','result_directory','digest'}
    if set(job)!=fields or job['kind']!='AdminCandidateSourceProduction':
        raise ValueError('candidate_source_frozen_assignment')
    review=read_owned(job['gate_review_path'],uid=21005,gid=21001,limit=262144)
    artifact=read_owned(job['gate_application_path'],uid=21005,gid=21001,limit=2097152)
    applied=artifact['application'];candidate=applied['candidate_bundle'];validate_envelope(candidate)
    if (review.get('kind')!='GateBoundedCandidateApplication' or review.get('application_verified') is not True
            or review.get('qualification_issued') is not False or artifact.get('kind')!='GateAppliedCandidate'
            or artifact.get('review_digest')!=review['digest'] or artifact.get('campaign_id')!=job['campaign_id']
            or review.get('application_digest')!=digest_jcs(applied)
            or review.get('candidate_bundle_digest')!=candidate['digest']
            or review.get('parent_subject_digest')!=job['parent_subject_digest']
            or review.get('campaign_id')!=job['campaign_id'] or review.get('deployment_epoch')!=job['deployment_epoch']
            or review.get('config_digest')!=digest_jcs(job['config'])):
        raise ValueError('candidate_source_actual_gate_application_required')
    repository=Path(job['repository']);info=repository.lstat()
    if (repository.is_symlink() or info.st_uid!=21010 or info.st_gid!=21003
            or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('candidate_admin_repository')
    parent_snapshot,parent_package=import_git_package(repository,job['parent_commit'],job['skill_path'])
    if parent_package!={p:t.encode() for p,t in applied['history_entry']['before_files'].items()}:
        raise ValueError('candidate_parent_actual_git_bytes')
    result_dir=_directory(job['result_directory'],21010,21001,0o750)
    name=job['digest'][7:];intent_path=result_dir/(name+'.intent.json')
    if intent_path.exists():
        intent=read_owned(intent_path,uid=21010,gid=21001,limit=262144)
        if intent.get('assignment_digest')!=job['digest']:raise ValueError('candidate_original_intent')
    else:
        intent={'kind':'AdminCandidateObjectIntent','assignment_digest':job['digest'],
            'timestamp':int(datetime.now(timezone.utc).timestamp())};intent['digest']=digest_jcs(intent)
        _publish(intent_path,intent,21001)
    files={p:t.encode() for p,t in applied['files'].items()}
    # The original reader also validates all ancestor directories and rejects
    # alternates and unsafe Git objects before this writer can add any bytes.
    with GitObjectReader(repository) as reader:
        tree=reader.object(job['parent_commit'],'commit',65536).split(b'\n',1)[0][5:].decode('ascii')
        entries=[];refs=[]
        for path,raw in sorted(files.items()):
            if path=='SKILL.md':entries.append(('100644','blob',_object(reader,'blob',raw),path))
            elif path.startswith('references/') and len(_path(path))==2:
                refs.append(('100644','blob',_object(reader,'blob',raw),path.split('/')[1]))
            else:raise ValueError('candidate_allowed_markdown_path')
        if refs:entries.append(('040000','tree',_tree(reader,refs),'references'))
        child=_tree(reader,entries);ancestors=[]
        for segment in _path(job['skill_path']):
            rows=reader.tree(tree);chosen=[e for e in rows if e[3]==segment]
            if len(chosen)!=1 or chosen[0][:2]!=('040000','tree'):raise ValueError('candidate_original_package_directory')
            ancestors.append((rows,segment));tree=chosen[0][2]
        for rows,segment in reversed(ancestors):
            child=_tree(reader,[e for e in rows if e[3]!=segment]+[('040000','tree',child,segment)])
        stamp=str(intent['timestamp'])
        commit=('tree '+child+'\nparent '+job['parent_commit']+'\nauthor SkillLoop <local@skillloop.invalid> '+stamp+
            ' +0000\ncommitter SkillLoop <local@skillloop.invalid> '+stamp+' +0000\n\nGate-approved bounded candidate\n').encode()
        oid=_object(reader,'commit',commit)
    snapshot,actual=import_git_package(repository,oid,job['skill_path'])
    if actual!=files or snapshot['body']['skill_digest']!=candidate['body']['skill_digest']:
        raise ValueError('candidate_actual_git_reconstruction')
    manifest={**job['parent_manifest'],'files':snapshot['body']['files']}
    admission={'source_snapshot':snapshot,'manifest':manifest,
        'approved_sources':{snapshot['digest']:digest_jcs(manifest)},
        'approved_subjects':{snapshot['digest']:candidate},'reference_resource_ids':job['reference_resource_ids'],
        'package_files':{p:base64.b64encode(raw).decode('ascii') for p,raw in files.items()}}
    validate_source_admission(admission,job['config'],candidate['digest'])
    grant={'kind':'AdminCampaignSourceAdmission','deployment_digest':job['deployment_digest'],
        'deployment_epoch':job['deployment_epoch'],'campaign_id':job['campaign_id'],'config':job['config'],
        'subject_digest':candidate['digest'],'admission':admission,'parent_subject_digest':job['parent_subject_digest'],
        'application_review_path':job['gate_review_path']};grant['digest']=digest_jcs(grant)
    inbox=_directory(job['inbox_directory'],21010,21003,0o750);target=inbox/(grant['digest'][7:]+'.json')
    if target.exists():
        if read_owned(target,uid=21010,gid=21003,limit=2097152)!=grant:raise ValueError('candidate_source_grant_conflict')
    else:_publish(target,grant,21003)
    result={'kind':'AdminCandidateSourceProduced','assignment_digest':job['digest'],'source_snapshot':snapshot,
        'subject_digest':candidate['digest'],'source_grant_digest':grant['digest'],
        'proxy_admission_verified':False,'qualification_issued':False};result['digest']=digest_jcs(result)
    return result
