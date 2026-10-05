"""Gate review of the original Controller operation and stage inventory.

The Controller archives its consistent operation DB and original journals
after roster freeze. This reviewer reads the archived bytes, rather than a
caller supplied completeness flag. The running evaluate operation may have
only the prefix through that archive step; every earlier operation must have
an original terminal result and complete stage receipts.
"""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import canonical_json_line, decode_json, digest_bytes, digest_jcs
from skillloop.proxy.wire import validate_control
from skillloop.runtime.archive_files import open_original, require_unchanged
from skillloop.runtime.operation_store import verify_operation_transitions


def _sealed_copy(root, row, *, limit, budget):
    budget()
    path=root/row['name']
    value=read_owned(path,uid=21001,gid=21005,limit=limit)
    if (row['bytes']!=len(canonical_json_line(value))
            or row['digest']!=digest_bytes(canonical_json_line(value))):
        raise ValueError('development_attempt_original_copy_changed')
    return value


def review_attempts(*, root, campaign, epoch, config_digest, deadline, spending):
    if os.geteuid()!=21005:
        raise PermissionError('development_attempt_actual_gate')
    root=Path(root);info=root.lstat()
    if (not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(21001,21005,0o750)):
        raise PermissionError('development_attempt_controller_snapshot_custody')
    started=time.monotonic()
    end=datetime.fromisoformat(deadline.replace('Z','+00:00'))
    def budget():
        if end.tzinfo is None or datetime.now(timezone.utc)>=end or time.monotonic()-started>=60:
            raise TimeoutError('development_attempt_original_review_clock')
    snapshot=read_owned(root/'snapshot.json',uid=21001,gid=21005,limit=1048576)
    early=snapshot.get('spending_state')
    if (type(early) is not dict or early.get('campaign_started_at')!=spending.get('campaign_started_at')
            or early.get('whole_round_binding')!=spending.get('whole_round_binding')
            or spending.get('executions',[])[:len(early.get('executions',[]))]!=early.get('executions')
            or spending.get('auxiliary_executions',[])[:len(early.get('auxiliary_executions',[]))]
                !=early.get('auxiliary_executions')):
        raise ValueError('development_attempt_original_spending_prefix_changed')
    if (snapshot.get('kind')!='ControllerOperationHistorySnapshot'
            or snapshot.get('producer_uid')!=21001 or snapshot.get('reader_gid')!=21005
            or snapshot.get('campaign')!=campaign or snapshot.get('deployment_epoch')!=epoch
            or snapshot.get('config_digest')!=config_digest or snapshot.get('deadline')!=deadline
            or type(snapshot.get('files')) is not list or len(snapshot['files'])>4096):
        raise ValueError('development_attempt_original_snapshot_binding')
    pin=snapshot['database'];database=root/'operations.sqlite'
    if (set(pin)!={'name','bytes','digest'} or pin['name']!='operations.sqlite'
            or type(pin['bytes']) is not int or not 0<pin['bytes']<=16777216):
        raise ValueError('development_attempt_original_database_pin')
    fd=open_original(database)
    checksum=hashlib.sha256();size=0
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if ((before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode),before.st_size,before.st_nlink)
                !=(21001,21005,0o640,pin['bytes'],1)):
            raise PermissionError('development_attempt_actual_database_custody')
        for block in iter(lambda:stream.read(1048576),b''):
            budget();checksum.update(block);size+=len(block)
        after=os.fstat(stream.fileno())
    require_unchanged(database,before,after)
    if size!=pin['bytes'] or 'sha256:'+checksum.hexdigest()!=pin['digest']:
        raise ValueError('development_attempt_original_database_changed')
    files={}
    for row in snapshot['files']:
        budget()
        if (type(row) is not dict or set(row)!={'name','original_path','original_uid','bytes','digest'}
                or type(row['original_path']) is not str
                or PurePosixPath(row['original_path']).is_absolute()
                or '..' in PurePosixPath(row['original_path']).parts
                or row['original_path'] in files or row['original_uid'] not in {21001,21006,21007,21011}):
            raise ValueError('development_attempt_original_file_inventory')
        files[row['original_path']]=row
    identities=[]
    for name,row in files.items():
        if row['original_uid']==21001 and PurePosixPath(name).name=='identity.json':
            value=_sealed_copy(root,row,limit=262144,budget=budget)
            if value.get('kind')=='CampaignRouteIdentity':
                identities.append((str(PurePosixPath(name).parent),value))
    missing=[];completed=0;running=0
    with closing(sqlite3.connect(database.as_uri()+'?mode=ro&immutable=1',uri=True,timeout=2)) as db:
        db.execute('PRAGMA query_only=ON')
        if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
            raise ValueError('development_attempt_original_database_integrity')
        transition=verify_operation_transitions(db,epoch,budget=budget)
        rows=db.execute('SELECT ref,owner,parameters,request,route,ticket,state,result,error FROM operations').fetchall()
        if len(rows)!=transition['operations'] or not rows:
            raise ValueError('development_attempt_original_operation_inventory')
        for ref,owner,parameters,raw_request,raw_route,raw_ticket,state,raw_result,error in rows:
            budget();request=decode_json(raw_request);route=decode_json(raw_route);ticket=decode_json(raw_ticket)
            validate_control(ticket)
            if (request.get('digest')!=digest_jcs({k:v for k,v in request.items() if k!='digest'})
                    or route.get('digest')!=digest_jcs({k:v for k,v in route.items() if k!='digest'})
                    or ref!='op-'+digest_jcs({'epoch':epoch,'owner':owner,'operation':request['operation_id']})[7:]
                    or parameters!=digest_jcs({'command':request['command'],'parameters':request['parameters']})
                    or route['command']!=request['command']
                    or route['parameters_digest']!=digest_jcs(request['parameters'])
                    or ticket['body']['operation_ref']!=ref
                    or ticket['body']['expected_result_kind']!=route['result_kind']):
                raise ValueError('development_attempt_original_operation_binding')
            matches=[prefix for prefix,value in identities
                if value.get('request_digest')==request['digest'] and value.get('route_digest')==route['digest']]
            if len(matches)!=1:
                missing.append('route_journal_missing_or_ambiguous');continue
            prefix=matches[0]
            if any(name.startswith(prefix+'/') and PurePosixPath(name).name.endswith(('.started.json','.completed.json'))
                    and (not PurePosixPath(name).name[:4].isdecimal()
                        or int(PurePosixPath(name).name[:4])>=len(route['steps'])) for name in files):
                missing.append('unexpected_stage_receipt')
            archive_indices=[i for i,step in enumerate(route['steps']) if step['action']=='operation_archive']
            current=(state=='running' and request['command']=='evaluate'
                and route.get('campaign_digest')==campaign and len(archive_indices)==1)
            if current:running+=1
            elif state=='completed':completed+=1
            else:missing.append('nonterminal_or_failed_operation')
            limit=archive_indices[0] if current else len(route['steps'])
            for index,step in enumerate(route['steps']):
                token=str(index).zfill(4);base=prefix+'/'+token
                began_row=files.get(base+'.started.json');done_row=files.get(base+'.completed.json')
                if index>limit or index==limit and current:
                    if index==limit and current and began_row is None:
                        missing.append('current_archive_stage_not_started')
                    elif index==limit and current:
                        began=_sealed_copy(root,began_row,limit=262144,budget=budget)
                        if (began.get('kind')!='CampaignStageStarted'
                                or began.get('step_digest')!=digest_jcs(step)
                                or began.get('request_digest')!=request['digest']):
                            raise ValueError('development_attempt_current_archive_stage_binding')
                    if done_row is not None or index>limit and began_row is not None:
                        missing.append('stage_after_archive_snapshot')
                    continue
                if began_row is None or done_row is None:
                    missing.append('stage_receipt_missing');continue
                began=_sealed_copy(root,began_row,limit=262144,budget=budget)
                done=_sealed_copy(root,done_row,limit=16777216,budget=budget)
                if (began.get('kind')!='CampaignStageStarted' or done.get('kind')!='CampaignStageCompleted'
                        or began.get('step_digest')!=digest_jcs(step)
                        or done.get('step_digest')!=digest_jcs(step)
                        or began.get('request_digest')!=request['digest']
                        or done.get('request_digest')!=request['digest']):
                    raise ValueError('development_attempt_original_stage_binding')
            if state=='completed':
                result=decode_json(raw_result)
                if result.get('digest')!=digest_jcs({k:v for k,v in result.items() if k!='digest'}):
                    raise ValueError('development_attempt_original_result_changed')
    if running!=1:missing.append('current_evaluation_operation_missing')
    value={'kind':'GateDevelopmentAttemptAudit','campaign':campaign,'deployment_epoch':epoch,
        'config_digest':config_digest,'snapshot_digest':snapshot['digest'],
        'database_digest':pin['digest'],'operations_reviewed':len(rows),
        'completed_operations':completed,'running_evaluation_operations':running,
        'transition_count':transition['transitions'],
        'incomplete_reasons':sorted(set(missing)),
        'all_attempt_history_complete':not missing and running==1}
    value['digest']=digest_jcs(value)
    return value
