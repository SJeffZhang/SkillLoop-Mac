"""Independently match encrypted source inventory to private campaign obligations.

Task byte coverage is derived from actual durable receipts and indexed files.
It never grants deletion or implies that operational/credential stores have
been archived merely because all task receipts are present.
"""
import os
from pathlib import Path,PurePosixPath
import stat
from skillloop.protocol import decode_json,digest_bytes,digest_jcs
from scripts.spec_v22_core import execution_record


# These categories need producers bound to actual owner snapshots, rather than
# caller-declared booleans or arbitrary collections of files.
UNBOUND_CATEGORIES=('discovery_and_candidate_raw_history',
    'qualification_and_registry_snapshots',
    'operation_recovery_and_resource_ownership','archive_and_restore_lifecycle')


def review_campaign_inventory(*,policy,inventory,budget):
    if os.geteuid()!=21005:raise PermissionError('campaign_archive_gate_uid')
    roots={r['alias']:Path(r['path']) for r in policy['sources']}
    rows={r['path']:r for r in inventory['files']}
    if len(rows)!=len(inventory['files']):raise ValueError('campaign_archive_duplicate_file')

    def load(row,limit=16777216):
        budget()
        alias,relative=row['path'].split('/',1)
        path=roots[alias]/relative
        if row['bytes']>limit:raise ValueError('campaign_archive_object_capacity')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                    or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode),before.st_size)
                        !=(row['uid'],row['gid'],row['mode'],row['bytes'])):
                raise PermissionError('campaign_archive_original_file_custody')
            raw=stream.read(limit+1);after=os.fstat(stream.fileno())
        if (len(raw)!=row['bytes'] or digest_bytes(raw)!=row['digest']
                or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
                    !=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
            raise ValueError('campaign_archive_file_changed')
        return decode_json(raw)

    def original(locator):
        path=Path(locator)
        matches=[]
        for alias,root in roots.items():
            if path.is_relative_to(root):
                name=alias+'/'+path.relative_to(root).as_posix()
                if name in rows:matches.append(rows[name])
        if len(matches)!=1 or matches[0]['uid']!=21005 or matches[0]['gid']!=21005:
            raise ValueError('campaign_archive_original_gate_object_required')
        value=load(matches[0])
        if type(value) is not dict or value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):
            raise ValueError('campaign_archive_gate_object_seal')
        return value

    evidence=original(policy['campaign_gate_evidence_path'])
    obligations=original(policy['archive_obligations_path'])
    if (evidence.get('kind')!='FormalCampaignGateEvidence'
            or obligations.get('kind')!='PrivateCampaignArchiveObligations'
            or evidence.get('archive_obligations_digest')!=obligations['digest']
            or evidence['bindings']['campaign']!=policy['campaign']
            or evidence['bindings']['deployment_epoch']!=policy['deployment_epoch']
            or obligations.get('campaign_id')!=policy['campaign']
            or obligations.get('deployment_epoch')!=policy['deployment_epoch']
            or obligations.get('config_digest')!=evidence['bindings']['config_digest']
            or obligations.get('assignment_digest')!=evidence['assignment_digest']):
        raise ValueError('campaign_archive_current_gate_obligations')
    tasks=obligations.get('tasks')
    if (type(tasks) is not list or not tasks or len(tasks)>128
            or len({r['intent_digest'] for r in tasks})!=len(tasks)
            or len({r['execution_record_digest'] for r in tasks})!=len(tasks)):
        raise ValueError('campaign_archive_full_unique_task_obligations')

    objects={}
    for row in rows.values():
        budget()
        if not row['path'].endswith('.json') or row['bytes']>16777216:continue
        try:value=load(row)
        except (UnicodeError,ValueError) as error:
            # Raw model output may be a .json file without being a sealed
            # internal object. Changed files/custody must never be ignored.
            if isinstance(error,ValueError) and str(error) in {
                    'campaign_archive_file_changed','campaign_archive_object_capacity'}:raise
            continue
        if (type(value) is dict and type(value.get('digest')) is str
                and value['digest']==digest_jcs({k:v for k,v in value.items() if k!='digest'})):
            objects.setdefault(value['digest'],[]).append((row,value))

    def resolve(digest,kind):
        candidates=[(r,v) for r,v in objects.get(digest,[]) if v.get('kind')==kind]
        if not candidates:raise ValueError('campaign_archive_missing_'+kind)
        if any(v!=candidates[0][1] for _,v in candidates):raise ValueError('campaign_archive_ambiguous_object')
        return candidates

    fact_kinds={'whole-round':'FrozenWholeRound','development-assignment':'FormalDevelopmentRosterAssignment',
        'development-evidence':'FormalDevelopmentRosterEvidence','roster-freeze':'FrozenCampaignSubjectRoster',
        'authority-snapshot':'EvaluatorGateAuthoritySnapshot','model-lifecycle':'GatePrivateModelLifecycleReview',
        'spending':'CampaignGateSpendingSnapshot','source-history':'ProxyCampaignSourceAuthoritySnapshot'}
    if set(evidence.get('archive_fact_digests',{}))!=set(fact_kinds):
        raise ValueError('campaign_archive_original_fact_bindings_required')
    facts={name:resolve(evidence['archive_fact_digests'][name],kind)[0][1]
        for name,kind in fact_kinds.items()}
    if (facts['whole-round']['digest']!=obligations['whole_round_manifest_digest']
            or facts['development-assignment']['digest']!=obligations['development_assignment_digest']
            or facts['roster-freeze']['digest']!=obligations['roster_freeze_digest']
            or facts['roster-freeze']['development_evidence_digest']!=facts['development-evidence']['digest']
            or facts['spending']['digest']!=evidence['spending_snapshot_digest']
            or facts['authority-snapshot']['digest']!=evidence['authority_snapshot_digest']
            or facts['model-lifecycle']['digest']!=evidence['lifecycle_digest']):
        raise ValueError('campaign_archive_original_fact_chain')
    source_history=facts['source-history']
    from skillloop.proxy.archive_projection import verify_source_history
    source_map=verify_source_history(source_history,campaign=policy['campaign'],epoch=policy['deployment_epoch'],
        config_digest=evidence['bindings']['config_digest'],trust_revision=evidence['bindings']['trust_revision'])
    if (not set(evidence['bindings']['subjects'].values())<=set(source_map)
            or not any(row['uid']==21003 and row['gid']==21005 for row,_ in
                resolve(source_history['digest'],'ProxyCampaignSourceAuthoritySnapshot'))):
        raise ValueError('campaign_archive_original_proxy_source_projection_required')
    covered=[];protected={}
    for task in tasks:
        budget()
        evaluation=resolve(task['evaluation_digest'],'FormalTaskEvaluation')[0][1]
        review=resolve(task['task_review_digest'],'FormalTaskEvidenceReview')[0][1]
        archive=resolve(task['archive_review_digest'],'FormalTaskArchiveReview')[0][1]
        receipts=resolve(task['archive_receipt_digest'],'DurableReviewedTaskArchive')
        request=evaluation['run_request']['body']
        recomputed=execution_record(evaluation['run_request'],evaluation['result'],evaluation['evidence_index'],evaluation['task_binding'])
        if (evaluation['execution_record']!=recomputed or recomputed['digest']!=task['execution_record_digest']
                or evaluation['run_request']['digest']!=task['run_request_digest']
                or evaluation['intent_digest']!=task['intent_digest'] or evaluation['entry_digest']!=task['entry_digest']
                or (request['subject_digest'],request['case_digest'],request['repetition_index'])
                    !=(task['subject_digest'],task['case_digest'],task['repetition_index'])
                or request['config_digest']!=obligations['config_digest']
                or evaluation['deployment_epoch']!=policy['deployment_epoch']
                or review.get('evidence_complete') is not True or archive.get('complete') is not True
                or review['evaluation_digest']!=evaluation['digest']
                or archive['task_review_digest']!=review['digest']
                or archive['archive_receipt_digest']!=task['archive_receipt_digest']):
            raise ValueError('campaign_archive_independent_task_chain')
        for receipt_row,receipt in receipts:
            files=receipt['files'];prefix=str(PurePosixPath(receipt_row['path']).parent)+'/'
            if (receipt['intent_digest']!=task['intent_digest'] or receipt['entry_digest']!=task['entry_digest']
                    or receipt['review_digest']!=review['digest']
                    or digest_jcs(files)!=task['archive_inventory_digest']
                    or archive['inventory_digest']!=task['archive_inventory_digest']
                    or type(files) is not list or len(files)>4096
                    or len({r['path'] for r in files})!=len(files)):
                raise ValueError('campaign_archive_original_receipt_inventory')
            total=0
            for file in files:
                budget();relative=PurePosixPath(file['path'])
                if relative.is_absolute() or '..' in relative.parts or str(relative)!=file['path']:
                    raise ValueError('campaign_archive_receipt_relative_path')
                actual=rows.get(prefix+file['path'])
                if actual is None or (actual['digest'],actual['bytes'])!=(file['digest'],file['bytes']):
                    raise ValueError('campaign_archive_missing_original_raw_bytes')
                total+=file['bytes']
            if total!=receipt['total_bytes']:raise ValueError('campaign_archive_receipt_byte_total')
        if task['privacy_domain']=='protected':protected[task['intent_digest']]=task
        covered.append({'intent_digest':task['intent_digest'],'archive_receipt_digest':task['archive_receipt_digest']})
    # The Factory/session database must itself be included and independently
    # reopened, not inferred from the presence of its JSON snapshot receipt.
    snapshot=facts['authority-snapshot']
    snapshot_copies=resolve(snapshot['digest'],'EvaluatorGateAuthoritySnapshot')
    authority_locations=[]
    for row,value in snapshot_copies:
        if row['uid']!=21004 or row['gid']!=21005:continue
        prefix=str(PurePosixPath(row['path']).parent)+'/'
        database=rows.get(prefix+'authority.sqlite')
        if (database is None or (database['digest'],database['bytes'])
                !=(snapshot['database_digest'],snapshot['database_size_bytes'])):
            raise ValueError('campaign_archive_factory_database_missing')
        alias,relative=row['path'].split('/',1)
        authority_locations.append((roots[alias]/relative).parent)
    if not authority_locations:raise ValueError('campaign_archive_actual_evaluator_snapshot_required')
    from skillloop.protection.authority import ProtectionAuthority
    for location in authority_locations:
        budget();authority=ProtectionAuthority(location,readonly=True)
        bundle=authority.resolve_formal_bundle(campaign=policy['campaign'],opaque_ref=snapshot['opaque_ref'])
        if (bundle['bundle']['epoch_id']!=obligations['factory_epoch_id']
                or bundle['subjects']!=evidence['bindings']['subjects']):
            raise ValueError('campaign_archive_original_factory_identity')
        with authority.connect() as db:
            db.set_progress_handler(lambda: (budget() or 0),1000)
            if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:
                raise ValueError('campaign_archive_factory_database_integrity')
            sessions=db.execute('SELECT b.binding,s.state,s.result_digest FROM formal_session_bindings b JOIN sessions s ON s.key=b.key WHERE s.epoch=?',
                (bundle['bundle']['epoch_id'],)).fetchall()
        actual={}
        for raw,state,result_digest in sessions:
            budget();binding=decode_json(raw);intent=binding['intent_digest'];task=protected.get(intent)
            if (state!='complete' or intent in actual or task is None
                    or binding['campaign']!=policy['campaign']
                    or binding['request_digest']!=task['run_request_digest']
                    or binding['entry_digest']!=task['entry_digest']
                    or result_digest!=task['execution_record_digest']):
                raise ValueError('campaign_archive_complete_original_session_results')
            actual[intent]=task
        required={(item['subject_digest'],item['case_digest'],item['repetition_index'])
            for item in bundle['private_plan']['body']['items']
            if item['requirement']=='required' and item['phase']=='protected'}
        if (set(actual)!=set(protected) or required!={(t['subject_digest'],t['case_digest'],t['repetition_index']) for t in protected.values()}):
            raise ValueError('campaign_archive_full_factory_matrix')
    result={'kind':'IndependentCampaignArchiveCoverage','campaign':policy['campaign'],
        'deployment_epoch':policy['deployment_epoch'],'campaign_gate_evidence_digest':evidence['digest'],
        'archive_obligations_digest':obligations['digest'],'source_inventory_digest':inventory['digest'],
        'reviewed_tasks':covered,'all_reviewed_task_bytes_present':True,
        'original_gate_fact_digests':evidence['archive_fact_digests'],
        'factory_and_session_database_verified':True,'source_and_approval_history_verified':True,
        'missing_categories':list(UNBOUND_CATEGORIES),'campaign_coverage_complete':False,
        'deletion_authorized':False}
    result['digest']=digest_jcs(result)
    return result
