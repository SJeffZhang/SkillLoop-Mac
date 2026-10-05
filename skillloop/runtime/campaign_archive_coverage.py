"""Independently match encrypted source inventory to private campaign obligations.

Task byte coverage is derived from actual durable receipts and indexed files.
It never grants deletion or implies that operational/credential stores have
been archived merely because all task receipts are present.
"""
import os
import hashlib
from pathlib import Path,PurePosixPath
import stat
from skillloop.protocol import canonical_json_line,decode_json,digest_bytes,digest_jcs
from scripts.spec_v22_core import execution_record
from skillloop.runtime.archive_files import open_original,require_unchanged


# Source coverage is assessed before encryption completes. The encryption and
# later restore receipts cannot be inputs to their own original inventory;
# their acceptance remains a separate post-archive review, and this review
# never authorizes deletion of the source evidence.
# The remaining category needs actual owner snapshots rather than a flag.
UNBOUND_CATEGORIES=('qualification_and_registry_snapshots',
    'operation_recovery_and_resource_ownership')


def review_campaign_inventory(*,policy,inventory,budget):
    if os.geteuid()!=21005:raise PermissionError('campaign_archive_gate_uid')
    roots={r['alias']:Path(r['path']) for r in policy['sources']}
    rows={r['path']:r for r in inventory['files']}
    if len(rows)!=len(inventory['files']):raise ValueError('campaign_archive_duplicate_file')

    def load(row,limit=16777216,decode=True):
        budget()
        alias,relative=row['path'].split('/',1)
        path=roots[alias]/relative
        if row['bytes']>limit:raise ValueError('campaign_archive_object_capacity')
        fd=open_original(path)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                    or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode),before.st_size)
                        !=(row['uid'],row['gid'],row['mode'],row['bytes'])):
                raise PermissionError('campaign_archive_original_file_custody')
            checksum=hashlib.sha256();size=0;parts=[]
            while True:
                budget();block=stream.read(min(1048576,limit-size+1))
                if not block:break
                size+=len(block)
                if size>limit or size>row['bytes']:
                    raise ValueError('campaign_archive_file_changed')
                checksum.update(block)
                if decode:parts.append(block)
            after=os.fstat(stream.fileno())
        require_unchanged(path,before,after)
        if size!=row['bytes'] or 'sha256:'+checksum.hexdigest()!=row['digest']:
            raise ValueError('campaign_archive_file_changed')
        # Binary evidence and SQLite backups are verified incrementally. They
        # are never retained as a second full database in the Gate's memory.
        return decode_json(b''.join(parts)) if decode else None

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
                    'campaign_archive_file_changed','campaign_archive_object_capacity',
                    'archive_original_path_or_bytes_changed',
                    'archive_original_absolute_canonical_path'}:raise
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
        'spending':'CampaignGateSpendingSnapshot','source-history':'ProxyCampaignSourceAuthoritySnapshot',
        'development-attempt-audit':'GateDevelopmentAttemptAudit'}
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
    attempt_audit=facts['development-attempt-audit']
    if (attempt_audit.get('campaign')!=policy['campaign']
            or attempt_audit.get('deployment_epoch')!=policy['deployment_epoch']
            or attempt_audit.get('config_digest')!=evidence['bindings']['config_digest']
            or type(attempt_audit.get('all_attempt_history_complete')) is not bool
            or type(attempt_audit.get('proposal_inference_attempts_reviewed')) is not int
            or type(attempt_audit.get('proposal_original_response_bytes_verified')) is not bool):
        raise ValueError('campaign_archive_original_development_attempt_audit')
    raw_pins=facts['development-evidence'].get('reviewed_raw_inputs')
    if type(raw_pins) is not list or not 1<=len(raw_pins)<=512:
        raise ValueError('campaign_archive_discovery_original_inputs_required')
    raw_covered=[];raw_index={}
    for pin in raw_pins:
        if (type(pin) is not dict or type(pin.get('name')) is not str
                or type(pin.get('bytes_digest')) is not str
                or pin['name']!='reviewed-raw-'+pin['bytes_digest'][7:]+'.bin'
                or type(pin.get('size_bytes')) is not int
                or not 0<=pin['size_bytes']<=33554432
                or type(pin.get('original_name')) is not str
                or Path(pin['original_name']).name!=pin['original_name']
                or pin.get('original_uid') not in {21001,21005,21007,21011}
                or pin.get('original_gid')!=21001):
            raise ValueError('campaign_archive_discovery_original_input_pin')
        copies=[r for r in rows.values() if PurePosixPath(r['path']).name==pin['name']
            and r['uid']==21005 and r['gid']==21005 and r['mode']==0o600]
        if not copies:raise ValueError('campaign_archive_missing_discovery_original_bytes')
        for row in copies:
            if row['bytes']!=pin['size_bytes'] or row['digest']!=pin['bytes_digest']:
                raise ValueError('campaign_archive_discovery_original_copy_mismatch')
            load(row,limit=33554432,decode=False)
        raw_covered.append(pin['bytes_digest'])
        raw_index.setdefault((pin['original_name'],pin['bytes_digest']),[]).extend(copies)
    development=facts['development-evidence'];assignment=facts['development-assignment']
    def reviewed_original(name,value,kind):
        if value.get('kind')!=kind:
            raise ValueError('campaign_archive_original_discovery_object_kind')
        checksum=digest_bytes(canonical_json_line(value))
        copies=raw_index.get((name,checksum),[])
        if not copies:
            raise ValueError('campaign_archive_missing_reviewed_discovery_object')
        if any(load(row,limit=16777216)!=value for row in copies):
            raise ValueError('campaign_archive_changed_reviewed_discovery_object')
    reviewed_original('job.json',assignment,'FormalDevelopmentRosterAssignment')
    applications=development.get('applications');scans=development.get('scans')
    if (type(applications) is not list or len(applications)>2
            or type(scans) is not dict or set(scans)!=set(development['subjects'].values())
            or facts['roster-freeze']['repair_rounds_used']!=len(applications)):
        raise ValueError('campaign_archive_original_discovery_candidate_roster')
    parent=evidence['bindings']['subjects']['submitted']
    for number,application in enumerate(applications,1):
        budget()
        if (application.get('repair_round')!=number
                or application.get('parent_subject_digest')!=parent
                or application.get('campaign_id')!=policy['campaign']
                or application.get('deployment_epoch')!=policy['deployment_epoch']
                or application.get('application_verified') is not True):
            raise ValueError('campaign_archive_original_candidate_parent_chain')
        reviewed_original(application['assignment_digest'][7:]+'.json',application,
            'GateBoundedCandidateApplication')
        if any((pin['original_name'],pin['bytes_digest']) not in raw_index
                for pin in application['reviewed_raw_inputs']):
            raise ValueError('campaign_archive_candidate_original_model_inputs_missing')
        parent=application['candidate_bundle_digest']
    semantic_digests=set();scan_reviews={}
    required_reviews={scan['review_digest'] for scan in scans.values()}
    for pin in raw_pins:
        if pin['original_uid']!=21005 or not pin['original_name'].endswith('.json'):
            continue
        copies=raw_index[(pin['original_name'],pin['bytes_digest'])]
        if copies[0]['bytes']>262144:continue
        value=load(copies[0],limit=262144)
        if value.get('kind')!='ScanEvidenceReview':continue
        if (value.get('digest') not in required_reviews
                or value.get('evidence_complete') is not True
                or ('raw-report.json',value.get('raw_report_digest')) not in raw_index
                or any(load(row,limit=262144)!=value for row in copies)):
            raise ValueError('campaign_archive_original_scan_review_and_report')
        scan_reviews[value['digest']]=value
    if set(scan_reviews)!=required_reviews:
        raise ValueError('campaign_archive_missing_original_scan_review')
    for subject,scan in scans.items():
        budget()
        if (subject not in development['subjects'].values()
                or scan['scanner_report']['body']['status']!='complete'
                or type(scan.get('semantic_evidence_digest')) is not str):
            raise ValueError('campaign_archive_complete_semantic_discovery_required')
        semantic_digests.add(scan['semantic_evidence_digest'])
    if len(semantic_digests)!=len(scans):
        raise ValueError('campaign_archive_distinct_semantic_source_evidence')
    observed_semantic=set()
    for pin in raw_pins:
        if pin['original_name']!='discovery.json':continue
        copies=raw_index[(pin['original_name'],pin['bytes_digest'])]
        value=load(copies[0],limit=16777216)
        if (value.get('kind')!='GatewaySemanticDiscoveryEvidence'
                or value.get('digest') not in semantic_digests
                or any(load(row,limit=16777216)!=value for row in copies)):
            raise ValueError('campaign_archive_original_semantic_model_evidence')
        observed_semantic.add(value['digest'])
    if observed_semantic!=semantic_digests:
        raise ValueError('campaign_archive_missing_semantic_model_evidence')
    source_history=facts['source-history']
    from skillloop.proxy.archive_projection import verify_source_history
    source_map=verify_source_history(source_history,campaign=policy['campaign'],epoch=policy['deployment_epoch'],
        config_digest=evidence['bindings']['config_digest'],trust_revision=evidence['bindings']['trust_revision'])
    if (attempt_audit['proposal_inference_attempts_reviewed']!=len(
            source_history['development_inference_history']['proposal_attempts'])
            or attempt_audit['proposal_original_response_bytes_verified'] is not True
            or attempt_audit['all_attempt_history_complete'] is not True):
        raise ValueError('campaign_archive_original_proposal_attempt_history_incomplete')
    if (not set(evidence['bindings']['subjects'].values())<=set(source_map)
            or not any(row['uid']==21003 and row['gid']==21005 for row,_ in
                resolve(source_history['digest'],'ProxyCampaignSourceAuthoritySnapshot'))):
        raise ValueError('campaign_archive_original_proxy_source_projection_required')
    issuer_candidates=[(row,value) for candidates in objects.values() for row,value in candidates
        if value.get('kind')=='GateWithdrawnQualificationSnapshot'
        and value.get('campaign')==policy['campaign']]
    if len(issuer_candidates)!=1:
        raise ValueError('campaign_archive_actual_withdrawn_issuer_snapshot_required')
    issuer_row,issuer_snapshot=issuer_candidates[0]
    if (issuer_row['uid']!=21005 or issuer_row['gid']!=21005
            or issuer_snapshot.get('bindings')!=evidence['bindings']
            or issuer_snapshot.get('deployment_epoch')!=policy['deployment_epoch']
            or issuer_snapshot.get('qualification_revoked') is not True
            or type(issuer_snapshot.get('files')) is not list or len(issuer_snapshot['files'])!=2):
        raise ValueError('campaign_archive_issuer_original_binding')
    import sqlite3
    from contextlib import closing
    versions=set()
    for pin in issuer_snapshot['files']:
        budget()
        if (set(pin)!={'name','bytes','digest','user_version'} or pin['user_version'] not in (2,3)
                or Path(pin['name']).name!=pin['name'] or pin['user_version'] in versions):
            raise ValueError('campaign_archive_issuer_snapshot_inventory')
        versions.add(pin['user_version'])
        locator=str(PurePosixPath(issuer_row['path']).parent/pin['name']);row=rows.get(locator)
        if (row is None or row['uid']!=21005 or row['gid']!=21005 or row['mode']!=0o600
                or row['digest']!=pin['digest'] or row['bytes']!=pin['bytes']):
            raise ValueError('campaign_archive_issuer_database_original_missing')
        load(row,limit=268435456,decode=False)
        alias,relative=locator.split('/',1);database=roots[alias]/relative
        with closing(sqlite3.connect(database.as_uri()+'?mode=ro&immutable=1',uri=True,timeout=2)) as db:
            db.set_progress_handler(lambda:(budget() or 0),1000)
            if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)] or db.execute('PRAGMA user_version').fetchone()!=(pin['user_version'],):
                raise ValueError('campaign_archive_issuer_database_integrity')
            if pin['user_version']==2:
                issued=db.execute('SELECT bindings_digest,proof,revoked FROM issued_campaigns WHERE campaign=?',(policy['campaign'],)).fetchone()
                if issued is None or issued[0]!=digest_jcs(evidence['bindings']) or issued[2]!=1:
                    raise ValueError('campaign_archive_actual_issuer_not_revoked')
            else:
                issued=db.execute('SELECT bindings_digest,proof FROM private_campaign_proofs WHERE campaign=?',(policy['campaign'],)).fetchone()
                if issued is None or issued[0]!=digest_jcs(evidence['bindings']):
                    raise ValueError('campaign_archive_original_private_qualification_missing')
            proof=decode_json(issued[1])
            if proof.get('digest')!=digest_jcs({k:v for k,v in proof.items() if k!='digest'}):
                raise ValueError('campaign_archive_issuer_original_proof_seal')
        load(row,limit=268435456,decode=False)
    registry_candidates=[(row,value) for candidates in objects.values() for row,value in candidates
        if value.get('kind')=='ControllerWithdrawnRegistrySnapshot' and value.get('campaign')==policy['campaign']]
    if len(registry_candidates)!=1:raise ValueError('campaign_archive_actual_registry_snapshot_required')
    registry_row,registry_snapshot=registry_candidates[0]
    if (registry_row['uid']!=21001 or registry_row['gid']!=21005
            or registry_snapshot.get('bindings')!=evidence['bindings']
            or registry_snapshot.get('campaign_dispatch_closed') is not True
            or registry_snapshot.get('withdrawal',{}).get('gate_withdrawal_digest')!=issuer_snapshot['withdrawal_digest']
            or registry_snapshot.get('database_name')!='registry.sqlite'):
        raise ValueError('campaign_archive_original_registry_snapshot_binding')
    locator=str(PurePosixPath(registry_row['path']).parent/'registry.sqlite');row=rows.get(locator)
    if (row is None or row['uid']!=21001 or row['gid']!=21005 or row['mode']!=0o640
            or row['digest']!=registry_snapshot['database_digest'] or row['bytes']!=registry_snapshot['database_size_bytes']):
        raise ValueError('campaign_archive_original_registry_database_missing')
    load(row,limit=268435456,decode=False)
    alias,relative=locator.split('/',1);database=roots[alias]/relative
    with closing(sqlite3.connect(database.as_uri()+'?mode=ro&immutable=1',uri=True,timeout=2)) as db:
        db.set_progress_handler(lambda:(budget() or 0),1000)
        if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]:raise ValueError('campaign_archive_registry_database_integrity')
        original=db.execute('SELECT bindings FROM formal_campaigns WHERE campaign=?',(policy['campaign'],)).fetchone()
        withdrawals=db.execute("SELECT result FROM promotions WHERE operation LIKE 'archive-withdraw-%'").fetchall()
        if (original is None or decode_json(original[0])!=evidence['bindings']
                or not any(decode_json(value[0])==registry_snapshot['withdrawal'] for value in withdrawals)):
            raise ValueError('campaign_archive_actual_registry_closed_campaign_required')
    load(row,limit=268435456,decode=False)
    history_candidates=[(row,value) for candidates in objects.values() for row,value in candidates
        if value.get('kind')=='ControllerOperationHistorySnapshot' and value.get('campaign')==policy['campaign']]
    if not history_candidates or len(history_candidates)>4:
        raise ValueError('campaign_archive_actual_operation_history_required')
    if sum(value['digest']==attempt_audit['snapshot_digest'] for _,value in history_candidates)!=1:
        raise ValueError('campaign_archive_original_prequalification_history_missing')
    operation_histories=[]
    for history_row,history in sorted(history_candidates,key=lambda item:item[1]['digest']):
        if (history_row['uid']!=21001 or history_row['gid']!=21005
                or history.get('deployment_epoch')!=policy['deployment_epoch']
                or history.get('config_digest')!=evidence['bindings']['config_digest']
                or history['spending_state']['whole_round_binding']!=facts['spending']['state']['whole_round_binding']
                or history['spending_state']['campaign_started_at']!=facts['spending']['state']['campaign_started_at']):
            raise ValueError('campaign_archive_original_operation_history_binding')
        for pin in [history['database'],*history['files']]:
            budget()
            if Path(pin['name']).name!=pin['name']:raise ValueError('campaign_archive_history_snapshot_path')
            locator=str(PurePosixPath(history_row['path']).parent/pin['name']);row=rows.get(locator)
            if (row is None or row['uid']!=21001 or row['gid']!=21005 or row['mode']!=0o640
                    or row['bytes']!=pin['bytes'] or row['digest']!=pin['digest']):
                raise ValueError('campaign_archive_operation_original_bytes_missing')
            load(row,limit=268435456,decode=False)
        locator=str(PurePosixPath(history_row['path']).parent/history['database']['name'])
        alias,relative=locator.split('/',1);database=roots[alias]/relative
        with closing(sqlite3.connect(database.as_uri()+'?mode=ro&immutable=1',uri=True,timeout=2)) as db:
            db.set_progress_handler(lambda:(budget() or 0),1000)
            if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)] or db.execute('SELECT version,epoch FROM identity').fetchall()!=[(3,policy['deployment_epoch'])]:
                raise ValueError('campaign_archive_actual_operation_store_integrity')
            from skillloop.runtime.operation_store import verify_operation_transitions
            operation_history=verify_operation_transitions(db,policy['deployment_epoch'],budget=budget)
            for request,route,ticket,state,result,error in db.execute('SELECT request,route,ticket,state,result,error FROM operations'):
                for raw in (request,route,ticket):
                    value=decode_json(raw)
                    if value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):
                        raise ValueError('campaign_archive_original_operation_object_seal')
                if state not in {'accepted','running','completed','failed'}:
                    raise ValueError('campaign_archive_original_operation_state')
                if result is not None:decode_json(result)
        operation_histories.append({'snapshot_digest':history['digest'],'transition_history':operation_history})
    # This preserves the actual recovery store and declared source bytes, but
    # it cannot infer physical evidence leases or an exhaustive model attempt
    # catalog from Controller metadata alone.
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
                or bundle['subjects']!=evidence['bindings']['subjects']
                or bundle['private_plan']['digest']!=source_history['protected_plan_digest']):
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
        'reviewed_discovery_raw_digests':raw_covered,'reviewed_discovery_bytes_present':True,
        'discovery_candidate_history_verified':True,
        'original_gate_fact_digests':evidence['archive_fact_digests'],
        'factory_and_session_database_verified':True,'source_and_approval_history_verified':True,
        'withdrawn_issuer_databases_verified':True,'issuer_snapshot_digest':issuer_snapshot['digest'],
        'withdrawn_registry_database_verified':True,'registry_snapshot_digest':registry_snapshot['digest'],
        'operation_transition_histories_verified':operation_histories,
        'operation_history_original_bytes_verified':True,
        'archive_restore_lifecycle_pending':True,
        'missing_categories':[c for c in UNBOUND_CATEGORIES if c!='qualification_and_registry_snapshots'],'campaign_coverage_complete':False,
        'deletion_authorized':False}
    result['digest']=digest_jcs(result)
    return result
