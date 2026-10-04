"""Gate-owned qualification issuance and controller-only current consumption.

This database contains qualification metadata, not private cases or model traces.
An administrator provisions its directory/file grant to the frozen Gate UID and
controller GID. No digest or caller-supplied issuer authenticates its producer.
Whole-round raw review remains mandatory before this issuer is called.
"""
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import stat

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs, make_envelope, validate_envelope
from skillloop.ci.attestation_consumption import validate_consumption
from scripts.spec_v22_core import validate_attestation, execution_record

GATE_UID = 21005
CONTROLLER_UID = 21001


def _path(path, *, create=False):
    path = Path(path).absolute()
    # This is a dedicated metadata directory, never an arbitrary evidence root.
    if path.parent.is_symlink() or path.is_symlink():
        raise PermissionError('qualification_path_symlink')
    parent = path.parent.stat()
    if (parent.st_uid != GATE_UID or parent.st_gid != CONTROLLER_UID or
            stat.S_IMODE(parent.st_mode) != 0o750):
        raise PermissionError('qualification_directory_grant')
    if create and not path.exists():
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o640)
        try:
            os.fchmod(fd, 0o640)
            os.fchown(fd, -1, CONTROLLER_UID)
        finally:
            os.close(fd)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != GATE_UID or
            info.st_gid != CONTROLLER_UID or stat.S_IMODE(info.st_mode) != 0o640):
        raise PermissionError('qualification_file_grant')
    return path


def _private_path(path):
    path=Path(path)
    if not path.is_absolute() or path.is_symlink() or path.parent.is_symlink():
        raise PermissionError('qualification_private_path')
    parent=path.parent.lstat()
    if (parent.st_uid!=GATE_UID or parent.st_gid!=GATE_UID or stat.S_IMODE(parent.st_mode)!=0o700):
        raise PermissionError('qualification_private_gate_directory')
    if not path.exists():
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        os.close(fd)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=GATE_UID or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
        raise PermissionError('qualification_private_gate_file')
    return path


class QualificationIssuer:
    """Only the real Gate process writes/renews/revokes this deployment store."""
    def __init__(self, path, *, deployment_epoch, config_digest, authority_directory, private_path):
        if os.geteuid() != GATE_UID:
            raise PermissionError('gate_issuer_uid_required')
        self.path = _path(path, create=True)
        self.private_path = _private_path(private_path)
        if self.private_path==self.path:raise ValueError("qualification_separate_private_store_required")
        self.epoch, self.config = deployment_epoch, config_digest
        self.authority_directory=authority_directory
        with closing(self.connect()) as db:
            version=db.execute('PRAGMA user_version').fetchone()[0]
            existing=db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if version!=2 and (version!=0 or existing):
                raise ValueError('qualification_new_v2_directory_required')
            db.executescript('''CREATE TABLE IF NOT EXISTS qualification_identity(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),epoch TEXT,config TEXT);
                CREATE TABLE IF NOT EXISTS issued_campaigns(campaign TEXT PRIMARY KEY,
                generation INTEGER,bindings_digest TEXT,proof BLOB,revoked INTEGER NOT NULL DEFAULT 0);''')
            row = db.execute('SELECT epoch,config FROM qualification_identity WHERE singleton=1').fetchone()
            if row and row != (self.epoch, self.config):
                raise ValueError('qualification_deployment_mismatch')
            db.execute('INSERT OR IGNORE INTO qualification_identity VALUES(1,?,?)', (self.epoch, self.config))
            db.execute('PRAGMA user_version=2');db.commit()
        with closing(sqlite3.connect(self.private_path)) as db:
            db.execute('PRAGMA synchronous=FULL')
            version=db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0,2):raise ValueError('qualification_private_schema_version')
            if version==0 and db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                raise ValueError('qualification_private_new_store_required')
            db.execute('CREATE TABLE IF NOT EXISTS private_campaign_proofs(campaign TEXT PRIMARY KEY,bindings_digest TEXT NOT NULL,proof BLOB NOT NULL)')
            db.execute('PRAGMA user_version=2');db.commit()

    def connect(self):
        _path(self.path)
        db = sqlite3.connect(self.path, timeout=2)
        # Read-only controller access must not need writable WAL/SHM files.
        db.execute('PRAGMA journal_mode=DELETE')
        db.execute('PRAGMA synchronous=FULL')
        return db

    def issue_campaign(self, *, campaign, generation, source_snapshot_digest,
                       trust_revision, subjects, chains, approval_expires_at, reviewed_tasks):
        if os.geteuid() != GATE_UID:
            raise PermissionError('gate_issuer_uid_required')
        if (type(generation) is not int or generation < 1 or
                type(trust_revision) is not int or trust_revision < 1 or
                'submitted' not in subjects or set(chains) != set(subjects) or
                type(reviewed_tasks) is not dict or set(reviewed_tasks)!=set(subjects) or
                set(subjects) - {'submitted', 'finalist', 'active'}):
            raise ValueError('qualification_complete_subject_pair_required')
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expiry = datetime.fromisoformat(approval_expires_at.replace('Z', '+00:00'))
        if expiry.tzinfo is None or expiry <= now:
            raise ValueError('qualification_approval_expired')
        expiry = min(now + timedelta(hours=24), expiry)
        attestations = {}
        provenance = {}
        approval_bindings = {}
        for role, subject in subjects.items():
            chain = chains[role]
            for name in ('context','gate','plan','suite','required_run_manifest'):
                validate_envelope(chain[name])
            records=chain['records']
            if type(records) is not dict or not records or len(records)>128:
                raise ValueError('qualification_complete_execution_records_required')
            for key, record in records.items():
                validate_envelope(record)
                if key!=record['digest']:raise ValueError('qualification_execution_index_digest')
            tasks=reviewed_tasks[role]
            if type(tasks) is not list or len(tasks)!=len(records):
                raise ValueError('qualification_actual_task_reviews_required')
            from skillloop.discovery.formal_task_gate import read_owned
            actual={};role_reviews=[];approvals=set()
            suite_cases={row['case_digest']:row for row in chain['suite']['body']['cases']}
            if len(suite_cases)!=len(chain['suite']['body']['cases']):
                raise ValueError('qualification_duplicate_suite_case')
            for task in tasks:
                if type(task) is not dict or set(task)!={'evaluation_path','review_path','archive_review_path'}:
                    raise ValueError('qualification_task_review_custody_paths')
                evaluation=read_owned(task['evaluation_path'],uid=21004,gid=21004,limit=16777216)
                validate_envelope(evaluation['run_request'])
                request=evaluation['run_request']
                case=suite_cases.get(request['body']['case_digest'])
                if (case is None or request['kind']!='RunRequest'
                        or request['body']['subject_digest']!=subject
                        or request['body']['config_digest']!=self.config):
                    raise ValueError('qualification_current_subject_case_required')
                # Protected reviews never become Controller-readable merely
                # because a public qualification projection is being issued.
                private=case['split']=='protected'
                review=read_owned(task['review_path'],uid=21005,gid=21004 if private else 21001,limit=16777216)
                recomputed=execution_record(request,evaluation['result'],
                    evaluation['evidence_index'],evaluation['task_binding'])
                if (evaluation.get('kind')!='FormalTaskEvaluation' or evaluation.get('evaluator_uid')!=21004
                        or review.get('kind')!='FormalTaskEvidenceReview' or review.get('gate_uid')!=21005
                        or review.get('evidence_complete') is not True
                        or any(review.get(k)!=evaluation.get(k) for k in
                               ('entry_digest','intent_digest','runtime_capture_digest','authority_snapshot_digest'))
                        or review.get('evaluation_digest')!=evaluation['digest']
                        or evaluation['execution_record']!=recomputed
                        or review.get('execution_record_digest')!=recomputed['digest']):
                    raise ValueError('qualification_independent_task_review_mismatch')
                archive=read_owned(task['archive_review_path'],uid=21005,
                    gid=21004 if private else 21001,limit=16777216)
                if (archive.get('kind')!='FormalTaskArchiveReview' or archive.get('gate_uid')!=21005
                        or archive.get('complete') is not True
                        or archive.get('task_review_digest')!=review['digest']
                        or archive.get('entry_digest')!=review['entry_digest']
                        or archive.get('intent_digest')!=review['intent_digest']):
                    raise ValueError('qualification_independent_archive_review_required')
                record=evaluation['execution_record'];validate_envelope(record)
                if (evaluation.get('deployment_epoch')!=self.epoch
                        or evaluation.get('trust_revision')!=trust_revision
                        or (role=='submitted' and evaluation.get('source_snapshot_digest')!=source_snapshot_digest)
                        or not evaluation.get('approval_digest')):
                    raise ValueError('qualification_actual_task_authority_binding')
                approvals.add(evaluation['approval_digest'])
                if record['digest'] in actual:raise ValueError('qualification_task_review_reused')
                actual[record['digest']]=record
                role_reviews.append({'evaluation_digest':evaluation['digest'],'review_digest':review['digest'],
                    'archive_review_digest':archive['digest']})
            if actual!=records:
                raise ValueError('qualification_chain_records_not_actual_reviewed_records')
            provenance[role]=sorted(role_reviews,key=lambda r:r['evaluation_digest'])
            approval_bindings[role]=sorted(approvals)
            context, gate = chain['context'], chain['gate']
            body = context['body']
            if (gate['body']['subject_digest'] != subject or
                    body['config_digest'] != self.config or approvals!={body['approval_digest']} or
                    any(body[k] is not True for k in ('contract_approved', 'runtime_verified',
                        'source_immutable', 'scanner_complete', 'authorization_verified', 'evidence_verified')) or
                    body['incomplete_reasons'] or body['definite_failures'] or
                    body['unresolved_high_findings'] or gate['body']['verdict'] not in {'pass','fail'} or
                    gate['body']['incomplete_reasons']):
                raise ValueError('qualification_unverified_or_failed_gate')
            # Rebuild the Gate and required-run manifest from the actual reviewed
            # executions. A supplied Gate label, even with a valid wire digest,
            # cannot substitute for the independent reduction.
            from scripts.spec_v22_core import (reduce_case, attach_execution_records,
                evaluate_gate, validate_required_run_manifest)
            reductions=[]
            for template in chain['templates']:
                selected=[record for record in actual.values()
                    if chain['result_index'][record['body']['result_digest']]['body']['case_digest']==template['digest']]
                if selected:
                    results=[chain['result_index'][record['body']['result_digest']] for record in selected]
                    reductions.append(attach_execution_records(reduce_case(results,template),
                        selected,chain['result_index']))
            rebuilt=evaluate_gate(subject,chain['suite'],chain['plan'],reductions,context)
            if rebuilt!=gate:
                raise ValueError('qualification_gate_not_independent_actual_reduction')
            entries=[]
            for item in chain['plan']['body']['items']:
                if item['subject_digest']!=subject or item['requirement']!='required':continue
                matches=[record['digest'] for record in actual.values()
                    if all(chain['result_index'][record['body']['result_digest']]['body'][name]==item[name]
                        for name in ('subject_digest','case_digest','repetition_index'))]
                entries.append({'item_id':item['item_id'],'run_record_digests':sorted(matches)})
            manifest=make_envelope('RequiredRunManifest',{'subject_digest':subject,
                'plan_digest':chain['plan']['digest'],'entries':entries})
            validate_required_run_manifest(manifest,chain['plan'],actual,chain['result_index'])
            if manifest!=chain['required_run_manifest']:
                raise ValueError('qualification_manifest_not_actual_complete_runs')
            a = make_envelope('EvaluationAttestation', {
                'subject_digest': subject, 'plan_digest': chain['plan']['digest'],
                'suite_digest': chain['suite']['digest'], 'config_digest': self.config,
                'required_run_manifest_digest': chain['required_run_manifest']['digest'],
                'gate_result_digest': gate['digest'], 'verdict': gate['body']['verdict'], 'issuer': 'local-authority',
                'issued_at': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'expires_at': expiry.strftime('%Y-%m-%dT%H:%M:%SZ'), 'trust_revision': trust_revision})
            validate_attestation(a, gate, chain['required_run_manifest'], chain['plan'],
                chain['suite'], chain['records'], chain['result_index'], chain['templates'], context)
            attestations[role] = a
        bindings = {'campaign': campaign, 'generation': generation, 'deployment_epoch': self.epoch,
                    'config_digest': self.config, 'source_snapshot_digest': source_snapshot_digest,
                    'trust_revision': trust_revision, 'subjects': subjects}
        evidence_bindings = {role: {name: chains[role][name]['digest'] for name in
            ('context','gate','required_run_manifest','plan','suite')} for role in subjects}
        fingerprint = digest_jcs(bindings)
        proof = {'kind': 'IssuedCampaignQualification', 'bindings': bindings,
                 'attestations': attestations, 'evidence_bindings': evidence_bindings,
                 'task_review_provenance':provenance,
                 'approval_bindings':approval_bindings,
                 'producer_uid': GATE_UID, 'production_ready': False}
        proof['digest'] = digest_jcs(proof)
        from skillloop.proxy.qualification_authority import current_authority
        with current_authority(self.authority_directory,epoch=self.epoch,config_digest=self.config,
                trust_revision=trust_revision,approval_digests={a for refs in approval_bindings.values() for a in refs}) as authority, closing(self.connect()) as db:
            admitted={row['subject_digest']:row for row in authority.get('source_admissions',[])
                if row['campaign_id']==campaign}
            if any(subject not in admitted for subject in subjects.values()):
                raise ValueError('qualification_actual_campaign_source_admission_required')
            if admitted[subjects['submitted']]['source_snapshot_digest']!=source_snapshot_digest:
                raise ValueError('qualification_submitted_source_changed')
            for row in authority['approvals']:
                if row['approval_digest'] not in {a for refs in approval_bindings.values() for a in refs}:continue
                for date in (row['expires_at'],row['factory_expires_at']):
                    if date is not None and expiry>datetime.fromisoformat(date.replace('Z','+00:00')):
                        raise ValueError('qualification_expiry_exceeds_actual_authority')
            # Commit the complete proof in Gate-only custody before publishing
            # minimal eligibility. An interrupted publication reuses this exact
            # proof and original UTC; it cannot renew the campaign's TTL.
            with closing(sqlite3.connect(self.private_path,timeout=2)) as private:
                private.execute('PRAGMA synchronous=FULL');private.execute('BEGIN IMMEDIATE')
                old=private.execute('SELECT bindings_digest,proof FROM private_campaign_proofs WHERE campaign=?',(campaign,)).fetchone()
                if old:
                    original=decode_json(old[1])
                    if (old[0]!=fingerprint or original.get('digest')!=digest_jcs({k:v for k,v in original.items() if k!='digest'})
                            or original.get('evidence_bindings')!=evidence_bindings
                            or original.get('task_review_provenance')!=provenance
                            or original.get('approval_bindings')!=approval_bindings):
                        raise ValueError('qualification_campaign_evidence_changed')
                    proof=original
                else:
                    private.execute('INSERT INTO private_campaign_proofs VALUES(?,?,?)',
                        (campaign,fingerprint,canonical_json_line(proof)))
                private.commit()
            assessments={role:{**{k:a['body'][k] for k in
                ('subject_digest','verdict','issued_at','expires_at','issuer','trust_revision')},
                'attestation_digest':a['digest']} for role,a in proof['attestations'].items()}
            public={'kind':'IssuedCampaignEligibility','bindings':bindings,'assessments':assessments,
                'approval_bindings':approval_bindings,'producer_uid':GATE_UID,'production_ready':False}
            public['digest']=digest_jcs(public)
            db.execute('BEGIN IMMEDIATE')
            prior=db.execute('SELECT generation,bindings_digest,proof,revoked FROM issued_campaigns WHERE campaign=?',(campaign,)).fetchone()
            if prior:
                if prior!=(generation,fingerprint,canonical_json_line(public),0):
                    raise ValueError('qualification_immutable_campaign')
            else:
                db.execute('INSERT INTO issued_campaigns VALUES(?,?,?,?,0)',
                    (campaign,generation,fingerprint,canonical_json_line(public)))
            db.commit()
        return public

    def revoke(self, campaign, *, expected_generation):
        if os.geteuid() != GATE_UID:
            raise PermissionError('gate_issuer_uid_required')
        with closing(self.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT generation FROM issued_campaigns WHERE campaign=?', (campaign,)).fetchone()
            if row != (expected_generation,):
                raise ValueError('qualification_generation_mismatch')
            db.execute('UPDATE issued_campaigns SET revoked=1 WHERE campaign=?', (campaign,))
            db.commit()


@contextmanager
def current_qualification(path, *, campaign, expected_bindings, subject_role, authority_directory):
    """Controller reads the live issuer-owned database, not caller-provided proof.

    The controller must obtain expected generation/source/config from its current
    authoritative registry; caller input from a package/PR is never sufficient.
    """
    if os.geteuid() != CONTROLLER_UID:
        raise PermissionError('controller_consumer_uid_required')
    path = _path(path)
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
        db.execute('BEGIN')
        row = db.execute('SELECT bindings_digest,proof,revoked FROM issued_campaigns WHERE campaign=?', (campaign,)).fetchone()
        identity = db.execute('SELECT epoch,config FROM qualification_identity WHERE singleton=1').fetchone()
        if not row:raise ValueError('qualification_missing')
        if row[2]:raise ValueError('qualification_revoked')
        if row[0] != digest_jcs(expected_bindings):
            raise ValueError('qualification_binding_mismatch')
        proof = decode_json(row[1])
        if proof.get('digest') != digest_jcs({k:v for k,v in proof.items() if k != 'digest'}):
            raise ValueError('qualification_store_digest')
        if (proof['bindings'] != expected_bindings or
                identity != (expected_bindings['deployment_epoch'], expected_bindings['config_digest'])):
            raise ValueError('qualification_live_identity')
        if (db.execute('PRAGMA user_version').fetchone()!=(2,) or proof.get('kind')!='IssuedCampaignEligibility'
                or set(proof)!={'kind','bindings','assessments','approval_bindings','producer_uid','production_ready','digest'}
                or proof.get('producer_uid')!=GATE_UID or proof.get('production_ready') is not False):
            raise ValueError('qualification_private_legacy_projection_denied')
        assessments=proof['assessments']
        if set(assessments)!=set(expected_bindings['subjects']) or subject_role not in assessments:
            raise ValueError('qualification_complete_subject_pair_required')
        now=datetime.now(timezone.utc)
        for role,assessment in assessments.items():
            if (set(assessment)!={'subject_digest','verdict','issued_at','expires_at','issuer','trust_revision','attestation_digest'}
                    or assessment['subject_digest']!=expected_bindings['subjects'][role]
                    or assessment['issuer']!='local-authority' or assessment['trust_revision']!=expected_bindings['trust_revision']
                    or assessment['verdict'] not in {'pass','fail'}):
                raise ValueError('qualification_assessment_binding')
            issued=datetime.fromisoformat(assessment['issued_at'].replace('Z','+00:00'))
            expiry=datetime.fromisoformat(assessment['expires_at'].replace('Z','+00:00'))
            if issued.tzinfo is None or expiry.tzinfo is None or not timedelta(0)<expiry-issued<=timedelta(hours=24):
                raise ValueError('consumption_ttl_invalid')
            if now<issued:raise ValueError('consumption_not_yet_valid')
            if now>=expiry:raise ValueError('consumption_expired')
        selected=assessments[subject_role]
        if selected['verdict']!='pass':raise ValueError('consumption_not_pass')
        approvals=proof.get('approval_bindings',{})
        if set(approvals)!=set(assessments) or any(type(refs) is not list or not refs for refs in approvals.values()):
            raise ValueError('qualification_actual_approval_bindings_missing')
        from skillloop.proxy.qualification_authority import current_authority
        with current_authority(authority_directory,epoch=expected_bindings['deployment_epoch'],
                config_digest=expected_bindings['config_digest'],trust_revision=expected_bindings['trust_revision'],
                approval_digests={a for refs in approvals.values() for a in refs}) as authority:
            admitted={a['subject_digest']:a for a in authority.get('source_admissions',[]) if a['campaign_id']==campaign}
            if (any(subject not in admitted for subject in expected_bindings['subjects'].values())
                    or admitted[expected_bindings['subjects']['submitted']]['source_snapshot_digest']!=expected_bindings['source_snapshot_digest']):
                raise ValueError('qualification_authority_changed')
            # Registry only consumes the authenticated credential identity and
            # aggregate status. Private plans/matrices never cross this grant.
            yield {'kind':'CurrentCampaignEligibility','digest':selected['attestation_digest'],
                'body':dict(selected),'production_ready':False}


def consume_current(path, *, campaign, expected_bindings, subject_role, authority_directory):
    with current_qualification(path,campaign=campaign,expected_bindings=expected_bindings,subject_role=subject_role,
                               authority_directory=authority_directory) as attestation:
        return attestation
