"""Controller-owned active registry backed by live Gate qualification custody."""
from contextlib import closing,contextmanager
import os
import re
from pathlib import Path
import sqlite3
import stat
import uuid
import time

from skillloop.protocol import canonical_json_line, decode_json, digest_jcs, make_envelope, validate_envelope
from .qualification_store import current_qualification


class CampaignRegistry:
    def __init__(self, path):
        if os.geteuid() != 21001:
            raise PermissionError('controller_registry_uid_required')
        path = Path(path).absolute()
        parent = path.parent.lstat()
        if (path.parent.is_symlink() or parent.st_uid != 21001 or
                stat.S_IMODE(parent.st_mode) != 0o700 or path.is_symlink()):
            raise PermissionError('controller_registry_directory')
        if path.exists():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 21001 or stat.S_IMODE(info.st_mode) != 0o600:
                raise PermissionError('controller_registry_file')
        previous = os.umask(0o077)
        try:
            self.path=path
            with closing(sqlite3.connect(path)) as db:
                db.execute('PRAGMA synchronous=FULL')
                db.executescript('''CREATE TABLE IF NOT EXISTS projects(project TEXT PRIMARY KEY,generation INTEGER,head TEXT,config TEXT);
                    CREATE TABLE IF NOT EXISTS formal_campaigns(
                    campaign TEXT PRIMARY KEY,project TEXT,profile TEXT,source BLOB,bindings BLOB);
                    CREATE TABLE IF NOT EXISTS active_subjects(project TEXT,profile TEXT,revision INTEGER,result BLOB,
                    PRIMARY KEY(project,profile));
                    CREATE TABLE IF NOT EXISTS promotions(operation TEXT PRIMARY KEY,parameters TEXT,result BLOB);
                    CREATE TABLE IF NOT EXISTS active_campaigns(project TEXT,profile TEXT,campaign TEXT NOT NULL,
                    PRIMARY KEY(project,profile));
                    CREATE TABLE IF NOT EXISTS evaluation_operations(operation TEXT PRIMARY KEY,parameters TEXT,bindings BLOB);
                    CREATE TABLE IF NOT EXISTS campaign_roster_freezes(campaign TEXT PRIMARY KEY,
                    original_bindings BLOB NOT NULL,gate_freeze BLOB NOT NULL,final_bindings BLOB NOT NULL);
                    CREATE TABLE IF NOT EXISTS campaign_original_clocks(campaign TEXT PRIMARY KEY,
                    started_at REAL NOT NULL,deadline TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS project_rounds(project TEXT PRIMARY KEY,epoch TEXT NOT NULL,generation INTEGER NOT NULL,head TEXT NOT NULL,config TEXT NOT NULL);''')
                db.commit()
        finally:
            os.umask(previous)

    @staticmethod
    def _archive_fence(db,campaign):
        # The original committed withdrawal operation is the authority. No
        # caller flag or second independently mutable archived boolean is used.
        for (raw,) in db.execute("SELECT result FROM promotions WHERE operation LIKE 'archive-withdraw-%'"):
            value=decode_json(raw)
            if value.get('kind')=='RegistryArchiveWithdrawal' and value.get('campaign')==campaign:
                if value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):
                    raise ValueError('campaign_archive_fence_integrity')
                raise ValueError('campaign_closed_by_archive_withdrawal')

    def begin_evaluation(self, *, project, profile, source, config_digest,
                         deployment_epoch, trust_revision, subjects, operation_id,
                         campaign_started_at=None):
        """Persist generation and exact source scope atomically before dispatch.

        Only trusted Controller code calls this after full budget/source/approval
        admission. This creates no model execution and does not assert admission.
        """
        if os.geteuid()!=21001:raise PermissionError('controller_registry_uid_required')
        validate_envelope(source)
        digest_pattern=r'sha256:[0-9a-f]{64}'
        if (source['kind']!='SourceSnapshot' or source['body']['source_kind']!='git_commit'
                or source['body']['immutable'] is not True
                or profile not in {'orders_total','refunds_total','markdown_index'}
                or type(subjects) is not dict or not subjects.get('submitted')
                or set(subjects)-{'submitted','finalist','active'}
                or any(type(v) is not str or not re.fullmatch(digest_pattern,v) for v in subjects.values())
                or not re.fullmatch(digest_pattern,config_digest)
                or type(trust_revision) is not int or not 1<=trust_revision<=9007199254740991
                or any(type(v) is not str or not 1<=len(v)<=256 for v in (project,deployment_epoch,operation_id))):
            raise ValueError('evaluation_frozen_binding_required')
        parameters={'project':project,'profile':profile,'source_snapshot_digest':source['digest'],
                    'config_digest':config_digest,'deployment_epoch':deployment_epoch,
                    'trust_revision':trust_revision,'subjects':subjects}
        if campaign_started_at is not None:
            if (type(campaign_started_at) not in (int,float)
                    or not 0<campaign_started_at<=time.time()
                    or time.time()-campaign_started_at>=28800):
                raise ValueError('evaluation_original_real_clock_required')
            parameters['campaign_started_at']=campaign_started_at
        fingerprint=digest_jcs(parameters)
        # The campaign must exist before bounded repair discovers a finalist.
        # Its stable identity binds the submitted source and original round;
        # changing the later subject roster cannot create a second budget.
        campaign=digest_jcs({k:v for k,v in parameters.items() if k not in {'subjects','campaign_started_at'}} |
                            {'submitted_subject':subjects['submitted']})
        with closing(sqlite3.connect(self.path,timeout=2)) as db:
            db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
            self._archive_fence(db,campaign)
            if campaign_started_at is not None:
                from datetime import datetime,timezone
                deadline=datetime.fromtimestamp(campaign_started_at+28800,timezone.utc).isoformat().replace('+00:00','Z')
                clock=db.execute('SELECT started_at,deadline FROM campaign_original_clocks WHERE campaign=?',(campaign,)).fetchone()
                if clock is not None and clock!=(campaign_started_at,deadline):
                    raise ValueError('evaluation_original_clock_changed')
                db.execute('INSERT OR IGNORE INTO campaign_original_clocks VALUES(?,?,?)',
                           (campaign,campaign_started_at,deadline))
            operation=db.execute('SELECT parameters,bindings FROM evaluation_operations WHERE operation=?',
                                 (operation_id,)).fetchone()
            if operation:
                if operation[0]!=fingerprint:raise ValueError('evaluation_operation_conflict')
                # Original operation identity survives supersession, but downstream
                # dispatch/consumption must still check the live generation.
                return decode_json(operation[1])
            prior=db.execute('SELECT project,profile,source,bindings FROM formal_campaigns WHERE campaign=?',
                             (campaign,)).fetchone()
            if prior:
                if prior[:3]!=(project,profile,canonical_json_line(source)):
                    raise ValueError('evaluation_campaign_conflict')
                bindings=decode_json(prior[3])
                if bindings['subjects']!=subjects:
                    raise ValueError('evaluation_subject_roster_requires_finalist_freeze')
                current=db.execute('SELECT generation,head,config FROM projects WHERE project=?',(project,)).fetchone()
                if current!=(bindings['generation'],source['body']['source_commit_sha'],config_digest):
                    raise ValueError('evaluation_superseded_campaign')
            else:
                row=db.execute('SELECT generation,head,config FROM projects WHERE project=?',(project,)).fetchone()
                admitted=db.execute('SELECT epoch,generation,head,config FROM project_rounds WHERE project=?',(project,)).fetchone()
                if admitted and admitted[0]==deployment_epoch:
                    if (admitted[2:]!=(source['body']['source_commit_sha'],config_digest)
                            or row!=admitted[1:]):
                        raise ValueError('evaluation_same_round_identity_changed')
                    generation=admitted[1]
                else:
                    generation=row[0]+1 if row else 1
                    if generation>9007199254740991:raise ValueError('evaluation_generation_exhausted')
                    db.execute('INSERT OR REPLACE INTO project_rounds VALUES(?,?,?,?,?)',
                        (project,deployment_epoch,generation,source['body']['source_commit_sha'],config_digest))
                bindings={'campaign':campaign,'generation':generation,'deployment_epoch':deployment_epoch,
                          'config_digest':config_digest,'source_snapshot_digest':source['digest'],
                          'trust_revision':trust_revision,'subjects':subjects}
                db.execute('INSERT OR REPLACE INTO projects VALUES(?,?,?,?)',
                           (project,generation,source['body']['source_commit_sha'],config_digest))
                db.execute('INSERT INTO formal_campaigns VALUES(?,?,?,?,?)',
                           (campaign,project,profile,canonical_json_line(source),canonical_json_line(bindings)))
            db.execute('INSERT INTO evaluation_operations VALUES(?,?,?)',
                       (operation_id,fingerprint,canonical_json_line(bindings)))
            db.commit()
            return bindings

    def freeze_subjects(self,*,campaign,gate_freeze_path):
        """Consume the real Gate's development freeze once, before Factory use.

        This records the final roster, not source authorization or eligibility.
        The original campaign/generation/budget identity and original roster
        remain durable. A new finalist never creates a replacement campaign.
        """
        if os.geteuid()!=21001:raise PermissionError('controller_registry_uid_required')
        from skillloop.discovery.formal_task_gate import read_owned
        from datetime import datetime,timezone
        freeze=read_owned(gate_freeze_path,uid=21005,gid=21001,limit=262144)
        fields={'kind','campaign_id','generation','deployment_epoch','config_digest',
                'source_snapshot_digest','trust_revision','subjects','development_plan_digest',
                'development_evidence_digest','repair_rounds_allowed','repair_rounds_used',
                'protected_evaluation','deadline','digest'}
        if (set(freeze)!=fields or freeze['kind']!='FrozenCampaignSubjectRoster'
                or freeze['campaign_id']!=campaign or freeze['protected_evaluation']!='not_started'
                or type(freeze['repair_rounds_allowed']) is not int
                or freeze['repair_rounds_allowed'] not in (0,1,2)
                or type(freeze['repair_rounds_used']) is not int
                or not 0<=freeze['repair_rounds_used']<=freeze['repair_rounds_allowed']
                or type(freeze['subjects']) is not dict or 'submitted' not in freeze['subjects']
                or set(freeze['subjects'])-{'submitted','finalist','active'}
                or any(type(d) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',d)
                       for d in [*freeze['subjects'].values(),freeze['development_plan_digest'],
                                 freeze['development_evidence_digest']])):
            raise ValueError('campaign_roster_actual_gate_freeze_required')
        deadline=datetime.fromisoformat(freeze['deadline'].replace('Z','+00:00'))
        if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline:
            raise ValueError('campaign_roster_original_clock_expired')
        with closing(sqlite3.connect(self.path,timeout=2)) as db:
            db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
            self._archive_fence(db,campaign)
            row=db.execute('SELECT project,source,bindings FROM formal_campaigns WHERE campaign=?',
                           (campaign,)).fetchone()
            if row is None:raise ValueError('formal_campaign_not_registered')
            clock=db.execute('SELECT deadline FROM campaign_original_clocks WHERE campaign=?',(campaign,)).fetchone()
            if clock is None or clock[0]!=freeze['deadline']:
                raise ValueError('campaign_roster_original_clock_binding_missing')
            project,source,bindings=row[0],decode_json(row[1]),decode_json(row[2])
            current=db.execute('SELECT generation,head,config FROM projects WHERE project=?',(project,)).fetchone()
            if current!=(bindings['generation'],source['body']['source_commit_sha'],bindings['config_digest']):
                raise ValueError('campaign_roster_superseded_generation')
            prior=db.execute('SELECT gate_freeze,final_bindings FROM campaign_roster_freezes WHERE campaign=?',
                             (campaign,)).fetchone()
            if prior:
                if prior[0]!=canonical_json_line(freeze):raise ValueError('campaign_roster_already_frozen')
                return decode_json(prior[1])
            if (any(freeze[k]!=bindings[k] for k in ('generation','deployment_epoch','config_digest',
                    'source_snapshot_digest','trust_revision'))
                    or freeze['subjects']['submitted']!=bindings['subjects']['submitted']
                    or freeze['subjects'].get('active')!=bindings['subjects'].get('active')):
                raise ValueError('campaign_roster_original_binding_changed')
            final={**bindings,'subjects':freeze['subjects']}
            db.execute('INSERT INTO campaign_roster_freezes VALUES(?,?,?,?)',
                (campaign,canonical_json_line(bindings),canonical_json_line(freeze),canonical_json_line(final)))
            db.execute('UPDATE formal_campaigns SET bindings=? WHERE campaign=?',
                       (canonical_json_line(final),campaign))
            db.commit()
            return final

    def close_protected_task(self,*,plan_path,controller,ledger,engine,whole_round_manifest_path,journal_directory):
        """Production campaign caller; private evidence stays in role mounts."""
        from skillloop.runtime.protected_flow import ProtectedTaskCloser
        return ProtectedTaskCloser(engine=engine,ledger=ledger,registry=self,controller=controller,
            whole_round_manifest_path=whole_round_manifest_path,journal_directory=journal_directory).close(plan_path)

    def frozen_subjects(self,*,campaign):
        """Factory dispatch must resolve this committed freeze before payloads."""
        with self.private_scope(campaign=campaign) as state:
            return state

    @contextmanager
    def private_scope(self,*,campaign):
        """Hold the current frozen generation through one private role action."""
        if os.geteuid()!=21001:raise PermissionError('controller_registry_uid_required')
        with closing(sqlite3.connect(self.path,timeout=2)) as db:
            if db.execute('PRAGMA journal_mode').fetchone()!=('delete',):
                raise ValueError('campaign_registry_serialized_private_scope_required')
            db.execute('BEGIN')
            self._archive_fence(db,campaign)
            row=db.execute('SELECT final_bindings,gate_freeze FROM campaign_roster_freezes WHERE campaign=?',
                           (campaign,)).fetchone()
            if row is None:raise ValueError('campaign_roster_not_frozen')
            bindings,freeze=map(decode_json,row)
            clock=db.execute('SELECT deadline FROM campaign_original_clocks WHERE campaign=?',(campaign,)).fetchone()
            if clock is None or clock[0]!=freeze['deadline']:
                raise ValueError('campaign_roster_original_clock_changed')
            from datetime import datetime,timezone
            deadline=datetime.fromisoformat(freeze['deadline'].replace('Z','+00:00'))
            current=db.execute('SELECT p.generation,p.head,p.config,c.source,c.bindings FROM projects p JOIN formal_campaigns c ON c.project=p.project WHERE c.campaign=?',
                               (campaign,)).fetchone()
            if (current is None or current[:3]!=(bindings['generation'],
                    decode_json(current[3])['body']['source_commit_sha'],bindings['config_digest'])
                    or decode_json(current[4])!=bindings or deadline.tzinfo is None
                    or datetime.now(timezone.utc)>=deadline):
                raise ValueError('campaign_roster_stale_or_expired')
            yield {'bindings':bindings,'gate_freeze':freeze}

    @contextmanager
    def development_scope(self,*,campaign):
        """Resolve current development authority before generator/patcher start."""
        if os.geteuid()!=21001:raise PermissionError('controller_registry_uid_required')
        from datetime import datetime,timezone
        with closing(sqlite3.connect(self.path,timeout=2)) as db:
            if db.execute('PRAGMA journal_mode').fetchone()!=('delete',):
                raise ValueError('campaign_development_serialization_requires_delete_journal')
            db.execute('BEGIN')
            self._archive_fence(db,campaign)
            if db.execute('SELECT 1 FROM campaign_roster_freezes WHERE campaign=?',(campaign,)).fetchone():
                raise ValueError('campaign_development_closed_after_freeze')
            row=db.execute('SELECT c.source,c.bindings,p.generation,p.head,p.config,t.deadline FROM formal_campaigns c JOIN projects p ON p.project=c.project JOIN campaign_original_clocks t ON t.campaign=c.campaign WHERE c.campaign=?',
                           (campaign,)).fetchone()
            if row is None:raise ValueError('campaign_development_original_admission_missing')
            source,bindings=decode_json(row[0]),decode_json(row[1])
            deadline=datetime.fromisoformat(row[5].replace('Z','+00:00'))
            if (row[2:5]!=(bindings['generation'],source['body']['source_commit_sha'],bindings['config_digest'])
                    or deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline):
                raise ValueError('campaign_development_stale_or_expired')
            # Retain this read transaction through the actual proposal call.
            # A concurrent roster freeze cannot commit and release private
            # payloads while an admitted development proposal is in flight.
            yield {'bindings':bindings,'deadline':row[5]}

    def bind_campaign(self, *, project, profile, source, bindings):
        """Trusted controller records the new frozen campaign before evaluation."""
        if os.geteuid()!=21001:raise PermissionError('controller_registry_uid_required')
        validate_envelope(source)
        if (source['kind'] != 'SourceSnapshot' or source['body']['source_kind'] != 'git_commit'
                or source['body']['immutable'] is not True or
                source['digest'] != bindings['source_snapshot_digest'] or
                not bindings['subjects'].get('submitted')):
            raise ValueError('formal_campaign_source_binding')
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
            self._archive_fence(db,bindings['campaign'])
            current = db.execute('SELECT generation,head,config FROM projects WHERE project=?', (project,)).fetchone()
            if current != (bindings['generation'], source['body']['source_commit_sha'], bindings['config_digest']):
                raise ValueError('formal_campaign_current_generation')
            values = (project,profile,canonical_json_line(source),canonical_json_line(bindings))
            prior = db.execute('SELECT project,profile,source,bindings FROM formal_campaigns WHERE campaign=?',
                               (bindings['campaign'],)).fetchone()
            if prior and prior != values:
                raise ValueError('formal_campaign_immutable')
            db.execute('INSERT OR IGNORE INTO formal_campaigns VALUES(?,?,?,?,?)', (bindings['campaign'], *values));db.commit()

    def promote(self, *, qualification_path, authority_directory, campaign, subject, expected_active_revision, operation_id=None):
        if os.geteuid() != 21001:
            raise PermissionError('controller_registry_uid_required')
        if type(expected_active_revision) is not int or expected_active_revision < 0:
            raise ValueError('active_revision_required')
        operation = operation_id or 'promote-'+uuid.uuid4().hex
        if type(operation) is not str or not 1 <= len(operation) <= 256:
            raise ValueError('promotion_operation_id')
        parameters = digest_jcs([campaign,subject,expected_active_revision])
        with closing(sqlite3.connect(self.path,timeout=2)) as db:
            db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
            self._archive_fence(db,campaign)
            row = db.execute('SELECT project,profile,source,bindings FROM formal_campaigns WHERE campaign=?', (campaign,)).fetchone()
            if not row:
                raise ValueError('formal_campaign_not_registered')
            project,profile = row[:2];source,bindings = decode_json(row[2]),decode_json(row[3])
            # Adoption is for the submitted exact Git commit. A passing finalist
            # cannot confer eligibility on a different submitted source/head.
            if bindings['subjects']['submitted'] != subject:
                raise ValueError('promotion_requires_evaluated_submitted_git_subject')
            current = db.execute('SELECT generation,head,config FROM projects WHERE project=?', (project,)).fetchone()
            if current != (bindings['generation'], source['body']['source_commit_sha'], bindings['config_digest']):
                raise ValueError('promotion_stale_generation')
            # Hold the issuer read transaction through the local registry commit.
            # Gate revoke cannot acknowledge while this protected consumption runs.
            with current_qualification(qualification_path,campaign=campaign,expected_bindings=bindings,
                    subject_role='submitted',authority_directory=authority_directory) as attestation:
                old = db.execute('SELECT parameters,result FROM promotions WHERE operation=?', (operation,)).fetchone()
                if old:
                    if old[0] != parameters:
                        raise ValueError('promotion_operation_conflict')
                    return decode_json(old[1])
                active = db.execute('SELECT revision FROM active_subjects WHERE project=? AND profile=?', (project,profile)).fetchone()
                revision = active[0] if active else 0
                if revision != expected_active_revision:
                    raise ValueError('active_revision_conflict')
                result = make_envelope('RegistryEntry', {'project_id':project,'profile_id':profile,
                    'subject_digest':subject,'evaluation_attestation_digest':attestation['digest'],
                    'source_commit_sha':source['body']['source_commit_sha'],'generation':bindings['generation'],
                    'eligibility':'eligible','trust_revision':bindings['trust_revision']})
                db.execute('INSERT OR REPLACE INTO active_subjects VALUES(?,?,?,?)', (project,profile,revision+1,canonical_json_line(result)))
                db.execute('INSERT OR REPLACE INTO active_campaigns VALUES(?,?,?)',(project,profile,campaign))
                db.execute('INSERT INTO promotions VALUES(?,?,?)', (operation,parameters,canonical_json_line(result)))
                db.commit()
                return result

    def withdraw_for_archive(self, *, withdrawal_path, qualification_path,
                             expected_active_revision, operation_id):
        """Invalidate only the active entry linked to the withdrawn campaign.

        Gate withdrawal precedes this local CAS. The issuer read transaction
        confirms the actual revoked row through the Registry commit; this is
        not a distributed atomic archive/deletion transaction.
        """
        if os.geteuid()!=21001:raise PermissionError('controller_registry_uid_required')
        if type(expected_active_revision) is not int or expected_active_revision<0:
            raise ValueError('archive_active_revision_required')
        if type(operation_id) is not str or not 1<=len(operation_id)<=256:
            raise ValueError('archive_withdrawal_operation_id')
        from skillloop.discovery.formal_task_gate import read_owned
        from .qualification_store import _path
        completion=read_owned(withdrawal_path,uid=21005,gid=21001,limit=262144)
        receipt=completion.get('withdrawal',{})
        if (completion.get('kind')!='FormalQualificationWithdrawalCompletion'
                or completion.get('qualification_revoked') is not True
                or completion.get('deletion_authorized') is not False
                or receipt.get('kind')!='GateQualificationWithdrawal'
                or receipt.get('producer_uid')!=21005 or receipt.get('qualification_revoked') is not True
                or receipt.get('deletion_authorized') is not False
                or digest_jcs({k:v for k,v in receipt.items() if k!='digest'})!=receipt.get('digest')):
            raise ValueError('archive_gate_withdrawal_required')
        bindings=receipt['bindings'];campaign=bindings['campaign']
        operation='archive-withdraw-'+operation_id
        parameters=digest_jcs([completion['digest'],expected_active_revision])
        with closing(sqlite3.connect(self.path,timeout=2)) as db:
            db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT project,profile,bindings FROM formal_campaigns WHERE campaign=?',(campaign,)).fetchone()
            if row is None or decode_json(row[2])!=bindings:
                raise ValueError('archive_original_registered_campaign_required')
            project,profile=row[:2]
            with closing(sqlite3.connect(_path(qualification_path).as_uri()+'?mode=ro',uri=True,timeout=2)) as issuer:
                issuer.execute('BEGIN')
                identity=issuer.execute('SELECT epoch,config FROM qualification_identity WHERE singleton=1').fetchone()
                qualification=issuer.execute('SELECT bindings_digest,proof,revoked FROM issued_campaigns WHERE campaign=?',(campaign,)).fetchone()
                if (issuer.execute('PRAGMA user_version').fetchone()!=(2,)
                        or identity!=(bindings['deployment_epoch'],bindings['config_digest'])
                        or qualification is None or qualification[0]!=digest_jcs(bindings) or qualification[2]!=1):
                    raise ValueError('archive_live_issuer_withdrawal_required')
                proof=decode_json(qualification[1])
                if (proof.get('digest')!=receipt['eligibility_digest'] or proof.get('bindings')!=bindings
                        or digest_jcs({k:v for k,v in proof.items() if k!='digest'})!=proof.get('digest')):
                    raise ValueError('archive_withdrawal_original_eligibility_changed')
                old=db.execute('SELECT parameters,result FROM promotions WHERE operation=?',(operation,)).fetchone()
                if old:
                    if old[0]!=parameters:raise ValueError('archive_withdrawal_operation_conflict')
                    return decode_json(old[1])
                link=db.execute('SELECT campaign FROM active_campaigns WHERE project=? AND profile=?',(project,profile)).fetchone()
                active=db.execute('SELECT revision,result FROM active_subjects WHERE project=? AND profile=?',(project,profile)).fetchone()
                changed=False
                if link==(campaign,):
                    if active is None or active[0]!=expected_active_revision:
                        raise ValueError('archive_active_revision_conflict')
                    original=decode_json(active[1]);validate_envelope(original)
                    if original['kind']!='RegistryEntry' or original['body']['subject_digest']!=bindings['subjects']['submitted']:
                        raise ValueError('archive_active_original_subject_binding')
                    if original['body']['eligibility']=='eligible':
                        updated=make_envelope('RegistryEntry',{**original['body'],'eligibility':'revoked'})
                        db.execute('UPDATE active_subjects SET revision=?,result=? WHERE project=? AND profile=?',
                            (active[0]+1,canonical_json_line(updated),project,profile));changed=True
                result={'kind':'RegistryArchiveWithdrawal','campaign':campaign,
                    'gate_withdrawal_digest':receipt['digest'],'active_entry_changed':changed,
                    'qualification_revoked':True,'deletion_authorized':False}
                result['digest']=digest_jcs(result)
                db.execute('INSERT INTO promotions VALUES(?,?,?)',(operation,parameters,canonical_json_line(result)))
                db.commit()
                return result

    def active(self, *, project, profile, qualification_path, authority_directory):
        """Resolve current eligibility at consumption, never trust stored pass.

        This reads the real Gate-owned issuer under the same lock order as
        promote. Old rows lacking a full campaign binding are rejected, not
        silently migrated into eligibility. Missing/tampered evidence raises.
        """
        if os.geteuid()!=21001:raise PermissionError('controller_registry_uid_required')
        with closing(sqlite3.connect(self.path,timeout=2)) as db:
            db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT revision,result FROM active_subjects WHERE project=? AND profile=?',(project,profile)).fetchone()
            if row is None:return None
            result=decode_json(row[1]);validate_envelope(result)
            if result['kind']!='RegistryEntry' or result['body']['project_id']!=project or result['body']['profile_id']!=profile:
                raise ValueError('active_registry_entry_binding')
            if result['body']['eligibility']!='eligible':return result
            link=db.execute('SELECT campaign FROM active_campaigns WHERE project=? AND profile=?',(project,profile)).fetchone()
            if link is None:raise ValueError('active_original_campaign_binding_missing')
            campaign=db.execute('SELECT source,bindings FROM formal_campaigns WHERE campaign=? AND project=? AND profile=?',(link[0],project,profile)).fetchone()
            if campaign is None:raise ValueError('active_original_campaign_missing')
            source,bindings=map(decode_json,campaign)
            current=db.execute('SELECT generation,head,config FROM projects WHERE project=?',(project,)).fetchone()
            stale=current!=(bindings['generation'],source['body']['source_commit_sha'],bindings['config_digest'])
            eligibility='stale' if stale else None
            if not stale:
                try:
                    with current_qualification(qualification_path,campaign=link[0],expected_bindings=bindings,
                            subject_role='submitted',authority_directory=authority_directory) as proof:
                        if (proof['digest']!=result['body']['evaluation_attestation_digest']
                                or bindings['subjects']['submitted']!=result['body']['subject_digest']):
                            raise ValueError('active_attestation_changed')
                        # Commit while issuer read custody still blocks revoke ACK.
                        db.commit()
                        return result
                except ValueError as error:
                    if str(error)=='consumption_expired':eligibility='expired'
                    elif str(error) in {'qualification_revoked','qualification_approval_revoked'}:eligibility='revoked'
                    elif str(error)=='qualification_authority_changed':eligibility='stale'
                    else:raise
            updated=make_envelope('RegistryEntry',{**result['body'],'eligibility':eligibility})
            db.execute('UPDATE active_subjects SET revision=?,result=? WHERE project=? AND profile=?',
                       (row[0]+1,canonical_json_line(updated),project,profile))
            db.commit()
            return updated
