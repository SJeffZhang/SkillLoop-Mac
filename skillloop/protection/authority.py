"""Durable epoch and delivery reservations; no delivered-session reexecution."""
import os
import re
import secrets
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from skillloop.protocol import canonical_json_line,decode_json,digest_jcs,validate_envelope

class ProtectionAuthority:
    def __init__(self, root: Path, *, readonly=False):
        self.readonly=readonly
        if readonly:
            self.path=root/'authority.sqlite'
            parent=root.lstat();info=self.path.lstat()
            if root.is_symlink() or self.path.is_symlink() or not stat.S_ISDIR(parent.st_mode) or not stat.S_ISREG(info.st_mode):
                raise PermissionError('protected_authority_read_path')
            if os.geteuid()==21005:
                if (parent.st_uid!=21004 or parent.st_gid!=21005 or stat.S_IMODE(parent.st_mode)!=0o750 or
                        info.st_uid!=21004 or info.st_gid!=21005 or stat.S_IMODE(info.st_mode)!=0o640):
                    raise PermissionError('protected_authority_gate_read_grant')
                from skillloop.discovery.formal_task_gate import read_owned
                import hashlib
                from datetime import datetime,timezone
                snapshot=read_owned(root/'snapshot.json',uid=21004,gid=21005,limit=262144)
                if (snapshot.get('kind')!='EvaluatorGateAuthoritySnapshot'
                        or snapshot.get('producer_uid')!=21004 or snapshot.get('reader_gid')!=21005
                        or snapshot.get('original_database_permissions_changed') is not False
                        or snapshot.get('qualification_issued') is not False
                        or type(snapshot.get('maximum_database_bytes')) is not int
                        or not 1<=snapshot['maximum_database_bytes']<=536870912
                        or info.st_nlink!=1 or info.st_size!=snapshot.get('database_size_bytes')
                        or not 1<=info.st_size<=snapshot['maximum_database_bytes']
                        or type(snapshot.get('timeout_seconds')) is not int or not 1<=snapshot['timeout_seconds']<=30
                        or type(snapshot.get('elapsed_seconds')) not in (int,float)
                        or not 0<=snapshot['elapsed_seconds']<=snapshot['timeout_seconds']):
                    raise ValueError('protected_authority_consistent_snapshot_manifest')
                expiry=datetime.fromisoformat(snapshot['campaign_deadline'].replace('Z','+00:00'))
                exported=datetime.fromisoformat(snapshot['exported_at'].replace('Z','+00:00'))
                if (expiry.tzinfo is None or exported.tzinfo is None or exported>datetime.now(timezone.utc)
                        or exported>=expiry or expiry<=datetime.now(timezone.utc)):
                    raise TimeoutError('protected_authority_snapshot_original_clock')
                h=hashlib.sha256()
                fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as stream:
                    before=os.fstat(stream.fileno())
                    for block in iter(lambda:stream.read(1048576),b''):
                        if datetime.now(timezone.utc)>=expiry:raise TimeoutError('protected_authority_snapshot_review_clock')
                        h.update(block)
                    after=os.fstat(stream.fileno())
                pin=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
                if pin(info)!=pin(before) or pin(before)!=pin(after) or 'sha256:'+h.hexdigest()!=snapshot['database_digest']:
                    raise ValueError('protected_authority_consistent_snapshot_changed')
                self.snapshot=snapshot
                self.snapshot_identity=pin(after)
            elif parent.st_uid!=os.geteuid() or parent.st_mode&0o077 or info.st_uid!=os.geteuid() or info.st_mode&0o077:
                raise PermissionError('protected_authority_private_owner')
            return
        root=Path(root)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info=root.lstat()
        if (root.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700):
            raise ValueError('private_directory_permissions')
        self.path = root / 'authority.sqlite'
        self._check_writable_path()
        if not os.path.lexists(self.path):
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            os.close(fd)
        with self.connect() as db:
            db.executescript('''BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS epochs (
                campaign TEXT PRIMARY KEY, finalist TEXT NOT NULL, epoch TEXT UNIQUE NOT NULL,
                projection TEXT UNIQUE NOT NULL, opaque_ref TEXT UNIQUE NOT NULL, factory TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS payloads (digest TEXT PRIMARY KEY, epoch TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (key TEXT PRIMARY KEY, epoch TEXT NOT NULL,
                state TEXT NOT NULL, result_digest TEXT);
                CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, key TEXT NOT NULL,
                old_state TEXT, new_state TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS formal_session_bindings (
                key TEXT PRIMARY KEY, binding BLOB NOT NULL, assignment_digest TEXT);''')
        # Internal transport claims have a checked migration version. DDL and
        # its version commit together; a partially upgraded deployment cannot
        # call claim methods against a missing/unrecognized table.
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS formal_runtime_schema (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL)')
            version=db.execute('SELECT version FROM formal_runtime_schema WHERE singleton=1').fetchone()
            if version is not None and version!=(1,):
                raise ValueError('formal_private_runtime_schema_version')
            db.execute('CREATE TABLE IF NOT EXISTS formal_runtime_materializations (session_key TEXT PRIMARY KEY REFERENCES sessions(key), launch_action TEXT UNIQUE NOT NULL, opaque_ref TEXT UNIQUE NOT NULL, launch_digest TEXT UNIQUE NOT NULL, runtime_action TEXT UNIQUE)')
            columns=[row[1] for row in db.execute('PRAGMA table_info(formal_runtime_materializations)')]
            if columns!=['session_key','launch_action','opaque_ref','launch_digest','runtime_action']:
                raise ValueError('formal_private_runtime_schema_shape')
            unique=set()
            for index in db.execute('PRAGMA index_list(formal_runtime_materializations)').fetchall():
                if index[2]:
                    unique.add(tuple(row[2] for row in db.execute('SELECT seqno,cid,name FROM pragma_index_info(?)',(index[1],))))
            if not {('session_key',),('launch_action',),('opaque_ref',),('launch_digest',),('runtime_action',)}<=unique:
                raise ValueError('formal_private_runtime_schema_unique_constraints')
            if version is None:db.execute('INSERT INTO formal_runtime_schema VALUES(1,1)')
        os.chmod(self.path, 0o600)
    @contextmanager
    def connect(self):
        if not self.readonly:self._check_writable_path()
        if self.readonly and hasattr(self,'snapshot_identity'):
            info=self.path.lstat()
            if (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=self.snapshot_identity:
                raise ValueError('protected_authority_snapshot_changed_after_admission')
        db=(sqlite3.connect(self.path.absolute().as_uri()+('?mode=ro&immutable=1' if hasattr(self,'snapshot_identity') else '?mode=ro'),uri=True,timeout=10)
            if self.readonly else sqlite3.connect(self.path,timeout=10))
        try:
            db.execute('PRAGMA synchronous=FULL')
            if self.readonly:db.execute('PRAGMA query_only=ON')
            with db:yield db
        finally:db.close()
    def _check_writable_path(self):
        parent=self.path.parent.lstat()
        if (self.path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid!=os.geteuid() or stat.S_IMODE(parent.st_mode)!=0o700):
            raise PermissionError('protected_authority_private_owner')
        if os.path.lexists(self.path):
            info=self.path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1):
                raise PermissionError('protected_authority_private_database')

    def export_gate_snapshot(self, *, campaign, opaque_ref, output_directory,
                             maximum_bytes, timeout_seconds):
        """Publish a bounded consistent copy; never grant Gate the writable DB."""
        import hashlib
        import time
        from datetime import datetime,timezone
        from skillloop.protection.current_task import _directory,_publish
        if (self.readonly or os.geteuid()!=21004 or 21005 not in set(os.getgroups())|{os.getegid()}
                or type(maximum_bytes) is not int or not 1<=maximum_bytes<=536870912
                or type(timeout_seconds) is not int or not 1<=timeout_seconds<=30):
            raise PermissionError('formal_private_gate_snapshot_actual_evaluator')
        record=self.resolve_formal_bundle(campaign=campaign,opaque_ref=opaque_ref)
        deadline=datetime.fromisoformat(record['deadline'].replace('Z','+00:00'))
        if deadline.tzinfo is None or (deadline-datetime.now(timezone.utc)).total_seconds()<=timeout_seconds+120:
            raise TimeoutError('formal_private_snapshot_original_clock')
        output=_directory(output_directory,21004,21005,0o750)
        if any(output.iterdir()):raise FileExistsError('formal_private_snapshot_fresh_directory_required')
        started=time.monotonic()
        def bounded(*_):
            if time.monotonic()-started>=timeout_seconds or (deadline-datetime.now(timezone.utc)).total_seconds()<=120:
                raise TimeoutError('formal_private_snapshot_export_clock')
            if pending.exists() and pending.stat().st_size>maximum_bytes:
                raise ValueError('formal_private_snapshot_export_capacity')
        pending=output/'authority.pending'
        fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        destination=sqlite3.connect(pending,timeout=min(10,timeout_seconds))
        try:
            destination.execute('PRAGMA journal_mode=DELETE')
            destination.execute('PRAGMA synchronous=FULL')
            with self.connect() as source:
                source.backup(destination,pages=64,progress=bounded,sleep=0.01)
            bounded()
            destination.set_progress_handler(lambda: int(time.monotonic()-started>=timeout_seconds),1000)
            if destination.execute('PRAGMA integrity_check').fetchone()!=('ok',):
                raise ValueError('formal_private_snapshot_integrity')
            row=destination.execute('SELECT record FROM formal_private_bundles WHERE campaign=?',(campaign,)).fetchone()
            if row is None or decode_json(row[0])!=record:
                raise ValueError('formal_private_snapshot_committed_bundle_changed')
        finally:
            destination.close()
        bounded()
        h=hashlib.sha256()
        fd=os.open(pending,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'r+b') as stream:
            info=os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=21004
                    or not 1<=info.st_size<=maximum_bytes):
                raise PermissionError('formal_private_snapshot_file_custody')
            for block in iter(lambda:stream.read(1048576),b''):
                bounded();h.update(block)
            os.fchown(stream.fileno(),-1,21005);os.fchmod(stream.fileno(),0o640);os.fsync(stream.fileno())
        bounded()
        final=output/'authority.sqlite'
        os.rename(pending,final)
        receipt={'kind':'EvaluatorGateAuthoritySnapshot','campaign_id':campaign,'opaque_ref':opaque_ref,
            'private_record_digest':record['digest'],'deployment_epoch':record['deployment_epoch'],
            'config_digest':record['config_digest'],'database_digest':'sha256:'+h.hexdigest(),
            'database_size_bytes':info.st_size,'maximum_database_bytes':maximum_bytes,
            'timeout_seconds':timeout_seconds,'elapsed_seconds':time.monotonic()-started,
            'exported_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
            'campaign_deadline':record['deadline'],'producer_uid':21004,'reader_gid':21005,
            'original_database_permissions_changed':False,'qualification_issued':False}
        receipt['digest']=digest_jcs(receipt)
        _publish(output/'snapshot.json',receipt,21005)
        return receipt

    def resolve_formal_bundle(self,*,campaign,opaque_ref):
        """Resolve the full committed plan only inside Evaluator/Gate custody."""
        if os.geteuid() not in {21004,21005} or (os.geteuid()==21005 and not self.readonly):
            raise PermissionError('private_bundle_resolution_role')
        if (type(campaign) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',campaign)
                or type(opaque_ref) is not str or not re.fullmatch(r'protected-[0-9a-f]{32}',opaque_ref)):
            raise ValueError('private_bundle_opaque_identity')
        with self.connect() as db:
            row=db.execute('SELECT record FROM formal_private_bundles WHERE campaign=?',(campaign,)).fetchone()
            epoch=db.execute('SELECT epoch,opaque_ref FROM epochs WHERE campaign=?',(campaign,)).fetchone()
        if row is None:raise ValueError('private_bundle_not_committed')
        record=decode_json(row[0])
        if (record.get('kind')!='FormalPrivateFactoryBundle'
                or record.get('campaign_id')!=campaign or record.get('opaque_ref')!=opaque_ref
                or record.get('digest')!=digest_jcs({k:v for k,v in record.items() if k!='digest'})
                or epoch!=(record['bundle']['epoch_id'],opaque_ref)):
            raise ValueError('private_bundle_committed_identity')
        if self.readonly and hasattr(self,'snapshot'):
            if any(self.snapshot[a]!=record[b] for a,b in (('campaign_id','campaign_id'),
                    ('opaque_ref','opaque_ref'),('private_record_digest','digest'),
                    ('deployment_epoch','deployment_epoch'),('config_digest','config_digest'),('campaign_deadline','deadline'))):
                raise ValueError('protected_authority_snapshot_bundle_binding')
        from scripts.spec_v22_core import validate_plan
        validate_plan(record['private_plan'],record['compiled']['suite'])
        return record

    def reserve_formal_session(self,*,campaign,private_record_digest,subject,case,repetition):
        """Reserve only a task from this epoch's complete committed bundle.

        The Controller cannot supply a replacement suite or release a second
        session after a failed or unknown delivery. No private input is returned.
        """
        from datetime import datetime,timezone
        if self.readonly or os.geteuid()!=21004:
            raise PermissionError('formal_private_session_actual_evaluator')
        if (any(type(d) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',d)
                for d in (campaign,private_record_digest,subject,case))
                or type(repetition) is not int or not 0<=repetition<3):
            raise ValueError('formal_private_session_identity')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT record FROM formal_private_bundles WHERE campaign=?',(campaign,)).fetchone()
            if row is None:raise ValueError('formal_private_committed_bundle_required')
            record=decode_json(row[0])
            if (record.get('digest')!=private_record_digest
                    or private_record_digest!=digest_jcs({k:v for k,v in record.items() if k!='digest'})
                    or record.get('kind')!='FormalPrivateFactoryBundle' or record.get('campaign_id')!=campaign
                    or subject not in record['subjects'].values()):
                raise ValueError('formal_private_frozen_roster_binding')
            deadline=datetime.fromisoformat(record['deadline'].replace('Z','+00:00'))
            if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline:
                raise ValueError('formal_private_original_clock_expired')
            cases=[c for c in record['compiled']['cases'].values() if c['digest']==case]
            if (len(cases)!=1 or cases[0]['body']['split']!='protected'
                    or cases[0]['body']['repetitions']!=3):
                raise ValueError('formal_private_current_epoch_case_required')
            from scripts.spec_v22_core import validate_plan
            plan=record.get('private_plan')
            if type(plan) is not dict:raise ValueError('formal_private_evaluator_plan_required')
            validate_plan(plan,record['compiled']['suite'])
            selected=[item for item in plan['body']['items'] if item['subject_digest']==subject
                and item['case_digest']==case and item['repetition_index']==repetition
                and item['phase']=='protected' and item['requirement']=='required']
            if len(selected)!=1:raise ValueError('formal_private_full_plan_session_not_reserved')
            epoch=record['bundle']['epoch_id']
            committed=db.execute('SELECT epoch,opaque_ref FROM epochs WHERE campaign=?',(campaign,)).fetchone()
            if committed!=(epoch,record['opaque_ref']):
                raise ValueError('formal_private_atomic_bundle_epoch_mismatch')
            key=digest_jcs([record['deployment_epoch'],campaign,epoch,subject,case,repetition])
            if db.execute('SELECT 1 FROM sessions WHERE key=?',(key,)).fetchone():
                raise ValueError('no_protected_reexecution')
            db.execute('INSERT INTO sessions VALUES(?,?,?,NULL)',(key,epoch,'reserved'))
            db.execute('INSERT INTO audit(key,old_state,new_state) VALUES(?,NULL,?)',(key,'reserved'))
            binding={'campaign':campaign,'private_record_digest':private_record_digest,
                'deployment_epoch':record['deployment_epoch'],'config_digest':record['config_digest'],
                'epoch':epoch,'subject':subject,'case':case,'repetition':repetition,'deadline':record['deadline']}
            db.execute('INSERT INTO formal_session_bindings VALUES(?,?,NULL)',(key,canonical_json_line(binding)))
        return key

    def deliver_formal_session(self,*,key,assignment_path):
        """Commit delivery before exposing the current request to a Runtime.

        A crash between this commit and transport stays delivered/unknown; it
        never makes the task available again. The full suite stays private.
        """
        from datetime import datetime,timezone
        from skillloop.discovery.formal_task_gate import read_owned
        if self.readonly or os.geteuid()!=21004:raise PermissionError('formal_private_session_actual_evaluator')
        job=read_owned(assignment_path,uid=21004,gid=21004,limit=8388608)
        entry,intent=job.get('entry'),job.get('intent')
        assignment_fields={'kind','entry','intent','campaign_deadline','digest'}
        if (set(job) not in (assignment_fields,assignment_fields | {'runtime_materials'})
                or job.get('kind')!='FormalPrivateDeliveryAssignment' or type(entry) is not dict or type(intent) is not dict
                or entry.get('digest')!=digest_jcs({k:v for k,v in entry.items() if k!='digest'})
                or intent.get('digest')!=digest_jcs({k:v for k,v in intent.items() if k!='digest'})):
            raise ValueError('formal_private_current_assignment_required')
        request=intent['run_request'];validate_envelope(request)
        from skillloop.runtime.mac_entry import verify_protected_entry
        verify_protected_entry(entry,image=entry['config']['mac_runtime_image'],
            source_digest=entry['source_index_digest'],model_port=entry['config']['model_service_port'])
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT binding,assignment_digest FROM formal_session_bindings WHERE key=?',(key,)).fetchone()
            if row is None or row[1] is not None:raise ValueError('formal_private_session_not_reserved')
            pins=decode_json(row[0]);q=request['body']
            stored=db.execute('SELECT record FROM formal_private_bundles WHERE campaign=?',(pins['campaign'],)).fetchone()
            if stored is None:raise ValueError('formal_private_bundle_missing')
            original=decode_json(stored[0])
            expected_compiled=original['compiled']
            actual_compiled={k:v for k,v in entry['compiled'].items() if k not in {'subject_digest','skill_digest'}}
            import base64
            from skillloop.protocol import digest_bytes
            expected_inputs={name:base64.b64decode(value['base64_bytes'],validate=True)
                             for name,value in original['bundle']['inputs'].items()}
            expected_output=base64.b64decode(original['bundle']['expected_bytes']['base64_bytes'],validate=True)
            if (original['digest']!=pins['private_record_digest']
                    or original['digest']!=digest_jcs({k:v for k,v in original.items() if k!='digest'})
                    or actual_compiled!=expected_compiled or entry['plan']!=original['private_plan']
                    or {name:base64.b64decode(value,validate=True) for name,value in entry['private_inputs'].items()}!=expected_inputs
                    or entry['private_expected_digest']!=digest_bytes(expected_output)):
                raise ValueError('formal_private_actual_committed_suite_and_payload_required')
            from skillloop.loader import ApprovedPackageLoader,validate_source_admission
            from skillloop.families.registry import FamilyRegistry
            from skillloop.families.task_world import formal_task
            from scripts.spec_v22_core import canonical_policy
            from skillloop.families.builders import build_artifact
            admission=entry['source_admission']
            validate_source_admission(admission,original['config'],pins['subject'])
            package={name:base64.b64decode(raw,validate=True) for name,raw in admission['package_files'].items()}
            loader=ApprovedPackageLoader(approved_sources=admission['approved_sources'],
                reference_resource_ids=admission['reference_resource_ids'],
                approved_subjects=admission.get('approved_subjects'))
            profile=original['compiled']['profile_id']
            selected=loader.select(admission['source_snapshot'],package,admission['manifest'],
                profile_id=profile,family_id=FamilyRegistry().profile(profile)['family_id'])
            candidate=loader.approved_subjects.get(selected.source_snapshot_digest)
            if 'runtime_materials' in job:
                materials=job['runtime_materials']
                if (type(materials) is not dict or set(materials)!=
                        {'mutation','package_resources','tokenizer_hashes','model_lifecycle_digest'}
                        or materials['tokenizer_hashes']!=original['config']['tokenizer_hashes']
                        or materials['model_lifecycle_digest']!=entry['model_lifecycle_digest']
                        or materials['package_resources']!={'instruction':selected.files[0][1],
                            'references':[part[1] for part in selected.files[1:]]}):
                    raise ValueError('formal_private_prepared_runtime_materials')
                rendered=materials['mutation']
                spec=original['compiled']['mutations'].get(entry['case_id'])
                if spec is None:
                    if rendered is not None:raise ValueError('formal_private_unplanned_mutation')
                else:
                    notes=FamilyRegistry().profile(profile)['input_bindings']['notes']
                    if (type(rendered) is not dict or set(rendered)!=
                            {'spec','source_digest','payload_digest','rendered_digest','rendered_utf8','rendered_token_count'}
                            or rendered['spec']!=spec or rendered['source_digest']!=digest_bytes(expected_inputs[notes])
                            or rendered['rendered_digest']!=digest_bytes(rendered['rendered_utf8'].encode('utf-8'))
                            or type(rendered['rendered_token_count']) is not int or rendered['rendered_token_count']<0):
                        raise ValueError('formal_private_current_rendered_mutation')
            if (selected.subject_digest!=pins['subject'] or candidate is None
                    or candidate['body']['policy_digest']!=canonical_policy(intent['policy'])['digest']
                    or digest_bytes(package['SKILL.md'])!=entry['compiled']['skill_digest']
                    or build_artifact(profile,expected_inputs)!=expected_output):
                raise ValueError('formal_private_actual_subject_and_business_world')
            # An authentic private entry alone does not bind the separate task
            # intent. Rebuild its complete current world from committed bytes
            # before moving the session to delivered.
            expected_binding,expected_request,raw_inputs=formal_task(
                domain=intent['domain'],policy=intent['policy'],profile_id=profile,
                subject_digest=pins['subject'],case_digest=pins['case'],
                suite_digest=original['compiled']['suite']['digest'],plan_digest=original['private_plan']['digest'],
                repetition_index=pins['repetition'],run_id='run-'+entry['digest'][7:],
                task_instance_id='task-'+entry['digest'][7:],config_digest=original['config_digest'],
                initial_world_digest=digest_jcs({'profile_id':profile,
                    'inputs':{name:digest_bytes(raw) for name,raw in expected_inputs.items()},
                    'expected_digest':digest_bytes(expected_output)}),
                inputs=expected_inputs,package_resources=selected.resource_bytes())
            if (intent.get('kind')!='EvaluatorPrivateTask' or intent.get('profile_id')!=profile
                    or intent.get('deployment_epoch')!=original['deployment_epoch']
                    or intent.get('config')!=original['config'] or intent.get('plan')!=original['private_plan']
                    or intent.get('suite')!=original['compiled']['suite']
                    or intent.get('source_admission')!=admission
                    or intent.get('binding')!=expected_binding or request!=expected_request
                    or intent.get('input_resources')!={name:base64.b64encode(raw).decode('ascii')
                        for name,raw in raw_inputs.items()}
                    or entry['source_index_digest']!=original['source_index_digest']
                    or entry['approval_factory_digest']!=original['factory_profile_digest']
                    or entry['development_suite_epoch_id']!=original['development_suite_epoch_id']):
                raise ValueError('formal_private_current_intent_not_committed_world')
            deadline=datetime.fromisoformat(pins['deadline'].replace('Z','+00:00'))
            task_deadline=datetime.fromisoformat(intent['run_deadline'].replace('Z','+00:00'))
            if (task_deadline.tzinfo is None or task_deadline>deadline
                    or not 0<(task_deadline-datetime.now(timezone.utc)).total_seconds()
                        <=original['config']['proxy_deadline_seconds']):
                raise ValueError('formal_private_current_task_deadline')
            if (datetime.now(timezone.utc)>=deadline or job['campaign_deadline']!=pins['deadline']
                    or entry.get('kind')!='protected'
                    or entry.get('epoch_id')!=pins['epoch'] or entry.get('campaign_id')!=pins['campaign']
                    or intent.get('campaign_id')!=pins['campaign']
                    or entry['config'].get('deployment_epoch')!=pins['deployment_epoch']
                    or digest_jcs(entry['config'])!=pins['config_digest']
                    or entry['compiled']['subject_digest']!=pins['subject']
                    or entry['compiled']['cases'][entry['case_id']]['digest']!=pins['case']
                    or entry['repetition']!=pins['repetition']
                    or (q['subject_digest'],q['case_digest'],q['repetition_index'])
                        !=(pins['subject'],pins['case'],pins['repetition'])):
                raise ValueError('formal_private_current_task_binding')
            count=db.execute("UPDATE sessions SET state='delivered' WHERE key=? AND state='reserved'",(key,)).rowcount
            if count!=1:raise ValueError('formal_private_no_redelivery')
            pins.update(intent_digest=intent['digest'],entry_digest=entry['digest'],request_digest=request['digest'])
            db.execute('UPDATE formal_session_bindings SET assignment_digest=?,binding=? WHERE key=?',
                (job['digest'],canonical_json_line(pins),key))
            db.execute("INSERT INTO audit(key,old_state,new_state) VALUES(?,'reserved','delivered')",(key,))
        return {'key':key,'assignment_digest':job['digest'],'state':'delivered','automatic_reexecution_allowed':False}

    def claim_formal_launch(self, *, key, action_digest, reference):
        """Reserve one immutable launch per delivered session before publication."""
        if (self.readonly or os.geteuid()!=21004
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',action_digest)
                or reference.get('kind')!='EvaluatorOpaqueRunReference'
                or reference.get('digest')!=digest_jcs({k:v for k,v in reference.items() if k!='digest'})
                or not re.fullmatch(r'private-run-[0-9a-f]{32}',reference.get('opaque_ref',''))):
            raise PermissionError('formal_private_launch_claim_identity')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT s.state,b.binding FROM sessions s JOIN formal_session_bindings b ON b.key=s.key WHERE s.key=?',(key,)).fetchone()
            if row is None or row[0]!='delivered':raise ValueError('formal_private_launch_session_not_delivered')
            pins=decode_json(row[1])
            if (reference['campaign_id']!=pins['campaign'] or reference['deployment_epoch']!=pins['deployment_epoch']
                    or reference['run_request_digest']!=pins.get('request_digest')):
                raise ValueError('formal_private_launch_committed_request')
            if db.execute('SELECT 1 FROM formal_runtime_materializations WHERE session_key=?',(key,)).fetchone():
                raise RuntimeError('formal_private_launch_already_claimed_original_recovery_required')
            db.execute('INSERT INTO formal_runtime_materializations VALUES(?,?,?,?,NULL)',
                (key,action_digest,reference['opaque_ref'],reference['digest']))

    def claim_formal_runtime(self, *, key, launch_action, reference, runtime_action):
        """A new action ID cannot dispatch an already claimed private session."""
        if (self.readonly or os.geteuid()!=21004
                or any(not re.fullmatch(r'sha256:[0-9a-f]{64}',value) for value in (launch_action,runtime_action))):
            raise PermissionError('formal_private_runtime_claim_identity')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT m.launch_action,m.opaque_ref,m.launch_digest,m.runtime_action,s.state FROM formal_runtime_materializations m JOIN sessions s ON s.key=m.session_key WHERE m.session_key=?',(key,)).fetchone()
            if (row is None or row[:3]!=(launch_action,reference['opaque_ref'],reference['digest'])
                    or row[4]!='delivered'):
                raise ValueError('formal_private_runtime_original_launch_required')
            if row[3] is not None:
                raise RuntimeError('formal_private_runtime_already_claimed_original_recovery_required')
            db.execute('UPDATE formal_runtime_materializations SET runtime_action=? WHERE session_key=? AND runtime_action IS NULL',
                       (runtime_action,key))

    def formal_session_identity(self,key):
        if not (os.geteuid()==21004 and not self.readonly or os.geteuid()==21005 and self.readonly):
            raise PermissionError('formal_private_session_identity_role')
        with self.connect() as db:
            row=db.execute('SELECT binding FROM formal_session_bindings WHERE key=?',(key,)).fetchone()
        if row is None:raise ValueError('formal_private_session_missing')
        return decode_json(row[0])

    def finish_formal_session(self,*,key,evaluation_path=None,gate_review_path=None):
        """Only a matching real Evaluator/Gate pair can close delivery complete."""
        from skillloop.discovery.formal_task_gate import read_owned
        from scripts.spec_v22_core import execution_record
        if self.readonly or os.geteuid()!=21004:raise PermissionError('formal_private_session_actual_evaluator')
        if (evaluation_path is None)!=(gate_review_path is None):
            raise ValueError('formal_private_complete_review_pair_required')
        result_digest=None;state='unknown'
        if evaluation_path is not None:
            evaluation=read_owned(evaluation_path,uid=21004,gid=21004,limit=16777216)
            gate=read_owned(gate_review_path,uid=21005,gid=21004,limit=262144)
            record=execution_record(evaluation['run_request'],evaluation['result'],
                evaluation['evidence_index'],evaluation['task_binding'])
            if (evaluation.get('kind')!='FormalTaskEvaluation' or evaluation.get('evaluator_uid')!=21004
                    or gate.get('kind')!='FormalTaskEvidenceReview' or gate.get('gate_uid')!=21005
                    or gate.get('evidence_complete') is not True
                    or evaluation['evidence_index']['body']['complete'] is not True
                    or record!=evaluation['execution_record']
                    or gate.get('evaluation_digest')!=evaluation['digest']
                    or gate.get('execution_record_digest')!=record['digest']
                    or gate.get('intent_digest')!=evaluation['intent_digest']
                    or gate.get('entry_digest')!=evaluation['entry_digest']):
                raise ValueError('formal_private_real_independent_review_required')
            result_digest=record['digest'];state='complete'
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT binding,assignment_digest FROM formal_session_bindings WHERE key=?',(key,)).fetchone()
            if row is None or row[1] is None:raise ValueError('formal_private_delivery_required')
            if state=='complete':
                pins=decode_json(row[0]);q=evaluation['run_request']['body']
                if (evaluation['intent_digest']!=pins['intent_digest']
                        or evaluation['entry_digest']!=pins['entry_digest']
                        or evaluation['run_request']['digest']!=pins['request_digest']
                        or evaluation['deployment_epoch']!=pins['deployment_epoch']
                        or (q['subject_digest'],q['case_digest'],q['repetition_index'])
                            !=(pins['subject'],pins['case'],pins['repetition'])):
                    raise ValueError('formal_private_complete_session_binding')
            previous=db.execute('SELECT state,result_digest FROM sessions WHERE key=?',(key,)).fetchone()
            if previous==(state,result_digest):
                # Recover the original terminal result after a lost response;
                # no new delivery, model request, audit transition or TTL.
                return state
            if previous is None or previous[0]!='delivered':
                raise ValueError('formal_private_terminal_session_conflict')
            count=db.execute('UPDATE sessions SET state=?,result_digest=? WHERE key=? AND state=?',
                (state,result_digest,key,'delivered')).rowcount
            if count!=1:raise ValueError('formal_private_terminal_session_conflict')
            db.execute('INSERT INTO audit(key,old_state,new_state) VALUES(?,?,?)',(key,'delivered',state))
        return state
    def used(self):
        with self.connect() as db:
            return ([x[0] for x in db.execute('SELECT epoch FROM epochs')],
                [x[0] for x in db.execute('SELECT projection FROM epochs')],
                [x[0] for x in db.execute('SELECT digest FROM payloads')])
    def create_epoch(self, *, campaign, finalist, validation, factory_digest):
        if self.readonly:raise PermissionError('protected_authority_read_only')
        opaque='protected-'+secrets.token_hex(16)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT INTO epochs VALUES(?,?,?,?,?,?)', (campaign,finalist,
                validation['epoch_id'],validation['business_projection_digest'],opaque,factory_digest))
            db.executemany('INSERT INTO payloads VALUES(?,?)',
                [(d,validation['epoch_id']) for d in validation['payload_digests']])
        return opaque
    def reserve(self, deployment, campaign, epoch, subject, case, repetition):
        if self.readonly:raise PermissionError('protected_authority_read_only')
        key=digest_jcs([deployment,campaign,epoch,subject,case,repetition])
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='formal_private_bundles'").fetchone():
                if db.execute('SELECT 1 FROM formal_private_bundles WHERE campaign=?',(campaign,)).fetchone():
                    raise ValueError('formal_private_pinned_reservation_required')
            if db.execute('SELECT 1 FROM epochs WHERE campaign=? AND epoch=?',(campaign,epoch)).fetchone() is None:
                raise ValueError('unknown_epoch')
            if db.execute('SELECT 1 FROM sessions WHERE key=?',(key,)).fetchone():
                raise ValueError('no_protected_reexecution')
            db.execute('INSERT INTO sessions VALUES(?,?,?,NULL)',(key,epoch,'reserved'))
            db.execute('INSERT INTO audit(key,old_state,new_state) VALUES(?,NULL,?)',(key,'reserved'))
        return key
    def transition(self, key, expected, state, result_digest=None):
        if self.readonly:raise PermissionError('protected_authority_read_only')
        if (expected,state) not in {('reserved','delivered'),('reserved','not_delivered'),
                ('delivered','unknown'),('delivered','complete')}:
            raise ValueError('invalid_delivery_transition')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM formal_session_bindings WHERE key=?',(key,)).fetchone():
                raise ValueError('formal_private_authenticated_transition_required')
            count=db.execute('UPDATE sessions SET state=?,result_digest=? WHERE key=? AND state=?',
                (state,result_digest,key,expected)).rowcount
            if count!=1: raise ValueError('session_cas_conflict')
            db.execute('INSERT INTO audit(key,old_state,new_state) VALUES(?,?,?)',(key,expected,state))
    def state(self, key):
        with self.connect() as db:
            row=db.execute('SELECT state,result_digest FROM sessions WHERE key=?',(key,)).fetchone()
        return row
