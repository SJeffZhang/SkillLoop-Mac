"""Trusted Controller-to-Proxy bootstrap of an exact, approved imported task.

This is a local provisioning API, not a new tool/RPC method. Its file must be
written by the Controller in its private, Proxy-readable deployment directory.
The Runtime never receives this directory or the authority database. Starting
an admitted task still requires the real Controller start_run RPC and its lease.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import stat
import re
from contextlib import closing

from scripts.spec_v22_core import validate_plan
from skillloop.loader import ApprovedPackageLoader, validate_source_admission
from skillloop.protocol import canonical_json_line, decode_json, digest_bytes, digest_jcs, validate_envelope
from skillloop.proxy.store import ProxyError


def deployment_deadline(value):
    """Internal deployment clock preserves its original fractional UTC time.

    Core task/Lease stamps remain exact seconds; this parser does not alter
    that frozen grammar or round a campaign deadline into a new clock.
    """
    from datetime import datetime,timezone
    if (type(value) is not str or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z',value)):
        raise ValueError('task_deployment_original_utc_deadline')
    return datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc)


def validate_campaign_catalog(campaigns):
    if type(campaigns) is not dict or not 1 <= len(campaigns) <= 3:
        raise ValueError('task_admission_campaign_count')
    digest_pattern = re.compile(r'sha256:[0-9a-f]{64}\Z')
    for campaign, pins in campaigns.items():
        if (type(pins) is not dict or set(pins) != {'config_digest', 'plan_digest',
                'subjects', 'approval_operation', 'generation', 'disk_bytes'}
                or any(type(v) is not str or not digest_pattern.fullmatch(v)
                       for v in [campaign, pins['config_digest'], pins['plan_digest']])
                or type(pins['generation']) is not int or pins['generation']<1
                or pins['disk_bytes']!=2147483648 or type(pins['disk_bytes']) is not int
                or type(pins['approval_operation']) is not str
                or not 1 <= len(pins['approval_operation']) <= 256
                or type(pins['subjects']) is not dict or not 1 <= len(pins['subjects']) <= 4):
            raise ValueError('task_admission_campaign_catalog')
        for subject, source in pins['subjects'].items():
            if (type(source) is not dict or set(source) != {'source_snapshot_digest', 'skill_manifest_digest'}
                    or any(type(v) is not str or not digest_pattern.fullmatch(v)
                           for v in [subject, *source.values()])):
                raise ValueError('task_admission_subject_catalog')


class ControllerTaskAdmission:
    def __init__(self, store, *, admitted_campaigns, source_repositories=None):
        if os.geteuid() != 21003:
            raise PermissionError('task_admission_proxy_uid_required')
        # These complete campaign pins come from the administrator-owned sealed
        # deployment, not from the Controller request or Skill self declarations.
        self.store = store
        self.campaigns = decode_json(canonical_json_line(admitted_campaigns))
        validate_campaign_catalog(self.campaigns)
        self.source_repositories = decode_json(canonical_json_line(source_repositories or {}))
        if (type(self.source_repositories) is not dict
                or any(campaign not in self.campaigns for campaign in self.source_repositories)):
            raise ValueError('task_source_repository_catalog')
        for pin in self.source_repositories.values():
            if (type(pin) is not dict or set(pin)!={'repository','skill_path'}
                    or type(pin['repository']) is not str or not Path(pin['repository']).is_absolute()
                    or type(pin['skill_path']) is not str):
                raise ValueError('task_source_repository_pin')
            from skillloop.source import _path
            _path(pin['skill_path'])
        with store._transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS controller_task_admissions(intent TEXT PRIMARY KEY,task TEXT UNIQUE NOT NULL,receipt BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS controller_task_slots(campaign TEXT NOT NULL,item TEXT NOT NULL,task TEXT UNIQUE NOT NULL,PRIMARY KEY(campaign,item))')
            db.execute('CREATE TABLE IF NOT EXISTS controller_task_catalog(singleton INTEGER PRIMARY KEY CHECK(singleton=1),digest TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS controller_plan_heads(campaign TEXT PRIMARY KEY,plan TEXT NOT NULL,revision_digest TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS controller_plan_revisions(digest TEXT PRIMARY KEY,campaign TEXT NOT NULL,authorization BLOB NOT NULL,receipt BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS controller_source_admissions(campaign TEXT NOT NULL,subject TEXT NOT NULL,admission_digest TEXT NOT NULL,source_pins BLOB NOT NULL,authorization BLOB NOT NULL,PRIMARY KEY(campaign,subject))')
            db.execute('CREATE TABLE IF NOT EXISTS evaluator_protected_campaigns('
                       'campaign TEXT PRIMARY KEY,development_plan TEXT NOT NULL,protected_plan TEXT NOT NULL)')
            identity = digest_jcs(self.campaigns)
            row = db.execute('SELECT digest FROM controller_task_catalog WHERE singleton=1').fetchone()
            if row and row[0] != identity:
                raise ValueError('task_admission_catalog_changed')
            db.execute('INSERT OR IGNORE INTO controller_task_catalog VALUES(1,?)', (identity,))
            for campaign,pins in self.campaigns.items():
                db.execute('INSERT OR IGNORE INTO controller_plan_heads VALUES(?,?,NULL)',
                           (campaign,pins['plan_digest']))

    def _subject_pins(self,campaign,db=None):
        result=decode_json(canonical_json_line(self.campaigns[campaign]['subjects']))
        if db is None:
            with closing(self.store._connect()) as connection:
                rows=connection.execute('SELECT subject,source_pins FROM controller_source_admissions WHERE campaign=?',
                                        (campaign,)).fetchall()
        else:
            rows=db.execute('SELECT subject,source_pins FROM controller_source_admissions WHERE campaign=?',
                            (campaign,)).fetchall()
        for subject,raw in rows:result[subject]=decode_json(raw)
        return result

    def authorize_source(self,path):
        """Resolve an actual Admin source grant, retaining bounded repair lineage."""
        from skillloop.discovery.formal_task_gate import read_owned
        from skillloop.proxy.store import _parse,_now
        value=read_owned(path,uid=21010,gid=21003,limit=2097152)
        fields={'kind','deployment_digest','deployment_epoch','campaign_id','config',
                'subject_digest','admission','parent_subject_digest','application_review_path','digest'}
        if (set(value)!=fields or value['kind']!='AdminCampaignSourceAdmission'
                or value['deployment_epoch']!=self.store.deployment_epoch):
            raise ValueError('task_source_admin_authorization')
        campaign=value['campaign_id'];pins=self.campaigns.get(campaign)
        if pins is None or digest_jcs(value['config'])!=pins['config_digest']:
            raise ProxyError('denied')
        if value['config'].get('source_admission_authority')!='admin_campaign_catalog_v1':
            raise ValueError('task_source_frozen_authority_required')
        subject=value['subject_digest'];admission=value['admission']
        validate_source_admission(admission,value['config'],subject)
        encoded=admission['package_files']
        if (type(encoded) is not dict or not 1<=len(encoded)<=32
                or any(type(raw) is not str or len(raw)>5464 for raw in encoded.values())):
            raise ValueError('task_source_package_capacity')
        package={key:base64.b64decode(raw,validate=True) for key,raw in encoded.items()}
        # A declared commit and an immutable flag do not prove Git provenance.
        # Resolve only the deployment-owned repository, never a request path.
        repository_pin=self.source_repositories.get(campaign)
        if repository_pin is None:raise ValueError('task_source_actual_repository_required')
        repository=Path(repository_pin['repository']);info=repository.lstat()
        if (repository.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid!=21010 or info.st_gid!=21003
                or stat.S_IMODE(info.st_mode)!=0o750):
            raise PermissionError('task_source_admin_repository_custody')
        from skillloop.source import import_git_package
        actual_snapshot,actual_package=import_git_package(repository,
            admission['source_snapshot']['body']['source_commit_sha'],repository_pin['skill_path'])
        if actual_snapshot!=admission['source_snapshot'] or actual_package!=package:
            raise ValueError('task_source_actual_git_objects_changed')
        source={'source_snapshot_digest':admission['source_snapshot']['digest'],
                'skill_manifest_digest':digest_jcs(admission['manifest'])}
        approved={source['source_snapshot_digest']:source['skill_manifest_digest']}
        if admission['approved_sources']!=approved:raise ValueError('task_source_exact_admin_catalog')
        from skillloop.families.registry import FamilyRegistry
        profile=admission['manifest']['profile_id']
        loader=ApprovedPackageLoader(approved_sources=approved,
            reference_resource_ids=admission['reference_resource_ids'],
            approved_subjects=admission.get('approved_subjects'))
        selected=loader.select(admission['source_snapshot'],package,admission['manifest'],
            profile_id=profile,family_id=FamilyRegistry().profile(profile)['family_id'])
        if selected.subject_digest!=subject:raise ValueError('task_source_candidate_identity')
        original=pins['subjects'].get(subject)
        parent=value['parent_subject_digest']
        if original is not None:
            if original!=source or parent is not None or value['application_review_path'] is not None:
                raise ValueError('task_source_original_catalog_changed')
        else:
            known=self._subject_pins(campaign)
            if type(value['application_review_path']) is not str:
                raise ValueError('task_source_bounded_parent_required')
            if parent not in known:raise ProxyError('version_conflict')
            review=read_owned(value['application_review_path'],uid=21005,gid=21001,limit=262144)
            if (review.get('kind')!='GateBoundedCandidateApplication'
                    or review.get('campaign_id')!=campaign
                    or review.get('deployment_epoch')!=self.store.deployment_epoch
                    or review.get('config_digest')!=pins['config_digest']
                    or review.get('parent_subject_digest')!=parent
                    or review.get('candidate_bundle_digest')!=subject
                    or review.get('package_digest')!=admission['source_snapshot']['body']['skill_digest']
                    or review.get('qualification_issued') is not False
                    or review.get('application_verified') is not True
                    or type(review.get('repair_round')) is not int or not 1<=review['repair_round']<=2
                    or review['repair_round']!=known[parent].get('repair_round',0)+1):
                raise ValueError('task_source_actual_bounded_application_review')
            source.update(repair_round=review['repair_round'],application_review=review)
        source['git_provenance']={'repository_pin_digest':digest_jcs(repository_pin),
            'source_commit_sha':actual_snapshot['body']['source_commit_sha'],
            'snapshot_digest':actual_snapshot['digest'],'package_bytes_verified':True}
        with self.store._transaction() as db:
            old=db.execute('SELECT admission_digest,source_pins,authorization FROM controller_source_admissions WHERE campaign=? AND subject=?',
                           (campaign,subject)).fetchone()
            if old is not None:
                if tuple(old)!=(digest_jcs(admission),canonical_json_line(source),canonical_json_line(value)):
                    raise ValueError('task_source_immutable_grant_conflict')
                return subject
            deployment=db.execute('SELECT digest,deadline FROM formal_proxy_deployment WHERE singleton=1').fetchone()
            if deployment is None or deployment[0]!=value['deployment_digest']:raise ProxyError('denied')
            if _now()>=deployment_deadline(deployment[1]):raise ProxyError('expired')
            if db.execute('SELECT 1 FROM evaluator_protected_campaigns WHERE campaign=?', (campaign,)).fetchone():
                raise ValueError('task_source_development_closed_after_private_delivery')
            current=self._subject_pins(campaign,db)
            if subject not in current and len(current)>=4:raise ProxyError('queue_full')
            if parent is not None and parent not in current:raise ProxyError('denied')
            revisions=db.execute('SELECT authorization FROM controller_plan_revisions WHERE campaign=?',(campaign,)).fetchall()
            if any(decode_json(row[0])['plan']['body']['phase']=='protected' for row in revisions):
                raise ValueError('task_source_development_closed_after_private_plan')
            db.execute('INSERT INTO controller_source_admissions VALUES(?,?,?,?,?)',
                (campaign,subject,digest_jcs(admission),canonical_json_line(source),canonical_json_line(value)))
            return subject

    def revise_plan(self,path):
        """Apply an Admin-sealed append revision without resetting the campaign.

        This authorizes plan rows only. It cannot add a source, candidate,
        approval, Factory session, budget, or qualification to the catalog.
        """
        from skillloop.discovery.formal_task_gate import read_owned
        from skillloop.proxy.store import _parse,_now
        value=read_owned(path,uid=21010,gid=21003,limit=2097152)
        if (set(value)!={'kind','deployment_digest','deployment_epoch','campaign_id',
                        'parent_plan','parent_suite','plan','suite','reason','digest'}
                or value['kind']!='AdminCampaignPlanRevision'
                or value['deployment_epoch']!=self.store.deployment_epoch
                or type(value['reason']) is not str or not 1<=len(value['reason'])<=512):
            raise ValueError('task_plan_revision_admin_binding')
        campaign=value['campaign_id'];pins=self.campaigns.get(campaign)
        if pins is None:raise ProxyError('denied')
        parent,plan=value['parent_plan'],value['plan']
        validate_plan(parent,value['parent_suite']);validate_plan(plan,value['suite'])
        old,new=parent['body'],plan['body']
        known_subjects=self._subject_pins(campaign)
        immutable=('campaign_id','config_digest','max_campaign_rollouts',
                   'max_campaign_execution_ms','runtime_profile_digest','terminal_reserve_ms')
        if (any(new[k]!=old[k] for k in immutable)
                or new['campaign_id']!=campaign or new['config_digest']!=pins['config_digest']
                or new['revision']!=old['revision']+1 or new['parent_plan_digest']!=parent['digest']
                or new['max_campaign_rollouts']!=128 or new['max_campaign_execution_ms']!=28800000
                or new['terminal_reserve_ms']<120000
                or new['reserved_auxiliary_ms']<old['reserved_auxiliary_ms']
                or len(new['items'])<=len(old['items'])
                or new['items'][:len(old['items'])]!=old['items']
                or len(new['items'])>128
                or any(item['subject_digest'] not in known_subjects for item in new['items'])
                or old['phase']=='protected'):
            raise ValueError('task_plan_revision_append_only_frozen_identity')
        # Existing cases keep all semantics, including repetitions and oracle
        # bindings. A revised suite may append discoveries/private cases only.
        old_cases={c['case_digest']:c for c in value['parent_suite']['body']['cases']}
        new_cases={c['case_digest']:c for c in value['suite']['body']['cases']}
        old_suite,new_suite=value['parent_suite']['body'],value['suite']['body']
        if (any(new_cases.get(key)!=case for key,case in old_cases.items())
                or any(new_suite[k]!=old_suite[k] for k in ('profile_id','objective_registry_digest'))
                or new_suite['base_case_digests'][:len(old_suite['base_case_digests'])]!=old_suite['base_case_digests']
                or new_suite['history_case_digests'][:len(old_suite['history_case_digests'])]!=old_suite['history_case_digests']):
            raise ValueError('task_plan_revision_old_cases_changed')
        with self.store._transaction() as db:
            existing=db.execute('SELECT authorization,receipt FROM controller_plan_revisions WHERE digest=?',
                                (value['digest'],)).fetchone()
            if existing:
                if existing[0]!=canonical_json_line(value):raise ValueError('task_plan_revision_conflict')
                return decode_json(existing[1])
            deployment=db.execute('SELECT digest,deadline FROM formal_proxy_deployment WHERE singleton=1').fetchone()
            if deployment is None or deployment[0]!=value['deployment_digest']:
                raise ValueError('task_plan_revision_original_deployment')
            if _now()>=deployment_deadline(deployment[1]):raise ProxyError('expired')
            if db.execute('SELECT 1 FROM evaluator_protected_campaigns WHERE campaign=?', (campaign,)).fetchone():
                raise ValueError('task_plan_development_closed_after_private_delivery')
            head=db.execute('SELECT plan FROM controller_plan_heads WHERE campaign=?',(campaign,)).fetchone()
            if head is None or tuple(head)!=(parent['digest'],):raise ProxyError('version_conflict')
            if db.execute('SELECT 1 FROM tasks t LEFT JOIN runs r ON r.run_id=t.run_id WHERE t.campaign_id=? AND (r.run_id IS NULL OR r.state IN (\'active\',\'finalizing\')) LIMIT 1',
                          (campaign,)).fetchone():
                raise ProxyError('queue_full')
            if db.execute('SELECT count(*) FROM controller_plan_revisions WHERE campaign=?',(campaign,)).fetchone()[0]>=32:
                raise ProxyError('queue_full')
            held=db.execute('SELECT plan,generation,disk_bytes,state FROM campaign_storage_reservations WHERE campaign=?',(campaign,)).fetchone()
            if held is not None:
                if tuple(held)!=(parent['digest'],pins['generation'],pins['disk_bytes'],'reserved'):
                    raise ProxyError('version_conflict')
                db.execute('UPDATE campaign_storage_reservations SET plan=? WHERE campaign=?',(plan['digest'],campaign))
            receipt={'kind':'ProxyCampaignPlanRevision','campaign_id':campaign,
                'deployment_epoch':self.store.deployment_epoch,'authorization_digest':value['digest'],
                'parent_plan_digest':parent['digest'],'plan_digest':plan['digest'],
                'original_deadline':deployment[1],'generation':pins['generation'],
                'new_capacity_allocated':False,'qualification_issued':False,'producer_uid':21003}
            receipt['digest']=digest_jcs(receipt)
            db.execute('INSERT INTO controller_plan_revisions VALUES(?,?,?,?)',
                       (value['digest'],campaign,canonical_json_line(value),canonical_json_line(receipt)))
            db.execute('UPDATE controller_plan_heads SET plan=?,revision_digest=? WHERE campaign=?',
                       (plan['digest'],value['digest'],campaign))
            return receipt

    def admit(self, path, *, expected_digest=None):
        path = Path(path)
        parent = path.parent.lstat()
        if (not path.is_absolute() or path.is_symlink() or path.parent.is_symlink()
                or parent.st_uid != 21001 or parent.st_gid != 21003
                or stat.S_IMODE(parent.st_mode) != 0o750):
            raise PermissionError('task_admission_controller_directory')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 21001 or info.st_gid != 21003
                    or stat.S_IMODE(info.st_mode) != 0o640 or info.st_size > 2097152):
                raise PermissionError('task_admission_controller_file')
            raw = stream.read(2097153)
        if len(raw) > 2097152:
            raise ValueError('task_admission_size')
        intent = decode_json(raw)
        required = {'kind', 'deployment_epoch', 'campaign_id', 'profile_id', 'domain', 'policy',
                    'binding', 'run_request', 'plan', 'suite', 'run_deadline', 'config',
                    'source_admission', 'input_resources', 'digest'}
        if (type(intent) is not dict or set(intent) != required or intent['kind'] != 'ControllerImportedTask'
                or intent['digest'] != digest_jcs({k: v for k, v in intent.items() if k != 'digest'})
                or intent['deployment_epoch'] != self.store.deployment_epoch
                or (expected_digest is not None and intent['digest'] != expected_digest)):
            raise ValueError('task_admission_intent')
        pins = self.campaigns.get(intent['campaign_id'])
        if not pins or digest_jcs(intent['config']) != pins['config_digest']:
            raise ProxyError('denied')
        plan = intent['plan']
        if plan['body']['phase']!='dev' or intent['suite']['body']['visibility']=='private_evaluation':
            raise PermissionError('controller_inbox_private_plan_forbidden')
        validate_plan(plan, intent['suite'])
        if (plan['body']['campaign_id'] != intent['campaign_id']
                or plan['body']['config_digest'] != pins['config_digest']
                or plan['body']['reserved_rollouts'] > 128):
            raise ValueError('task_admission_plan')
        request = validate_envelope(intent['run_request'])
        binding = validate_envelope(intent['binding'])
        domain = validate_envelope(intent['domain'])
        validate_envelope(intent['policy'])
        if request['kind'] != 'RunRequest' or binding['kind'] != 'TaskBinding' or domain['kind'] != 'AuthorizationDomain':
            raise ValueError('task_admission_object_kind')
        rb = request['body']
        items = [item for item in plan['body']['items'] if all(item[k] == rb[k] for k in
                 ('subject_digest', 'case_digest', 'repetition_index')) and item['requirement'] == 'required']
        if (len(items) != 1 or rb['plan_digest'] != plan['digest'] or rb['suite_digest'] != intent['suite']['digest']
                or rb['config_digest'] != pins['config_digest']):
            raise ValueError('task_admission_reserved_item')
        admission = intent['source_admission']
        validate_source_admission(admission, intent['config'], rb['subject_digest'])
        source = self._subject_pins(intent['campaign_id']).get(rb['subject_digest'])
        if (source is None or admission['source_snapshot']['digest'] != source['source_snapshot_digest']
                or digest_jcs(admission['manifest']) != source['skill_manifest_digest']):
            raise ValueError('task_admission_source_pins')
        encoded = admission['package_files']
        if (type(encoded) is not dict or not 1 <= len(encoded) <= 32
                or any(type(v) is not str or len(v) > 5464 for v in encoded.values())):
            raise ValueError('task_admission_package_bound')
        package = {k: base64.b64decode(v, validate=True) for k, v in encoded.items()}
        input_encoded = intent['input_resources']
        if type(input_encoded) is not dict or len(input_encoded) > 32 or any(type(v) is not str or len(v) > 131072 for v in input_encoded.values()):
            raise ValueError('task_admission_input_bound')
        inputs = {k: base64.b64decode(v, validate=True) for k, v in input_encoded.items()}
        # Ignore the request's approved_sources map as an authority source. Build
        # it from the already admitted deployment pins and compare for drift.
        approved = {source['source_snapshot_digest']: source['skill_manifest_digest']}
        if admission['approved_sources'] != approved:
            raise ValueError('task_admission_approved_source_catalog')
        loader = ApprovedPackageLoader(approved_sources=approved, reference_resource_ids=admission['reference_resource_ids'],
                                       approved_subjects=admission.get('approved_subjects'))
        from skillloop.proxy.store import _parse, _now
        deadline = _parse(intent['run_deadline'])
        seconds = intent['config'].get('proxy_deadline_seconds')
        task = binding['body']['task_instance_id']
        with self.store._transaction() as db:
            old = db.execute('SELECT receipt FROM controller_task_admissions WHERE intent=?', (intent['digest'],)).fetchone()
            if old:
                return decode_json(old[0])
            if db.execute('SELECT 1 FROM evaluator_protected_campaigns WHERE campaign=?', (intent['campaign_id'],)).fetchone():
                raise ProxyError('denied')
            if intent['config'].get('source_admission_authority') is not None:
                grant=db.execute('SELECT admission_digest FROM controller_source_admissions WHERE campaign=? AND subject=?',
                                 (intent['campaign_id'],rb['subject_digest'])).fetchone()
                if grant is None or grant[0]!=digest_jcs(admission):raise ProxyError('denied')
            head=db.execute('SELECT plan FROM controller_plan_heads WHERE campaign=?',(intent['campaign_id'],)).fetchone()
            if head is None or tuple(head)!=(plan['digest'],):raise ProxyError('version_conflict')
            deployment = db.execute('SELECT deadline FROM formal_proxy_deployment WHERE singleton=1').fetchone()
            if (deployment is None or deadline > deployment_deadline(deployment[0]) or type(seconds) is not int
                    or not 1 <= seconds <= 300 or not 0 < (deadline-_now()).total_seconds() <= seconds):
                raise ProxyError('expired')
            if db.execute('SELECT 1 FROM controller_task_slots WHERE campaign=? AND item=?',
                          (intent['campaign_id'], items[0]['item_id'])).fetchone():
                raise ProxyError('version_conflict')
            if db.execute('SELECT count(*) FROM controller_task_slots WHERE campaign=?', (intent['campaign_id'],)).fetchone()[0] >= 128:
                raise ProxyError('queue_full')
            issued = db.execute('SELECT role,method,result_json FROM operations WHERE operation_id=?',
                                (pins['approval_operation'],)).fetchone()
            if issued is None or tuple(issued[:2]) != ('admin', 'approve_domain'):
                raise ProxyError('approval_required')
            approval_result = decode_json(issued[2])
            from skillloop.proxy.wire import validate_control
            validate_control(approval_result)
            if approval_result['kind'] != 'ApprovalResult' or approval_result['body']['state'] != 'active':
                raise ProxyError('approval_required')
            approval_digest = approval_result['body']['approval_ref']
            self.store.stage_imported_task(loader=loader, source_snapshot=admission['source_snapshot'],
                package_files=package, skill_manifest=admission['manifest'], input_resources=inputs,
                domain=domain, policy=intent['policy'], binding=binding, run_request=request,
                profile_id=intent['profile_id'], approval_digest=approval_digest,
                run_deadline=intent['run_deadline'], campaign_id=intent['campaign_id'], _transaction_db=db)
            receipt = {'kind': 'ControllerTaskAdmission', 'intent_digest': intent['digest'],
                       'deployment_epoch': self.store.deployment_epoch, 'campaign_id': intent['campaign_id'],
                       'plan_digest': plan['digest'], 'item_id': items[0]['item_id'],
                       'run_request_digest': request['digest'], 'task_binding_digest': binding['digest'],
                       'approval_digest': approval_digest,
                       'trust_revision': approval_result['body']['effective_trust_revision'], 'producer_uid': 21003,
                       'qualification_issued': False}
            receipt['digest'] = digest_jcs(receipt)
            db.execute('INSERT INTO controller_task_slots VALUES(?,?,?)', (intent['campaign_id'],items[0]['item_id'],task))
            db.execute('INSERT INTO controller_task_admissions VALUES(?,?,?)', (intent['digest'],task,canonical_json_line(receipt)))
            return receipt
