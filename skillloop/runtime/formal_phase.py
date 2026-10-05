"""Serial formal plan execution inside a whole campaign's original budget.

Plans are produced by development/repair/private factories in the same round.
No legacy archive is consulted and no previously spent victim is replayed.
"""
from datetime import datetime, timezone
import base64
import os
from pathlib import Path
import time
import stat

from skillloop.protocol import digest_jcs, canonical_json_line
from skillloop.runtime.formal_execution import execute_admitted,prepare_development_materials
from skillloop.runtime.task_controller import FormalTaskController, imported_task_intent
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.repair.budget import SpendingLedger
from scripts.spec_v22_core import validate_plan
from skillloop.runtime.round_manifest import read_round_manifest, admit_phase


def _private_session_cost(unit):
    if unit['entry'].get('kind')=='protected' or unit.get('private_session_context') is not None:
        raise PermissionError('protected_phase_requires_private_evaluator_dispatch')
    return 0,0


class FormalPhaseExecutor:
    def __init__(self, *, controller, ledger, tokenizer, journal_directory, whole_round_manifest_path):
        if (os.geteuid()!=21001 or not isinstance(controller,FormalTaskController)
                or not isinstance(ledger,SpendingLedger) or not isinstance(tokenizer,ExactLocalTokenizer)):
            raise PermissionError('formal_phase_actual_roles_required')
        self.controller,self.ledger,self.tokenizer=controller,ledger,tokenizer
        self._manifest_path=whole_round_manifest_path
        self.round_manifest=read_round_manifest(whole_round_manifest_path)
        self.directory=Path(journal_directory)
        info=self.directory.lstat()
        if (not self.directory.is_absolute() or self.directory.is_symlink() or info.st_uid!=21001
                or info.st_mode&0o077):
            raise PermissionError('formal_phase_private_journal')

    def _save(self,path,value):
        value['digest']=digest_jcs({k:v for k,v in value.items() if k!='digest'})
        raw=canonical_json_line(value)
        if len(raw)>262144:
            raise ValueError('formal_phase_original_journal_capacity')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)

    def close_protected_task(self,*,closing_plan_path,registry,engine,journal_directory):
        # The whole campaign caller invokes this after the original private
        # Runtime completion. Full entries/plans never enter this dev executor.
        from skillloop.ci.campaign_registry import CampaignRegistry
        if type(registry) is not CampaignRegistry:raise PermissionError('formal_phase_actual_campaign_registry')
        return registry.close_protected_task(plan_path=closing_plan_path,controller=self.controller,
            ledger=self.ledger,engine=engine,whole_round_manifest_path=self._manifest_path,
            journal_directory=journal_directory)

    def recover_completed(self, phase, _depth=0):
        """Recover a lost summary response, never call a task producer again."""
        from skillloop.runtime.protected_flow import _controller_record
        from skillloop.discovery.formal_task_gate import read_owned
        if _depth>32:raise ValueError('formal_phase_original_parent_chain_capacity')
        if (phase.get('kind')!='FrozenFormalPhase' or phase.get('phase')!='dev'
                or phase.get('digest')!=digest_jcs({k:v for k,v in phase.items() if k!='digest'})):
            raise ValueError('formal_phase_recovery_original_phase')
        admit_phase(self.round_manifest,phase,self.ledger,self.controller.epoch)
        root=self.directory/phase['digest'][7:]
        admission=_controller_record(root/'admission.json')
        summary=_controller_record(root/'summary.json')
        if (admission.get('kind')!='FormalPhaseAdmission' or admission.get('phase_digest')!=phase['digest']
                or admission.get('whole_round_manifest_digest')!=self.round_manifest['digest']
                or admission.get('original_started_at')!=self.ledger.campaign_started_at
                or summary.get('kind')!='FormalPhaseExecutionSummary' or summary.get('phase_digest')!=phase['digest']
                or summary.get('campaign_started_at')!=self.ledger.campaign_started_at
                or summary.get('complete') is not True or summary.get('problems')!=[]
                or summary.get('unexecuted_entry_digests')!=[]):
            raise RuntimeError('formal_phase_original_complete_summary_required')
        from skillloop.discovery.phase_chain import development_parent
        parent=development_parent(phase)
        rebuilt=(list(self.recover_completed(parent,_depth+1)['completed']) if parent is not None else [])
        if (admission.get('carried_phase_digest')!=(parent['digest'] if parent is not None else None)
                or admission.get('carried_completed_entries')!=rebuilt
                or set(admission.get('required_item_ids',[]))!={i['item_id'] for i in phase['plan']['body']['items']
                    if i['requirement']=='required'}
                or len(admission.get('required_item_ids',[]))!=len(set(admission.get('required_item_ids',[])))):
            raise ValueError('formal_phase_original_complete_admission_and_parent')
        for unit in phase['entries']:
            token=digest_jcs(unit['entry']['entry_id'])[7:]
            prepared=_controller_record(root/('task-'+token+'.prepared.json'))
            completed=_controller_record(root/('task-'+token+'.completed.json'))
            attempted=_controller_record(root/('task-'+token+'.runtime-intent.json'))
            lease=_controller_record(root/('task-'+token+'.lease.json'))
            review=read_owned(unit['gate_review_path'],uid=21005,gid=21001,limit=262144)
            archive=read_owned(unit['archive_review_path'],uid=21005,gid=21001,limit=262144)
            retirement=_controller_record(Path(unit['retirement_journal_directory'])/'retirement-completion.json')
            for record,kind in ((prepared,'FormalPhaseTaskPrepared'),(completed,'FormalPhaseTaskCompleted'),
                    (attempted,'FormalPhaseRuntimeIntent'),(lease,'FormalPhaseLeaseObserved')):
                if (record.get('kind')!=kind or record.get('phase_digest')!=phase['digest']
                        or record.get('entry_digest')!=unit['entry']['digest']
                        or record.get('unit_digest')!=digest_jcs(unit)
                        or record.get('intent_digest')!=prepared.get('intent_digest')):
                    raise ValueError('formal_phase_original_task_journal_chain')
            materials=prepared.get('materials')
            if (type(materials) is not dict or materials.get('kind')!='FormalDevelopmentMaterialsPrepared'
                    or materials.get('entry_digest')!=unit['entry']['digest']
                    or materials.get('model_request_sent') is not False
                    or materials.get('digest')!=digest_jcs({k:v for k,v in materials.items() if k!='digest'})):
                raise ValueError('formal_phase_original_prelease_materials_required')
            if (attempted.get('lease_digest')!=lease['started']['digest']
                    or completed.get('runtime_capture_digest')!=review.get('runtime_capture_digest')
                    or completed.get('retirement_digest')!=retirement['digest']
                    or review.get('kind')!='FormalTaskEvidenceReview' or review.get('evidence_complete') is not True
                    or review.get('entry_digest')!=unit['entry']['digest']
                    or review.get('intent_digest')!=prepared['intent_digest']
                    or archive.get('kind')!='FormalTaskArchiveReview' or archive.get('complete') is not True
                    or archive.get('task_review_digest')!=review['digest']
                    or archive.get('intent_digest')!=prepared['intent_digest']
                    or retirement.get('kind')!='FormalTaskRetirementCompletion'
                    or retirement.get('intent_digest')!=prepared['intent_digest']
                    or retirement.get('archive_review_digest')!=archive['digest']
                    or retirement.get('budget_closure')!='within_original_budget'
                    or retirement.get('runtime_resources_released') is not True
                    or retirement.get('independent_archive_review_complete') is not True):
                raise ValueError('formal_phase_original_review_and_retirement_required')
            rebuilt.append({'entry_digest':unit['entry']['digest'],
                'runtime_capture_digest':review['runtime_capture_digest']})
        if rebuilt!=summary['completed']:
            raise ValueError('formal_phase_original_summary_task_coverage')
        return summary

    def run(self, phase):
        # The frozen visibility contract grants the full protected manifest,
        # plan and result matrix only to Evaluator/Gate. Controller dispatch
        # must use opaque current-task envelopes, not reuse this dev executor.
        if phase.get('phase')!='dev':
            raise PermissionError('protected_phase_requires_private_evaluator_dispatch')
        if (phase.get('kind')!='FrozenFormalPhase'
                or phase.get('digest')!=digest_jcs({k:v for k,v in phase.items() if k!='digest'})
                or not phase.get('whole_round_manifest_digest')):
            raise ValueError('formal_phase_frozen_whole_round_required')
        campaign=admit_phase(self.round_manifest,phase,self.ledger,self.controller.epoch)
        plan,suite=phase['plan'],phase['suite'];validate_plan(plan,suite)
        entries=phase['entries']
        if type(entries) is not list or not entries or len(entries)>128:
            raise ValueError('formal_phase_complete_entries_required')
        original=self.ledger.campaign_started_at
        if original is None or phase['campaign_started_at']!=original:
            raise ValueError('formal_phase_original_clock_changed')
        deadline=datetime.fromisoformat(phase['campaign_deadline'].replace('Z','+00:00'))
        if deadline.tzinfo is None or deadline.timestamp()!=original+28800:
            raise ValueError('formal_phase_original_eight_hour_clock')
        required=[i for i in plan['body']['items'] if i['requirement']=='required' and i['phase']==phase['phase']]
        from skillloop.discovery.phase_chain import development_parent
        parent=development_parent(phase)
        carried=[];matched=[]
        if parent is not None:
            # This is read-only verification of the original same-round tasks,
            # not substitution of historical experiments or new inference.
            prior=self.recover_completed(parent)
            carried=list(prior['completed'])
            matched=[i['item_id'] for i in parent['plan']['body']['items'] if i['requirement']=='required']
        cost=phase['terminal_seconds'];keys=set()
        if type(cost) is not int or cost<120:raise ValueError('formal_phase_terminal_reserve')
        # Preflight the ENTIRE phase before staging its first task or Lease.
        for unit in entries:
            session_seconds,session_disk=_private_session_cost(unit)
            entry=unit['entry'];config=entry['config'];compiled=entry['compiled']
            if (entry['digest']!=digest_jcs({k:v for k,v in entry.items() if k!='digest'})
                    or entry['plan']!=plan or compiled['suite']!=suite
                    or config.get('whole_flow_required') is not True
                    or not self.tokenizer.snapshot_hashes
                    or self.tokenizer.snapshot_hashes!=config.get('tokenizer_hashes')
                    or config['deployment_epoch']!=self.controller.epoch
                    or config['worker_deadline_seconds']!=self.ledger.victim_seconds
                    or unit['evaluator_policy']['campaign_deadline']!=phase['campaign_deadline']
                    or unit['gate_policy']['campaign_deadline']!=phase['campaign_deadline']):
                raise ValueError('formal_phase_entry_identity')
            case=compiled['cases'][entry['case_id']]
            items=[i for i in required if i['subject_digest']==compiled['subject_digest']
                   and i['subject_role']==entry['role'] and i['case_digest']==case['digest']
                   and i['repetition_index']==entry['repetition']]
            if len(items)!=1 or items[0]['item_id'] in matched or entry['entry_id'] in keys:
                raise ValueError('formal_phase_reserved_pair_coverage')
            if items[0]['timeout_ms']!=config['worker_deadline_seconds']*1000 or items[0]['attempts_reserved']!=1:
                raise ValueError('formal_phase_task_plan_timeout_or_attempts_mismatch')
            matched.append(items[0]['item_id']);keys.add(entry['entry_id'])
            for policy in (unit['evaluator_policy'],unit['gate_policy']):
                if (policy.get('digest')!=digest_jcs({k:v for k,v in policy.items() if k!='digest'})
                        or policy['entry_digest']!=entry['digest']
                        or policy['deployment_epoch']!=self.controller.epoch
                        or policy['image']!=config['mac_runtime_image']):
                    raise ValueError('formal_phase_independent_role_policy')
            output=Path(unit['runtime_output'])
            if not output.is_absolute() or os.path.lexists(output):
                raise ValueError('formal_phase_fresh_runtime_output_required')
            parent=output.parent.lstat()
            if output.parent.is_symlink() or parent.st_uid!=21001 or parent.st_mode&0o022:
                raise PermissionError('formal_phase_runtime_output_parent')
            grants=((unit['evaluator_assignment_directory'],21001,21004,0o750),
                    (unit['gate_journal_directory'],21001,21001,0o700),
                    (unit['retirement_journal_directory'],21001,21001,0o700),
                    (str(Path(unit['gate_review_path']).parent),21005,21001,0o750))
            for name,uid,gid,mode in grants:
                path=Path(name);info=path.lstat()
                if (not path.is_absolute() or path.is_symlink() or not stat.S_ISDIR(info.st_mode)
                        or info.st_uid!=uid or info.st_gid!=gid or stat.S_IMODE(info.st_mode)!=mode):
                    raise PermissionError('formal_phase_role_directory_not_provisioned')
            if os.path.lexists(unit['gate_review_path']):
                raise ValueError('formal_phase_prior_review_requires_recovery')
            from skillloop.discovery.formal_task_gate import read_owned
            archive=read_owned(unit['archive_policy_path'],uid=21010,gid=21001,limit=262144)
            if (archive.get('kind')!='FrozenDurableTaskArchive'
                    or archive['digest']!=config.get('durable_task_archive_policy_digest')
                    or archive.get('campaign_deadline')!=phase['campaign_deadline']
                    or archive.get('deployment_epoch')!=self.controller.epoch
                    or archive.get('image')!=config['mac_runtime_image']
                    or type(archive.get('timeout_seconds')) is not int or not 1<=archive['timeout_seconds']<=60
                    or type(archive.get('maximum_bytes')) is not int
                    or archive['maximum_bytes']<config['maximum_runtime_evidence_bytes']
                        +unit['evaluator_policy']['maximum_database_bytes']+2097152
                    or type(unit['archive_sources']) is not dict
                    or set(unit['archive_sources'])!={'runtime','authority','evaluation','gate'}
                    or unit['archive_sources']['runtime']!=str(output)
                    or unit['archive_sources']['gate']!=unit['gate_review_path']
                    or any(type(p) is not str or not Path(p).is_absolute() for p in unit['archive_sources'].values())):
                raise ValueError('formal_phase_complete_durable_archive_not_admitted')
            archive_gate=unit['archive_gate_policy']
            if (archive_gate.get('kind')!='FrozenArchiveGateDispatch'
                    or archive_gate.get('digest')!=digest_jcs({k:v for k,v in archive_gate.items() if k!='digest'})
                    or archive_gate.get('entry_digest')!=entry['digest']
                    or archive_gate.get('image')!=config['mac_runtime_image']
                    or archive_gate.get('deployment_epoch')!=self.controller.epoch
                    or archive_gate.get('campaign_deadline')!=phase['campaign_deadline']
                    or type(archive_gate.get('timeout_seconds')) is not int
                    or not 1<=archive_gate['timeout_seconds']<=120
                    or archive_gate.get('maximum_bytes')!=archive['maximum_bytes']
                    or archive_gate.get('maximum_files')!=archive['maximum_files']
                    or set(archive_gate.get('mounts',{}))!={'archive','original_reviews','reviews'}
                    or archive_gate['mounts']['archive']!={'volume':archive['archive_volume'],'subpath':'.'}
                    or archive_gate['mounts']['original_reviews']!=unit['gate_policy']['mounts']['reviews']
                    or any(type(unit[k]) is not str or not Path(unit[k]).is_absolute()
                        for k in ('archive_gate_journal_directory','archive_review_path'))):
                raise ValueError('formal_phase_independent_archive_gate_not_admitted')
            if (unit['evaluator_policy']['mounts'].keys()!=
                    {'assignment','runtime','snapshot','evaluation','tokenizer'}
                    or unit['gate_policy']['mounts'].keys()!=
                    {'assignment','runtime','snapshot','evaluation','tokenizer','reviews'}):
                raise ValueError('formal_phase_role_mount_scope')
            for field in ('assignment','runtime','snapshot','evaluation','tokenizer'):
                if unit['evaluator_policy']['mounts'][field]!=unit['gate_policy']['mounts'][field]:
                    raise ValueError('formal_phase_evaluator_gate_evidence_mount_mismatch')
            resources=unit['resource_context']
            if (type(resources) is not dict or resources.get('proxy_server_uid')!=21003
                    or resources.get('tokenizer_mount')!=unit['evaluator_policy']['mounts']['tokenizer']):
                raise ValueError('formal_phase_runtime_evaluator_tokenizer_mount_mismatch')
            from skillloop.protection.mac_runtime import worker_configuration
            worker_configuration(image=config['mac_runtime_image'],run_volume='preflight',
                socket_volume=resources['socket_volume'],model_volume=resources['model_volume'],
                runtime_uid=21002,tokenizer_mount=resources['tokenizer_mount'])
            if type(unit['admission_wait_seconds']) is not int or not 1<=unit['admission_wait_seconds']<=60:
                raise ValueError('formal_phase_admission_wait_bound')
            if (type(config.get('proxy_deadline_seconds')) is not int
                    or not 1<=config['proxy_deadline_seconds']<=300
                    or config['worker_deadline_seconds']+unit['admission_wait_seconds']+10
                        +session_seconds//2>=config['proxy_deadline_seconds']):
                raise ValueError('formal_phase_task_lease_full_cost_not_admitted')
            cost+=config['worker_deadline_seconds']+unit['evaluator_policy']['timeout_seconds']+unit['gate_policy']['timeout_seconds']+unit['admission_wait_seconds']+archive['timeout_seconds']+archive_gate['timeout_seconds']+120+session_seconds
        if (len(entries)>campaign['reserved_victim_attempts']
                or any(unit['entry']['profile']!=campaign['profile'] for unit in entries)):
            raise ValueError('formal_phase_whole_campaign_profile_or_attempts')
        if len(matched)!=len(required) or cost>phase['reserved_phase_seconds']:
            raise ValueError('formal_phase_full_auxiliary_cost_unreserved')
        if cost>(deadline-datetime.now(timezone.utc)).total_seconds():
            raise TimeoutError('formal_phase_full_original_budget_exhausted')
        spent=self.ledger.read()['executions']
        if len(spent)+len(entries)>campaign['reserved_victim_attempts']:
            raise ValueError('formal_phase_full_victim_reservation_exhausted')
        if any(item['item_key'] in keys for item in spent):
            raise RuntimeError('formal_phase_spent_items_require_recovery_no_replay')
        auxiliary_stage='protected' if phase['phase']=='protected' else 'development'
        auxiliary_bound=campaign['stages'][auxiliary_stage]
        prior_auxiliary=self.ledger.read().get('auxiliary_executions',[])
        if sum(e['stage']==auxiliary_stage for e in prior_auxiliary)+len(entries)>auxiliary_bound['count']:
            raise ValueError('formal_phase_complete_auxiliary_slots_not_reserved')
        for unit in entries:
            session_seconds,session_disk=_private_session_cost(unit)
            archive=read_owned(unit['archive_policy_path'],uid=21010,gid=21001,limit=262144)
            if (unit['admission_wait_seconds']+unit['evaluator_policy']['timeout_seconds']
                    +unit['gate_policy']['timeout_seconds']+archive['timeout_seconds']+unit['archive_gate_policy']['timeout_seconds']+120+session_seconds>auxiliary_bound['seconds']
                    or unit['evaluator_policy']['maximum_database_bytes']
                        +unit['entry']['config']['maximum_runtime_evidence_bytes']+2097152+archive['maximum_bytes']
                        +session_disk>auxiliary_bound['disk_bytes']):
                raise ValueError('formal_phase_complete_auxiliary_bounds_not_reserved')
        phase_root=self.directory/phase['digest'][7:];phase_root.mkdir(mode=0o700)
        self._save(phase_root/'admission.json',{'kind':'FormalPhaseAdmission',
            'phase_digest':phase['digest'],'whole_round_manifest_digest':phase['whole_round_manifest_digest'],
            'original_started_at':original,'reserved_phase_seconds':phase['reserved_phase_seconds'],
            'complete_cost_seconds':cost,'required_item_ids':matched,
            'carried_phase_digest':parent['digest'] if parent is not None else None,
            'carried_completed_entries':carried})
        reservation=self.controller.reserve_campaign(plan['body']['campaign_id'],plan['digest'])
        self._save(phase_root/'storage-admission.json', {'kind':'FormalPhaseStorageAdmission',
            'phase_digest':phase['digest'],'reservation':reservation})
        completed=list(carried);problems=[];visited=0
        for unit in entries:
            # Parent completions are part of the cumulative plan, not indices
            # into this revision's new task list. Record the current frontier
            # even if a task fails before admission or a model dispatch.
            visited+=1
            entry=unit['entry'];key=entry['entry_id'];capture=None
            try:
                if (deadline-datetime.now(timezone.utc)).total_seconds()<=phase['terminal_seconds']:
                    raise TimeoutError('formal_phase_terminal_boundary')
                if (deadline-datetime.now(timezone.utc)).total_seconds()<=entry['config']['worker_deadline_seconds']+unit['admission_wait_seconds']+phase['terminal_seconds']+10:
                    raise TimeoutError('formal_phase_original_clock_cannot_fit_next_task')
                # Reserve the complete independent review/closure bundle before
                # staging a task or issuing its lease. A failed admission or an
                # unknown process response cannot restore this slot.
                auxiliary_seconds=(unit['admission_wait_seconds']
                    +unit['evaluator_policy']['timeout_seconds']
                    +unit['gate_policy']['timeout_seconds']
                    +read_owned(unit['archive_policy_path'],uid=21010,gid=21001,limit=262144)['timeout_seconds']
                    +unit['archive_gate_policy']['timeout_seconds']+120+_private_session_cost(unit)[0])
                auxiliary=self.ledger.consume_auxiliary(
                    manifest=self.round_manifest,campaign=plan['body']['campaign_id'],
                    stage='protected' if phase['phase']=='protected' else 'development',
                    operation_key='task-custody-'+key,seconds=auxiliary_seconds,
                    input_tokens=0,output_tokens=0,
                    disk_bytes=unit['evaluator_policy']['maximum_database_bytes']
                        +entry['config']['maximum_runtime_evidence_bytes']+2097152
                        +read_owned(unit['archive_policy_path'],uid=21010,gid=21001,limit=262144)['maximum_bytes']
                        +_private_session_cost(unit)[1])
                self._save(phase_root/('cost-'+digest_jcs(key)[7:]+'.json'),
                    {'kind':'FormalTaskAuxiliaryAdmission','entry_digest':entry['digest'],
                     'spending':auxiliary,'whole_round_manifest_digest':self.round_manifest['digest']})
                inputs={k:base64.b64decode(v,validate=True) for k,v in unit['inputs'].items()}
                materials=prepare_development_materials(entry,inputs,self.tokenizer)
                intent=imported_task_intent(entry,domain=unit['domain'],policy=unit['policy'],
                    inputs=inputs,run_deadline=phase['campaign_deadline'])
                identity={'phase_digest':phase['digest'],'entry_digest':entry['digest'],
                    'unit_digest':digest_jcs(unit),'intent_digest':intent['digest']}
                token='task-'+digest_jcs(key)[7:]
                self._save(phase_root/(token+'.prepared.json'),{'kind':'FormalPhaseTaskPrepared',
                    **identity,'materials':materials.receipt})
                self.controller.publish(intent)
                started=time.monotonic()
                while self.controller.admission(intent) is None:
                    if time.monotonic()-started>=unit['admission_wait_seconds']:
                        raise TimeoutError('formal_phase_task_admission_unknown')
                    time.sleep(0.1)
                lease=self.controller.start(intent,operation_id='start-'+intent['digest'][7:])
                if lease is None:raise RuntimeError('formal_phase_admission_disappeared')
                self._save(phase_root/(token+'.lease.json'),{'kind':'FormalPhaseLeaseObserved',
                    **identity,'started':lease})
                self._save(phase_root/(token+'.runtime-intent.json'),{'kind':'FormalPhaseRuntimeIntent',
                    **identity,'lease_digest':lease['digest'],'automatic_reexecution_allowed':False})
                capture=execute_admitted(entry,intent,lease,unit['runtime_output'],
                    resource_context=unit['resource_context'],tokenizer=self.tokenizer,controller=self.controller,
                    ledger=self.ledger,evaluator_policy=unit['evaluator_policy'],
                    evaluator_assignment_directory=unit['evaluator_assignment_directory'],
                    gate_policy=unit['gate_policy'],gate_journal_directory=unit['gate_journal_directory'],
                    gate_review_path=unit['gate_review_path'],retirement_journal_directory=unit['retirement_journal_directory'],
                    archive_policy_path=unit['archive_policy_path'],archive_sources=unit['archive_sources'],
                    archive_gate_policy=unit['archive_gate_policy'],
                    archive_gate_journal_directory=unit['archive_gate_journal_directory'],
                    archive_review_path=unit['archive_review_path'],private_session_context=unit.get('private_session_context'),
                    prepared_materials=materials)
                from skillloop.runtime.protected_flow import _controller_record
                retirement=_controller_record(Path(unit['retirement_journal_directory'])/'retirement-completion.json')
                if (retirement.get('kind')!='FormalTaskRetirementCompletion'
                        or retirement.get('intent_digest')!=intent['digest']
                        or retirement.get('budget_closure')!='within_original_budget'
                        or retirement.get('runtime_resources_released') is not True):
                    raise ValueError('formal_phase_original_retirement_receipt')
                self._save(phase_root/(token+'.completed.json'),{'kind':'FormalPhaseTaskCompleted',
                    **identity,'runtime_capture_digest':capture['digest'],'retirement_digest':retirement['digest']})
                completed.append({'entry_digest':entry['digest'],'runtime_capture_digest':capture['digest']})
            except Exception as error:
                problems.append({'entry_digest':entry['digest'],'entry_id':key,'error_type':type(error).__name__,
                    'reason':str(error),'notes':list(getattr(error,'__notes__',[])),
                    'dependent_actions_blocked':True,'spent_attempts_preserved':True})
                self._save(phase_root/('task-'+digest_jcs(key)[7:]+'.failure.json'),
                    {'kind':'FormalPhaseTaskFailure','phase_digest':phase['digest'],
                     'unit_digest':digest_jcs(unit),'problem':problems[-1],'automatic_reexecution_allowed':False})
                # The shared Proxy/volume may have an uncertain active worker.
                # Stop this dependency chain; another independent profile may
                # continue only through its own admitted services and budget.
                break
        summary={'kind':'FormalPhaseExecutionSummary','phase_digest':phase['digest'],
            'completed':completed,'problems':problems,
            'unexecuted_entry_digests':[u['entry']['digest'] for u in entries[visited:]],
            'campaign_started_at':original,'finished_at':datetime.now(timezone.utc).isoformat(),
            'complete':not problems and len(completed)==len(required),'qualification_issued':False}
        self._save(phase_root/'summary.json',summary)
        return summary
