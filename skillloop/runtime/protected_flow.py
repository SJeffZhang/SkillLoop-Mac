"""Persistent Controller caller for the original protected task's closing chain.

The plan contains opaque dispatch policies and paths, never private entries or
results. Recovery consumes only a completed original dispatch journal; a started
step without proof is blocked rather than called again.
"""
from datetime import datetime,timezone
import os
from pathlib import Path
import re,time
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import decode_json,digest_jcs
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.private_session_dispatch import dispatch_session_action
from skillloop.runtime.private_retirement import retire_private_runtime
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.task_controller import FormalTaskController
from skillloop.ci.campaign_registry import CampaignRegistry
from skillloop.repair.budget import SpendingLedger
from skillloop.runtime.round_manifest import read_round_manifest
from skillloop.protection.current_task import _directory

STAGES=('capture','evaluate','task_gate','session_complete','archive',
        'archive_gate','terminal_authority_snapshot','retirement_gate')


def _controller_record(path):
    import stat
    from skillloop.runtime.archive_files import open_original, require_unchanged, identity
    path=Path(path);parent=path.parent.lstat()
    if (path.is_symlink() or path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid!=21001 or stat.S_IMODE(parent.st_mode)!=0o700):
        raise PermissionError('protected_flow_controller_record_directory')
    fd=open_original(path)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=21001 or before.st_nlink!=1
                or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>8388608):
            raise PermissionError('protected_flow_controller_record_file')
        raw=stream.read(8388609);after=os.fstat(stream.fileno())
    if len(raw)!=before.st_size or identity(before)!=identity(after):
        raise ValueError('protected_flow_record_changed')
    require_unchanged(path,before,after)
    current_parent=path.parent.lstat()
    if any(getattr(parent,k)!=getattr(current_parent,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode')):
        raise ValueError('protected_flow_record_directory_changed')
    value=decode_json(raw)
    if type(value) is not dict or value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):
        raise ValueError('protected_flow_record_seal')
    return value


class ProtectedTaskCloser:
    def __init__(self,*,engine,ledger,registry,controller,whole_round_manifest_path,journal_directory):
        if (os.geteuid()!=21001 or type(engine) is not DockerEngine or type(ledger) is not SpendingLedger
                or type(registry) is not CampaignRegistry or type(controller) is not FormalTaskController):
            raise PermissionError('protected_flow_actual_controller_services')
        self.engine,self.ledger,self.registry,self.controller=engine,ledger,registry,controller
        self.manifest_path=whole_round_manifest_path
        self.whole=read_round_manifest(whole_round_manifest_path)
        self.root=_directory(journal_directory,21001,21001,0o700)

    def close(self,plan_path):
        plan=read_owned(plan_path,uid=21010,gid=21001,limit=2097152)
        if plan.get('kind')=='FrozenProtectedClosingProduction':
            plan=self._produce_plan(plan)
        fields={'kind','campaign_digest','deployment_epoch','whole_round_manifest_digest','campaign_deadline',
                'reference_path','runtime_completion_path','runtime_completion_digest','steps',
                'retirement_grant_path','retirement_journal','cleanup_journal','retirement_seconds','cleanup_seconds','digest'}
        if (set(plan)!=fields or plan['kind']!='FrozenProtectedTaskClosingFlow'
                or plan['whole_round_manifest_digest']!=self.whole['digest']
                or plan['deployment_epoch']!=self.whole['deployment_epoch']
                or plan['deployment_epoch']!=self.controller.epoch
                or [s.get('stage') for s in plan['steps']]!=list(STAGES)):
            raise ValueError('protected_flow_frozen_complete_chain')
        deadline=datetime.fromisoformat(plan['campaign_deadline'].replace('Z','+00:00'))
        if deadline.tzinfo is None or self.ledger.campaign_started_at is None or deadline.timestamp()!=self.ledger.campaign_started_at+28800:
            raise ValueError('protected_flow_original_clock')
        reference=read_owned(plan['reference_path'],uid=21004,gid=21001,limit=262144)
        completion=_controller_record(plan['runtime_completion_path'])
        if (completion.get('kind')!='OpaquePrivateRuntimeCompletion'
                or completion['digest']!=plan['runtime_completion_digest']
                or completion.get('reference_digest')!=reference['digest']
                or reference.get('campaign_id')!=plan['campaign_digest']):
            raise ValueError('protected_flow_original_runtime')
        if any(type(plan[k]) is not int or not 1<=plan[k]<=120 for k in ('retirement_seconds','cleanup_seconds')):
            raise ValueError('protected_flow_frozen_terminal_costs')
        with self.registry.private_scope(campaign=plan['campaign_digest']) as state:
            if state['gate_freeze']['deadline']!=plan['campaign_deadline']:
                raise ValueError('protected_flow_current_frozen_registry_clock')
        policies=[]
        for step in plan['steps']:
            expected={'stage','policy_path','policy_digest','journal_directory','archive_mount_policy_path','archive_attestation_directory'}
            if set(step)!=expected:raise ValueError('protected_flow_step_shape')
            policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=2097152)
            gate=step['stage'] in {'task_gate','archive_gate','retirement_gate'}
            if (policy['digest']!=step['policy_digest'] or policy['campaign_digest']!=plan['campaign_digest']
                    or policy['campaign_deadline']!=plan['campaign_deadline']
                    or policy['whole_round_manifest_digest']!=self.whole['digest']
                    or policy['kind']!=('FrozenOpaquePrivateGateDispatch' if gate else 'FrozenOpaquePrivateSessionDispatch')
                    or (step['stage']=='archive')!=('archive_output' in policy['mounts'])
                    or (step['stage']=='archive_gate')!=('archive' in policy['mounts'])
                    or (step['stage']=='retirement_gate')!=('retirement_grants' in policy['mounts'])
                    or (step['stage']=='archive')!=(step['archive_mount_policy_path'] is not None and step['archive_attestation_directory'] is not None)):
                raise ValueError('protected_flow_exact_stage_policy')
            policies.append(policy)
        journals=[s['journal_directory'] for s in plan['steps']]+[plan['retirement_journal'],plan['cleanup_journal'],str(self.root)]
        if len(journals)!=len(set(journals)) or any(not Path(p).is_absolute() for p in journals):
            raise ValueError('protected_flow_distinct_absolute_operation_journals')
        scope=next((c for c in self.whole['campaigns'] if c['campaign_digest']==plan['campaign_digest']),None)
        if scope is None:raise ValueError('protected_flow_whole_campaign_scope')
        bound=scope['stages']['protected']
        if any(p['timeout_seconds']+60>bound['seconds'] or p['maximum_evidence_bytes']>bound['disk_bytes'] for p in policies):
            raise ValueError('protected_flow_unreserved_complete_step_cost')
        remaining=[p for step,p in zip(plan['steps'],policies) if not (self.root/(step['stage']+'.done.json')).exists()]
        if ((deadline-datetime.now(timezone.utc)).total_seconds()<=
                sum(p['timeout_seconds']+60 for p in remaining)+plan['retirement_seconds']+plan['cleanup_seconds']+120):
            raise TimeoutError('protected_flow_full_remaining_chain_not_admitted')
        if not (self.root/'flow-intent.json').exists():
            if any(p.name!='production.json' for p in self.root.iterdir()):
                raise ValueError('protected_flow_unrecognized_existing_journal')
            _save(self.root,'flow-intent.json',{'kind':'ProtectedTaskClosingIntent','plan_digest':plan['digest'],
                'reference_digest':reference['digest'],'completion_digest':completion['digest']})
        elif _controller_record(self.root/'flow-intent.json')['plan_digest']!=plan['digest']:
            raise ValueError('protected_flow_same_operation_changed_parameters')
        if (self.root/'flow-completion.json').exists():return _controller_record(self.root/'flow-completion.json')
        processes=[]
        for step,policy in zip(plan['steps'],policies):
            stage=step['stage'];done=self.root/(stage+'.done.json');started=self.root/(stage+'.started.json')
            if done.exists():
                result=_controller_record(done)
                if result['policy_digest']!=policy['digest']:raise ValueError('protected_flow_changed_completed_step')
                stored=result['completion']
                if stored.get('action_digest')!=policy['action_digest'] or stored.get('wait',{}).get('StatusCode')!=0:
                    raise ValueError('protected_flow_completed_original_action')
                processes.append(stored['inspection']);continue
            if (deadline-datetime.now(timezone.utc)).total_seconds()<=policy['timeout_seconds']+120:
                raise TimeoutError('protected_flow_original_terminal_reserve')
            if started.exists():
                previous=_controller_record(started)
                if previous['policy_digest']!=policy['digest']:raise ValueError('protected_flow_changed_started_step')
                # Only the original process's committed completion can advance.
                from skillloop.runtime.private_session_dispatch import recover_session_completion
                result=recover_session_completion(journal_directory=step['journal_directory'],
                    engine=self.engine,policy=policy)
                if result is None:
                    raise RuntimeError('protected_flow_unknown_original_dispatch_no_replay')
            else:
                _save(self.root,started.name,{'kind':'ProtectedClosingStepStarted','policy_digest':policy['digest'],
                    'automatic_reexecution_allowed':False})
                result=dispatch_session_action(policy=policy,journal_directory=step['journal_directory'],
                    engine=self.engine,ledger=self.ledger,registry=self.registry,whole_round_manifest_path=self.manifest_path,
                    archive_mount_policy_path=step['archive_mount_policy_path'],
                    archive_attestation_directory=step['archive_attestation_directory'])
            _save(self.root,done.name,{'kind':'ProtectedClosingStepComplete','policy_digest':policy['digest'],'completion':result})
            processes.append(result['inspection'])
        grant=read_owned(plan['retirement_grant_path'],uid=21005,gid=21001,limit=262144)
        if (grant.get('kind')!='OpaquePrivateRetirementGrant' or grant.get('reference_digest')!=reference['digest']
                or grant.get('completion_digest')!=completion['digest'] or grant.get('session_complete') is not True
                or grant.get('archive_verified') is not True):
            raise ValueError('protected_flow_gate_authorization_before_aux_cleanup')
        helper=completion.get('handoff',{}).get('inspection')
        if helper is not None:processes.append(helper)
        self._terminal_cost(plan,'cleanup',plan['cleanup_seconds'])
        cleanup=retire_auxiliary_processes(processes=processes,journal_directory=plan['cleanup_journal'],engine=self.engine)
        retirement=self.root/'retirement.done.json'
        if retirement.exists():released=_controller_record(retirement)['completion']
        else:
            original=Path(plan['retirement_journal'])/'retirement-completion.json'
            if original.exists():released=_controller_record(original)
            else:
                self._terminal_cost(plan,'retirement',plan['retirement_seconds'])
                released=retire_private_runtime(reference=reference,completion=completion,
                    grant_path=plan['retirement_grant_path'],journal_directory=plan['retirement_journal'],engine=self.engine)
            if released.get('reference_digest')!=reference['digest'] or released.get('original_runtime_resources_released') is not True:
                raise ValueError('protected_flow_original_retirement_result')
            _save(self.root,retirement.name,{'kind':'ProtectedClosingRetirementComplete','completion':released})
        return _save(self.root,'flow-completion.json',{'kind':'ProtectedTaskClosingCompletion',
            'plan_digest':plan['digest'],'reference_digest':reference['digest'],
            'runtime_retirement_digest':released['digest'],'auxiliary_cleanup_digest':cleanup['digest'],
            'private_evidence_preserved':True,'qualification_issued':False})


    def _produce_plan(self,recipe):
        """Bind the closing recipe to the original opaque Runtime receipt.

        Only Controller metadata is read here. Private assignments and all
        Evaluator/Gate outputs remain in their existing role-owned mounts.
        A partial publication is never regenerated from a newer completion.
        """
        fields={'kind','campaign_digest','deployment_epoch','whole_round_manifest_digest','campaign_deadline',
                'reference_path','runtime_completion_path','steps','retirement_grant_path',
                'retirement_journal','cleanup_journal','retirement_seconds','cleanup_seconds'}
        if (set(recipe)!={'kind','flow_template','digest'} or type(recipe['flow_template']) is not dict
                or set(recipe['flow_template'])!=fields
                or recipe['flow_template']['kind']!='FrozenProtectedTaskClosingFlow'):
            raise ValueError('protected_flow_production_recipe')
        plan=dict(recipe['flow_template'])
        if (plan['deployment_epoch']!=self.controller.epoch
                or plan['deployment_epoch']!=self.whole['deployment_epoch']
                or plan['whole_round_manifest_digest']!=self.whole['digest']
                or plan['campaign_digest'] not in {c['campaign_digest'] for c in self.whole['campaigns']}):
            raise ValueError('protected_flow_production_original_deployment')
        for key in ('reference_path','runtime_completion_path'):
            path=Path(plan[key])
            if not path.is_absolute() or '..' in path.parts:
                raise ValueError('protected_flow_production_original_path')
        reference=read_owned(plan['reference_path'],uid=21004,gid=21001,limit=262144)
        completion=_controller_record(plan['runtime_completion_path'])
        if (reference.get('kind')!='EvaluatorOpaqueRunReference'
                or reference.get('campaign_id')!=plan['campaign_digest']
                or reference.get('deployment_epoch')!=plan['deployment_epoch']
                or completion.get('kind')!='OpaquePrivateRuntimeCompletion'
                or completion.get('reference_digest')!=reference['digest']
                or completion.get('evidence_released') is not False):
            raise ValueError('protected_flow_production_original_runtime')
        plan['runtime_completion_digest']=completion['digest'];plan['digest']=digest_jcs(plan)
        path=self.root/'production.json'
        if os.path.lexists(path):
            original=_controller_record(path)
            if (original.get('kind')!='ProtectedClosingPlanProduced'
                    or original.get('recipe_digest')!=recipe['digest']
                    or original.get('reference_digest')!=reference['digest']
                    or original.get('plan')!=plan
                    or original.get('budget_closure')!='within_original_budget'):
                raise ValueError('protected_flow_production_original_conflict')
            return original['plan']
        if any(self.root.iterdir()):raise RuntimeError('protected_flow_production_partial_unknown')
        deadline=datetime.fromisoformat(plan['campaign_deadline'].replace('Z','+00:00'))
        if (deadline.tzinfo is None or self.ledger.campaign_started_at is None
                or deadline.timestamp()!=self.ledger.campaign_started_at+28800
                or (deadline-datetime.now(timezone.utc)).total_seconds()<=30):
            raise TimeoutError('protected_flow_production_original_clock')
        with self.registry.private_scope(campaign=plan['campaign_digest']) as state:
            if state['gate_freeze']['deadline']!=plan['campaign_deadline']:
                raise ValueError('protected_flow_production_current_registry')
            began=time.monotonic()
            cost=self.ledger.consume_auxiliary(manifest=self.whole,campaign=plan['campaign_digest'],
                stage='protected',operation_key='private-closing-plan-'+recipe['digest'][7:],
                seconds=30,input_tokens=0,output_tokens=0,disk_bytes=1048576)
            elapsed=time.monotonic()-began
            within=elapsed<=30 and datetime.now(timezone.utc)<deadline
            _save(self.root,'production.json',{'kind':'ProtectedClosingPlanProduced',
                'recipe_digest':recipe['digest'],'reference_digest':reference['digest'],
                'plan':plan,'spending':cost,'elapsed_seconds':elapsed,
                'budget_closure':'within_original_budget' if within else 'inconclusive_expired_budget_closure',
                'qualification_issued':False})
            if not within:raise TimeoutError('protected_flow_production_original_budget_expired')
            return plan


    def _terminal_cost(self,plan,stage,seconds):
        path=self.root/(stage+'.cost.json')
        key='private-close-'+plan['digest'][7:]+'-'+stage
        if path.exists():
            old=_controller_record(path)
            if old['spending']['operation_key']!=key:raise ValueError('protected_flow_changed_terminal_spending')
            return old
        # If charging committed but publication was lost, consume refuses the
        # spent key. Recovery must preserve that uncertainty, not charge twice.
        spending=self.ledger.consume_auxiliary(manifest=self.whole,campaign=plan['campaign_digest'],
            stage='protected',operation_key=key,seconds=seconds,input_tokens=0,output_tokens=0,disk_bytes=2097152)
        return _save(self.root,path.name,{'kind':'ProtectedClosingTerminalSpending','spending':spending})


def retire_auxiliary_processes(*,processes,journal_directory,engine):
    """Delete stopped original helpers only; preserve every evidence volume."""
    if os.geteuid()!=21001 or type(engine) is not DockerEngine:raise PermissionError('protected_aux_actual_controller')
    root=_directory(journal_directory,21001,21001,0o700)
    ids=[p['Id'] for p in processes]
    if len(ids)!=len(set(ids)):raise ValueError('protected_aux_duplicate_process')
    intent=root/'intent.json'
    if intent.exists():
        old=_controller_record(intent)
        if old['processes']!=processes:raise ValueError('protected_aux_changed_original_resources')
    else:_save(root,'intent.json',{'kind':'ProtectedAuxiliaryCleanupIntent','processes':processes,'volumes_deleted':False})
    for original in processes:
        identifier=original['Id']
        if not re.fullmatch(r'[0-9a-f]{64}',identifier):raise ValueError('protected_aux_container_id')
        done=root/(identifier+'.removed.json')
        if done.exists():
            receipt=_controller_record(done)
            if receipt.get('kind')!='ProtectedAuxiliaryRemoved' or receipt.get('container_id')!=identifier:
                raise ValueError('protected_aux_changed_removal_receipt')
            continue
        started=root/(identifier+'.removing.json')
        removing=_controller_record(started) if started.exists() else None
        if removing is not None and (removing.get('kind')!='ProtectedAuxiliaryRemoving'
                or removing.get('inspection',{}).get('Id')!=identifier
                or removing['inspection'].get('Config')!=original.get('Config')
                or removing['inspection'].get('Image')!=original.get('Image')):
            raise ValueError('protected_aux_changed_original_removal')
        from skillloop.runtime.docker_api import DockerEngineError
        try:actual=engine.inspect(identifier)
        except DockerEngineError as error:
            # Only an original durable removal intent permits reconciling 404.
            # Timeouts, disconnects and other status codes remain unknown.
            if error.status!=404 or removing is None:raise
            _save(root,done.name,{'kind':'ProtectedAuxiliaryRemoved','container_id':identifier,
                'reconciled_original_intent_digest':removing['digest'],'actual_inspection_status':404})
            continue
        if (actual.get('Id')!=identifier or actual.get('Image')!=original.get('Image')
                or actual.get('Config')!=original.get('Config')
                or actual.get('Config',{}).get('User') not in {'21004:21004','21005:21005','21002:21002'}
                or actual.get('State',{}).get('Running') is not False
                or actual.get('State',{}).get('ExitCode')!=0
                or actual.get('Config',{}).get('Labels',{}).get('skillloop.role') not in {'private_session','private_evidence_handoff'}
                or actual.get('HostConfig',{}).get('NetworkMode')!='none'
                or actual.get('HostConfig',{}).get('LogConfig',{}).get('Type')!='none'):
            raise ValueError('protected_aux_original_stopped_identity')
        if removing is None:
            _save(root,started.name,{'kind':'ProtectedAuxiliaryRemoving','inspection':actual})
        # No volume deletion: private raw, snapshots and archive remain owned.
        engine.request('DELETE','/containers/'+identifier+'?force=false&v=false')
        _save(root,done.name,{'kind':'ProtectedAuxiliaryRemoved','container_id':identifier})
    if (root/'completion.json').exists():return _controller_record(root/'completion.json')
    return _save(root,'completion.json',{'kind':'ProtectedAuxiliaryCleanupComplete','container_ids':ids,
        'volumes_deleted':False,'evidence_preserved':True})
