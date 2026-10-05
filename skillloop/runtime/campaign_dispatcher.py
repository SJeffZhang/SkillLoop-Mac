"""Typed production dispatch for administrator-frozen operator campaign routes."""
import os
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs,validate_envelope
from skillloop.proxy.wire import validate_control
from skillloop.runtime.protected_flow import _controller_record


ACTION_FIELDS={
    'campaign_inspection':{'qualification_path','authority_directory','report_path'},
    'import_source':{'approved_repository'},
    'archive_role':{'policy_path','journal_directory'},
    'archive_close':{'policy_path','dispatch_journal','review_path','journal_directory'},
    'operation_archive':{'policy_path','journal_directory'},
    'registry_snapshot':{'policy_path','journal_directory'},
    'registry_withdraw':{'withdrawal_path','qualification_path','expected_active_revision'},
    'register_campaign':{'registration_path','authority_directory'},
    'deployment':{'manifest_path','journal_directory','start_roles'},
    'role_command':{'role','assignment_directory','role_command','rpc_params','manifest_path','deployment_journal','timeout_seconds','closure_seconds','maximum_evidence_bytes','journal_directory','result_path'},
    'proxy_controller':{'method','rpc_params','journal_directory'},
    'development':{'plan_path'},
    'roster_freeze':{'policy_path','assignment_directory','roster_directory','journal_directory','authority_directory'},
    'harden_review':{'policy_path','assignment_directory','roster_directory','journal_directory','authority_directory'},
    'lifecycle_review':{'policy_path','manifest_path','deployment_journal','journal_directory','result_path'},
    'private_factory':{'policy_path','assignment_directory','projection_directory','gate_freeze_path','journal_directory'},
    'private_session':{'policy_path','journal_directory'},
    'private_resources':{'policy_path','reference_path','journal_directory'},
    'private_start':{'reference_path','minimum_remaining_seconds','evaluator_directory'},
    'private_runtime':{'policy_path','reference_path','started_path','journal_directory'},
    'protected_close':{'plan_path','journal_directory'},
    'static_scan':{'deployment_path'},
    'qualification_withdraw':{'assignment_directory','manifest_path','deployment_journal','result_path','timeout_seconds','closure_seconds','maximum_evidence_bytes','journal_directory'},
    'campaign_gate_assignment':{'policy_path','assignment_directory'},
    'campaign_gate':{'assignment_directory','manifest_path','deployment_journal','result_path','timeout_seconds','closure_seconds','maximum_evidence_bytes','journal_directory'},
    'promote':{'qualification_path','authority_directory'},
    'semantic_discovery':{'assignment_directory','manifest_path','deployment_journal','result_path','timeout_seconds','closure_seconds','maximum_evidence_bytes','journal_directory'},
    'native_gateway':{'policy_path','gateway_policy_directory','bridge_directory','journal_directory'},
    'native_gateway_close':{'dispatch_journal','journal_directory'},
    'proposal':{'policy_path','assignment_directory','evidence_directory','journal_directory'},
    'application_gate':{'policy_path','assignment_directory','reviews_directory','journal_directory'},
}


def validate_dispatch_route(route):
    """Reject missing or unsupported callers before accepting any operation.

    Future role outputs may not exist yet. Validate their exact locator shape,
    then each production caller verifies actual custody at consumption time.
    """
    if type(route.get('steps')) is not list or not 1<=len(route['steps'])<=2048:
        raise ValueError('campaign_bounded_complete_route')
    campaign=route.get('campaign_digest')
    if campaign is not None and (type(campaign) is not str or len(campaign)!=71
            or not campaign.startswith('sha256:') or any(c not in '0123456789abcdef' for c in campaign[7:])):
        raise ValueError('campaign_route_exact_campaign')
    producing={'register_campaign','development','roster_freeze','harden_review','private_factory','private_session','private_resources',
        'private_start','private_runtime','lifecycle_review','semantic_discovery','native_gateway','native_gateway_close','proposal','application_gate','campaign_gate_assignment','campaign_gate','promote'}
    if any(step.get('action') in producing for step in route['steps']) and campaign is None:
        raise ValueError('campaign_route_work_requires_campaign_binding')
    if any(step.get('action')=='campaign_inspection' for step in route['steps']) and (
            route.get('command')!='inspect' or campaign is None):
        raise PermissionError('campaign_inspection_read_only_command_required')
    journals={route['journal_directory']}
    for step in route['steps']:
        if type(step) is not dict:raise ValueError('campaign_step_shape')
        action=step.get('action');fields=ACTION_FIELDS.get(action)
        if fields is None or set(step)!=fields|{'action'}:
            raise ValueError('campaign_required_typed_provider')
        for key,value in step.items():
            if key.endswith(('_path','_directory')) or key=='approved_repository':
                if type(value) is not str or not Path(value).is_absolute() or '..' in Path(value).parts:
                    raise ValueError('campaign_fixed_absolute_locator')
            if key=='deployment_journal' and value==route['journal_directory']:
                raise ValueError('campaign_deployment_and_route_journal_distinct')
            if key=='journal_directory':
                if value in journals:raise ValueError('campaign_distinct_original_journals')
                journals.add(value)
        if action=='deployment' and (type(step['start_roles']) is not list
                or not set(step['start_roles'])<={'proxy','controller','model_gateway','admin','report'}):
            raise PermissionError('campaign_worker_requires_original_task_admission')
        if action=='role_command' and (step['role'] not in {'admin','report'}
                or type(step['rpc_params']) is not dict or type(step['timeout_seconds']) is not int
                or not 1<=step['timeout_seconds']<=120
                or type(step['closure_seconds']) is not int or not 30<=step['closure_seconds']<=120
                or type(step['maximum_evidence_bytes']) is not int or not 4194304<=step['maximum_evidence_bytes']<=8388608):
            raise ValueError('campaign_role_command_bound')
        if action=='role_command':
            from skillloop.runtime.role_command_worker import ADMIN_PROXY_COMMANDS
            allowed={'report'} if step['role']=='report' else set(ADMIN_PROXY_COMMANDS)|{'produce-candidate','produce-plan','produce-phase','produce-deployment','import-lifecycle'}
            if step['role_command'] not in allowed:
                raise ValueError('campaign_actual_role_command_provider_required')
        if action in {'campaign_gate','qualification_withdraw'} and (type(step['timeout_seconds']) is not int
                or not 1<=step['timeout_seconds']<=120 or type(step['maximum_evidence_bytes']) is not int
                or not 1<=step['maximum_evidence_bytes']<=268435456
                or type(step['closure_seconds']) is not int or not 30<=step['closure_seconds']<=120):
            raise ValueError('campaign_final_gate_full_cost_bound')
        if action=='semantic_discovery' and (type(step['timeout_seconds']) is not int
                or not 1<=step['timeout_seconds']<=1200
                or type(step['closure_seconds']) is not int or not 30<=step['closure_seconds']<=120
                or type(step['maximum_evidence_bytes']) is not int or not 67108864<=step['maximum_evidence_bytes']<=268435456):
            raise ValueError('campaign_semantic_original_worker_bound')
        if action=='private_start' and (type(step['minimum_remaining_seconds']) is not int
                or not 1<=step['minimum_remaining_seconds']<=300):
            raise ValueError('campaign_original_lease_window')
    for key in ('journal_directory','result_path','result_binding_path'):
        value=route[key]
        if type(value) is not str or not Path(value).is_absolute() or '..' in Path(value).parts:
            raise ValueError('campaign_original_route_locator')


class CampaignDispatcher:
    def __init__(self,*,controller,registry,ledger,engine,tokenizer,whole_round_manifest_path,phase_journal):
        from skillloop.runtime.formal_phase import FormalPhaseExecutor
        self.controller,self.registry,self.ledger,self.engine=controller,registry,ledger,engine
        self.manifest_path=whole_round_manifest_path
        self.phase=FormalPhaseExecutor(controller=controller,ledger=ledger,tokenizer=tokenizer,
            journal_directory=phase_journal,whole_round_manifest_path=whole_round_manifest_path)
    def preserve_failure(self,request,route,error):
        """Keep Controller diagnostics private before publishing stable failure."""
        import traceback
        from datetime import datetime,timezone
        from skillloop.protection.current_task import _directory
        from skillloop.runtime.proposal_dispatch import _save
        if os.geteuid()!=21001:raise PermissionError('campaign_failure_actual_controller')
        validate_dispatch_route(route)
        journal=_directory(route['journal_directory'],21001,21001,0o700)
        name='failure-'+request['digest'][7:]+'.json'
        if os.path.lexists(journal/name):
            original=_controller_record(journal/name)
            if (original.get('kind')!='ControllerCampaignDispatchFailure'
                    or original.get('request_digest')!=request['digest']
                    or original.get('route_digest')!=route['digest']):
                raise ValueError('campaign_original_failure_identity')
            return original
        details=''.join(traceback.format_exception(type(error),error,error.__traceback__))
        raw=details.encode('utf-8')
        # This is bounded Controller diagnostics, not an import of private
        # worker logs or a claim that a truncated traceback is complete.
        truncated=len(raw)>65536
        details=raw[:65536].decode('utf-8','replace')
        return _save(journal,name,{'kind':'ControllerCampaignDispatchFailure',
            'request_digest':request['digest'],'route_digest':route['digest'],
            'error_type':type(error).__name__,'controller_traceback':details,
            'diagnostics_complete':not truncated,'recorded_at':datetime.now(timezone.utc).isoformat(),
            'automatic_reexecution_allowed':False,'evidence_released':False,
            'public_error_code':'unavailable'})
    def reconcile_original_retirements(self,request,route):
        """Continue a recorded process removal, never an inference or delivery.

        Called during original-operation recovery before proving the remaining
        unstarted tail. Only the first incomplete, already started archive-close
        stage with a durable resource retirement intent can be reconciled.
        """
        if os.geteuid()!=21001:raise PermissionError('campaign_recovery_controller')
        validate_dispatch_route(route)
        from skillloop.protection.current_task import _directory
        from skillloop.runtime.proposal_dispatch import _save
        journal=_directory(route['journal_directory'],21001,21001,0o700)
        identity=_controller_record(journal/'identity.json')
        if (identity.get('kind')!='CampaignRouteIdentity' or identity.get('request_digest')!=request['digest']
                or identity.get('route_digest')!=route['digest']):
            raise ValueError('campaign_recovery_original_journal_identity')
        for index,step in enumerate(route['steps']):
            token=str(index).zfill(4);done=journal/(token+'.completed.json')
            started=journal/(token+'.started.json')
            if done.exists():
                saved=_controller_record(done);begin=_controller_record(started)
                for value,kind in ((saved,'CampaignStageCompleted'),(begin,'CampaignStageStarted')):
                    if (value.get('kind')!=kind or value.get('request_digest')!=request['digest']
                            or value.get('step_digest')!=digest_jcs(step)):
                        raise ValueError('campaign_recovery_original_prefix')
                continue
            if not started.exists():return
            begin=_controller_record(started)
            if (begin.get('kind')!='CampaignStageStarted' or begin.get('request_digest')!=request['digest']
                    or begin.get('step_digest')!=digest_jcs(step)):
                raise ValueError('campaign_recovery_original_started_stage')
            if step['action'] in {'private_runtime','private_session','private_resources','protected_close'}:
                campaign=route['campaign_digest']
                if step['action']=='private_runtime':
                    from skillloop.runtime.private_runtime_dispatch import recover_private_runtime_completion,resolve_private_runtime_policy
                    original=_controller_record(Path(step['journal_directory'])/'intent.json')
                    policy=resolve_private_runtime_policy(step['policy_path'],reference_path=step['reference_path'])
                    reference=read_owned(step['reference_path'],uid=21004,gid=21001,limit=262144)
                    lease=read_owned(step['started_path'],uid=21001,gid=21004,limit=262144)
                    if (original.get('policy')!=policy or original.get('reference')!=reference
                            or original.get('started')!=lease):
                        raise ValueError('campaign_private_recovery_original_dispatch')
                    result=recover_private_runtime_completion(journal_directory=step['journal_directory'],
                        engine=self.engine,expected_campaign=campaign)
                elif step['action']=='private_resources':
                    from skillloop.runtime.private_resources import prepare_private_resources
                    if not (Path(step['journal_directory'])/'intent.json').exists():return
                    result=prepare_private_resources(policy_path=step['policy_path'],reference_path=step['reference_path'],
                        journal_directory=step['journal_directory'],whole_round_manifest_path=self.manifest_path,
                        engine=self.engine,ledger=self.ledger,registry=self.registry)
                elif step['action']=='private_session':
                    from skillloop.runtime.private_session_dispatch import recover_session_completion,resolve_session_policy
                    policy=resolve_session_policy(step['policy_path'])
                    if policy.get('campaign_digest')!=campaign:
                        raise ValueError('campaign_private_recovery_original_session')
                    result=recover_session_completion(journal_directory=step['journal_directory'],
                        engine=self.engine,policy=policy)
                else:
                    # Only an existing flow intent allows continuing proved
                    # original step receipts and their unstarted closing tail.
                    if not (Path(step['journal_directory'])/'flow-intent.json').exists():return
                    result=self.registry.close_protected_task(plan_path=step['plan_path'],controller=self.controller,
                        ledger=self.ledger,engine=self.engine,whole_round_manifest_path=self.manifest_path,
                        journal_directory=step['journal_directory'])
                if result is None:return
                _save(journal,done.name,{'kind':'CampaignStageCompleted','step_digest':digest_jcs(step),
                    'request_digest':request['digest'],'result':result})
                return
            if step['action']=='campaign_gate_assignment':
                if not (Path(step['assignment_directory'])/'production.json').exists():return
                from skillloop.runtime.campaign_gate_assignment import produce_campaign_gate_assignment
                result=produce_campaign_gate_assignment(policy_path=step['policy_path'],
                    assignment_directory=step['assignment_directory'],campaign=route['campaign_digest'],
                    whole=self.phase.round_manifest,registry=self.registry,ledger=self.ledger)
                _save(journal,done.name,{'kind':'CampaignStageCompleted','step_digest':digest_jcs(step),
                    'request_digest':request['digest'],'result':result})
                return
            if step['action'] in {'native_gateway','native_gateway_close'}:
                from skillloop.runtime.proposal_dispatch import recover_model_bridge, close_model_bridge
                if step['action']=='native_gateway':
                    if not (Path(step['journal_directory'])/'ready.json').exists():
                        # Reconcile a possibly-created original process only.
                        # Containment is never a successful start receipt.
                        if (Path(step['journal_directory'])/'spending.json').exists():
                            from skillloop.runtime.proposal_dispatch import preserve_failed_model_bridge
                            preserve_failed_model_bridge(journal_directory=step['journal_directory'],
                                engine=self.engine,expected_campaign=route['campaign_digest'])
                        return
                    result=recover_model_bridge(journal_directory=step['journal_directory'],engine=self.engine)
                else:
                    if not (Path(step['journal_directory'])/'intent.json').exists():return
                    result=close_model_bridge(dispatch_journal=step['dispatch_journal'],
                        journal_directory=step['journal_directory'],engine=self.engine,expected_campaign=route['campaign_digest'])
                _save(journal,done.name,{'kind':'CampaignStageCompleted','step_digest':digest_jcs(step),
                    'request_digest':request['digest'],'result':result})
                return
            if step['action']=='development':
                # Only a completely committed original phase can close a lost
                # response. A partial phase or task start remains unknown.
                phase=read_owned(step['plan_path'],uid=21010,gid=21001,limit=8388608)
                result=self.phase.recover_completed(phase)
                _save(journal,done.name,{'kind':'CampaignStageCompleted','step_digest':digest_jcs(step),
                    'request_digest':request['digest'],'result':result})
                return
            if step['action'] in {'semantic_discovery','campaign_gate','qualification_withdraw'}:
                if not (Path(step['journal_directory'])/'removing.json').exists():return
                from skillloop.runtime.campaign_auxiliary import recover_auxiliary_retirement
                result=recover_auxiliary_retirement(step,self.engine)
                _save(journal,done.name,{'kind':'CampaignStageCompleted','step_digest':digest_jcs(step),
                    'request_digest':request['digest'],'result':result})
                return
            if step['action']=='role_command':
                if not (Path(step['journal_directory'])/'removing.json').exists():return
                from skillloop.runtime.role_command_dispatch import recover_role_command_retirement
                result=recover_role_command_retirement(step=step,engine=self.engine)
                _save(journal,done.name,{'kind':'CampaignStageCompleted','step_digest':digest_jcs(step),
                    'request_digest':request['digest'],'result':result})
                return
            if step['action'] in {'roster_freeze','harden_review'}:
                if not (Path(step['journal_directory'])/'consumed.json').exists():return
                from skillloop.runtime.roster_dispatch import recover_roster_retirement
                policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=2097152)
                expected=('FrozenDevelopmentHardenDispatch' if step['action']=='harden_review'
                          else 'FrozenDevelopmentRosterDispatch')
                if policy.get('kind')!=expected:
                    raise ValueError('campaign_recovery_original_roster_policy')
                result=recover_roster_retirement(journal_directory=step['journal_directory'],
                    policy_digest=policy['digest'],engine=self.engine)
                if step['action']=='harden_review' and request['command']=='harden' and (
                        request['parameters']!={'campaign':policy['campaign_digest'],
                            'parent_subject':result['body']['parent_subject_digest']}):
                    raise ValueError('harden_original_operator_parent_binding')
                _save(journal,done.name,{'kind':'CampaignStageCompleted','step_digest':digest_jcs(step),
                    'request_digest':request['digest'],'result':result})
                return
            if step['action']=='lifecycle_review':
                # A raw review without a recorded removal is not retryable.
                removing=Path(step['journal_directory'])/'removing.json'
                if not removing.exists():return
                from skillloop.runtime.lifecycle_dispatch import recover_lifecycle_retirement
                policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=262144)
                result=recover_lifecycle_retirement(journal_directory=step['journal_directory'],
                    policy_digest=policy['digest'],engine=self.engine)
                _save(journal,done.name,{'kind':'CampaignStageCompleted','step_digest':digest_jcs(step),
                    'request_digest':request['digest'],'result':result})
                return
            if step['action']!='archive_close':return
            # Presence and custody of the original intent is checked before the
            # caller, so recovery cannot initialize a new cleanup operation.
            intent=_controller_record(Path(step['journal_directory'])/'intent.json')
            if intent.get('kind')!='ArchiveRoleRetirementIntent':
                raise ValueError('campaign_recovery_original_retirement_required')
            from skillloop.runtime.archive_dispatch import close_archive_role
            result=close_archive_role(policy_path=step['policy_path'],dispatch_journal=step['dispatch_journal'],
                review_path=step['review_path'],journal_directory=step['journal_directory'],engine=self.engine)
            _save(journal,done.name,{'kind':'CampaignStageCompleted','step_digest':digest_jcs(step),
                'request_digest':request['digest'],'result':result})
            return
    def recover_unstarted_tail(self,request,route):
        """Prove a committed prefix before requeueing the original operation.

        This never calls a provider. An unmatched started marker, missing
        prefix record, partial final projection or changed identity is unknown.
        """
        if os.geteuid()!=21001:raise PermissionError('campaign_recovery_controller')
        validate_dispatch_route(route)
        from skillloop.protection.current_task import _directory
        from skillloop.runtime.proposal_dispatch import _save
        journal=_directory(route['journal_directory'],21001,21001,0o700)
        identity=_controller_record(journal/'identity.json')
        if (identity.get('kind')!='CampaignRouteIdentity'
                or identity.get('request_digest')!=request['digest']
                or identity.get('route_digest')!=route['digest']):
            raise ValueError('campaign_recovery_original_journal_identity')
        stages=[];tail=False
        for index,step in enumerate(route['steps']):
            token=str(index).zfill(4)
            started=journal/(token+'.started.json');completed=journal/(token+'.completed.json')
            if not os.path.lexists(completed):
                if os.path.lexists(started):raise RuntimeError('campaign_started_stage_unknown_no_reexecution')
                tail=True;continue
            if tail:raise ValueError('campaign_recovery_noncontiguous_original_prefix')
            begin=_controller_record(started);saved=_controller_record(completed)
            for value,kind in ((begin,'CampaignStageStarted'),(saved,'CampaignStageCompleted')):
                if (value.get('kind')!=kind or value.get('step_digest')!=digest_jcs(step)
                        or value.get('request_digest')!=request['digest']):
                    raise ValueError('campaign_recovery_original_stage_pair_required')
            stages.append(digest_jcs(saved['result']))
        if tail and any(os.path.lexists(route[k]) for k in ('result_path','result_binding_path')):
            raise RuntimeError('campaign_recovery_final_projection_requires_original_result')
        proof={'kind':'ControllerUnstartedTailRecovery','request_digest':request['digest'],
            'route_digest':route['digest'],'completed_stage_receipts':stages,
            'next_stage_index':len(stages),'reexecute_started_stage':False}
        name='recovery-prefix-'+str(len(stages)).zfill(4)+'.json'
        if os.path.lexists(journal/name):
            existing=_controller_record(journal/name)
            if {k:v for k,v in existing.items() if k!='digest'}!=proof:
                raise ValueError('campaign_recovery_original_proof_changed')
            return existing
        return _save(journal,name,proof)
    def recover_final(self,request,route):
        # Read only the already published original role result. No campaign
        # step, Engine start, model inference or private delivery is called.
        result=read_owned(route['result_path'],uid=route['result_uid'],gid=21001,limit=2097152)
        binding=read_owned(route['result_binding_path'],uid=21001,gid=21001,limit=262144)
        if (binding.get('kind')!='OperatorFinalResultBinding' or binding.get('request_digest')!=request['digest']
                or binding.get('route_digest')!=route['digest'] or binding.get('result_digest')!=result['digest'] or binding.get('result_producer_uid')!=route['result_uid']
                or type(binding.get('stage_receipts')) is not list or not binding['stage_receipts']
                or result['kind']!=route['result_kind']
                or result['kind'] in {'CIResult','HardenResult'} and route['result_uid']!=21005):
            raise ValueError('operator_recovery_original_final_projection_required')
        stages=[]
        journal=Path(route['journal_directory'])
        identity=_controller_record(journal/'identity.json')
        if identity.get('request_digest')!=request['digest'] or identity.get('route_digest')!=route['digest']:
            raise ValueError('campaign_recovery_original_journal_identity')
        for index,step in enumerate(route['steps']):
            saved=_controller_record(journal/(str(index).zfill(4)+'.completed.json'))
            if saved.get('request_digest')!=request['digest'] or saved.get('step_digest')!=digest_jcs(step):
                raise ValueError('campaign_recovery_complete_original_stages_required')
            stages.append(digest_jcs(saved['result']))
        if binding['stage_receipts']!=stages:raise ValueError('campaign_recovery_stage_chain_mismatch')
        try:validate_control(result)
        except ValueError:validate_envelope(result)
        return result
    def execute(self,request,route):
        if os.geteuid()!=21001:raise PermissionError('campaign_dispatch_actual_controller')
        if (route.get('kind')!='FrozenOperatorCampaignRoute'
                or route.get('command')!=request['command']
                or route.get('parameters_digest')!=digest_jcs(request['parameters'])):
            raise ValueError('campaign_route_exact_admission')
        validate_dispatch_route(route)
        # These are original production callers, never shell commands, arbitrary
        # scripts or local result fixtures. Missing stage providers stay blocked.
        from skillloop.protection.current_task import _directory,_publish
        from skillloop.runtime.proposal_dispatch import _save
        if request['command']=='harden':
            proposals=[step for step in route['steps'] if step['action']=='proposal']
            if len(proposals)!=1:raise ValueError('harden_one_original_patcher_assignment')
            job=read_owned(Path(proposals[0]['assignment_directory'])/'job.json',uid=21001,gid=21007,limit=2097152)
            if (job.get('kind')!='FormalNativeProposalAssignment' or job.get('role_uid')!=21007
                    or request['parameters']!={'campaign':route['campaign_digest'],
                        'parent_subject':job.get('parent_subject_digest')}
                    or job.get('parent_subject_digest') is None):
                raise ValueError('harden_original_parent_before_any_side_effect')
        journal=_directory(route['journal_directory'],21001,21001,0o700)
        identity={'kind':'CampaignRouteIdentity','request_digest':request['digest'],'route_digest':route['digest']}
        original=journal/'identity.json'
        if original.exists():
            saved=_controller_record(original)
            if any(saved.get(k)!=v for k,v in identity.items()):raise ValueError('campaign_original_route_identity')
        else:_save(journal,'identity.json',identity)
        stage_receipts=[]
        campaign=route['campaign_digest']
        if campaign is not None and campaign not in {c['campaign_digest'] for c in self.phase.round_manifest['campaigns']}:
            raise ValueError('campaign_route_original_whole_manifest_scope')
        for index,step in enumerate(route['steps']):
            token=str(index).zfill(4)
            finished=journal/(token+'.completed.json')
            if finished.exists():
                saved=_controller_record(finished)
                if saved.get('step_digest')!=digest_jcs(step) or saved.get('request_digest')!=request['digest']:
                    raise ValueError('campaign_original_stage_completion_binding')
                result=saved['result'];stage_receipts.append(digest_jcs(result));continue
            if (journal/(token+'.started.json')).exists():
                raise RuntimeError('campaign_started_stage_unknown_no_reexecution')
            # Evidence preservation/withdrawal remains available after cancel.
            # No new model, task, candidate, qualification or promotion may
            # start from this route after the actual Proxy cancellation commit.
            if campaign is not None and step['action'] in {'register_campaign','development','roster_freeze','harden_review',
                    'private_factory','private_session','private_resources','private_start','private_runtime','lifecycle_review','semantic_discovery',
                    'native_gateway','proposal','application_gate','campaign_gate_assignment','campaign_gate','promote','static_scan'} or (
                    campaign is not None and step['action']=='role_command' and step['role']=='admin'):
                from skillloop.proxy.qualification_authority import require_campaign_not_cancelled
                require_campaign_not_cancelled('/authority-projection',epoch=self.controller.epoch,campaign=campaign)
            _save(journal,token+'.started.json',{'kind':'CampaignStageStarted',
                'step_digest':digest_jcs(step),'request_digest':request['digest']})
            if step['action']=='import_source':
                from skillloop.source import import_git_package
                params=request['parameters']
                if params['git_repo']!=step['approved_repository']:
                    raise PermissionError('operator_git_repository_not_admitted')
                result=import_git_package(Path(step['approved_repository']),params['commit'],params['skill_path'])[0]
            elif step['action']=='register_campaign':
                from skillloop.runtime.campaign_admission import register_campaign
                result=register_campaign(registration_path=step['registration_path'],
                    authority_directory=step['authority_directory'],registry=self.registry,
                    ledger=self.ledger,whole_round_manifest_path=self.manifest_path,
                    operation_id=request['operation_id'])
            elif step['action']=='deployment':
                from skillloop.runtime.whole_deployment import WholeRoleDeployment
                deployment=WholeRoleDeployment(manifest_path=step['manifest_path'],journal_directory=step['journal_directory'],engine=self.engine,
                    ledger=self.ledger,whole_round_manifest_path=self.manifest_path)
                result=deployment.provision()
                for role in step['start_roles']:
                    if role in {'runtime','protected_evaluator','generator','patcher','scanner','gate'}:
                        raise PermissionError('campaign_worker_requires_original_task_admission')
                    deployment.start_role(role,request['operation_id']+'-'+role)
            elif step['action']=='role_command':
                from skillloop.runtime.role_command_dispatch import dispatch_role_command
                result=dispatch_role_command(step=step,operation_id=request['operation_id'],
                    whole_round_manifest_path=self.manifest_path,ledger=self.ledger,engine=self.engine)
            elif step['action']=='proxy_controller':
                # Revoke/cancel delegate to frozen Controller RPC authority;
                # caller authorization was checked as actual Admin in service.
                from datetime import datetime,timedelta,timezone
                from skillloop.proxy.wire import make_control,validate_control
                from skillloop.runtime.proposal_dispatch import _save
                from skillloop.protection.current_task import _directory
                if step['method']!={'admin revoke':'revoke_approval','admin cancel':'cancel_run'}.get(request['command']):
                    raise PermissionError('operator_controller_delegation_scope')
                directory=_directory(step['journal_directory'],21001,21001,0o700)
                if any(directory.iterdir()):raise RuntimeError('operator_original_control_response_requires_recovery')
                params=step['rpc_params']
                if request['command']=='admin cancel':
                    if set(request['parameters'])!={'campaign'} or request['parameters']['campaign']!=campaign:
                        raise ValueError('admin_cancel_exact_campaign')
                    params=self.controller.campaign_cancellation_params(request['parameters']['campaign'])
                message=make_control('ControlRequest',{'operation_id':request['operation_id'],
                    'deadline':(datetime.now(timezone.utc)+timedelta(seconds=9)).isoformat().replace('+00:00','Z'),
                    'method':step['method'],'params':params})
                _save(directory,'request.json',{'kind':'DelegatedControllerRequest','request':message})
                result=self.controller.client._send('control.sock',message)['result'];validate_control(result)
                if request['command']=='admin cancel' and (result['kind']!='CancellationResult'
                        or result['body']['campaign_public_ref']!=request['parameters']['campaign']
                        or result['body']['run_id']!=params['run_id']
                        or result['body']['effective_fence']!=params['expected_fence']+1):
                    raise ValueError('admin_cancel_original_authority_result')
                _save(directory,'response.json',{'kind':'DelegatedControllerResponse','result':result})
            elif step['action']=='development':
                phase=read_owned(step['plan_path'],uid=21010,gid=21001,limit=8388608)
                result=self.phase.run(phase)
                if result.get('complete') is not True:raise RuntimeError('campaign_development_incomplete')
            elif step['action']=='semantic_discovery':
                from skillloop.runtime.whole_deployment import WholeRoleDeployment
                job=read_owned(Path(step['assignment_directory'])/'job.json',uid=21001,gid=21011,limit=2097152)
                if job.get('kind')!='FormalGatewaySemanticDiscovery' or job['worker_seconds']!=step['timeout_seconds']:
                    raise ValueError('campaign_semantic_original_assignment')
                deployment=WholeRoleDeployment(manifest_path=step['manifest_path'],journal_directory=step['deployment_journal'],
                    engine=self.engine,ledger=self.ledger,whole_round_manifest_path=self.manifest_path)
                if deployment.role_config('model_gateway','skillloop.discovery.semantic_worker')['Cmd']!=['-m','skillloop.discovery.semantic_worker']:
                    raise ValueError('campaign_semantic_fixed_gateway_entry')
                evidence_bytes=67108864+job['model_policy']['max_chat_requests']*14680064
                if (job['campaign_digest']!=campaign or evidence_bytes>step['maximum_evidence_bytes']
                        or job['whole_round_manifest_digest']!=deployment.whole['digest']):
                    raise ValueError('campaign_semantic_original_full_cost_binding')
                from skillloop.runtime.campaign_auxiliary import begin_auxiliary,observe_auxiliary,finish_auxiliary,preserve_auxiliary_failure
                config=deployment.role_config('model_gateway','skillloop.discovery.semantic_worker')
                begin_auxiliary(step,deployment.deadline,21011,config)
                cost=self.ledger.consume_auxiliary(manifest=deployment.whole,campaign=job['campaign_digest'],
                    stage='import_scan',operation_key='semantic-'+job['digest'][7:],seconds=job['worker_seconds']+step['closure_seconds'],
                    input_tokens=job['model_policy']['max_chat_requests']*16384,
                    output_tokens=job['model_policy']['max_chat_requests']*job['model_policy']['max_output_tokens'],
                    disk_bytes=step['maximum_evidence_bytes'])
                try:
                    observed=deployment.start_role('model_gateway',request['operation_id']+'-semantic',module='skillloop.discovery.semantic_worker')
                    observe_auxiliary(step,observed['inspection'])
                    identifier=observed['inspection']['Id'];wait=self.engine.wait(identifier,step['timeout_seconds'])
                    actual=self.engine.inspect(identifier)
                    if wait.get('StatusCode')!=0 or actual['State']['Running'] or actual['State']['ExitCode']!=0:
                        raise RuntimeError('campaign_semantic_original_process_incomplete')
                    result=read_owned(step['result_path'],uid=21011,gid=21001,limit=8388608)
                    if result.get('assignment_digest')!=job['digest'] or result['scanner_report']['body']['status']!='complete':
                        raise ValueError('campaign_semantic_complete_coverage_required')
                    result=finish_auxiliary(step,actual,result,self.engine.inspect(deployment.provision()['keeper']['Id']),self.engine)
                except BaseException as error:
                    if not (Path(step['journal_directory'])/'created.json').exists():
                        try:deployment.preserve_failed_role('model_gateway',request['operation_id']+'-semantic',
                            module='skillloop.discovery.semantic_worker',closure_seconds=step['closure_seconds'])
                        except BaseException as secondary:
                            error.add_note('semantic_unknown_create_preservation:'+type(secondary).__name__)
                    try:preserve_auxiliary_failure(step,self.engine,error)
                    except BaseException as secondary:
                        error.add_note('semantic_original_failure_preservation:'+type(secondary).__name__)
                    raise
            elif step['action']=='native_gateway':
                from skillloop.runtime.proposal_dispatch import dispatch_model_bridge
                policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=2097152)
                if policy.get('campaign_digest')!=campaign:
                    raise ValueError('campaign_native_gateway_original_scope')
                result=dispatch_model_bridge(policy=policy,
                    gateway_policy_directory=step['gateway_policy_directory'],bridge_directory=step['bridge_directory'],
                    journal_directory=step['journal_directory'],whole_round_manifest_path=self.manifest_path,
                    ledger=self.ledger,engine=self.engine)
            elif step['action']=='native_gateway_close':
                from skillloop.runtime.proposal_dispatch import close_model_bridge
                result=close_model_bridge(dispatch_journal=step['dispatch_journal'],
                    journal_directory=step['journal_directory'],engine=self.engine,expected_campaign=campaign)
            elif step['action']=='proposal':
                from skillloop.runtime.proposal_dispatch import dispatch_proposal
                result=dispatch_proposal(policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=2097152),
                    assignment_directory=step['assignment_directory'],evidence_directory=step['evidence_directory'],
                    journal_directory=step['journal_directory'],whole_round_manifest_path=self.manifest_path,
                    ledger=self.ledger,engine=self.engine,registry=self.registry)
            elif step['action']=='application_gate':
                from skillloop.runtime.proposal_dispatch import dispatch_application_gate
                result=dispatch_application_gate(policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=2097152),
                    assignment_directory=step['assignment_directory'],reviews_directory=step['reviews_directory'],
                    journal_directory=step['journal_directory'],whole_round_manifest_path=self.manifest_path,
                    ledger=self.ledger,engine=self.engine,registry=self.registry)
            elif step['action'] in {'roster_freeze','harden_review'}:
                from skillloop.runtime.roster_dispatch import dispatch_roster_gate
                result=dispatch_roster_gate(policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=2097152),
                    assignment_directory=step['assignment_directory'],roster_directory=step['roster_directory'],
                    journal_directory=step['journal_directory'],authority_directory=step['authority_directory'],
                    whole_round_manifest_path=self.manifest_path,registry=self.registry,ledger=self.ledger,engine=self.engine,
                    harden_only=step['action']=='harden_review',executor=self.phase)
                if step['action']=='harden_review' and request['command']=='harden' and (
                        request['parameters']!={'campaign':campaign,
                            'parent_subject':result['body']['parent_subject_digest']}):
                    raise ValueError('harden_original_operator_parent_binding')
            elif step['action']=='lifecycle_review':
                from skillloop.runtime.lifecycle_dispatch import dispatch_lifecycle_review
                result=dispatch_lifecycle_review(policy_path=step['policy_path'],manifest_path=step['manifest_path'],
                    deployment_journal=step['deployment_journal'],journal_directory=step['journal_directory'],
                    result_path=step['result_path'],whole_round_manifest_path=self.manifest_path,
                    ledger=self.ledger,engine=self.engine)
            elif step['action']=='private_factory':
                from skillloop.runtime.factory_dispatch import dispatch_private_factory
                result=dispatch_private_factory(policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=2097152),
                    assignment_directory=step['assignment_directory'],projection_directory=step['projection_directory'],
                    gate_freeze_path=step['gate_freeze_path'],journal_directory=step['journal_directory'],
                    whole_round_manifest_path=self.manifest_path,ledger=self.ledger,registry=self.registry,engine=self.engine)
            elif step['action']=='private_session':
                from skillloop.runtime.private_session_dispatch import dispatch_session_action,resolve_session_policy
                result=dispatch_session_action(policy=resolve_session_policy(step['policy_path']),
                    journal_directory=step['journal_directory'],engine=self.engine,ledger=self.ledger,registry=self.registry,
                    whole_round_manifest_path=self.manifest_path)
            elif step['action']=='private_resources':
                from skillloop.runtime.private_resources import prepare_private_resources
                result=prepare_private_resources(policy_path=step['policy_path'],reference_path=step['reference_path'],
                    journal_directory=step['journal_directory'],whole_round_manifest_path=self.manifest_path,
                    engine=self.engine,ledger=self.ledger,registry=self.registry)
            elif step['action']=='private_start':
                # Current materials and warm-up are prepared by the preceding
                # Evaluator action before acquiring this short original Lease.
                result=self.controller.start_private_reference(step['reference_path'],
                    minimum_remaining_seconds=step['minimum_remaining_seconds'])
                published=self.controller.publish_private_start(step['reference_path'],
                    evaluator_directory=step['evaluator_directory'])
                if result!=published:raise ValueError('campaign_original_private_start_publication')
            elif step['action']=='private_runtime':
                from skillloop.runtime.private_runtime_dispatch import dispatch_private_runtime
                result=dispatch_private_runtime(policy_path=step['policy_path'],reference_path=step['reference_path'],
                    started_path=step['started_path'],journal_directory=step['journal_directory'],
                    whole_round_manifest_path=self.manifest_path,engine=self.engine,ledger=self.ledger,
                    registry=self.registry,controller=self.controller)
            elif step['action']=='protected_close':
                result=self.registry.close_protected_task(plan_path=step['plan_path'],controller=self.controller,
                    ledger=self.ledger,engine=self.engine,whole_round_manifest_path=self.manifest_path,
                    journal_directory=step['journal_directory'])
            elif step['action']=='static_scan':
                from skillloop.discovery.scan_service import ScanController
                result=ScanController(step['deployment_path']).scan(request['parameters']['snapshot'],
                    scanner_profile=request['parameters'].get('scanner_profile'),operation_id=request['operation_id'])
            elif step['action']=='campaign_gate_assignment':
                from skillloop.runtime.campaign_gate_assignment import produce_campaign_gate_assignment
                result=produce_campaign_gate_assignment(policy_path=step['policy_path'],
                    assignment_directory=step['assignment_directory'],campaign=campaign,
                    whole=self.phase.round_manifest,registry=self.registry,ledger=self.ledger)
            elif step['action'] in {'campaign_gate','qualification_withdraw'}:
                from skillloop.runtime.whole_deployment import WholeRoleDeployment
                from skillloop.protection.current_task import _directory,_publish
                job=read_owned(Path(step['assignment_directory'])/'job.json',uid=21001,gid=21005,limit=262144)
                deployment=WholeRoleDeployment(manifest_path=step['manifest_path'],journal_directory=step['deployment_journal'],
                    engine=self.engine,ledger=self.ledger,whole_round_manifest_path=self.manifest_path)
                withdrawing=step['action']=='qualification_withdraw'
                module='skillloop.ci.qualification_withdrawal' if withdrawing else 'skillloop.ci.campaign_gate'
                expected_kind='FormalQualificationWithdrawalAssignment' if withdrawing else 'FormalCampaignGateAssignment'
                if deployment.role_config('gate',module)['Cmd']!=['-m',module]:
                    raise ValueError('campaign_final_gate_fixed_role_entry')
                if not withdrawing:
                    expected='SKILLLOOP_RAW_HISTORY_MAX_BYTES='+str(step['maximum_evidence_bytes'])
                    configured=[e for e in deployment.role_config('gate',module)['Env']
                                if e.startswith('SKILLLOOP_RAW_HISTORY_MAX_BYTES=')]
                    if configured!=[expected]:
                        raise ValueError('campaign_final_gate_original_raw_capacity_config')
                with self.registry.private_scope(campaign=job['bindings']['campaign']) as state:
                    if (job.get('kind')!=expected_kind or job['bindings']!=state['bindings']
                            or job['deadline']!=state['gate_freeze']['deadline']
                            or job['whole_round_manifest_digest']!=deployment.whole['digest']):
                        raise ValueError('campaign_final_gate_live_original_roster')
                    if state['bindings']['campaign']!=campaign:
                        raise ValueError('campaign_final_gate_original_route_scope')
                    from skillloop.runtime.campaign_auxiliary import begin_auxiliary,observe_auxiliary,finish_auxiliary,preserve_auxiliary_failure
                    config=deployment.role_config('gate',module)
                    begin_auxiliary(step,deployment.deadline,21005,config)
                    self.ledger.consume_auxiliary(manifest=deployment.whole,campaign=state['bindings']['campaign'],
                        stage='resource_archive_restore' if withdrawing else 'gate_qualification_report',
                        operation_key=('qualification-withdraw-' if withdrawing else 'campaign-gate-')+job['digest'][7:],
                        seconds=step['timeout_seconds']+step['closure_seconds'],input_tokens=0,output_tokens=0,
                        disk_bytes=step['maximum_evidence_bytes'])
                    # Actual role creation is charged before taking this ledger
                    # snapshot; starting this same created container adds no slot.
                    try:
                        deployment.create_role('gate',request['operation_id']+('-withdraw' if withdrawing else '-campaign-gate'),module=module)
                        spending={'kind':'CampaignGateSpendingSnapshot','assignment_digest':job['digest'],'state':self.ledger.read()}
                        spending['digest']=digest_jcs(spending)
                        directory=_directory(step['assignment_directory'],21001,21005,0o750)
                        _publish(directory/'spending.json',spending,21005)
                        observed=deployment.start_role('gate',request['operation_id']+('-withdraw' if withdrawing else '-campaign-gate'),module=module)
                        observe_auxiliary(step,observed['inspection'])
                        identifier=observed['inspection']['Id'];wait=self.engine.wait(identifier,step['timeout_seconds'])
                        actual=self.engine.inspect(identifier)
                        if wait.get('StatusCode')!=0 or actual['State']['Running'] or actual['State']['ExitCode']!=0:
                            raise RuntimeError('campaign_final_gate_original_failure_preserve_private_evidence')
                        result=read_owned(step['result_path'],uid=21005,gid=21001,limit=262144)
                        if result.get('kind')!=('FormalQualificationWithdrawalCompletion' if withdrawing else 'FormalCampaignGateCompletion') or result.get('assignment_digest')!=job['digest']:
                            raise ValueError('campaign_final_gate_actual_aggregate_required')
                        result=finish_auxiliary(step,actual,result,self.engine.inspect(deployment.provision()['keeper']['Id']),self.engine)
                    except BaseException as error:
                        if not (Path(step['journal_directory'])/'created.json').exists():
                            try:deployment.preserve_failed_role('gate',request['operation_id']+
                                ('-withdraw' if withdrawing else '-campaign-gate'),module=module,
                                closure_seconds=step['closure_seconds'])
                            except BaseException as secondary:
                                error.add_note('campaign_gate_unknown_create_preservation:'+type(secondary).__name__)
                        try:preserve_auxiliary_failure(step,self.engine,error)
                        except BaseException as secondary:
                            error.add_note('campaign_gate_original_failure_preservation:'+type(secondary).__name__)
                        raise
            elif step['action']=='registry_withdraw':
                result=self.registry.withdraw_for_archive(withdrawal_path=step['withdrawal_path'],
                    qualification_path=step['qualification_path'],
                    expected_active_revision=step['expected_active_revision'],operation_id=request['operation_id'])
            elif step['action']=='operation_archive':
                from skillloop.runtime.operation_archive import preserve_operation_history
                result=preserve_operation_history(policy_path=step['policy_path'],journal_directory=step['journal_directory'],
                    store=self.operation_store,ledger=self.ledger,whole_round_manifest_path=self.manifest_path)
            elif step['action']=='registry_snapshot':
                from skillloop.ci.registry_archive import dispatch_registry_snapshot
                result=dispatch_registry_snapshot(registry=self.registry,policy_path=step['policy_path'],
                    journal_directory=step['journal_directory'],ledger=self.ledger,
                    whole_round_manifest_path=self.manifest_path)
            elif step['action']=='archive_role':
                from skillloop.runtime.archive_dispatch import dispatch_archive_action
                result=dispatch_archive_action(policy_path=step['policy_path'],
                    journal_directory=step['journal_directory'],whole_round_manifest_path=self.manifest_path,
                    ledger=self.ledger,engine=self.engine)
            elif step['action']=='archive_close':
                from skillloop.runtime.archive_dispatch import close_archive_role
                result=close_archive_role(policy_path=step['policy_path'],dispatch_journal=step['dispatch_journal'],
                    review_path=step['review_path'],journal_directory=step['journal_directory'],engine=self.engine)
            elif step['action']=='campaign_inspection':
                if request['command']!='inspect' or request['parameters']!={'campaign':campaign}:
                    raise PermissionError('inspection_exact_operator_request')
                result=self.registry.inspect_campaign(campaign=campaign,
                    qualification_path=step['qualification_path'],authority_directory=step['authority_directory'],
                    report_path=step['report_path'])
            elif step['action']=='promote':
                p=request['parameters']
                result=self.registry.promote(qualification_path=step['qualification_path'],
                    authority_directory=step['authority_directory'],campaign=p['campaign'],subject=p['subject'],
                    expected_active_revision=p['expected_active_revision'],operation_id=request['operation_id'])
            else:
                raise RuntimeError('campaign_required_provider_unavailable')
            if type(result) is not dict:raise ValueError('campaign_production_stage_result_required')
            _save(journal,token+'.completed.json',{'kind':'CampaignStageCompleted',
                'step_digest':digest_jcs(step),'request_digest':request['digest'],'result':result})
            # Several production dispatchers return actual process metadata and
            # opaque commits rather than API envelopes. Hash their full return
            # value without synthesizing a public business result.
            stage_receipts.append(digest_jcs(result))
        if route['result_uid']==21001 and route['result_kind'] not in {'CIResult','HardenResult'}:
            # Publish only the actual final production return value. Controller
            # cannot synthesize evaluation verdicts or qualification facts.
            if result.get('kind')!=route['result_kind']:
                raise ValueError('operator_actual_production_result_required')
            try:validate_control(result)
            except ValueError:validate_envelope(result)
            _directory(Path(route['result_path']).parent,21001,21001,0o750)
            if os.path.lexists(route['result_path']):
                if read_owned(route['result_path'],uid=21001,gid=21001,limit=2097152)!=result:
                    raise ValueError('campaign_original_final_result_changed')
            else:_publish(Path(route['result_path']),result,21001)
        # Only the role-owned final projection may become a public CLI result.
        # A process completion, helper result or historical Check cannot replace it.
        result=read_owned(route['result_path'],uid=route['result_uid'],gid=21001,limit=2097152)
        try:validate_control(result)
        except ValueError:validate_envelope(result)
        if result['kind']!=route['result_kind']:
            raise ValueError('campaign_final_projection_kind')
        if route['result_kind'] in {'CIResult','HardenResult'} and route['result_uid']!=21005:
            raise PermissionError('campaign_actual_gate_result_required')
        # The Controller authenticates a role-owned result and binds its own
        # completed orchestration history. Gate and Reporter have no authority
        # or mount to read all Controller route journals.
        binding={'kind':'OperatorFinalResultBinding','request_digest':request['digest'],
            'route_digest':route['digest'],'result_digest':result['digest'],
            'stage_receipts':stage_receipts,'result_producer_uid':route['result_uid']}
        binding['digest']=digest_jcs(binding)
        _directory(Path(route['result_binding_path']).parent,21001,21001,0o750)
        if os.path.lexists(route['result_binding_path']):
            if read_owned(route['result_binding_path'],uid=21001,gid=21001,limit=262144)!=binding:
                raise ValueError('campaign_original_final_binding_changed')
        else:_publish(Path(route['result_binding_path']),binding,21001)
        binding=read_owned(route['result_binding_path'],uid=21001,gid=21001,limit=262144)
        if (binding.get('kind')!='OperatorFinalResultBinding'
                or binding.get('request_digest')!=request['digest'] or binding.get('route_digest')!=route['digest']
                or binding.get('result_digest')!=result['digest'] or binding.get('stage_receipts')!=stage_receipts
                or binding.get('result_producer_uid')!=route['result_uid']):
            raise ValueError('campaign_current_complete_route_result_binding')
        if result['kind']!=route['result_kind']:raise ValueError('campaign_final_projection_kind')
        if route['result_kind'] in {'CIResult','HardenResult'} and route['result_uid']!=21005:
            raise PermissionError('campaign_actual_gate_result_required')
        return result
