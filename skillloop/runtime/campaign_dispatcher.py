"""Typed production dispatch for administrator-frozen operator campaign routes."""
import os
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs,validate_envelope
from skillloop.proxy.wire import validate_control
from skillloop.runtime.protected_flow import _controller_record


ACTION_FIELDS={
    'import_source':{'approved_repository'},
    'archive_role':{'policy_path','journal_directory'},
    'archive_close':{'policy_path','dispatch_journal','review_path','journal_directory'},
    'registry_withdraw':{'withdrawal_path','qualification_path','expected_active_revision'},
    'register_campaign':{'registration_path','authority_directory'},
    'deployment':{'manifest_path','journal_directory','start_roles'},
    'role_command':{'role','assignment_directory','role_command','rpc_params','manifest_path','deployment_journal','timeout_seconds','result_path'},
    'proxy_controller':{'method','rpc_params','journal_directory'},
    'development':{'plan_path'},
    'roster_freeze':{'policy_path','assignment_directory','roster_directory','journal_directory','authority_directory'},
    'private_factory':{'policy_path','assignment_directory','projection_directory','gate_freeze_path','journal_directory'},
    'private_session':{'policy_path','journal_directory'},
    'private_start':{'reference_path','minimum_remaining_seconds','evaluator_directory'},
    'private_runtime':{'policy_path','reference_path','started_path','journal_directory'},
    'protected_close':{'plan_path','journal_directory'},
    'static_scan':{'deployment_path'},
    'qualification_withdraw':{'assignment_directory','manifest_path','deployment_journal','result_path','timeout_seconds','maximum_evidence_bytes'},
    'campaign_gate':{'assignment_directory','manifest_path','deployment_journal','result_path','timeout_seconds','maximum_evidence_bytes'},
    'promote':{'qualification_path','authority_directory'},
    'semantic_discovery':{'assignment_directory','manifest_path','deployment_journal','result_path','timeout_seconds'},
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
                or not 1<=step['timeout_seconds']<=120):
            raise ValueError('campaign_role_command_bound')
        if action in {'campaign_gate','qualification_withdraw'} and (type(step['timeout_seconds']) is not int
                or not 1<=step['timeout_seconds']<=120 or type(step['maximum_evidence_bytes']) is not int
                or not 1<=step['maximum_evidence_bytes']<=268435456):
            raise ValueError('campaign_final_gate_full_cost_bound')
        if action=='semantic_discovery' and (type(step['timeout_seconds']) is not int
                or not 1<=step['timeout_seconds']<=1200):
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
    def recover_final(self,request,route):
        # Read only the already published original role result. No campaign
        # step, Engine start, model inference or private delivery is called.
        result=read_owned(route['result_path'],uid=route['result_uid'],gid=21001,limit=2097152)
        binding=read_owned(route['result_binding_path'],uid=route['result_uid'],gid=21001,limit=262144)
        if (binding.get('kind')!='OperatorFinalResultBinding' or binding.get('request_digest')!=request['digest']
                or binding.get('route_digest')!=route['digest'] or binding.get('result_digest')!=result['digest']
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
        from skillloop.protection.current_task import _directory
        from skillloop.runtime.proposal_dispatch import _save
        journal=_directory(route['journal_directory'],21001,21001,0o700)
        identity={'kind':'CampaignRouteIdentity','request_digest':request['digest'],'route_digest':route['digest']}
        original=journal/'identity.json'
        if original.exists():
            saved=_controller_record(original)
            if any(saved.get(k)!=v for k,v in identity.items()):raise ValueError('campaign_original_route_identity')
        else:_save(journal,'identity.json',identity)
        stage_receipts=[]
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
                from skillloop.runtime.whole_deployment import WholeRoleDeployment
                from skillloop.protection.current_task import _directory,_publish
                role=step['role']
                if role not in {'admin','report'}:raise PermissionError('operator_delegated_role_scope')
                uid=21010 if role=='admin' else 21009
                directory=_directory(step['assignment_directory'],21001,uid,0o750)
                job={'kind':'DelegatedRoleCommand','command':step['role_command'],
                    'operation_id':request['operation_id'],'params':step['rpc_params']}
                job['digest']=digest_jcs(job)
                _publish(directory/'job.json',job,uid)
                deployment=WholeRoleDeployment(manifest_path=step['manifest_path'],journal_directory=step['deployment_journal'],
                    engine=self.engine,ledger=self.ledger,whole_round_manifest_path=self.manifest_path)
                observed=deployment.start_role(role,request['operation_id']+'-'+role)
                identifier=observed['inspection']['Id']
                wait=self.engine.wait(identifier,step['timeout_seconds']);actual=self.engine.inspect(identifier)
                if wait.get('StatusCode')!=0 or actual.get('State',{}).get('Running') is not False or actual.get('State',{}).get('ExitCode')!=0:
                    raise RuntimeError('operator_delegated_original_role_failed')
                result=read_owned(step['result_path'],uid=uid,gid=21001,limit=2097152)
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
                message=make_control('ControlRequest',{'operation_id':request['operation_id'],
                    'deadline':(datetime.now(timezone.utc)+timedelta(seconds=9)).isoformat().replace('+00:00','Z'),
                    'method':step['method'],'params':step['rpc_params']})
                _save(directory,'request.json',{'kind':'DelegatedControllerRequest','request':message})
                result=self.controller.client._send('control.sock',message)['result'];validate_control(result)
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
                if deployment.plan['roles']['model_gateway']['config']['Cmd']!=['-m','skillloop.discovery.semantic_worker']:
                    raise ValueError('campaign_semantic_fixed_gateway_entry')
                cost=self.ledger.consume_auxiliary(manifest=deployment.whole,campaign=job['campaign_digest'],
                    stage='import_scan',operation_key='semantic-'+job['digest'][7:],seconds=job['worker_seconds']+60,
                    input_tokens=job['model_policy']['max_chat_requests']*16384,
                    output_tokens=job['model_policy']['max_chat_requests']*job['model_policy']['max_output_tokens'],
                    disk_bytes=67108864+job['model_policy']['max_chat_requests']*14680064)
                observed=deployment.start_role('model_gateway',request['operation_id']+'-semantic')
                identifier=observed['inspection']['Id'];wait=self.engine.wait(identifier,step['timeout_seconds'])
                actual=self.engine.inspect(identifier)
                if wait.get('StatusCode')!=0 or actual['State']['Running'] or actual['State']['ExitCode']!=0:
                    raise RuntimeError('campaign_semantic_original_process_incomplete')
                result=read_owned(step['result_path'],uid=21011,gid=21001,limit=8388608)
                if result.get('assignment_digest')!=job['digest'] or result['scanner_report']['body']['status']!='complete':
                    raise ValueError('campaign_semantic_complete_coverage_required')
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
            elif step['action']=='roster_freeze':
                from skillloop.runtime.roster_dispatch import dispatch_roster_gate
                result=dispatch_roster_gate(policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=2097152),
                    assignment_directory=step['assignment_directory'],roster_directory=step['roster_directory'],
                    journal_directory=step['journal_directory'],authority_directory=step['authority_directory'],
                    whole_round_manifest_path=self.manifest_path,registry=self.registry,ledger=self.ledger,engine=self.engine)
            elif step['action']=='private_factory':
                from skillloop.runtime.factory_dispatch import dispatch_private_factory
                result=dispatch_private_factory(policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=2097152),
                    assignment_directory=step['assignment_directory'],projection_directory=step['projection_directory'],
                    gate_freeze_path=step['gate_freeze_path'],journal_directory=step['journal_directory'],
                    whole_round_manifest_path=self.manifest_path,ledger=self.ledger,registry=self.registry,engine=self.engine)
            elif step['action']=='private_session':
                from skillloop.runtime.private_session_dispatch import dispatch_session_action
                result=dispatch_session_action(policy=read_owned(step['policy_path'],uid=21010,gid=21001,limit=2097152),
                    journal_directory=step['journal_directory'],engine=self.engine,ledger=self.ledger,registry=self.registry,
                    whole_round_manifest_path=self.manifest_path)
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
            elif step['action'] in {'campaign_gate','qualification_withdraw'}:
                from skillloop.runtime.whole_deployment import WholeRoleDeployment
                from skillloop.protection.current_task import _directory,_publish
                job=read_owned(Path(step['assignment_directory'])/'job.json',uid=21001,gid=21005,limit=262144)
                deployment=WholeRoleDeployment(manifest_path=step['manifest_path'],journal_directory=step['deployment_journal'],
                    engine=self.engine,ledger=self.ledger,whole_round_manifest_path=self.manifest_path)
                withdrawing=step['action']=='qualification_withdraw'
                module='skillloop.ci.qualification_withdrawal' if withdrawing else 'skillloop.ci.campaign_gate'
                expected_kind='FormalQualificationWithdrawalAssignment' if withdrawing else 'FormalCampaignGateAssignment'
                if deployment.plan['roles']['gate']['config']['Cmd']!=['-m',module]:
                    raise ValueError('campaign_final_gate_fixed_role_entry')
                with self.registry.private_scope(campaign=job['bindings']['campaign']) as state:
                    if (job.get('kind')!=expected_kind or job['bindings']!=state['bindings']
                            or job['deadline']!=state['gate_freeze']['deadline']
                            or job['whole_round_manifest_digest']!=deployment.whole['digest']):
                        raise ValueError('campaign_final_gate_live_original_roster')
                    self.ledger.consume_auxiliary(manifest=deployment.whole,campaign=state['bindings']['campaign'],
                        stage='resource_archive_restore' if withdrawing else 'gate_qualification_report',
                        operation_key=('qualification-withdraw-' if withdrawing else 'campaign-gate-')+job['digest'][7:],
                        seconds=step['timeout_seconds']+60,input_tokens=0,output_tokens=0,
                        disk_bytes=step['maximum_evidence_bytes'])
                    # Actual role creation is charged before taking this ledger
                    # snapshot; starting this same created container adds no slot.
                    deployment.create_role('gate',request['operation_id']+('-withdraw' if withdrawing else '-campaign-gate'))
                    if not withdrawing:
                        spending={'kind':'CampaignGateSpendingSnapshot','assignment_digest':job['digest'],'state':self.ledger.read()}
                        spending['digest']=digest_jcs(spending)
                        directory=_directory(step['assignment_directory'],21001,21005,0o750)
                        _publish(directory/'spending.json',spending,21005)
                    observed=deployment.start_role('gate',request['operation_id']+('-withdraw' if withdrawing else '-campaign-gate'))
                    identifier=observed['inspection']['Id'];wait=self.engine.wait(identifier,step['timeout_seconds'])
                    actual=self.engine.inspect(identifier)
                    if wait.get('StatusCode')!=0 or actual['State']['Running'] or actual['State']['ExitCode']!=0:
                        raise RuntimeError('campaign_final_gate_original_failure_preserve_private_evidence')
                    result=read_owned(step['result_path'],uid=21005,gid=21001,limit=262144)
                    if result.get('kind')!=('FormalQualificationWithdrawalCompletion' if withdrawing else 'FormalCampaignGateCompletion') or result.get('assignment_digest')!=job['digest']:
                        raise ValueError('campaign_final_gate_actual_aggregate_required')
            elif step['action']=='registry_withdraw':
                result=self.registry.withdraw_for_archive(withdrawal_path=step['withdrawal_path'],
                    qualification_path=step['qualification_path'],
                    expected_active_revision=step['expected_active_revision'],operation_id=request['operation_id'])
            elif step['action']=='archive_role':
                from skillloop.runtime.archive_dispatch import dispatch_archive_action
                result=dispatch_archive_action(policy_path=step['policy_path'],
                    journal_directory=step['journal_directory'],whole_round_manifest_path=self.manifest_path,
                    ledger=self.ledger,engine=self.engine)
            elif step['action']=='archive_close':
                from skillloop.runtime.archive_dispatch import close_archive_role
                result=close_archive_role(policy_path=step['policy_path'],dispatch_journal=step['dispatch_journal'],
                    review_path=step['review_path'],journal_directory=step['journal_directory'],engine=self.engine)
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
            from skillloop.protection.current_task import _directory,_publish
            for target in (route['result_path'],route['result_binding_path']):
                _directory(Path(target).parent,21001,21001,0o750)
            binding={'kind':'OperatorFinalResultBinding','request_digest':request['digest'],
                'route_digest':route['digest'],'result_digest':result['digest'],'stage_receipts':stage_receipts}
            binding['digest']=digest_jcs(binding)
            _publish(Path(route['result_path']),result,21001)
            _publish(Path(route['result_binding_path']),binding,21001)
        # Only the role-owned final projection may become a public CLI result.
        # A process completion, helper result or historical Check cannot replace it.
        result=read_owned(route['result_path'],uid=route['result_uid'],gid=21001,limit=2097152)
        try:validate_control(result)
        except ValueError:validate_envelope(result)
        binding=read_owned(route['result_binding_path'],uid=route['result_uid'],gid=21001,limit=262144)
        if (binding.get('kind')!='OperatorFinalResultBinding'
                or binding.get('request_digest')!=request['digest'] or binding.get('route_digest')!=route['digest']
                or binding.get('result_digest')!=result['digest'] or binding.get('stage_receipts')!=stage_receipts):
            raise ValueError('campaign_current_complete_route_result_binding')
        if result['kind']!=route['result_kind']:raise ValueError('campaign_final_projection_kind')
        if route['result_kind'] in {'CIResult','HardenResult'} and route['result_uid']!=21005:
            raise PermissionError('campaign_actual_gate_result_required')
        return result
