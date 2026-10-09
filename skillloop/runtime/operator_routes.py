"""Admission of the complete frozen CLI before any deployment side effect."""
from datetime import datetime
import json
from pathlib import Path
import re

from skillloop.protocol import canonical_json_line, digest_jcs
from skillloop.runtime.operation_store import WIRE_LIMIT


def validate_operator_routes(routes, *, campaign_digest, deadline):
    from skillloop.runtime.campaign_dispatcher import validate_dispatch_route
    profile = json.loads((Path(__file__).resolve().parents[2] /
        'specs/v2.2/operations/cli.json').read_text())
    commands = {item['name']: item for item in profile['commands']}
    if len(commands) != 17:
        raise ValueError('operator_frozen_cli_complete_contract')
    end = datetime.fromisoformat(deadline.replace('Z', '+00:00'))
    if end.tzinfo is None:
        raise ValueError('operator_original_deadline_timezone')
    if type(routes) is not list or not 17 <= len(routes) <= 2048:
        raise ValueError('operator_all_frozen_cli_routes_required')
    fields = {'kind','campaign_digest','command','parameters_digest','result_kind',
        'deadline','steps','result_path','result_binding_path','result_uid',
        'journal_directory','digest'}
    admitted = {}; covered = set(); journals = set(); bindings = set()
    for route in routes:
        if (type(route) is not dict or set(route) != fields
                or route['kind'] != 'FrozenOperatorCampaignRoute'
                or route['digest'] != digest_jcs({k:v for k,v in route.items() if k != 'digest'})
                or len(canonical_json_line(route)) > WIRE_LIMIT):
            raise ValueError('operator_complete_route_shape')
        command = commands.get(route['command'])
        if (command is None or command['stdout_schema'] != route['result_kind']
                or type(route['result_uid']) is not int
                or route['result_uid'] not in {21001,21005,21009,21010}
                or route['result_kind'] in {'CIResult','HardenResult'} and route['result_uid'] != 21005):
            raise ValueError('operator_frozen_cli_result_contract')
        if (type(route['parameters_digest']) is not str
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', route['parameters_digest'])
                or route['campaign_digest'] not in {None,campaign_digest}):
            raise ValueError('operator_route_parameters_and_campaign')
        route_end = datetime.fromisoformat(route['deadline'].replace('Z', '+00:00'))
        if route_end.tzinfo is None or route_end > end:
            raise ValueError('operator_route_original_deployment_deadline')
        validate_dispatch_route(route)
        if route['command']=='evaluate':
            _validate_evaluation_sequence(route)
        # A sealed Admin declaration cannot expand a read-only CLI command
        # into a privileged campaign operation. Validate the actual callers,
        # rather than accepting a final public result after arbitrary writes.
        read_actions={'import':'import_source','scan':'static_scan','inspect':'campaign_inspection'}
        if route['command'] in read_actions and (
                len(route['steps'])!=1 or route['steps'][0]['action']!=read_actions[route['command']]):
            raise PermissionError('operator_frozen_read_command_provider')
        if route['command']=='inspect' and route['result_uid']!=21001:
            raise PermissionError('operator_actual_registry_inspection_provider')
        if route['command']=='report' and (
                len(route['steps'])!=1 or route['steps'][0]['action']!='role_command'
                or route['steps'][0]['role']!='report' or route['steps'][0]['role_command']!='report'
                or route['steps'][0]['result_path']!=route['result_path']
                or route['result_uid']!=21009):
            raise PermissionError('operator_reporter_public_projection_only')
        # The short routes must end at their actual public result producer.
        # A preceding process completion or an unrelated result file is not a
        # substitute for the frozen CLI object, even if its kind is declared.
        direct={'import':('import_source',21001),'scan':('static_scan',21001),
            'inspect':('campaign_inspection',21001),'promote':('promote',21001),
            'admin cancel':('proxy_controller',21001),'admin revoke':('proxy_controller',21001)}
        if route['command'] in direct:
            action,uid=direct[route['command']]
            if (len(route['steps'])!=1 or route['steps'][0]['action']!=action
                    or route['result_uid']!=uid):
                raise PermissionError('operator_actual_direct_result_producer_required')
        delegated={'admin approve-domain':'approve-domain',
            'admin approve-factory':'approve-factory',
            'admin review-finding':'review-finding',
            'admin retire-history':'retire-history'}
        if route['command'] in delegated and (
                len(route['steps'])!=1 or route['steps'][0]['action']!='role_command'
                or route['steps'][0]['role']!='admin'
                or route['steps'][0]['role_command']!=delegated[route['command']]
                or route['steps'][0]['result_path']!=route['result_path']
                or route['result_uid']!=21010):
            raise PermissionError('operator_actual_admin_result_producer_required')
        if route['command']=='harden' and (
                route['steps'][-1]['action']!='harden_review'
                or sum(s['action']=='proposal' for s in route['steps'])!=1
                or sum(s['action']=='application_gate' for s in route['steps'])!=1
                or any(s['action'] in {'roster_freeze','private_factory','private_session',
                    'private_resources','private_start','private_runtime','protected_close','campaign_gate','promote',
                    'campaign_gate_assignment','qualification_withdraw','registry_withdraw','archive_role','archive_close'}
                    for s in route['steps'])):
            raise PermissionError('operator_harden_one_current_dev_round_only')
        if route['command'] in {'admin cancel','admin revoke'} and (
                len(route['steps']) != 1 or route['steps'][0]['action'] != 'proxy_controller'
                or route['steps'][0]['method'] != {
                    'admin cancel':'cancel_run','admin revoke':'revoke_approval'}[route['command']]):
            raise PermissionError('operator_control_lane_frozen_rpc_only')
        key = (route['command'],route['parameters_digest'])
        if key in admitted:
            raise ValueError('operator_duplicate_route')
        # Two operations must not claim the same mutable recovery journal.
        # Deployment journals and immutable input/result projections may be shared.
        own = {route['journal_directory']} | {
            step['journal_directory'] for step in route['steps'] if 'journal_directory' in step and step['action'] != 'deployment'}
        if any(str(Path(path)) != path for path in own | {route['result_binding_path']}):
            raise ValueError('operator_canonical_recovery_locator_required')
        if journals & own or route['result_binding_path'] in bindings:
            raise ValueError('operator_routes_original_recovery_custody_conflict')
        journals.update(own); bindings.add(route['result_binding_path'])
        admitted[key] = route; covered.add(route['command'])
    if covered != set(commands):
        raise ValueError('operator_all_frozen_cli_routes_required')
    return admitted


def _validate_evaluation_sequence(route):
    """Require actual whole-campaign callers, without asserting their success.

    Inputs may still be future role outputs. Each caller checks their custody
    and original binding when reached; this prevents a short declaration from
    being admitted as the formal full evaluation route.
    """
    actions=[step['action'] for step in route['steps']]
    once=('register_campaign','roster_freeze','operation_archive','private_factory','lifecycle_review','campaign_gate_assignment','campaign_gate')
    if (route['campaign_digest'] is None or route['result_uid']!=21005
            or any(actions.count(action)!=1 for action in once)
            or any(action not in actions for action in ('semantic_discovery','discovery_suite','development','private_session'))
            or any(action in actions for action in ('harden_review','qualification_withdraw',
                'registry_withdraw','archive_close','promote'))):
        raise PermissionError('operator_complete_evaluation_callers_required')
    registered=actions.index('register_campaign');frozen=actions.index('roster_freeze')
    attempt_audit=actions.index('operation_archive')
    factory=actions.index('private_factory');lifecycle=actions.index('lifecycle_review')
    gate=actions.index('campaign_gate');assignment=actions.index('campaign_gate_assignment')
    imports=[index for index,step in enumerate(route['steps']) if step['action']=='role_command'
        and step.get('role')=='admin' and step.get('role_command')=='import-lifecycle']
    if len(imports)!=1 or not factory<imports[0]<lifecycle:
        raise ValueError('operator_evaluation_original_host_lifecycle_import_required')
    if not max(factory,lifecycle)<assignment<gate:
        raise ValueError('operator_evaluation_current_gate_assignment_order')
    if route['steps'][assignment]['assignment_directory']!=route['steps'][gate]['assignment_directory']:
        raise ValueError('operator_evaluation_same_produced_gate_assignment')
    if not registered<frozen<attempt_audit<factory<gate or not frozen<lifecycle<gate:
        raise ValueError('operator_evaluation_original_phase_order')
    private_policy=[index for index,step in enumerate(route['steps']) if step['action']=='role_command'
        and step.get('role')=='admin' and step.get('role_command')=='produce-private-policy']
    if len(private_policy)!=1 or not frozen<private_policy[0]<assignment:
        raise ValueError('operator_evaluation_current_private_policy_producer_required')
    development={'semantic_discovery','discovery_suite','development','proposal','application_gate'}
    if any(not registered<index<frozen for index,action in enumerate(actions) if action in development):
        raise ValueError('operator_evaluation_development_before_freeze')
    if not any(action=='semantic_discovery' for action in actions[registered+1:actions.index('development')]):
        raise ValueError('operator_evaluation_discovery_before_development')
    first_development=actions.index('development')
    if not any(action=='discovery_suite' for action in actions[actions.index('semantic_discovery')+1:first_development]):
        raise ValueError('operator_evaluation_actual_discovery_suite_before_development')
    # Reserve/materialize actions can occur between task stages, but a second
    # Lease or a final Gate cannot cross an unclosed original Runtime.
    state='idle';tasks=0
    for index,action in enumerate(actions):
        if action=='private_session' and not factory<index<gate:
            raise ValueError('operator_evaluation_session_after_factory')
        if action=='private_session' and index<=private_policy[0]:
            raise ValueError('operator_evaluation_private_policy_before_delivery')
        if action not in {'private_resources','private_start','private_runtime','protected_close'}:continue
        if not max(factory,lifecycle)<index<assignment:
            raise ValueError('operator_evaluation_protected_after_isolation')
        expected={'idle':'private_resources','prepared':'private_start','leased':'private_runtime','running':'protected_close'}[state]
        if action!=expected:raise ValueError('operator_evaluation_original_task_closure_order')
        if action=='private_resources':state='prepared'
        elif action=='private_start':state='leased'
        elif action=='private_runtime':state='running'
        else:state='idle';tasks+=1
    if state!='idle' or tasks==0:
        raise ValueError('operator_evaluation_full_protected_call_chain_required')
