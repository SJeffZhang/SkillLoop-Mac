"""Contain an original private dispatch without reading private worker output."""
from datetime import datetime,timezone
import os,re
from pathlib import Path

from skillloop.runtime.docker_api import DockerEngine,DockerEngineError
from skillloop.runtime.evaluation_dispatch import _verify_role_process
from skillloop.runtime.proposal_dispatch import _save


DISPATCHES={
    'runtime':('intent.json','spending.json','created.json','OpaquePrivateRuntimeIntent','OpaquePrivateRuntimeSpending'),
    'handoff':('handoff-intent.json','handoff-spending.json','handoff-created.json','OpaquePrivateHandoffIntent','OpaquePrivateHandoffSpending'),
    'session':('intent.json','spending.json','created.json','OpaquePrivateSessionDispatchIntent','OpaquePrivateSessionSpending'),
}


def preserve_original_private_process(*,journal_directory,dispatch,engine,expected_campaign=None,error_type=None):
    """Inspect/stop only; a 404 remains unknown and never authorizes delivery.

    The immutable pre-create intent pins the unique name and full configuration.
    No Docker logs, private files, process restart or resource deletion is used.
    All observations are append-only and retain the original reserved clock.
    """
    if os.geteuid()!=21001 or type(engine) is not DockerEngine or dispatch not in DISPATCHES:
        raise PermissionError('private_preservation_actual_controller')
    from skillloop.runtime.protected_flow import _controller_record
    root=Path(journal_directory)
    intent_name,cost_name,created_name,intent_kind,cost_kind=DISPATCHES[dispatch]
    intent=_controller_record(root/intent_name);cost=_controller_record(root/cost_name)
    if (intent.get('kind')!=intent_kind or cost.get('kind')!=cost_kind
            or type(intent.get('configuration')) is not dict
            or type(intent.get('container_name')) is not str
            or not re.fullmatch(r'skillloop-[A-Za-z0-9-]{1,100}',intent['container_name'])
            or type(intent.get('reserved_seconds')) is not int or intent['reserved_seconds']<=0
            or (expected_campaign is not None and intent.get('campaign_id')!=expected_campaign)):
        raise ValueError('private_preservation_original_intent_and_spending')
    config=intent['configuration'];uid=config.get('User')
    if (uid not in {'21002:21002','21004:21004','21005:21005'}
            or config.get('HostConfig',{}).get('LogConfig')!={'Type':'none','Config':{}}
            or config.get('HostConfig',{}).get('NetworkMode')!='none'):
        raise PermissionError('private_preservation_original_role_policy')
    started=datetime.fromisoformat(intent['started_at'].replace('Z','+00:00'))
    deadline=datetime.fromisoformat(intent['campaign_deadline'].replace('Z','+00:00'))
    if started.tzinfo is None or deadline.tzinfo is None or started>=deadline:
        raise ValueError('private_preservation_original_clock')
    # Reserve the next bounded observation name before any Engine mutation.
    name=next((dispatch+'-preservation-'+str(i).zfill(2)+'.json' for i in range(16)
               if not os.path.lexists(root/(dispatch+'-preservation-'+str(i).zfill(2)+'.json'))),None)
    if name is None:raise RuntimeError('private_preservation_observation_limit')
    observation={'kind':'OriginalPrivateProcessPreservation','dispatch':dispatch,
        'intent_digest':intent['digest'],'spending_digest':cost['digest'],
        'container_name':intent['container_name'],'error_type':error_type,
        'automatic_reexecution_allowed':False,'evidence_released':False,
        'qualification_issued':False,'private_result_verified':False}
    recorded_identifier=None
    if os.path.lexists(root/created_name):
        try:created=_controller_record(root/created_name)
        except (ValueError,PermissionError,OSError) as error:
            observation['created_record_error_type']=type(error).__name__
        else:
            recorded_identifier=created.get('container_id')
            if type(recorded_identifier) is not str or not re.fullmatch(r'[0-9a-f]{64}',recorded_identifier):
                raise ValueError('private_preservation_recorded_original_id')
    try:
        actual=engine.inspect(intent['container_name'])
    except DockerEngineError as error:
        if error.status!=404:raise
        observation.update(actual_inspection_status=404,delivery_status='unknown',original_process_stopped=None)
    else:
        identifier=actual.get('Id','')
        if (not re.fullmatch(r'[0-9a-f]{64}',identifier)
                or actual.get('Name')!='/'+intent['container_name']
                or (recorded_identifier is not None and identifier!=recorded_identifier)):
            raise ValueError('private_preservation_original_name_and_id')
        _verify_role_process(actual,identifier,config,config['HostConfig']['Mounts'])
        if actual['HostConfig'].get('LogConfig',{}).get('Type')!='none':
            raise PermissionError('private_preservation_no_controller_private_logs')
        # A lost stop response remains visible; the next observation may inspect
        # the same pinned process, never a replacement or a new private task.
        stop_error=None
        if actual.get('State',{}).get('Running') is True:
            try:engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
            except BaseException as error:stop_error=type(error).__name__
        try:
            terminal=engine.inspect(identifier)
            _verify_role_process(terminal,identifier,config,config['HostConfig']['Mounts'])
            stopped=terminal.get('State',{}).get('Running') is False
        except BaseException as error:
            terminal=None;stopped=None
            stop_error=stop_error or type(error).__name__
        observation.update(actual_inspection_status=200,inspection=actual,
            terminal_inspection=terminal,original_process_stopped=stopped,
            stop_error_type=stop_error,delivery_status='unknown')
    now=datetime.now(timezone.utc);elapsed=(now-started).total_seconds()
    observation.update(observed_at=now.isoformat(),elapsed_seconds=elapsed,
        budget_closure='within_original_budget' if 0<=elapsed<=intent['reserved_seconds'] and now<deadline
            else 'inconclusive_expired_budget_closure')
    return _save(root,name,observation)
