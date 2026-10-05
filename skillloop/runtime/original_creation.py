"""One original worker POST; unknown responses permit inspection/stop only."""
from datetime import datetime,timezone
import os,re
from skillloop.runtime.docker_api import DockerEngine,DockerEngineError
from skillloop.runtime.evaluation_dispatch import _verify_role_process
from skillloop.runtime.proposal_dispatch import _save
from skillloop.protection.current_task import _directory


def create_original_worker(*,engine,name,config,journal_directory,deadline):
    if (os.geteuid()!=21001 or type(engine) is not DockerEngine
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',name)):
        raise PermissionError('original_worker_creation_actual_controller')
    root=_directory(journal_directory,21001,21001,0o700)
    if os.path.lexists(root/'creation-attempt.json'):
        raise RuntimeError('original_worker_creation_already_attempted_no_post')
    began=datetime.now(timezone.utc)
    if deadline.tzinfo is None or began>=deadline:
        raise TimeoutError('original_worker_creation_deadline')
    intent=_save(root,'creation-attempt.json',{'kind':'OriginalWorkerCreationAttempt',
        'container_name':name,'configuration':config,'started_at':began.isoformat(),
        'deadline':deadline.isoformat(),'automatic_reexecution_allowed':False})
    try:
        identifier=engine.create(name,config)
        actual=engine.inspect(identifier,timeout=5)
        _verify_role_process(actual,identifier,config,config['HostConfig']['Mounts'])
        created=datetime.fromisoformat(actual['Created'].replace('Z','+00:00'))
        if (actual.get('Name')!='/'+name or created.tzinfo is None
                or not began<=created<=datetime.now(timezone.utc) or created>=deadline):
            raise ValueError('original_worker_created_identity_clock')
        _save(root,'creation-observed.json',{'kind':'OriginalWorkerCreationObserved',
            'intent_digest':intent['digest'],'container_id':identifier,'inspection':actual,
            'automatic_reexecution_allowed':False})
        return identifier
    except BaseException as original_error:
        value={'kind':'OriginalWorkerUnknownCreationPreservation','intent_digest':intent['digest'],
            'creation_error_type':type(original_error).__name__,'creation_status':'unknown',
            'automatic_reexecution_allowed':False,'evidence_released':False,
            'original_process_stopped':None}
        try:
            actual=engine.inspect(name,timeout=5);identifier=actual['Id']
            _verify_role_process(actual,identifier,config,config['HostConfig']['Mounts'])
            created=datetime.fromisoformat(actual['Created'].replace('Z','+00:00'))
            if (actual.get('Name')!='/'+name or created.tzinfo is None
                    or not began<=created<=datetime.now(timezone.utc) or created>=deadline):
                raise ValueError('original_worker_unknown_creation_identity_clock')
            value['inspection']=actual
            if actual.get('State',{}).get('Running') is True:
                engine.request('POST','/containers/'+identifier+'/stop?t=1',timeout=5)
            stopped=engine.inspect(identifier,timeout=5)
            _verify_role_process(stopped,identifier,config,config['HostConfig']['Mounts'])
            value['terminal_inspection']=stopped
            value['original_process_stopped']=stopped.get('State',{}).get('Running') is False
            if not value['original_process_stopped']:
                raise RuntimeError('original_worker_unknown_creation_not_stopped')
        except DockerEngineError as error:
            value['observation_error_type']=type(error).__name__
            value['observation_status']=error.status
            if error.status!=404:original_error.add_note('original_worker_creation_inspection_failed')
        except BaseException as error:
            value['observation_error_type']=type(error).__name__
            original_error.add_note('original_worker_creation_containment_unconfirmed:'+type(error).__name__)
        try:_save(root,'unknown-creation.json',value)
        except BaseException as error:
            original_error.add_note('original_worker_creation_evidence_unavailable:'+type(error).__name__)
        raise
