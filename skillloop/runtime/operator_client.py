"""Authenticated internal operator transport; public RPC enums stay unchanged."""
from datetime import datetime,timedelta,timezone
import os,socket,time,uuid
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import canonical_json_line,decode_json,digest_jcs,validate_envelope
from skillloop.proxy.wire import validate_control

CONFIG=Path('/etc/skillloop/operator.json')


def operator_request(command,parameters,operation_id=None,*,wait=True):
    if not hasattr(socket,'SO_PEERCRED'):raise PermissionError('formal_operator_linux_peer_required')
    # Trusted deployment chooses caller identity; environment variables cannot.
    cfg=read_owned(CONFIG,uid=21010,gid=os.geteuid(),limit=262144)
    if (cfg.get('kind')!='OperatorFrontendDeployment' or cfg.get('caller_uid')!=os.geteuid()
            or cfg.get('server_uid')!=21001 or not Path(cfg['socket']).is_absolute()):
        raise PermissionError('formal_operator_deployment_identity')
    original=operation_id or 'operator-'+uuid.uuid4().hex
    request={'kind':'InternalOperatorRequest','command':command,'parameters':parameters,'operation_id':original}
    request['digest']=digest_jcs(request)
    def exchange(value):
        raw_request=canonical_json_line(value)
        if len(raw_request)>262144:raise ValueError('operator_control_request_capacity')
        from skillloop.runtime.local_packet import exchange_packet
        allowance=10
        if value['kind']=='InternalOperatorQuery':
            allowance=min(allowance,(deadline-datetime.now(timezone.utc)).total_seconds())
            if allowance<=0:raise TimeoutError('operator_original_deadline')
        raw=exchange_packet(cfg['socket'],raw_request,timeout=allowance,
            expected_server_uid=21001,maximum_bytes=262144)
        reply=decode_json(raw)
        if type(reply) is not dict or set(reply)!={'ok','result','error_code'} or type(reply['ok']) is not bool:
            raise OSError('operator_response_shape')
        if not reply['ok']:
            if reply['error_code']=='permission_denied':raise PermissionError('operator_denied')
            if reply['error_code'] in {'invalid_args','conflict'}:raise ValueError('operator_invalid_or_conflict')
            raise TimeoutError('operator_unavailable_or_unknown')
        result=reply['result']
        try:return validate_control(result)
        except ValueError:return validate_envelope(result)
    result=exchange(request)
    if result.get('kind')!='OperationTicket' or not wait:return result
    deadline=datetime.fromisoformat(result['body']['deadline'].replace('Z','+00:00'))
    ticket=result
    while datetime.now(timezone.utc)<deadline:
        query={'kind':'InternalOperatorQuery','operation_ref':ticket['body']['operation_ref']}
        query['digest']=digest_jcs(query);result=exchange(query)
        if result['kind']!='OperationStatus':return result
        if result['body']['state'] in {'failed','cancelled'}:raise TimeoutError('operator_terminal_without_result')
        time.sleep(1)
    raise TimeoutError('operator_original_deadline')
