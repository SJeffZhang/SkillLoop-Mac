"""Trusted Linux bootstrap before the formal operator socket exists.

This entry has one sealed, Admin-supplied deployment policy. It runs the
existing Admin producer under UID 21010, then permanently drops to the
Controller UID before provisioning and starting the original Proxy and
Controller. It never handles a private task or issues an approval.
"""
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import stat
import time

from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import decode_json, digest_jcs
from skillloop.protection.current_task import _directory
from skillloop.runtime.docker_api import DockerEngine
from skillloop.runtime.proposal_dispatch import _save
from skillloop.runtime.round_manifest import read_round_manifest
from skillloop.runtime.whole_deployment import WholeRoleDeployment


LAUNCH = Path('/bootstrap-input/launch.json')


def _launch_document():
    fd = os.open(LAUNCH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 262144):
            raise PermissionError('bootstrap_original_root_launch_custody')
        value = decode_json(stream.read(262145))
    fields = {'kind', 'policy_path', 'manifest_path', 'whole_round_manifest_path',
              'ledger_path', 'journal_directory', 'deployment_journal_directory', 'victim_seconds',
              'campaign_started_at', 'campaign_digest', 'deployment_epoch',
              'engine_socket_gid', 'operator_socket', 'digest'}
    if (type(value) is not dict or set(value) != fields
            or value['kind'] != 'FrozenPreOperatorLaunch'
            or value['digest'] != digest_jcs({k:v for k,v in value.items() if k != 'digest'})
            or any(type(value[k]) is not str or not Path(value[k]).is_absolute()
                   or '..' in Path(value[k]).parts for k in
                   ('policy_path','manifest_path','whole_round_manifest_path',
                    'ledger_path','journal_directory','deployment_journal_directory','operator_socket'))
            or type(value['victim_seconds']) is not int or value['victim_seconds'] < 1
            or type(value['engine_socket_gid']) is not int
            or not 1 <= value['engine_socket_gid'] <= 4294967294
            or type(value['campaign_started_at']) not in (int,float)
            or not 0 < value['campaign_started_at'] <= time.time()):
        raise ValueError('bootstrap_sealed_original_launch')
    first=Path(value['journal_directory']);second=Path(value['deployment_journal_directory'])
    if first==second or first.is_relative_to(second) or second.is_relative_to(first):
        raise ValueError('bootstrap_distinct_original_journals')
    return value


def _admin_produce(path):
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([21001])
            os.setgid(21010)
            os.setuid(21010)
            from skillloop.runtime.whole_deployment_producer import produce_deployment
            produce_deployment(path)
        except BaseException:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise RuntimeError('bootstrap_original_admin_production_failed_preserve_input')


def _reserve_admin_producer(launch, whole):
    """Charge the original approval/deployment slot before Admin writes."""
    child=os.fork()
    if child==0:
        try:
            os.setgroups([21001]);os.setgid(21001);os.setuid(21001)
            from skillloop.repair.budget import SpendingLedger
            from skillloop.runtime.protected_flow import _controller_record
            ledger=SpendingLedger(Path(launch['ledger_path']),
                victim_seconds=launch['victim_seconds'],
                campaign_started_at=launch['campaign_started_at'])
            key='pre-operator-admin-'+launch['digest'][7:]
            requested={'seconds':120,'input_tokens':0,'output_tokens':0,'disk_bytes':2097152}
            state=ledger.read()
            if (state.get('whole_round_binding')!={'manifest_digest':whole['digest'],
                    'campaign':launch['campaign_digest']}
                    or state.get('campaign_started_at')!=launch['campaign_started_at']):
                raise ValueError('bootstrap_original_whole_cost_reservation_required')
            prior=[entry for entry in state.get('auxiliary_executions',[])
                if entry.get('operation_key')==key]
            if prior:
                if (len(prior)!=1 or prior[0].get('stage')!='approval_deployment'
                        or prior[0].get('requested_cost')!=requested):
                    raise ValueError('bootstrap_original_admin_cost_changed')
                spending=prior[0]
            else:
                spending=ledger.consume_auxiliary(manifest=whole,
                    campaign=launch['campaign_digest'],stage='approval_deployment',
                    operation_key=key,**requested)
            journal=Path(launch['journal_directory']);path=journal/'pre-operator-admin-cost.json'
            expected={'kind':'PreOperatorAdminProductionCost','launch_digest':launch['digest'],
                      'spending':spending}
            if path.exists():
                if _controller_record(path)!={**expected,'digest':digest_jcs(expected)}:
                    raise ValueError('bootstrap_original_admin_spending_receipt_changed')
            else:_save(journal,path.name,expected)
        except BaseException:
            os._exit(1)
        os._exit(0)
    _,status=os.waitpid(child,0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status)!=0:
        raise RuntimeError('bootstrap_original_admin_budget_unavailable')


def main():
    if os.geteuid() != 0 or not hasattr(socket, 'SO_PEERCRED'):
        raise PermissionError('bootstrap_trusted_linux_root_only')
    os.umask(0o077)
    launch = _launch_document()
    policy = read_owned(launch['policy_path'], uid=21010, gid=21001, limit=2097152)
    whole = read_round_manifest(launch['whole_round_manifest_path'])
    if (policy.get('kind') != 'FrozenWholeRoleProductionPolicy'
            or policy.get('campaign_digest') != launch['campaign_digest']
            or policy.get('deployment_epoch') != launch['deployment_epoch']
            or policy.get('whole_round_manifest_digest') != whole['digest']
            or whole['deployment_epoch'] != launch['deployment_epoch']
            or not any(c['campaign_digest'] == launch['campaign_digest'] for c in whole['campaigns'])
            or launch['manifest_path'] != str(Path(policy['output_directory'])/'deployment.json')):
        raise ValueError('bootstrap_original_admin_round_binding')
    deadline = datetime.fromisoformat(policy['deadline'].replace('Z','+00:00'))
    if (deadline.tzinfo is None
            or deadline.timestamp() != launch['campaign_started_at'] + 28800
            or datetime.now(timezone.utc) >= deadline):
        raise ValueError('bootstrap_original_campaign_clock')
    journal = _directory(launch['journal_directory'], 21001, 21001, 0o700)
    intent = journal/'pre-operator-intent.json'
    expected = {'kind':'PreOperatorBootstrapIntent','launch_digest':launch['digest'],
                'admin_policy_digest':policy['digest'], 'automatic_reexecution_allowed':False}
    if intent.exists():
        from skillloop.runtime.protected_flow import _controller_record
        if _controller_record(intent) != {**expected,'digest':digest_jcs(expected)}:
            raise ValueError('bootstrap_original_intent_changed')
    else:
        # Root only prepares this exact Controller-owned record. Every other
        # deployment effect is performed under the kernel identity of its
        # designated role, after this intent is durable.
        fd = os.open(intent, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        from skillloop.protocol import canonical_json_line
        with os.fdopen(fd,'wb') as stream:
            os.fchown(stream.fileno(),21001,21001)
            stream.write(canonical_json_line({**expected,'digest':digest_jcs(expected)}))
            stream.flush();os.fsync(stream.fileno())
        directory_fd = os.open(journal,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
    _reserve_admin_producer(launch,whole)
    _admin_produce(launch['policy_path'])
    os.setgroups(sorted({21001,launch['engine_socket_gid']}))
    os.setgid(21001)
    os.setuid(21001)
    from skillloop.repair.budget import SpendingLedger
    ledger = SpendingLedger(Path(launch['ledger_path']),
        victim_seconds=launch['victim_seconds'],
        campaign_started_at=launch['campaign_started_at'])
    state = ledger.read()
    if (state.get('whole_round_binding') != {'manifest_digest':whole['digest'],
                                             'campaign':launch['campaign_digest']}
            or state.get('campaign_started_at') != launch['campaign_started_at']):
        raise ValueError('bootstrap_original_whole_cost_reservation_required')
    engine = DockerEngine('/engine.sock')
    deployment = WholeRoleDeployment(manifest_path=launch['manifest_path'],
        journal_directory=launch['deployment_journal_directory'], engine=engine,ledger=ledger,
        whole_round_manifest_path=launch['whole_round_manifest_path'])
    if (deployment.plan['engine_socket_gid'] != launch['engine_socket_gid']
            or deployment.plan['campaign_digest'] != launch['campaign_digest']):
        raise ValueError('bootstrap_original_engine_and_campaign_identity')
    operator=[d['value'] for d in deployment.plan['documents']
        if d['value'].get('kind')=='OperatorServiceDeployment']
    if len(operator)!=1 or operator[0].get('socket')!=launch['operator_socket']:
        raise ValueError('bootstrap_actual_operator_socket_policy')
    deployment.provision()
    proxy = deployment.start_role('proxy','pre-operator-proxy')
    controller = deployment.start_role('controller','pre-operator-controller')
    for role,record in (('proxy',proxy),('controller',controller)):
        actual = engine.inspect(record['inspection']['Id'])
        if actual.get('State',{}).get('Running') is not True:
            raise RuntimeError('bootstrap_original_'+role+'_not_live_preserve_resources')
    endpoint = Path(launch['operator_socket'])
    if endpoint.is_symlink():raise PermissionError('bootstrap_operator_socket_symlink')
    socket_deadline=time.monotonic()+30
    while not endpoint.exists() and time.monotonic()<socket_deadline:
        actual=engine.inspect(controller['inspection']['Id'])
        if actual.get('State',{}).get('Running') is not True:
            raise RuntimeError('bootstrap_original_controller_exited_preserve_resources')
        time.sleep(0.1)
    info = endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 21001:
        raise PermissionError('bootstrap_operator_socket_actual_controller')
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as client:
        client.settimeout(3)
        client.connect(str(endpoint))
        import struct
        peer = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if peer[1] != 21001:raise PermissionError('bootstrap_original_controller_peer')
    completion={
        'kind':'PreOperatorBootstrapCompletion','launch_digest':launch['digest'],
        'deployment_digest':deployment.plan['digest'],'proxy_id':proxy['inspection']['Id'],
        'controller_id':controller['inspection']['Id'],'operator_socket':str(endpoint),
        'qualification_issued':False}
    completed=journal/'pre-operator-complete.json'
    if completed.exists():
        from skillloop.runtime.protected_flow import _controller_record
        if _controller_record(completed)!={**completion,'digest':digest_jcs(completion)}:
            raise ValueError('bootstrap_original_completion_changed')
    else:_save(journal,completed.name,completion)


if __name__ == '__main__':main()
