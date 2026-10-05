"""Actual Admin/Reporter command worker under a sealed Controller delegation."""
import os
from pathlib import Path
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import canonical_json_line
from skillloop.runtime.client import ProxyClient

ADMIN_PROXY_COMMANDS={'approve-domain':'approve_domain','approve-factory':'approve_factory',
    'review-finding':'review_finding','retire-history':'retire_history'}


def main():
    os.umask(0o077);uid=os.geteuid()
    if uid not in {21009,21010}:raise PermissionError('role_command_actual_identity')
    job=read_owned('/assignment/job.json',uid=21001,gid=uid,limit=262144)
    if set(job)!={'kind','command','operation_id','params','digest'} or job['kind']!='DelegatedRoleCommand':
        raise ValueError('role_command_sealed_assignment')
    if uid==21009:
        if job['command']!='report':raise PermissionError('reporter_only_public_projection')
        if set(job['params'])!={'campaign'}:raise ValueError('reporter_current_campaign_only')
        campaign=job['params']['campaign']
        import re
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',campaign):raise ValueError('reporter_campaign_identity')
        from skillloop.proxy.wire import validate_control
        result=read_owned(Path('/campaign-reports')/(campaign[7:]+'.json'),uid=21005,gid=21001,limit=2097152)
        validate_control(result)
        if result['kind']!='PublicReport' or result['body']['campaign_public_ref']!=campaign:
            raise ValueError('reporter_actual_gate_public_projection')
    elif job['command']=='import-lifecycle':
        from skillloop.protection.native_lifecycle_import import import_lifecycle
        if set(job['params'])!={'assignment_path'}:raise ValueError('lifecycle_import_delegation')
        result=import_lifecycle(job['params']['assignment_path'])
    elif job['command']=='produce-deployment':
        from skillloop.runtime.whole_deployment_producer import produce_deployment
        if set(job['params'])!={'assignment_path'}:raise ValueError('deployment_production_delegation')
        result=produce_deployment(job['params']['assignment_path'])
    elif job['command']=='produce-candidate':
        from skillloop.repair.candidate_source import produce_candidate
        if set(job['params'])!={'assignment_path'}:raise ValueError('candidate_production_delegation')
        result=produce_candidate(job['params']['assignment_path'])
    elif job['command']=='produce-plan':
        from skillloop.discovery.plan_production import produce_plan_revision
        if set(job['params'])!={'assignment_path'}:raise ValueError('plan_production_delegation')
        result=produce_plan_revision(job['params']['assignment_path'])
    else:
        # Archive actions use the actual encrypted role dispatch chain. The
        # business Proxy has no export/archive/restore implementation to call.
        method=ADMIN_PROXY_COMMANDS.get(job['command'])
        if method is None:raise PermissionError('admin_delegation_method_not_allowed')
        result=ProxyClient(Path('/proxy-sockets'),expected_server_uid=21003).control_request(
            method,job['params'],operation_id=job['operation_id'],admin=True)
    from skillloop.protection.current_task import _directory,_publish
    output=_directory('/result',uid,21001,0o750)
    # Public API objects already contain their own strict wire seal. Preserve
    # their bytes instead of wrapping a successful process as a business result.
    fd=os.open(output/'result.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'wb') as stream:
        os.fchown(stream.fileno(),-1,21001);os.fchmod(stream.fileno(),0o640)
        stream.write(canonical_json_line(result));stream.flush();os.fsync(stream.fileno())
    fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


if __name__=='__main__':main()
