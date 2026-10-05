"""Controller dispatch of the actual discovery-to-Suite Gate, never inference."""
import os
from pathlib import Path,PurePosixPath
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import digest_jcs
from skillloop.runtime.whole_deployment import WholeRoleDeployment
from skillloop.runtime.campaign_auxiliary import begin_auxiliary,observe_auxiliary,finish_auxiliary,preserve_auxiliary_failure
from skillloop.runtime.proposal_dispatch import _save


def verify_suite_locators(plan,step,config):
    """Both views must name the same original volume bytes, including overlays."""
    controller=plan['roles']['controller']['config']['HostConfig']['Mounts']
    worker=config['HostConfig']['Mounts']
    for target,path,readonly,uid,gid in (
            ('/assignment',step['assignment_directory'],True,21001,21005),
            ('/suite',str(Path(step['result_path']).parent),False,21005,21001)):
        canonical=PurePosixPath(path)
        if not canonical.is_absolute() or str(canonical)!=path or '..' in canonical.parts:
            raise ValueError('discovery_dispatch_canonical_locator')
        candidates=[m for m in controller if canonical.is_relative_to(PurePosixPath(m['Target']))]
        if not candidates:raise ValueError('discovery_dispatch_controller_alias_required')
        alias=max(candidates,key=lambda m:len(PurePosixPath(m['Target']).parts))
        if alias.get('Type')!='volume' or alias.get('Source')!=plan['volume']:
            raise PermissionError('discovery_dispatch_original_deployment_volume')
        sub=str(PurePosixPath(alias['VolumeOptions']['Subpath'])/canonical.relative_to(alias['Target']))
        declared=next((d for d in plan['directories'] if d['path']==sub),None)
        mounts=[m for m in worker if m.get('Target')==target]
        if (declared is None or (declared['uid'],declared['gid'],declared['mode'])!=(uid,gid,0o750)
                or len(mounts)!=1 or mounts[0].get('Type')!='volume'
                or mounts[0].get('Source')!=plan['volume'] or mounts[0].get('ReadOnly') is not readonly
                or mounts[0].get('VolumeOptions',{}).get('Subpath')!=sub):
            raise PermissionError('discovery_dispatch_same_actual_declared_custody')
    if ('SKILLLOOP_RAW_HISTORY_MAX_BYTES='+str(step['maximum_evidence_bytes'])) not in config['Env']:
        raise ValueError('discovery_dispatch_original_raw_history_capacity')
    if Path(step['result_path']).name!='compiled.json':raise ValueError('discovery_dispatch_fixed_output')


def dispatch_discovery_suite(*,step,operation_id,whole_round_manifest_path,ledger,engine,registry,campaign):
    if os.geteuid()!=21001:raise PermissionError('discovery_dispatch_actual_controller')
    deployment=WholeRoleDeployment(manifest_path=step['manifest_path'],journal_directory=step['deployment_journal'],
        engine=engine,ledger=ledger,whole_round_manifest_path=whole_round_manifest_path)
    module='skillloop.discovery.formal_suite_gate';config=deployment.role_config('gate',module)
    verify_suite_locators(deployment.plan,step,config)
    job=read_owned(Path(step['assignment_directory'])/'job.json',uid=21001,gid=21005,limit=8388608)
    process='discovery-suite-'+digest_jcs({'operation':operation_id,'job':job['digest']})[7:]
    if (job.get('kind')!='FormalDiscoverySuiteAssignment' or job.get('campaign_id')!=campaign
            or job.get('deadline')!=deployment.plan['deadline']
            or job.get('whole_round_manifest_digest')!=deployment.whole['digest']):
        raise ValueError('discovery_dispatch_original_campaign_assignment')
    with registry.development_scope(campaign=campaign) as admitted:
        if digest_jcs(job['config'])!=admitted['bindings']['config_digest']:
            raise ValueError('discovery_dispatch_original_config')
        begin_auxiliary(step,deployment.deadline,21005,config)
        cost=ledger.consume_auxiliary(manifest=deployment.whole,campaign=campaign,stage='import_scan',
            operation_key='discovery-suite-'+job['digest'][7:],seconds=step['timeout_seconds']+step['closure_seconds'],
            input_tokens=0,output_tokens=0,disk_bytes=step['maximum_evidence_bytes'])
        _save(Path(step['journal_directory']),'spending.json',{'kind':'FormalDiscoverySuiteSpending','spending':cost})
        try:
            observed=deployment.start_role('gate',process,module=module);observe_auxiliary(step,observed['inspection'])
            identifier=observed['inspection']['Id'];wait=engine.wait(identifier,step['timeout_seconds'])
            actual=engine.inspect(identifier)
            if wait.get('StatusCode')!=0 or actual['State']['Running'] or actual['State']['ExitCode']!=0:
                raise RuntimeError('discovery_dispatch_original_gate_incomplete')
            result=read_owned(step['result_path'],uid=21005,gid=21001,limit=8388608)
            if (result.get('kind')!='GateProducedDevelopmentSuite' or result.get('assignment_digest')!=job['digest']
                    or result.get('campaign_id')!=campaign or result.get('config_digest')!=digest_jcs(job['config'])
                    or result.get('qualification_issued') is not False):
                raise ValueError('discovery_dispatch_actual_gate_output_binding')
            return finish_auxiliary(step,actual,result,engine.inspect(deployment.provision()['keeper']['Id']),engine)
        except BaseException as error:
            if not (Path(step['journal_directory'])/'created.json').exists():
                try:deployment.preserve_failed_role('gate',process,module=module,closure_seconds=step['closure_seconds'])
                except BaseException as secondary:error.add_note('discovery_unknown_create_preservation:'+type(secondary).__name__)
            try:preserve_auxiliary_failure(step,engine,error)
            except BaseException as secondary:error.add_note('discovery_original_evidence_preservation:'+type(secondary).__name__)
            raise
