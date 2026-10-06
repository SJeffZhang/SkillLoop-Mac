"""Protected Evaluator creates one fresh private epoch after real Gate freeze.

Only an opaque commitment is handed to the Controller. Complete inputs, canary,
mutations and the random seed never enter a development or public projection.
This entry does not start a backend or release any private session to a Runtime.
"""
import base64
from datetime import datetime,timezone
import os
from pathlib import Path
import secrets
import stat

from scripts.spec_v22_core import validate_plan
from scripts.spec_v22_families import generate_private_suite,validate_private_suite
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protocol import canonical_json_line,digest_bytes,digest_jcs
from skillloop.protection.authority import ProtectionAuthority
from skillloop.protection.suite import compile_private,protected_plan
from skillloop.proxy.qualification_authority import current_authority
from skillloop.proxy.wire import make_control
from skillloop.runtime.gateway import ExactLocalTokenizer
from skillloop.runtime.round_manifest import read_round_manifest


def _encoded(value):
    if type(value) is bytes:return {'base64_bytes':base64.b64encode(value).decode()}
    if type(value) is dict:return {k:_encoded(v) for k,v in value.items()}
    if type(value) is list:return [_encoded(v) for v in value]
    if value is None or type(value) in {str,int,bool}:return value
    raise ValueError('private_factory_value_shape')


def _save(path,value,*,group=None):
    raw=canonical_json_line(value)
    if len(raw)>16777216:raise ValueError('private_factory_storage_capacity')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        if group is not None:os.fchown(stream.fileno(),-1,group);os.fchmod(stream.fileno(),0o640)
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def create_private_epoch(*,assignment_path,whole_round_manifest_path,tokenizer_path,
                         authority_directory,private_directory,projection_directory):
    if os.geteuid()!=21004 or 21001 not in set(os.getgroups())|{os.getegid()}:
        raise PermissionError('private_factory_actual_evaluator_role')
    job=read_owned(assignment_path,uid=21001,gid=21004,limit=8388608)
    fields={'kind','campaign_id','config','whole_round_manifest_digest','gate_freeze_path','gate_freeze_digest',
            'development','development_plan','factory_profile_digest','approval_digests',
            'trust_revision','deadline','digest'}
    if (set(job)!=fields or job['kind']!='FormalPrivateFactoryAssignment'
            or type(job['approval_digests']) is not list or not job['approval_digests']
            or len(job['approval_digests'])!=len(set(job['approval_digests']))
            or type(job['trust_revision']) is not int or job['trust_revision']<1):
        raise ValueError('private_factory_assignment')
    whole=read_round_manifest(whole_round_manifest_path)
    scope=next((c for c in whole['campaigns'] if c['campaign_digest']==job['campaign_id']),None)
    config=job['config'];config_digest=digest_jcs(config)
    deadline=datetime.fromisoformat(job['deadline'].replace('Z','+00:00'))
    if (scope is None or whole['digest']!=job['whole_round_manifest_digest']
            or deadline.tzinfo is None or not 120<(deadline-datetime.now(timezone.utc)).total_seconds()<=28800
            or config.get('whole_flow_required') is not True
            or config.get('deployment_epoch')!=whole['deployment_epoch']):
        raise ValueError('private_factory_original_round_identity')
    from skillloop.runtime.whole_source import whole_source_index
    source=Path(__file__).resolve().parents[2]
    if digest_jcs(whole_source_index(source))!=whole['source_digest']:
        raise ValueError('private_factory_actual_source_changed')
    factory_raw=(source/'specs/v2.2/families/private-suite-factory.json').read_bytes()
    if digest_bytes(factory_raw)!=job['factory_profile_digest']:
        raise ValueError('private_factory_exact_approved_rule')
    if job['gate_freeze_path']!='/roster/freeze.json':
        raise ValueError('private_factory_fixed_roster_path')
    freeze=read_owned(job['gate_freeze_path'],uid=21005,gid=21001,limit=262144)
    if (freeze.get('kind')!='FrozenCampaignSubjectRoster'
            or freeze['digest']!=job['gate_freeze_digest']
            or freeze.get('campaign_id')!=job['campaign_id']
            or freeze.get('deployment_epoch')!=whole['deployment_epoch']
            or freeze.get('config_digest')!=config_digest
            or freeze.get('trust_revision')!=job['trust_revision']
            or freeze.get('deadline')!=job['deadline']
            or freeze.get('protected_evaluation')!='not_started'
            or freeze.get('development_plan_digest')!=job['development_plan']['digest']
            or type(freeze.get('subjects')) is not dict or 'submitted' not in freeze['subjects']
            or set(freeze['subjects'])-{'submitted','finalist','active'}):
        raise ValueError('private_factory_actual_finalist_freeze')
    development=job['development'];validate_plan(job['development_plan'],development['suite'])
    if (development.get('profile_id')!=scope['profile']
            or development['suite']['body']['visibility']!='public_dev'
            or job['development_plan']['body']['campaign_id']!=job['campaign_id']
            or job['development_plan']['body']['config_digest']!=config_digest
            or job['development_plan']['body']['phase']!='dev'):
        raise ValueError('private_factory_development_identity')
    private=Path(private_directory);info=private.lstat()
    if (not private.is_absolute() or private.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21004 or info.st_gid!=21004 or stat.S_IMODE(info.st_mode)!=0o700):
        raise PermissionError('private_factory_private_bundle_store')
    projection=Path(projection_directory);info=projection.lstat()
    if (not projection.is_absolute() or projection.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid!=21004 or info.st_gid!=21001 or stat.S_IMODE(info.st_mode)!=0o750):
        raise PermissionError('private_factory_controller_metadata_projection')
    authority=ProtectionAuthority(private/'epoch-authority')
    intent={'kind':'PrivateFactoryGenerationIntent','assignment_digest':job['digest'],
        'whole_round_manifest_digest':whole['digest'],'deadline':job['deadline'],
        'automatic_regeneration_allowed':False}
    intent['digest']=digest_jcs(intent)
    # Even failure after CSPRNG generation is retained. Restart does not redraw
    # a seed or replace an already-created epoch under the same campaign.
    _save(private/(job['campaign_id'][7:]+'.generation-intent.json'),intent)
    with current_authority(authority_directory,epoch=whole['deployment_epoch'],config_digest=config_digest,
            trust_revision=job['trust_revision'],approval_digests=set(job['approval_digests']),campaign=job['campaign_id']) as live:
        heads=[row for row in live.get('plan_heads',[]) if row['campaign_id']==job['campaign_id']]
        if len(heads)!=1 or heads[0]['plan_digest']!=freeze['development_plan_digest']:
            raise ValueError('private_factory_actual_frozen_development_head')
        factory_refs={row['current_factory_ref'] for row in live['approvals']
                      if row['approval_digest'] in set(job['approval_digests'])}
        if len(factory_refs)!=1:raise ValueError('private_factory_effective_approval_identity')
        factory_approval_ref=next(iter(factory_refs))
        epochs,projections,payloads=authority.used()
        if type(development.get('mutations')) is not dict:raise ValueError('private_factory_dev_payload_index')
        if type(development.get('cases')) is not dict:raise ValueError('private_factory_dev_case_index')
        projections=projections+[case['body']['business_projection_digest']
            for case in development['cases'].values()]
        payloads=payloads+[m['body']['payload_bytes_digest'] for m in development['mutations'].values()]
        generated=generate_private_suite(scope['profile'],os.urandom(32))
        validation=validate_private_suite(generated,epochs,projections,payloads)
        if generated['epoch_id']==development['suite']['body'].get('epoch_id'):
            raise ValueError('private_factory_fresh_epoch_required')
        tokenizer=ExactLocalTokenizer(tokenizer_path,expected_hashes=config['tokenizer_hashes'])
        try:compiled=compile_private(generated,tokenizer,development)
        finally:tokenizer.close()
        # Full private plans are produced and committed inside this role.
        # They are never handed to Controller to build protected task entries.
        private_plan=protected_plan(compiled,
            {role:{'subject_digest':subject} for role,subject in freeze['subjects'].items()},
            job['campaign_id'],config,parent=job['development_plan'],
            runtime_profile_path=source/'specs/mac/runtime-profile.json')
        if private_plan['body']['reserved_rollouts']>scope['reserved_victim_attempts']:
            raise ValueError('private_factory_original_complete_victim_reservation')
        opaque='protected-'+secrets.token_hex(16)
        epoch_record=make_control('EpochRecord',{'campaign_digest':job['campaign_id'],
            'epoch_id':validation['epoch_id'],'factory_profile_digest':job['factory_profile_digest'],
            'private_suite_digest':compiled['suite']['digest'],
            'created_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),'sealed':True})
        private_record={'kind':'FormalPrivateFactoryBundle','assignment_digest':job['digest'],
            'campaign_id':job['campaign_id'],'whole_round_manifest_digest':whole['digest'],
            'deployment_epoch':whole['deployment_epoch'],'config_digest':config_digest,'config':config,
            'source_index_digest':whole['source_digest'],
            'development_suite_epoch_id':development['suite']['body'].get('epoch_id'),
            'deadline':job['deadline'],
            'freeze_digest':freeze['digest'],'subjects':freeze['subjects'],'factory_profile_digest':job['factory_profile_digest'],
            'trust_revision':job['trust_revision'],'approval_digests':job['approval_digests'],
            'development_plan_digest':freeze['development_plan_digest'],
            'factory_approval_ref':factory_approval_ref,
            'bundle':_encoded(generated),'compiled':compiled,'private_plan':private_plan,
            'validation':validation,'opaque_ref':opaque,
            'epoch_record':epoch_record,
            'private_inputs_released':False,'qualification_issued':False}
        private_record['digest']=digest_jcs(private_record)
        serialized=canonical_json_line(private_record)
        if len(serialized)>16777216:raise ValueError('private_factory_bundle_capacity')
        # Store the epoch, all deduplication pins and complete private bundle in
        # one real evaluator-owned SQLite transaction. No metadata-only commit
        # can assert that the full bundle survived a crash.
        with authority.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS formal_private_bundles(campaign TEXT PRIMARY KEY,assignment TEXT UNIQUE NOT NULL,record BLOB NOT NULL)')
            db.execute('BEGIN IMMEDIATE')
            if datetime.now(timezone.utc)>=deadline:raise TimeoutError('private_factory_original_clock_expired')
            db.execute('INSERT INTO epochs VALUES(?,?,?,?,?,?)',(job['campaign_id'],freeze['subjects'].get('finalist',freeze['subjects']['submitted']),
                validation['epoch_id'],validation['business_projection_digest'],opaque,job['factory_profile_digest']))
            db.executemany('INSERT INTO payloads VALUES(?,?)',[(d,validation['epoch_id']) for d in validation['payload_digests']])
            db.execute('INSERT INTO formal_private_bundles VALUES(?,?,?)',(job['campaign_id'],job['digest'],serialized))
        # Frozen visibility allows only the opaque aggregate outside Eval/Gate.
        result={'kind':'FormalPrivateFactoryCommit','campaign_public_ref':job['campaign_id'],
            'opaque_ref':opaque,'aggregate_status':'sealed'}
        result['digest']=digest_jcs(result)
        _save(projection/(job['digest'][7:]+'.json'),result,group=21001)
        # A frozen caller can locate this opaque commitment without knowing
        # the future roster-derived assignment digest. Ordinary independent
        # files preserve the original seal and one-link custody requirement.
        # The epoch is already committed: partial publication never regenerates.
        _save(projection/'commit.json',result,group=21001)
        return result


def main():
    os.umask(0o077)
    try:
        create_private_epoch(assignment_path='/assignment/job.json',whole_round_manifest_path='/whole-round/manifest.json',
            tokenizer_path='/model',authority_directory='/authority-projection',private_directory='/private',
            projection_directory='/factory-projection')
    except BaseException as error:
        # Docker logs are deliberately unavailable to Controller. Keep the
        # actual failure in the private role's evidence rather than losing it.
        import traceback
        try:
            private=Path('/private');info=private.lstat()
            if (os.geteuid()==21004 and info.st_uid==21004 and info.st_gid==21004
                    and stat.S_IMODE(info.st_mode)==0o700 and not private.is_symlink()):
                value={'kind':'PrivateFactoryExecutionFailure','error_type':type(error).__name__,
                    'private_traceback':traceback.format_exc(),'automatic_regeneration_allowed':False}
                value['digest']=digest_jcs(value)
                _save(private/'factory-execution-failure.json',value)
        except BaseException as custody_error:
            error.add_note('private_failure_evidence_preservation_error:'+type(custody_error).__name__)
        raise


if __name__=='__main__':main()
