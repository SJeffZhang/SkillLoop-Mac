"""Proxy-owned source/approval history export through an Admin file handoff.

The projection excludes task resources and private execution rows. Original
source grants (including package bytes), approval objects and Admin operation
history come from one authoritative transaction, not caller-provided facts.
"""
from datetime import datetime,timezone
from contextlib import closing
import os
from pathlib import Path
import re
import time
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory,_publish
from skillloop.protocol import canonical_json_line,decode_json,digest_jcs


def development_inference_history(db,*,campaign,epoch,config_digest,budget):
    """Read all original reservations, including unanswered ones, in this tx.

    Only public development request metadata is exported to Gate. Protected
    runs and task resources never enter this source-history projection.
    """
    tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'runtime_inference_attempts' not in tables:
        raise ValueError('source_archive_actual_inference_authority_missing')
    rows=db.execute('SELECT run_id,round_index,request_digest,reservation_json,response_digest,raw_response_digest,completed_at '
        'FROM runtime_inference_attempts ORDER BY run_id,round_index LIMIT 6145').fetchall()
    if len(rows)>6144:raise ValueError('source_archive_original_inference_history_capacity')
    runtime=[];proposals=[]
    for run,ordinal,request_digest,raw,response,raw_response,completed in rows:
        budget();reserved=decode_json(raw);request=reserved['request']
        if request['campaign_id']!=campaign or request['phase']!='dev':continue
        if (reserved.get('kind')!='ProxyRuntimeInferenceReserved'
                or reserved.get('digest')!=digest_jcs({k:v for k,v in reserved.items() if k!='digest'})
                or request['digest']!=digest_jcs({k:v for k,v in request.items() if k!='digest'})
                or request['digest']!=request_digest or request['run_id']!=run or request['round_index']!=ordinal
                or request['deployment_epoch']!=epoch or request['config_digest']!=config_digest):
            raise ValueError('source_archive_actual_runtime_reservation_binding')
        runtime.append({'run_id':run,'round_index':ordinal,'request_digest':request_digest,'reservation':reserved,
            'response_digest':response,'raw_response_digest':raw_response,'completed_at':completed,
            'status':'unknown' if response is None else 'recorded','redispatch_allowed':False})
    if 'proposal_inference_attempts' in tables:
        rows=db.execute('SELECT grant_digest,request_digest,role_uid,reservation_json,response_digest,raw_response_digest,completed_at '
            'FROM proposal_inference_attempts WHERE campaign=? ORDER BY grant_digest LIMIT 129',(campaign,)).fetchall()
        if len(rows)>128:raise ValueError('source_archive_original_proposal_history_capacity')
        for grant_digest,request_digest,uid,raw,response,raw_response,completed in rows:
            budget();reserved=decode_json(raw);request=reserved['request'];grant=request['grant']
            if (reserved.get('kind')!='ProxyProposalInferenceReserved'
                    or reserved.get('digest')!=digest_jcs({k:v for k,v in reserved.items() if k!='digest'})
                    or request['digest']!=digest_jcs({k:v for k,v in request.items() if k!='digest'})
                    or grant['digest']!=digest_jcs({k:v for k,v in grant.items() if k!='digest'})
                    or request['digest']!=request_digest or grant['digest']!=grant_digest
                    or grant['role_uid']!=uid or grant['campaign_id']!=campaign
                    or grant['deployment_epoch']!=epoch or grant['config_digest']!=config_digest):
                raise ValueError('source_archive_actual_proposal_reservation_binding')
            proposals.append({'grant_digest':grant_digest,'request_digest':request_digest,'role_uid':uid,'reservation':reserved,
                'response_digest':response,'raw_response_digest':raw_response,'completed_at':completed,
                'status':'unknown' if response is None else 'recorded','redispatch_allowed':False})
    value={'kind':'ProxyDevelopmentInferenceHistory','campaign':campaign,'deployment_epoch':epoch,
        'config_digest':config_digest,'runtime_attempts':runtime,'proposal_attempts':proposals,
        'unknown_count':sum(row['status']=='unknown' for row in runtime+proposals),
        'catalog_scope':'runtime_dev_and_generator_patcher_reservations',
        'all_development_attempt_history_complete':False,'private_resources_disclosed':False}
    value['digest']=digest_jcs(value)
    return value


class SourceArchiveInbox:
    def __init__(self,*,store,admission,authority,directory):
        if os.geteuid()!=21003 or 21005 not in set(os.getgroups())|{os.getegid()}:
            raise PermissionError('source_archive_actual_proxy_with_gate_group')
        self.store,self.admission,self.authority=store,admission,authority
        self.directory=_directory(directory,21010,21003,0o750);self.seen=set()
        with store._transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS campaign_archive_projections(request TEXT PRIMARY KEY,campaign TEXT NOT NULL,projection BLOB NOT NULL)')

    def poll(self):
        names=[]
        with os.scandir(self.directory) as entries:
            for entry in entries:
                if not re.fullmatch(r'[0-9a-f]{64}\.json',entry.name):raise ValueError('source_archive_request_filename')
                names.append(entry.name)
                if len(names)>3:raise ValueError('source_archive_one_request_per_campaign')
        for name in sorted(names):
            if name in self.seen:continue
            request=read_owned(self.directory/name,uid=21010,gid=21003,limit=262144)
            if request['digest']!='sha256:'+name[:-5]:raise ValueError('source_archive_request_digest')
            if self.export(request) is not None:self.seen.add(name)
            return

    def export(self,request):
        fields={'kind','deployment_epoch','deployment_digest','campaign','config_digest',
            'deadline','timeout_seconds','maximum_bytes','output_directory','digest'}
        if (set(request)!=fields or request['kind']!='AdminSourceArchiveProjection'
                or request['deployment_epoch']!=self.store.deployment_epoch
                or type(request['timeout_seconds']) is not int or not 1<=request['timeout_seconds']<=30
                or type(request['maximum_bytes']) is not int or not 1<=request['maximum_bytes']<=16777216):
            raise ValueError('source_archive_original_request')
        campaign=request['campaign'];pins=self.admission.campaigns.get(campaign)
        if pins is None or pins['config_digest']!=request['config_digest']:raise ValueError('source_archive_registered_campaign')
        output=_directory(request['output_directory'],21003,21005,0o750)
        target=output/'source-authority.json';started=time.monotonic()
        deadline=datetime.fromisoformat(request['deadline'].replace('Z','+00:00'))
        def budget():
            if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline or time.monotonic()-started>=request['timeout_seconds']:
                raise TimeoutError('source_archive_original_budget')
        budget()
        # A request can be provisioned before development has finished. Wait
        # for the actual Proxy private-plan fence, which forbids further source
        # admission, rather than exporting the first partial candidate roster.
        with closing(self.store._connect()) as check:
            frozen=check.execute('SELECT protected_plan FROM evaluator_protected_campaigns WHERE campaign=?',(campaign,)).fetchone()
        if frozen is None:return None
        # Persist the original projection before publication. Restart may
        # republish these exact bytes; it cannot take a newer authority view.
        with self.store._transaction() as db:
            db.set_progress_handler(lambda: (budget() or 0),1000)
            deployment=db.execute('SELECT digest,deadline FROM formal_proxy_deployment WHERE singleton=1').fetchone()
            if deployment is None or tuple(deployment)!=(request['deployment_digest'],request['deadline']):
                raise ValueError('source_archive_actual_deployment_binding')
            prior=db.execute('SELECT projection FROM campaign_archive_projections WHERE request=?',(request['digest'],)).fetchone()
            if prior is not None:value=decode_json(prior[0])
            else:
                if db.execute('SELECT 1 FROM campaign_archive_projections WHERE campaign=?',(campaign,)).fetchone():
                    raise ValueError('source_archive_original_projection_already_frozen')
                source_rows=db.execute('SELECT subject,admission_digest,source_pins,authorization FROM controller_source_admissions WHERE campaign=? ORDER BY subject',(campaign,)).fetchall()
                if not 1<=len(source_rows)<=4:raise ValueError('source_archive_complete_source_grants')
                sources=[{'subject':r[0],'admission_digest':r[1],'pins':decode_json(r[2]),'authorization':decode_json(r[3])} for r in source_rows]
                approvals=db.execute('SELECT a.approval_digest,a.domain_digest,a.domain_json,a.state,a.expires_at,a.trust_revision,a.committed_at,i.factory_approval_ref FROM approvals a JOIN issued_domain_approvals i ON i.approval_ref=a.approval_digest WHERE i.config_digest=? ORDER BY a.approval_digest LIMIT 1025',(request['config_digest'],)).fetchall()
                if not approvals or len(approvals)>1024:raise ValueError('source_archive_approval_history_capacity')
                history=[dict(zip(('approval_digest','domain_digest','domain','state','expires_at','trust_revision','committed_at','factory_approval_ref'),
                    [r[0],r[1],decode_json(r[2]),*r[3:]])) for r in approvals]
                refs={r['approval_digest'] for r in history}
                objects=[]
                for ref in sorted(refs):
                    budget();row=db.execute('SELECT raw_json FROM staged_objects WHERE digest=?',(ref,)).fetchone()
                    if row is None:raise ValueError('source_archive_original_approval_object_missing')
                    objects.append(decode_json(row[0]))
                operations=db.execute("SELECT operation_id,method,request_digest,result_json FROM operations WHERE role='admin' ORDER BY operation_id LIMIT 1025").fetchall()
                if len(operations)>1024 or any(r[3] is None for r in operations):raise ValueError('source_archive_admin_operation_capacity_or_unknown')
                factory_refs={r['factory_approval_ref'] for r in history}
                if not factory_refs<={decode_json(r[3])['body'].get('approval_ref') for r in operations}:
                    raise ValueError('source_archive_original_factory_approval_history_missing')
                revocations=db.execute("SELECT operation_id,request_digest,result_json FROM operations WHERE role='controller' AND method='revoke_approval' ORDER BY operation_id LIMIT 1025").fetchall()
                events=db.execute('SELECT event_id,event_type,event_digest,committed_at FROM accepted_events WHERE run_id IS NULL ORDER BY event_id LIMIT 2049').fetchall()
                if len(revocations)>1024 or len(events)>2048 or any(r[2] is None for r in revocations):
                    raise ValueError('source_archive_authority_history_capacity_or_unknown')
                identity=db.execute('SELECT deployment_epoch,trust_revision FROM trust_state WHERE singleton=1').fetchone()
                head=db.execute('SELECT plan,revision_digest FROM controller_plan_heads WHERE campaign=?',(campaign,)).fetchone()
                revisions=db.execute('SELECT authorization,receipt FROM controller_plan_revisions WHERE campaign=? ORDER BY digest',(campaign,)).fetchall()
                frozen_plan=db.execute('SELECT protected_plan FROM evaluator_protected_campaigns WHERE campaign=?',(campaign,)).fetchone()
                if frozen_plan is None:raise ValueError('source_archive_original_private_plan_fence_lost')
                inference_history=development_inference_history(db,campaign=campaign,epoch=identity[0],
                    config_digest=request['config_digest'],budget=budget)
                value={'kind':'ProxyCampaignSourceAuthoritySnapshot','producer_uid':21003,'reader_gid':21005,
                    'request_digest':request['digest'],'campaign':campaign,'deployment_epoch':identity[0],
                    'config_digest':request['config_digest'],'trust_revision':identity[1],
                    'protected_plan_digest':frozen_plan[0],'development_source_admission_closed':True,
                    'sources':sources,'approvals':history,'approval_objects':objects,
                    'admin_operations':[{'operation':r[0],'method':r[1],'request_digest':r[2],'result':decode_json(r[3])} for r in operations],
                    'approval_revocations':[{'operation':r[0],'request_digest':r[1],'result':decode_json(r[2])} for r in revocations],
                    'authority_events':[dict(zip(('event_id','event_type','event_digest','committed_at'),r)) for r in events],
                    'catalog':[{'category':key[0],'digest':key[1],'value':decode_json(raw)} for key,raw in sorted(self.authority.catalog.items())],
                    'plan_head':list(head) if head else None,
                    'plan_revisions':[{'authorization':decode_json(r[0]),'receipt':decode_json(r[1])} for r in revisions],
                    'development_inference_history':inference_history,
                    'exported_at':datetime.now(timezone.utc).isoformat(),
                    'task_resources_disclosed':False,'qualification_issued':False}
                value['digest']=digest_jcs(value)
                if len(canonical_json_line(value))>request['maximum_bytes']:raise ValueError('source_archive_original_byte_capacity')
                budget();db.execute('INSERT INTO campaign_archive_projections VALUES(?,?,?)',(request['digest'],campaign,canonical_json_line(value)))
        budget()
        if target.exists():
            if read_owned(target,uid=21003,gid=21005,limit=request['maximum_bytes'])!=value:
                raise ValueError('source_archive_original_publication_conflict')
        else:_publish(target,value,21005)
        return value


def verify_development_inference_history(value,*,campaign,epoch,config_digest):
    fields={'kind','campaign','deployment_epoch','config_digest','runtime_attempts','proposal_attempts',
        'unknown_count','catalog_scope','all_development_attempt_history_complete','private_resources_disclosed','digest'}
    if (type(value) is not dict or set(value)!=fields or value['kind']!='ProxyDevelopmentInferenceHistory'
            or value['digest']!=digest_jcs({k:v for k,v in value.items() if k!='digest'})
            or value['campaign']!=campaign or value['deployment_epoch']!=epoch or value['config_digest']!=config_digest
            or value['catalog_scope']!='runtime_dev_and_generator_patcher_reservations'
            or value['all_development_attempt_history_complete'] is not False
            or value['private_resources_disclosed'] is not False
            or type(value['runtime_attempts']) is not list or len(value['runtime_attempts'])>2048
            or type(value['proposal_attempts']) is not list or len(value['proposal_attempts'])>128):
        raise ValueError('archive_actual_development_inference_history')
    seen=set();rounds={};unknown=0
    for runtime,rows in ((True,value['runtime_attempts']),(False,value['proposal_attempts'])):
        specific={'run_id','round_index'} if runtime else {'grant_digest','role_uid'}
        for row in rows:
            if type(row) is not dict or set(row)!=specific|{'request_digest','reservation','response_digest',
                    'raw_response_digest','completed_at','status','redispatch_allowed'}:
                raise ValueError('archive_development_inference_attempt_shape')
            reserved=row['reservation'];request=reserved['request']
            if (reserved.get('kind')!=('ProxyRuntimeInferenceReserved' if runtime else 'ProxyProposalInferenceReserved')
                    or reserved.get('digest')!=digest_jcs({k:v for k,v in reserved.items() if k!='digest'})
                    or request['digest']!=digest_jcs({k:v for k,v in request.items() if k!='digest'})
                    or reserved['request_digest']!=request['digest'] or request['digest']!=row['request_digest']
                    or row['request_digest'] in seen or row['redispatch_allowed'] is not False):
                raise ValueError('archive_development_inference_original_request')
            seen.add(row['request_digest'])
            binding=request if runtime else request['grant']
            if (binding['campaign_id']!=campaign or binding['deployment_epoch']!=epoch or binding['config_digest']!=config_digest):
                raise ValueError('archive_development_inference_original_scope')
            if runtime:
                if (request['phase']!='dev' or row['run_id']!=request['run_id']
                        or row['round_index']!=request['round_index'] or type(row['round_index']) is not int
                        or not 0<=row['round_index']<16):
                    raise ValueError('archive_development_runtime_phase_and_round')
                rounds.setdefault(row['run_id'],[]).append(row['round_index'])
            elif (binding['digest']!=digest_jcs({k:v for k,v in binding.items() if k!='digest'})
                    or binding['digest']!=row['grant_digest'] or binding['role_uid']!=row['role_uid']
                    or row['role_uid'] not in {21006,21007}):
                raise ValueError('archive_development_proposal_original_grant')
            if row['response_digest'] is None:
                if row['status']!='unknown' or row['raw_response_digest'] is not None or row['completed_at'] is not None:
                    raise ValueError('archive_development_unanswered_attempt_preserved')
                unknown+=1
            elif (row['status']!='recorded' or not re.fullmatch(r'sha256:[0-9a-f]{64}',row['response_digest'])
                    or type(row['raw_response_digest']) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}',row['raw_response_digest'])
                    or type(row['completed_at']) is not str
                    or datetime.fromisoformat(row['completed_at'].replace('Z','+00:00')).tzinfo is None):
                raise ValueError('archive_development_original_response_pins')
    if any(sorted(indices)!=list(range(len(indices))) for indices in rounds.values()) or value['unknown_count']!=unknown:
        raise ValueError('archive_development_attempt_gap_or_unknown_count')
    return value


def verify_source_history(value,*,campaign,epoch,config_digest,trust_revision):
    """Gate reconstructs package/subject and approval bindings from the export."""
    import base64
    from skillloop.loader import ApprovedPackageLoader,validate_source_admission
    from skillloop.protocol import validate_envelope
    from skillloop.families.registry import FamilyRegistry
    if (value.get('kind')!='ProxyCampaignSourceAuthoritySnapshot' or value.get('producer_uid')!=21003
            or value.get('reader_gid')!=21005 or value.get('campaign')!=campaign
            or value.get('deployment_epoch')!=epoch or value.get('config_digest')!=config_digest
            or value.get('trust_revision')!=trust_revision or value.get('task_resources_disclosed') is not False
            or value.get('development_source_admission_closed') is not True):
        raise ValueError('archive_source_authority_identity')
    verify_development_inference_history(value.get('development_inference_history'),
        campaign=campaign,epoch=epoch,config_digest=config_digest)
    sources=value['sources']
    if not 1<=len(sources)<=4 or len({r['subject'] for r in sources})!=len(sources):
        raise ValueError('archive_source_authority_unique_grants')
    result={}
    for row in sources:
        grant=row['authorization'];admission=grant['admission'];subject=row['subject']
        if (grant.get('kind')!='AdminCampaignSourceAdmission' or grant['campaign_id']!=campaign
                or grant['deployment_epoch']!=epoch or grant['subject_digest']!=subject
                or digest_jcs({k:v for k,v in grant.items() if k!='digest'})!=grant.get('digest')
                or digest_jcs(grant['config'])!=config_digest or digest_jcs(admission)!=row['admission_digest']):
            raise ValueError('archive_source_original_admin_grant')
        validate_source_admission(admission,grant['config'],subject)
        package={name:base64.b64decode(raw,validate=True) for name,raw in admission['package_files'].items()}
        manifest=admission['manifest'];profile=manifest['profile_id']
        selected=ApprovedPackageLoader(approved_sources=admission['approved_sources'],
            reference_resource_ids=admission['reference_resource_ids'],
            approved_subjects=admission.get('approved_subjects')).select(admission['source_snapshot'],package,manifest,
                profile_id=profile,family_id=FamilyRegistry().profile(profile)['family_id'])
        pins=row['pins']
        if (selected.subject_digest!=subject or pins['source_snapshot_digest']!=admission['source_snapshot']['digest']
                or pins['skill_manifest_digest']!=digest_jcs(manifest)
                or pins['git_provenance'].get('package_bytes_verified') is not True):
            raise ValueError('archive_source_original_package_bytes')
        result[subject]={'campaign_id':campaign,'subject_digest':subject,
            'source_snapshot_digest':pins['source_snapshot_digest'],'skill_manifest_digest':pins['skill_manifest_digest'],
            'admission_digest':row['admission_digest'],'authorization_digest':grant['digest'],
            'git_provenance':pins['git_provenance']}
    objects={obj['digest']:obj for obj in value['approval_objects']}
    if len(objects)!=len(value['approval_objects']):raise ValueError('archive_approval_duplicate_object')
    for approval in value['approvals']:
        obj=objects.get(approval['approval_digest']);domain=approval['domain']
        if obj is None:raise ValueError('archive_approval_original_record_missing')
        validate_envelope(obj);validate_envelope(domain)
        if (obj['kind']!='ApprovalRecord' or domain['kind']!='AuthorizationDomain'
                or obj['body']['config_digest']!=config_digest
                or obj['body']['authorization_domain_digest']!=domain['digest']
                or domain['digest']!=approval['domain_digest']
                or obj['body']['trust_revision']>approval['trust_revision']
                or approval['state']!='revoked' and obj['body']['trust_revision']!=approval['trust_revision']
                or approval['state'] not in {'active','revoked','staged'}):
            raise ValueError('archive_approval_original_domain_binding')
        if approval['state']=='revoked':
            expected={'approval_digest':approval['approval_digest'],'trust_revision':approval['trust_revision'],'state':'revoked'}
            if (not any(r['result'].get('approval_digest')==approval['approval_digest']
                        and r['result'].get('trust_revision')==approval['trust_revision']
                        and r['result'].get('state')=='revoked'
                        and r['result'].get('committed_at')==approval['committed_at'] for r in value['approval_revocations'])
                    or not any(e['event_type']=='approval_revoked' and e['event_digest']==digest_jcs(expected)
                        and e['committed_at']==approval['committed_at'] for e in value['authority_events'])):
                raise ValueError('archive_original_revocation_history_missing')
    return result
