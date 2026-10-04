"""Proxy-owned source/approval history export through an Admin file handoff.

The projection excludes task resources and private execution rows. Original
source grants (including package bytes), approval objects and Admin operation
history come from one authoritative transaction, not caller-provided facts.
"""
from datetime import datetime,timezone
import os
from pathlib import Path
import re
import time
from skillloop.discovery.formal_task_gate import read_owned
from skillloop.protection.current_task import _directory,_publish
from skillloop.protocol import canonical_json_line,decode_json,digest_jcs


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
            self.export(request);self.seen.add(name);return

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
                value={'kind':'ProxyCampaignSourceAuthoritySnapshot','producer_uid':21003,'reader_gid':21005,
                    'request_digest':request['digest'],'campaign':campaign,'deployment_epoch':identity[0],
                    'config_digest':request['config_digest'],'trust_revision':identity[1],
                    'sources':sources,'approvals':history,'approval_objects':objects,
                    'admin_operations':[{'operation':r[0],'method':r[1],'request_digest':r[2],'result':decode_json(r[3])} for r in operations],
                    'approval_revocations':[{'operation':r[0],'request_digest':r[1],'result':decode_json(r[2])} for r in revocations],
                    'authority_events':[dict(zip(('event_id','event_type','event_digest','committed_at'),r)) for r in events],
                    'catalog':[{'category':key[0],'digest':key[1],'value':decode_json(raw)} for key,raw in sorted(self.authority.catalog.items())],
                    'plan_head':list(head) if head else None,
                    'plan_revisions':[{'authorization':decode_json(r[0]),'receipt':decode_json(r[1])} for r in revisions],
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


def verify_source_history(value,*,campaign,epoch,config_digest,trust_revision):
    """Gate reconstructs package/subject and approval bindings from the export."""
    import base64
    from skillloop.loader import ApprovedPackageLoader,validate_source_admission
    from skillloop.protocol import validate_envelope
    from skillloop.families.registry import FamilyRegistry
    if (value.get('kind')!='ProxyCampaignSourceAuthoritySnapshot' or value.get('producer_uid')!=21003
            or value.get('reader_gid')!=21005 or value.get('campaign')!=campaign
            or value.get('deployment_epoch')!=epoch or value.get('config_digest')!=config_digest
            or value.get('trust_revision')!=trust_revision or value.get('task_resources_disclosed') is not False):
        raise ValueError('archive_source_authority_identity')
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
