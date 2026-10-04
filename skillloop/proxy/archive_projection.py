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
                identity=db.execute('SELECT deployment_epoch,trust_revision FROM trust_state WHERE singleton=1').fetchone()
                head=db.execute('SELECT plan,revision_digest FROM controller_plan_heads WHERE campaign=?',(campaign,)).fetchone()
                revisions=db.execute('SELECT authorization,receipt FROM controller_plan_revisions WHERE campaign=? ORDER BY digest',(campaign,)).fetchall()
                value={'kind':'ProxyCampaignSourceAuthoritySnapshot','producer_uid':21003,'reader_gid':21005,
                    'request_digest':request['digest'],'campaign':campaign,'deployment_epoch':identity[0],
                    'config_digest':request['config_digest'],'trust_revision':identity[1],
                    'sources':sources,'approvals':history,'approval_objects':objects,
                    'admin_operations':[{'operation':r[0],'method':r[1],'request_digest':r[2],'result':decode_json(r[3])} for r in operations],
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
