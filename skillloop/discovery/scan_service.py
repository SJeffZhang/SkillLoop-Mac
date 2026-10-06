"""Formal scan entry: exact Git source, pinned offline OCI and durable operations.

The trusted operator provisions the deployment file and approved Git locators.
Packages cannot choose a repository, image, executable, mount or network policy.
This service does not qualify a subject; incomplete analyzer coverage stays so.
"""
from contextlib import closing
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import time
import uuid
import io
import tarfile
from pathlib import PurePosixPath
from urllib.parse import quote
from datetime import datetime, timezone

from skillloop.protocol import canonical_json_line, decode_json, digest_bytes, digest_jcs, validate_envelope
from skillloop.source import import_git_package
from skillloop.families.fixtures import parse_frontmatter
from skillloop.discovery.scanner import reduce_scan


def read_sealed(path, limit=262144):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:
            raise ValueError('scanner_evidence_file_bound')
        raw=stream.read(limit+1)
    if len(raw)>limit:raise ValueError('scanner_evidence_file_bound')
    value=decode_json(raw)
    if type(value) is not dict or value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'}):
        raise ValueError('scanner_evidence_seal')
    return value


def durable_save(path,value):
    path=Path(path)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        os.fchmod(stream.fileno(),0o600);stream.write(canonical_json_line(value));stream.flush();os.fsync(stream.fileno())
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)


def export_inventory(root):
    root=Path(root)
    if root.is_symlink() or not root.is_dir():raise ValueError('scanner_export_directory')
    files=[];total=0
    for path in sorted(root.rglob('*')):
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError('scanner_export_unsafe')
        if not stat.S_ISREG(info.st_mode):continue
        if path.parent==root and (path.name in {'review-accepted.json','resources-retired.json','volume-retired.json'}
                                 or re.fullmatch(r'retired-[0-9a-f]{64}\.json',path.name)):continue
        total+=info.st_size
        if total>34078720 or len(files)>=128:raise ValueError('scanner_export_bound')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            actual=os.fstat(stream.fileno())
            if not stat.S_ISREG(actual.st_mode) or actual.st_size!=info.st_size:
                raise ValueError('scanner_export_changed')
            raw=stream.read(info.st_size+1)
        if len(raw)!=info.st_size:raise ValueError('scanner_export_changed')
        files.append({'path':path.relative_to(root).as_posix(),'bytes':info.st_size,'digest':digest_bytes(raw)})
    return files


def read_deployment(path):
    path=Path(path).absolute()
    if path.is_symlink() or path.parent.is_symlink():raise PermissionError('scanner_deployment_path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o022:
            raise PermissionError('scanner_deployment_owner')
        raw=stream.read(262145)
    if len(raw)>262144:raise ValueError('scanner_deployment_bound')
    config=decode_json(raw)
    if type(config) is not dict or config.get('digest')!=digest_jcs({k:v for k,v in config.items() if k!='digest'}):
        raise ValueError('scanner_deployment_seal')
    required={'kind','deployment_epoch','image','scanner_profile_digest','timeout_seconds','wall_budget_seconds',
              'state_directory','approved_snapshots','digest'}
    if (set(config) not in (required,required|{'controller_state_mount','docker_engine_socket','campaign_deadline'}) or config['kind']!='OfflineScannerDeployment'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',config['image'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}',config['scanner_profile_digest'])
            or type(config['timeout_seconds']) is not int or not 1<=config['timeout_seconds']<=1200
            or type(config['wall_budget_seconds']) is not int
            or not config['timeout_seconds']+360<=config['wall_budget_seconds']<=1800
            or type(config['deployment_epoch']) is not str or not 1<=len(config['deployment_epoch'])<=256
            or type(config['approved_snapshots']) is not dict):
        raise ValueError('scanner_deployment_contract')
    if 'controller_state_mount' in config:
        if os.geteuid()!=21001:raise PermissionError('formal_scanner_controller_role')
        absolute=datetime.fromisoformat(config['campaign_deadline'].replace('Z','+00:00'))
        if absolute.tzinfo is None or not 60<(absolute-datetime.now(timezone.utc)).total_seconds()<=28800:
            raise ValueError('scanner_original_campaign_deadline')
        pin=config['controller_state_mount']
        if (type(pin) is not dict or set(pin)!={'volume','subpath'}
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',pin['volume'])
                or not PurePosixPath(pin['subpath']).parts or PurePosixPath(pin['subpath']).is_absolute()
                or '..' in PurePosixPath(pin['subpath']).parts
                or str(PurePosixPath(pin['subpath']))!=pin['subpath']
                or not Path(config['docker_engine_socket']).is_absolute()):
            raise ValueError('scanner_frozen_volume_mapping')
    return config


class ScanController:
    def __init__(self,deployment):
        self.config=read_deployment(deployment)
        self.root=Path(self.config['state_directory'])
        if not self.root.is_absolute() or self.root.is_symlink():raise PermissionError('scanner_state_directory')
        self.root.mkdir(parents=True,mode=0o700,exist_ok=True)
        info=self.root.stat()
        if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise PermissionError('scanner_state_owner')
        self.path=self.root/'operations.sqlite'
        if self.path.is_symlink():raise PermissionError('scanner_state_symlink')
        if self.path.exists():
            info=self.path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:
                raise PermissionError('scanner_operation_store_owner')
        old=os.umask(0o077)
        try:
            with closing(self.connect()) as db:
                db.execute('CREATE TABLE IF NOT EXISTS identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),digest TEXT)')
                db.execute('CREATE TABLE IF NOT EXISTS scans(operation TEXT PRIMARY KEY,parameters TEXT,state TEXT,result BLOB,container TEXT,root TEXT)')
                prior=db.execute('SELECT digest FROM identity WHERE singleton=1').fetchone()
                if prior and prior!=(self.config['digest'],):raise ValueError('scanner_store_deployment_changed')
                db.execute('INSERT OR IGNORE INTO identity VALUES(1,?)',(self.config['digest'],));db.commit()
        finally:os.umask(old)

    def connect(self):
        db=sqlite3.connect(self.path,timeout=2);db.execute('PRAGMA synchronous=FULL');return db

    def _engine_command(self,arguments,*,timeout):
        """Translate this service's fixed operations to Engine, never spawn CLI.

        Arguments originate solely in this module. A named-volume state mapping
        replaces Controller-local bind paths; arbitrary operator args are denied.
        """
        from skillloop.runtime.docker_api import DockerEngine
        engine=DockerEngine(self.config['docker_engine_socket'])
        def request(method,path,body=None,**options):
            return engine.request(method,path,body,timeout=timeout,**options)
        action=arguments[0]
        if arguments[:2]==['image','inspect']:
            result=[request('GET','/images/'+quote(arguments[2],safe='')+'/json')]
        elif arguments[:2]==['volume','inspect']:
            result=[request('GET','/volumes/'+quote(arguments[2],safe=''))]
        elif arguments[:2]==['volume','rm']:
            request('DELETE','/volumes/'+quote(arguments[2],safe=''));result=arguments[2]
        elif arguments[:2]==['volume','create']:
            labels={};options={};index=2
            while index<len(arguments)-1:
                flag,value=arguments[index:index+2];index+=2
                if flag not in {'--label','--opt'}:raise ValueError('scanner_engine_volume_argument')
                key,value=value.split('=',1)
                (labels if flag=='--label' else options)[key]=value
            result=request('POST','/volumes/create',{'Name':arguments[-1],'Driver':'local','DriverOpts':options,'Labels':labels})['Name']
        elif action in {'create','run'}:
            config={'Entrypoint':['python'],'Env':['PYTHONDONTWRITEBYTECODE=1'], 'Labels':{},
                'HostConfig':{'Mounts':[],'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges']}}
            index=1;name=None
            while index<len(arguments) and arguments[index].startswith('-'):
                flag=arguments[index];index+=1
                if flag in {'--pull=never','-d'}:continue
                if flag=='--read-only':config['HostConfig']['ReadonlyRootfs']=True;continue
                value=arguments[index];index+=1
                if flag=='--name':name=value
                elif flag=='--user':config['User']=value
                elif flag=='--network':config['HostConfig']['NetworkMode']=value
                elif flag=='--cap-drop':
                    if value!='ALL':raise ValueError('scanner_engine_capability')
                elif flag=='--security-opt':
                    if value!='no-new-privileges':raise ValueError('scanner_engine_security')
                elif flag=='--memory':
                    unit=value[-1];config['HostConfig']['Memory']=int(value[:-1])*({'m':1048576,'g':1073741824}[unit])
                elif flag=='--cpus':config['HostConfig']['NanoCpus']=int(value)*1000000000
                elif flag=='--pids-limit':config['HostConfig']['PidsLimit']=int(value)
                elif flag=='--ulimit':
                    key,bounds=value.split('=',1);soft,hard=bounds.split(':')
                    config['HostConfig']['Ulimits']=[{'Name':key,'Soft':int(soft),'Hard':int(hard)}]
                elif flag=='--label':
                    key,content=value.split('=',1);config['Labels'][key]=content
                elif flag=='--tmpfs':
                    target,options=value.split(':',1);config['HostConfig'].setdefault('Tmpfs',{})[target]=options
                elif flag=='--entrypoint':
                    if value!='python':raise ValueError('scanner_engine_entrypoint')
                elif flag=='--mount':
                    values={};readonly=False
                    for part in value.split(','):
                        if part=='readonly':readonly=True
                        else:key,content=part.split('=',1);values[key]=content
                    if set(values)!={'type','src','dst'}:raise ValueError('scanner_engine_mount_argument')
                    mount={'Type':'volume','Target':values['dst'],'ReadOnly':readonly}
                    if values['type']=='bind':
                        relative=Path(values['src']).relative_to(self.root)
                        if relative.parts[-1]!='subject' or values['dst']!='/subject' or not readonly:
                            raise ValueError('scanner_engine_subject_mount')
                        pin=self.config['controller_state_mount']
                        mount.update(Source=pin['volume'],VolumeOptions={'Subpath':pin['subpath']+'/'+relative.as_posix()})
                    elif values['type']=='volume':mount['Source']=values['src']
                    else:raise ValueError('scanner_engine_mount_type')
                    config['HostConfig']['Mounts'].append(mount)
                else:raise ValueError('scanner_engine_argument')
            if name is None or arguments[index]!=self.config['image']:raise ValueError('scanner_engine_frozen_image')
            config['Image']=arguments[index];config['Cmd']=arguments[index+1:]
            identifier=request('POST','/containers/create?name='+quote(name,safe=''),config)['Id']
            if action=='run':request('POST','/containers/'+identifier+'/start')
            result=identifier
        elif action=='inspect':result=[request('GET','/containers/'+arguments[1]+'/json')]
        elif action=='start':request('POST','/containers/'+arguments[1]+'/start');result=arguments[1]
        elif action=='wait':result=str(request('POST','/containers/'+arguments[1]+'/wait?condition=not-running')['StatusCode'])
        elif action=='stop':request('POST','/containers/'+arguments[-1]+'/stop?t=1');result=arguments[-1]
        elif action=='rm':request('DELETE','/containers/'+arguments[1]);result=arguments[1]
        elif action=='cp':
            identifier,source=arguments[1].split(':',1)
            if source!='/report/report.json':raise ValueError('scanner_engine_export_source')
            target=Path(arguments[2]);target.relative_to(self.root)
            raw=request('GET','/containers/'+identifier+'/archive?path='+quote(source,safe=''),raw=True,
                        maximum_response_bytes=33554432+1048576)
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
                members=archive.getmembers()
                if len(members)!=1 or not members[0].isreg() or members[0].name!='report.json' or members[0].size>33554432:
                    raise ValueError('scanner_engine_export_bound')
                fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream:
                    source_stream=archive.extractfile(members[0]);remaining=members[0].size
                    while remaining:
                        block=source_stream.read(min(1048576,remaining))
                        if not block:raise ValueError('scanner_engine_export_truncated')
                        stream.write(block);remaining-=len(block)
                    stream.flush();os.fsync(stream.fileno())
            result=''
        else:raise ValueError('scanner_engine_operation')
        stdout=canonical_json_line(result) if isinstance(result,(dict,list)) else (str(result)+'\n').encode()
        return subprocess.CompletedProcess(arguments,0,stdout,b'')

    def grant_roster_evidence(self,operation_id,review_path,*,output_directory,campaign_deadline):
        """Copy the actual reviewed scan into the roster Gate's narrow grant.

        The scanner operations DB and other campaign exports stay private. A
        failed/partial copy is retained; it cannot authorize another scan or
        overwrite evidence under the same operation.
        """
        if os.geteuid()!=21001 or 'controller_state_mount' not in self.config:
            raise PermissionError('scan_roster_actual_formal_controller')
        from skillloop.discovery.formal_task_gate import read_owned
        review=read_owned(review_path,uid=21005,gid=21001,limit=262144)
        deadline=datetime.fromisoformat(campaign_deadline.replace('Z','+00:00'))
        if (campaign_deadline!=self.config['campaign_deadline'] or deadline.tzinfo is None
                or (deadline-datetime.now(timezone.utc)).total_seconds()<=120):
            raise TimeoutError('scan_roster_original_terminal_reserve')
        began=time.monotonic()
        def budget():
            if time.monotonic()-began>60 or datetime.now(timezone.utc)>=deadline:
                raise TimeoutError('scan_roster_read_grant_budget')
        with closing(self.connect()) as db:
            row=db.execute('SELECT state,root FROM scans WHERE operation=?',(operation_id,)).fetchone()
        if row is None or row[0]!='completed':raise ValueError('scan_roster_completed_export_required')
        source=Path(row[1]);receipt=read_sealed(source/'scan-evidence.json')
        if (review.get('kind')!='ScanEvidenceReview' or review.get('evidence_complete') is not True
                or review.get('operation_id')!=operation_id or review.get('export_receipt_digest')!=receipt['digest']
                or review.get('deployment_digest')!=self.config['digest']
                or review.get('raw_report_digest')!=receipt['raw_report_digest']
                or review.get('raw_inventory_digest')!=digest_jcs(export_inventory(source))):
            raise ValueError('scan_roster_original_gate_custody_required')
        root=Path(output_directory);info=root.lstat()
        if (not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid!=21001 or info.st_gid!=21001 or stat.S_IMODE(info.st_mode)!=0o750):
            raise PermissionError('scan_roster_read_grant_root')
        target=root/receipt['digest'][7:];target.mkdir(mode=0o750)
        os.chown(target,-1,21001);os.chmod(target,0o750)
        pins={i['path']:i for i in export_inventory(source)}
        for name in ('raw-report.json','scan-evidence.json','source-snapshot.json'):
            budget();limit=33554432 if name=='raw-report.json' else 262144
            pin=pins[name]
            if pin['bytes']>limit:raise ValueError('scan_roster_copy_capacity')
            fd=os.open(source/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                meta=os.fstat(stream.fileno())
                if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=21001 or meta.st_size!=pin['bytes']:
                    raise PermissionError('scan_roster_actual_export_owner')
                raw=stream.read(limit+1)
            if len(raw)!=pin['bytes'] or digest_bytes(raw)!=pin['digest']:
                raise ValueError('scan_roster_export_changed')
            fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
            with os.fdopen(fd,'wb') as stream:
                os.fchown(stream.fileno(),-1,21001);os.fchmod(stream.fileno(),0o640)
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            if digest_bytes((target/name).read_bytes())!=pin['digest']:
                raise ValueError('scan_roster_durable_copy_changed')
        for directory in (target,root):
            budget();fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        return {'receipt_digest':receipt['digest'],'review_digest':review['digest'],
                'directory':str(target),'qualification_issued':False}

    def retire_reviewed(self,operation_id,review_path,*,campaign_deadline):
        """Retire exact scanner resources after Gate review, under the round clock.

        The caller supplies the already frozen campaign deadline. This method
        neither starts a scan nor resets its budget, and keeps the exported raw.
        """
        deadline=datetime.fromisoformat(campaign_deadline.replace('Z','+00:00'))
        if deadline.tzinfo is None:raise ValueError('scanner_retirement_deadline')
        review_path=Path(review_path)
        parent=review_path.parent.lstat();info=review_path.lstat()
        if (review_path.is_symlink() or review_path.parent.is_symlink() or
                not stat.S_ISREG(info.st_mode) or info.st_uid!=21005 or
                info.st_gid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o640 or
                parent.st_uid!=21005 or parent.st_gid!=os.geteuid() or
                stat.S_IMODE(parent.st_mode)!=0o750):
            raise PermissionError('scanner_independent_gate_review_grant')
        review=read_sealed(review_path)
        with closing(self.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT state,root FROM scans WHERE operation=?',(operation_id,)).fetchone()
            if row is None or row[0]!='completed':raise ValueError('scanner_retirement_completed_export_required')
            target=Path(row[1]);receipt=read_sealed(target/'scan-evidence.json')
            if (review.get('kind')!='ScanEvidenceReview' or review.get('operation_id')!=operation_id or
                    review.get('export_receipt_digest')!=receipt['digest'] or
                    review.get('evidence_complete') is not True or
                    review.get('qualification_issued') is not False or
                    review.get('deployment_digest')!=self.config['digest'] or
                    review.get('scanner_report_digest')!=receipt['scanner_report_digest'] or
                    review.get('raw_report_digest')!=receipt['raw_report_digest']):
                raise ValueError('scanner_retirement_review_identity')
            raw_path=target/'raw-report.json'
            if raw_path.is_symlink() or raw_path.stat().st_size>33554432 or digest_bytes(raw_path.read_bytes())!=receipt['raw_report_digest']:
                raise ValueError('scanner_retirement_raw_changed')
            if digest_jcs(export_inventory(target))!=review.get('raw_inventory_digest'):
                raise ValueError('scanner_retirement_inventory_changed')
            marker=target/'review-accepted.json'
            if marker.exists():
                if read_sealed(marker)['review_digest']!=review['digest']:raise ValueError('scanner_retirement_review_conflict')
            else:
                accepted={'kind':'ScanReviewAccepted','review_digest':review['digest'],'receipt_digest':receipt['digest']}
                accepted['digest']=digest_jcs(accepted);durable_save(marker,accepted)
            closed=target/'resources-retired.json'
            if closed.exists():
                saved=read_sealed(closed)
                if saved['review_digest']!=review['digest']:raise ValueError('scanner_retirement_closed_conflict')
                return saved
            fingerprint=db.execute('SELECT parameters FROM scans WHERE operation=?',(operation_id,)).fetchone()[0]
            def docker(args,check=True):
                left=(deadline-datetime.now(timezone.utc)).total_seconds()
                if left<=0:raise TimeoutError('scanner_campaign_cleanup_budget_expired')
                try:
                    result=(self._engine_command(args,timeout=min(20,left)) if 'controller_state_mount' in self.config
                            else subprocess.run(['docker',*args],capture_output=True,timeout=min(20,left)))
                except RuntimeError as error:
                    if check or not str(error).startswith('docker_engine_404:'):raise
                    result=subprocess.CompletedProcess(args,1,b'',str(error).encode())
                if check and result.returncode:raise OSError('scanner_retirement_engine_error')
                return result
            # Commit the accepted review before destructive resource operations.
            db.commit()
            retired=[]
            for identity in (receipt['container_id'],receipt['keeper_id']):
                probe=docker(['inspect',identity],check=False)
                if probe.returncode:
                    # A successful previous remove must have its own durable
                    # marker. Missing resources without that marker stay unknown.
                    done=target/('retired-'+identity+'.json')
                    if not done.exists():raise ValueError('scanner_retirement_missing_unaccounted_resource')
                    if read_sealed(done)['id']!=identity:raise ValueError('scanner_retirement_marker')
                    retired.append(identity);continue
                values=decode_json(probe.stdout)
                if (len(values)!=1 or values[0]['Id']!=identity or values[0]['Image']!=self.config['image'] or
                        values[0]['Config']['Labels'].get('skillloop.scan-operation')!=fingerprint):
                    raise ValueError('scanner_retirement_resource_identity')
                if values[0]['State']['Running']:docker(['stop','-t','1',identity])
                stopped=decode_json(docker(['inspect',identity]).stdout)
                if len(stopped)!=1 or stopped[0]['Id']!=identity or stopped[0]['State']['Running']:
                    raise ValueError('scanner_retirement_resource_running')
                docker(['rm',identity])
                done={'kind':'RetiredScanContainer','id':identity,'review_digest':review['digest']}
                done['digest']=digest_jcs(done);durable_save(target/('retired-'+identity+'.json'),done)
                retired.append(identity)
            volume=receipt['report_volume'];volume_marker=target/'volume-retired.json'
            if not volume_marker.exists():
                values=decode_json(docker(['volume','inspect',volume]).stdout)
                if (len(values)!=1 or values[0]['Name']!=volume or
                        values[0]['Labels'].get('skillloop.scan-operation')!=fingerprint):
                    raise ValueError('scanner_retirement_volume_identity')
                docker(['volume','rm',volume])
                done={'kind':'RetiredScanVolume','name':volume,'review_digest':review['digest']}
                done['digest']=digest_jcs(done);durable_save(volume_marker,done)
            else:
                if read_sealed(volume_marker)['review_digest']!=review['digest']:raise ValueError('scanner_retirement_volume_conflict')
            summary={'kind':'RetiredScanResources','operation_id':operation_id,'containers':retired,
                     'volume':volume,'review_digest':review['digest'],'raw_preserved':True}
            summary['digest']=digest_jcs(summary);durable_save(closed,summary)
            return summary

    def scan(self,snapshot,*,scanner_profile=None,operation_id=None):
        validate_envelope(snapshot)
        if snapshot['kind']!='SourceSnapshot':raise ValueError('scanner_source_kind')
        locator=self.config['approved_snapshots'].get(snapshot['digest'])
        if type(locator) is not dict or set(locator)!={'git_repository','commit','skill_path'}:
            raise PermissionError('scanner_snapshot_not_provisioned')
        if not Path(locator['git_repository']).is_absolute():raise PermissionError('scanner_repository_configuration')
        actual,package=import_git_package(Path(locator['git_repository']),locator['commit'],locator['skill_path'])
        if actual!=snapshot:raise ValueError('scanner_exact_source_mismatch')
        # The provisioned digest denotes the production reduction registry; a
        # caller's optional file can only repeat these bytes, never replace it.
        from skillloop.discovery.scanner import ANALYZERS
        registry_raw=ANALYZERS.read_bytes()
        if digest_bytes(registry_raw)!=self.config['scanner_profile_digest']:
            raise PermissionError('scanner_deployed_profile_changed')
        if scanner_profile is not None and (Path(scanner_profile).is_symlink() or
                Path(scanner_profile).stat().st_size>262144 or
                Path(scanner_profile).read_bytes()!=registry_raw):
            raise PermissionError('scanner_profile_not_provisioned')
        profile=parse_frontmatter(package['SKILL.md'])['profile_id']
        operation=operation_id or 'scan-'+uuid.uuid4().hex
        if type(operation) is not str or not 1<=len(operation)<=256:raise ValueError('scanner_operation_id')
        fingerprint=digest_jcs({'source':snapshot['digest'],'deployment':self.config['digest'],
                                'scanner_profile':self.config['scanner_profile_digest']})
        identity=digest_jcs([operation,fingerprint])[7:]
        target=self.root/identity;name='skillloop-scan-'+identity[:24]
        with closing(self.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            prior=db.execute('SELECT parameters,state,result FROM scans WHERE operation=?',(operation,)).fetchone()
            if prior:
                if prior[0]!=fingerprint:raise ValueError('scanner_operation_conflict')
                if prior[1]!='completed':raise PermissionError('scanner_operation_recovery_required_no_rerun')
                result=decode_json(prior[2]);validate_envelope(result)
                receipt=read_sealed(target/'scan-evidence.json')
                normalized=read_sealed(target/'normalized-report.json')
                raw_path=target/'raw-report.json'
                if (raw_path.is_symlink() or raw_path.stat().st_size>33554432 or
                        normalized!=result or receipt['scanner_report_digest']!=result['digest'] or
                        receipt['source_snapshot_digest']!=snapshot['digest'] or
                        receipt['deployment_digest']!=self.config['digest'] or
                        digest_bytes(raw_path.read_bytes())!=receipt['raw_report_digest']):
                    raise ValueError('scanner_replay_evidence_changed')
                return result
            started=time.monotonic();deadline=started+self.config['wall_budget_seconds'];container_id=None
            if 'campaign_deadline' in self.config:
                absolute=datetime.fromisoformat(self.config['campaign_deadline'].replace('Z','+00:00'))
                deadline=min(deadline,started+(absolute-datetime.now(timezone.utc)).total_seconds())
                if deadline-started<self.config['timeout_seconds']+360:
                    raise TimeoutError('scanner_full_original_budget_required')
            # Durable admission precedes OCI creation. A lost create/run response
            # leaves an unknown operation and never silently retries the scanner.
            db.execute('INSERT INTO scans VALUES(?,?,?,NULL,?,?)',
                       (operation,fingerprint,'started',name,str(target)));db.commit()
        # Reserve the last minute of the original wall budget for stopping an
        # unknown scanner. Cleanup never receives a reset clock or new budget.
        work_deadline=deadline-60
        volume=name+'-report';keeper_id=None
        def command(arguments,limit=30,check=True,cleanup=False):
            left=(deadline if cleanup else work_deadline)-time.monotonic()
            if left<=0:raise TimeoutError('scanner_stage_budget_expired')
            result=(self._engine_command(arguments,timeout=min(limit,left)) if 'controller_state_mount' in self.config
                    else subprocess.run(['docker',*arguments],capture_output=True,timeout=min(limit,left)))
            if check and result.returncode:raise OSError('scanner_engine_operation_failed')
            return result
        def save(path,value):
            durable_save(path,value)
        try:
            target.mkdir(mode=0o700)
            subject=target/'subject';subject.mkdir(mode=0o755)
            for relative,raw in package.items():
                path=subject/relative;path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
                with path.open('xb') as stream:stream.write(raw)
                os.chmod(path,0o444)
            save(target/'source-snapshot.json',snapshot)
            inspected=decode_json(command(['image','inspect',self.config['image']]).stdout)
            if len(inspected)!=1 or inspected[0]['Id']!=self.config['image'] or inspected[0]['Architecture']!='arm64':
                raise ValueError('scanner_image_identity')
            # A separate readonly keeper starts before the scanner can write the
            # bounded report tmpfs. Failed/stopped scanner evidence stays mounted.
            command(['volume','create','--label','skillloop.scan-operation='+fingerprint,
                '--label','skillloop.epoch='+self.config['deployment_epoch'],
                '--opt','type=tmpfs','--opt','device=tmpfs',
                '--opt','o=size=33554432,uid=21008,gid=21008,mode=0700',volume])
            keeper=command(['run','-d','--pull=never','--name',name+'-keeper','--user','21008:21008',
                '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                '--memory','128m','--pids-limit','16','--label','skillloop.scan-operation='+fingerprint,
                '--mount','type=volume,src='+volume+',dst=/report,readonly',
                # The original budget limits new scanner work. It must not
                # silently unmount the report tmpfs before an independent
                # review or failed-operation custody recovery has finished.
                '--entrypoint','python',self.config['image'],'-c','import time;time.sleep(2147483647)'])
            keeper_id=keeper.stdout.decode('ascii').strip()
            if not re.fullmatch('[0-9a-f]{64}',keeper_id):raise ValueError('scanner_keeper_identity')
            kept=decode_json(command(['inspect',keeper_id]).stdout)[0]
            if not kept['State']['Running'] or kept['Image']!=self.config['image']:
                raise ValueError('scanner_keeper_not_active')
            save(target/'keeper-created.json',{'id':keeper_id,'volume':volume,'image':self.config['image']})
            # Native scanner output remains in the isolated volume until review.
            created=command(['create','--pull=never','--name',name,'--user','21008:21008',
                '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
                '--memory','2g','--cpus','2','--pids-limit','128','--ulimit','nofile=128:128',
                '--label','skillloop.scan-operation='+fingerprint,
                '--label','skillloop.epoch='+self.config['deployment_epoch'],
                '--tmpfs','/tmp:rw,nosuid,nodev,size=128m',
                '--mount','type=volume,src='+volume+',dst=/report',
                '--mount','type=bind,src='+str(subject)+',dst=/subject,readonly',
                '--entrypoint','python',self.config['image'],'/opt/skillloop-scanner/offline_osv.py',
                'scan','/subject/SKILL.md','--no-llm','--format','json','--output','/report/report.json'])
            container_id=created.stdout.decode('ascii').strip()
            if not re.fullmatch('[0-9a-f]{64}',container_id):raise ValueError('scanner_container_identity')
            save(target/'container-created.json',{'id':container_id,'image':self.config['image'],'operation':operation})
            command(['start',container_id])
            waited=command(['wait',container_id],limit=self.config['timeout_seconds'])
            code=int(waited.stdout.decode('ascii').strip())
            live=decode_json(command(['inspect',container_id]).stdout)
            if len(live)!=1 or live[0]['Id']!=container_id or live[0]['State']['Running']:
                raise ValueError('scanner_terminal_identity')
            terminal=live[0]
            if (terminal['Image']!=self.config['image'] or terminal['Config']['User']!='21008:21008'
                    or terminal['State']['ExitCode']!=code
                    or terminal['Config']['Labels'].get('skillloop.scan-operation')!=fingerprint):
                raise ValueError('scanner_terminal_configuration')
            save(target/'container-terminal.json',terminal)
            command(['cp',container_id+':/report/report.json',str(target/'raw-report.json')])
            raw=(target/'raw-report.json').read_bytes();os.chmod(target/'raw-report.json',0o600)
            if len(raw)>33554432:raise ValueError('scanner_report_bound')
            report,findings,dispositions=reduce_scan(profile,raw,code,subject_digest=snapshot['body']['skill_digest'],
                                                    require_llm=False,allow_risk_exit=True)
            save(target/'normalized-report.json',report)
            save(target/'findings.json',{'findings':findings,'dispositions':dispositions})
            receipt={'kind':'FormalScanEvidence','source_snapshot_digest':snapshot['digest'],
                'deployment_digest':self.config['digest'],'container_id':container_id,'image':self.config['image'],
                'scanner_profile_digest':self.config['scanner_profile_digest'],
                'raw_report_digest':digest_bytes(raw),'scanner_report_digest':report['digest'],
                'upstream_exit_code':code,'profile_id':profile,'operation_id':operation,
                'elapsed_seconds':time.monotonic()-started,'semantic_scanning':False,'qualification_issued':False,
                'keeper_id':keeper_id,'report_volume':volume,'custody_state':'awaiting_independent_review'}
            receipt['digest']=digest_jcs(receipt);save(target/'scan-evidence.json',receipt)
            if 'controller_state_mount' in self.config:
                # Only this exact export is mounted into the real Gate. The
                # Controller's state root and its operations DB remain 0700.
                for path in [target,*target.rglob('*')]:
                    info=path.lstat()
                    if (info.st_uid!=21001 or stat.S_ISLNK(info.st_mode)
                            or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))):
                        raise PermissionError('scan_actual_gate_read_grant_owner')
                    os.chown(path,-1,21001)
                    os.chmod(path,0o750 if stat.S_ISDIR(info.st_mode) else 0o640)
            # Full-round Gate/administrative custody must review the native report
            # before retiring these exact resources. A successful scan is not Gate.
            with closing(self.connect()) as db:
                db.execute('BEGIN IMMEDIATE');db.execute('UPDATE scans SET state=?,result=? WHERE operation=? AND state=?',
                    ('completed',canonical_json_line(report),operation,'started'));db.commit()
            return report
        except BaseException as original:
            # Stop only the exact ID returned to this invocation; retain its raw
            # tmpfs and inspect/export during administrator recovery, not replay.
            cleanup_errors=[]
            if container_id is not None:
                try:
                    command(['stop','-t','1',container_id],cleanup=True)
                    terminal=decode_json(command(['inspect',container_id],cleanup=True).stdout)
                    if len(terminal)!=1 or terminal[0]['Id']!=container_id or terminal[0]['State']['Running']:
                        raise ValueError('scanner_cleanup_terminal_identity')
                    save(target/'failure-terminal.json',terminal[0])
                except BaseException as error:cleanup_errors.append({'stage':'stop','error':type(error).__name__})
                try:
                    command(['cp',container_id+':/report/report.json',str(target/'failure-raw-report.json')],
                            check=False,cleanup=True,limit=10)
                    exported=target/'failure-raw-report.json'
                    if exported.exists():os.chmod(exported,0o600)
                except BaseException as error:cleanup_errors.append({'stage':'export','error':type(error).__name__})
            if target.is_dir():
                try:save(target/'failure-custody.json',{'container_id':container_id,'keeper_id':keeper_id,
                    'report_volume':volume,'state':'unknown_no_replay','deployment_digest':self.config['digest'],
                    'original_error':type(original).__name__,'cleanup_errors':cleanup_errors})
                except BaseException as error:original.add_note('custody_save_error:'+type(error).__name__)
            try:
                with closing(self.connect()) as db:
                    db.execute('UPDATE scans SET state=? WHERE operation=? AND state=?',('unknown',operation,'started'));db.commit()
            except BaseException as error:original.add_note('operation_state_error:'+type(error).__name__)
            raise
