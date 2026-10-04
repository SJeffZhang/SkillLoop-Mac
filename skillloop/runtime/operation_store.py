"""Controller-owned durable acceptance, ownership and unknown operation state."""
from contextlib import closing
from datetime import datetime,timezone
import os,sqlite3,stat
from pathlib import Path
from skillloop.protocol import canonical_json_line,decode_json,digest_jcs,validate_envelope
from skillloop.proxy.wire import make_control,validate_control


class OperatorOperationStore:
    def __init__(self,path,epoch):
        if os.geteuid()!=21001:raise PermissionError('operator_store_actual_controller')
        self.path=Path(path);self.epoch=epoch;parent=self.path.parent.lstat()
        if self.path.is_symlink() or self.path.parent.is_symlink() or parent.st_uid!=21001 or stat.S_IMODE(parent.st_mode)!=0o700:
            raise PermissionError('operator_store_private_directory')
        if self.path.exists():
            info=self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=21001 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
                raise PermissionError('operator_store_private_file')
        old=os.umask(0o077)
        try:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                db.execute('CREATE TABLE IF NOT EXISTS identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,epoch TEXT NOT NULL)')
                row=db.execute('SELECT version,epoch FROM identity').fetchone()
                if row is not None and row!=(1,epoch):raise ValueError('operator_store_new_epoch_required')
                db.execute('INSERT OR IGNORE INTO identity VALUES(1,1,?)',(epoch,))
                db.execute('CREATE TABLE IF NOT EXISTS operations(ref TEXT PRIMARY KEY,owner INTEGER NOT NULL,parameters TEXT NOT NULL,request BLOB NOT NULL,route BLOB NOT NULL,ticket BLOB NOT NULL,state TEXT NOT NULL,result BLOB,error TEXT)')
                db.commit()
        finally:os.umask(old)
    def connect(self):
        # closing plus explicit commits prevents leaked connections on recovery.
        db=sqlite3.connect(self.path,timeout=2);db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA max_page_count=4096')
        return closing(db)
    def accept(self,owner,request,route):
        ref='op-'+digest_jcs({'epoch':self.epoch,'owner':owner,'operation':request['operation_id']})[7:]
        params=digest_jcs({'command':request['command'],'parameters':request['parameters']})
        ticket=make_control('OperationTicket',{'operation_ref':ref,'owner_role':'admin' if owner==21010 else 'controller' if owner==21001 else 'operator',
            'deadline':route['deadline'],'expected_result_kind':route['result_kind']})
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT parameters,ticket FROM operations WHERE ref=?',(ref,)).fetchone()
            if row:
                if row[0]!=params:raise ValueError('operator_same_id_parameter_conflict')
                return decode_json(row[1])
            if db.execute("SELECT count(*) FROM operations WHERE state IN ('accepted','running')").fetchone()[0]>=16:
                raise TimeoutError('operator_queue_full')
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,NULL,NULL)',
                (ref,owner,params,canonical_json_line(request),canonical_json_line(route),canonical_json_line(ticket),'accepted'));db.commit()
        return ticket
    def claim(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM operations WHERE state='running'").fetchone():return None
            row=db.execute("SELECT ref,request,route FROM operations WHERE state='accepted' ORDER BY rowid LIMIT 1").fetchone()
            if row is None:return None
            route=decode_json(row[2]);deadline=datetime.fromisoformat(route['deadline'].replace('Z','+00:00'))
            if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline:
                db.execute("UPDATE operations SET state='failed',error='deadline_exceeded' WHERE ref=?",(row[0],));db.commit();return None
            db.execute("UPDATE operations SET state='running' WHERE ref=?",(row[0],));db.commit()
            return row[0],decode_json(row[1]),route
    def complete(self,ref,result):
        try:validate_control(result)
        except ValueError:validate_envelope(result)
        if len(canonical_json_line(result))>2097152:raise ValueError('operator_result_capacity')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT ticket FROM operations WHERE ref=?',(ref,)).fetchone()
            if row is None or decode_json(row[0])['body']['expected_result_kind']!=result['kind']:
                raise ValueError('operator_expected_result_kind')
            if db.execute("UPDATE operations SET state='completed',result=? WHERE ref=? AND state='running'",(canonical_json_line(result),ref)).rowcount!=1:
                raise ValueError('operator_original_running_required')
            db.commit()
    def running(self):
        with self.connect() as db:
            return [(ref,decode_json(request),decode_json(route)) for ref,request,route in db.execute("SELECT ref,request,route FROM operations WHERE state='running'")]
    def fail(self,ref,reason='unavailable'):
        if reason not in {'unavailable','unknown_requires_recovery'}:raise ValueError('operator_stable_failure_code')
        with self.connect() as db:
            db.execute("UPDATE operations SET state='failed',error=? WHERE ref=? AND state='running'",(reason,ref));db.commit()
    def status(self,owner,ref):
        with self.connect() as db:row=db.execute('SELECT state,result,error FROM operations WHERE ref=? AND owner=?',(ref,owner)).fetchone()
        if row is None:raise PermissionError('operator_other_owner_operation')
        if row[0]=='completed':return decode_json(row[1])
        return make_control('OperationStatus',{'operation_ref':ref,'state':row[0],
            'result_kind':None,'result_digest':None,'error_code':row[2]})
