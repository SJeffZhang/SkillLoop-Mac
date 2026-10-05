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
                if row is not None and row!=(2,epoch):raise ValueError('operator_store_new_epoch_required')
                db.execute('INSERT OR IGNORE INTO identity VALUES(1,2,?)',(epoch,))
                db.execute('CREATE TABLE IF NOT EXISTS operations(ref TEXT PRIMARY KEY,owner INTEGER NOT NULL,parameters TEXT NOT NULL,request BLOB NOT NULL,route BLOB NOT NULL,ticket BLOB NOT NULL,state TEXT NOT NULL,result BLOB,error TEXT)')
                db.execute('CREATE TABLE IF NOT EXISTS operation_transitions(sequence INTEGER PRIMARY KEY AUTOINCREMENT,ref TEXT NOT NULL,state TEXT NOT NULL,reason TEXT,record BLOB NOT NULL)')
                db.execute("CREATE TRIGGER IF NOT EXISTS operation_transitions_no_update BEFORE UPDATE ON operation_transitions BEGIN SELECT RAISE(ABORT,'operation_history_immutable'); END")
                db.execute("CREATE TRIGGER IF NOT EXISTS operation_transitions_no_delete BEFORE DELETE ON operation_transitions BEGIN SELECT RAISE(ABORT,'operation_history_immutable'); END")
                db.commit()
        finally:os.umask(old)
    def connect(self):
        # closing plus explicit commits prevents leaked connections on recovery.
        db=sqlite3.connect(self.path,timeout=2);db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA max_page_count=4096')
        return closing(db)
    def _transition(self,db,ref,state,reason=None):
        previous=db.execute('SELECT record FROM operation_transitions WHERE ref=? ORDER BY sequence DESC LIMIT 1',(ref,)).fetchone()
        current=db.execute('SELECT state,result,error FROM operations WHERE ref=?',(ref,)).fetchone()
        if current is None or current[0]!=state:raise ValueError('operator_transition_actual_state_required')
        value={'kind':'OperatorOperationTransition','deployment_epoch':self.epoch,'operation_ref':ref,
            'state':state,'reason':reason,'recorded_at':datetime.now(timezone.utc).isoformat(),
            'previous_digest':None if previous is None else decode_json(previous[0])['digest'],
            'result_digest':None if current[1] is None else decode_json(current[1])['digest']}
        value['digest']=digest_jcs(value)
        db.execute('INSERT INTO operation_transitions(ref,state,reason,record) VALUES(?,?,?,?)',
            (ref,state,reason,canonical_json_line(value)))

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
            deadline=datetime.fromisoformat(route['deadline'].replace('Z','+00:00'))
            if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline:
                raise TimeoutError('operator_original_admission_deadline')
            controls={'admin cancel','admin revoke'}
            waiting=db.execute("SELECT request FROM operations WHERE state IN ('accepted','running') LIMIT 18").fetchall()
            lane=request['command'] in controls
            if sum((decode_json(raw)['command'] in controls)==lane for (raw,) in waiting)>=(1 if lane else 16):
                raise TimeoutError('operator_control_busy' if lane else 'operator_queue_full')
            # One bounded cancellation/revocation metadata slot is independent
            # of the 16 normal operations. It cannot start a campaign or model.
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?,NULL,NULL)',
                (ref,owner,params,canonical_json_line(request),canonical_json_line(route),canonical_json_line(ticket),'accepted'))
            self._transition(db,ref,'accepted','original_admission');db.commit()
        return ticket
    def claim(self,*,control_only=False):
        if type(control_only) is not bool:raise ValueError('operator_explicit_execution_lane')
        controls={'admin cancel','admin revoke'}
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            active=db.execute("SELECT request FROM operations WHERE state='running'").fetchall()
            if any((decode_json(raw)['command'] in controls)==control_only for (raw,) in active):return None
            pending=db.execute("SELECT ref,request,route FROM operations WHERE state='accepted' ORDER BY rowid LIMIT 18").fetchall()
            if len(pending)>17:raise ValueError('operator_original_queue_capacity')
            row=next((item for item in pending if (decode_json(item[1])['command'] in controls)==control_only),None)
            if row is None:return None
            route=decode_json(row[2]);deadline=datetime.fromisoformat(route['deadline'].replace('Z','+00:00'))
            if deadline.tzinfo is None or datetime.now(timezone.utc)>=deadline:
                db.execute("UPDATE operations SET state='failed',error='deadline_exceeded' WHERE ref=?",(row[0],))
                self._transition(db,row[0],'failed','deadline_exceeded');db.commit();return None
            db.execute("UPDATE operations SET state='running' WHERE ref=?",(row[0],))
            self._transition(db,row[0],'running','original_claim');db.commit()
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
            self._transition(db,ref,'completed','actual_result_committed');db.commit()
    def running(self):
        with self.connect() as db:
            return [(ref,decode_json(request),decode_json(route)) for ref,request,route in db.execute("SELECT ref,request,route FROM operations WHERE state='running'")]
    def requeue_unstarted_tail(self,ref,proof):
        if (os.geteuid()!=21001 or proof.get('kind')!='ControllerUnstartedTailRecovery'
                or proof.get('reexecute_started_stage') is not False
                or proof.get('digest')!=digest_jcs({k:v for k,v in proof.items() if k!='digest'})):
            raise PermissionError('operator_original_recovery_proof_required')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT request,route,state FROM operations WHERE ref=?',(ref,)).fetchone()
            if row is None or row[2]!='running':raise ValueError('operator_original_running_required')
            request,route=decode_json(row[0]),decode_json(row[1])
            receipts=proof.get('completed_stage_receipts')
            if (proof.get('request_digest')!=request['digest'] or proof.get('route_digest')!=route['digest']
                    or type(receipts) is not list or type(proof.get('next_stage_index')) is not int
                    or proof['next_stage_index']!=len(receipts) or len(receipts)>len(route['steps'])):
                raise ValueError('operator_recovery_original_unstarted_tail')
            # claim() rechecks the original deadline before any dispatch. No
            # replacement ticket, route, task, slot or clock is constructed.
            db.execute("UPDATE operations SET state='accepted',error=NULL WHERE ref=?",(ref,))
            self._transition(db,ref,'accepted','original_unstarted_tail_recovery');db.commit()
    def fail(self,ref,reason='unavailable'):
        if reason not in {'unavailable','unknown_requires_recovery'}:raise ValueError('operator_stable_failure_code')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("UPDATE operations SET state='failed',error=? WHERE ref=? AND state='running'",(reason,ref)).rowcount==1:
                self._transition(db,ref,'failed',reason)
            db.commit()
    def status(self,owner,ref):
        with self.connect() as db:row=db.execute('SELECT state,result,error FROM operations WHERE ref=? AND owner=?',(ref,owner)).fetchone()
        if row is None:raise PermissionError('operator_other_owner_operation')
        if row[0]=='completed':return decode_json(row[1])
        return make_control('OperationStatus',{'operation_ref':ref,'state':row[0],
            'result_kind':None,'result_digest':None,'error_code':row[2]})


def verify_operation_transitions(db,epoch,*,budget):
    """Rebuild immutable state history from an actual consistent snapshot."""
    heads={};clock={};count=0
    columns={'kind','deployment_epoch','operation_ref','state','reason','recorded_at','previous_digest','result_digest','digest'}
    for ref,state,reason,raw in db.execute('SELECT ref,state,reason,record FROM operation_transitions ORDER BY sequence'):
        budget();value=decode_json(raw);count+=1
        if (set(value)!=columns or value.get('kind')!='OperatorOperationTransition'
                or value.get('deployment_epoch')!=epoch or value.get('operation_ref')!=ref
                or value.get('state')!=state or value.get('reason')!=reason
                or value.get('digest')!=digest_jcs({k:v for k,v in value.items() if k!='digest'})):
            raise ValueError('operator_archive_transition_binding')
        prior=heads.get(ref)
        if value['previous_digest']!=(None if prior is None else prior['digest']):
            raise ValueError('operator_archive_transition_chain')
        timestamp=datetime.fromisoformat(value['recorded_at'])
        if (timestamp.tzinfo is None or timestamp>datetime.now(timezone.utc)
                or ref in clock and timestamp<clock[ref]):
            raise ValueError('operator_archive_transition_clock')
        valid=(prior is None and state=='accepted' and reason=='original_admission'
            or prior is not None and prior['state']=='accepted' and
                (state=='running' and reason=='original_claim' or state=='failed' and reason=='deadline_exceeded')
            or prior is not None and prior['state']=='running' and
                (state=='accepted' and reason=='original_unstarted_tail_recovery'
                or state=='completed' and reason=='actual_result_committed'
                or state=='failed' and reason in {'unavailable','unknown_requires_recovery'}))
        if not valid or (state=='completed')!=(value['result_digest'] is not None):
            raise ValueError('operator_archive_actual_transition_order')
        heads[ref]=value;clock[ref]=timestamp
    rows=0
    for ref,state,raw,error in db.execute('SELECT ref,state,result,error FROM operations'):
        budget();rows+=1;head=heads.get(ref)
        if (head is None or head['state']!=state
                or head['result_digest']!=(None if raw is None else decode_json(raw)['digest'])
                or error!=(head['reason'] if state=='failed' else None)):
            raise ValueError('operator_archive_current_state_history_mismatch')
    if rows!=len(heads):raise ValueError('operator_archive_orphan_transition')
    return {'operations':rows,'transitions':count,'head_digests':{ref:value['digest'] for ref,value in sorted(heads.items())}}
