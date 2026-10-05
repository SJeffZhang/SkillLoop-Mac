"""Gateway-only reservation of a current Runtime inference in the business DB.

Only identity and content digests cross this internal socket. It is neither a
new tool permission nor access to the private suite. A committed reservation is
spent even if the Gateway disappears before the native request or its reply.
"""
import os
import re
from skillloop.protocol import digest_jcs
from skillloop.proxy.store import ProxyError, _load, _now, _parse, _stamp

DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')


class RuntimeInferenceAuthority:
    def __init__(self, store):
        if os.geteuid() != 21003:
            raise PermissionError('inference_authority_actual_proxy')
        self.store = store
        with store._transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS runtime_inference_schema('
                       'singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL) STRICT')
            version = db.execute('SELECT version FROM runtime_inference_schema WHERE singleton=1').fetchone()
            if version is not None and version[0] != 1:
                raise ProxyError('unsupported_database_version')
            db.execute('CREATE TABLE IF NOT EXISTS runtime_inference_attempts('
                'run_id TEXT NOT NULL REFERENCES runs(run_id),round_index INTEGER NOT NULL,'
                'request_digest TEXT UNIQUE NOT NULL,reservation_json BLOB NOT NULL,'
                'response_digest TEXT,completed_at TEXT,PRIMARY KEY(run_id,round_index)) STRICT')
            expected = ['run_id','round_index','request_digest','reservation_json','response_digest','completed_at']
            if [r[1] for r in db.execute('PRAGMA table_info(runtime_inference_attempts)')] != expected:
                raise ProxyError('unsupported_database_version')
            if version is None:
                if db.execute('SELECT 1 FROM runtime_inference_attempts LIMIT 1').fetchone():
                    raise ProxyError('unsupported_database_version')
                db.execute('INSERT INTO runtime_inference_schema VALUES(1,1)')

    def reserve(self, request):
        fields = {'kind','deployment_epoch','campaign_id','config_digest','phase','run_id',
            'fencing_token','run_request_digest','task_binding_digest','round_index',
            'messages_digest','tools_digest','payload_digest','input_tokens','output_tokens','model_identity','deadline','digest'}
        if (type(request) is not dict or set(request) != fields
                or request['kind'] != 'RuntimeInferenceReservationRequest'
                or request['deployment_epoch'] != self.store.deployment_epoch
                or request['phase'] not in {'dev','protected'}
                or type(request['run_id']) is not str or not 1 <= len(request['run_id']) <= 256
                or type(request['fencing_token']) is not int or request['fencing_token'] < 1
                or type(request['round_index']) is not int or not 0 <= request['round_index'] < 16
                or type(request['input_tokens']) is not int or not 0 <= request['input_tokens'] <= 14336
                or type(request['output_tokens']) is not int or request['output_tokens'] != 2048
                or any(type(request[k]) is not str or not DIGEST.fullmatch(request[k]) for k in
                    ('campaign_id','config_digest','run_request_digest','task_binding_digest',
                     'messages_digest','tools_digest','payload_digest','digest'))
                or request['digest'] != digest_jcs({k:v for k,v in request.items() if k != 'digest'})):
            raise ProxyError('invalid_args')
        if (type(request['model_identity']) is not dict or set(request['model_identity']) !=
                {'model_id','model_manifest_digest','tokenizer_hashes'}):
            raise ProxyError('invalid_args')
        from skillloop.protocol import canonical_json_line
        with self.store._transaction() as db:
            run, task, approval = self.store._active_run(db, request['run_id'], request['fencing_token'])
            self.store._check_live(run, approval, db=db)
            original = _load(self.store._one(db,
                'SELECT raw_json FROM staged_objects WHERE digest=? AND kind=?',
                (task['run_request_digest'], 'RunRequest'))[0])
            if (request['campaign_id'] != task['campaign_id']
                    or request['config_digest'] != original['body']['config_digest']
                    or request['run_request_digest'] != task['run_request_digest']
                    or request['task_binding_digest'] != task['binding_digest']):
                raise ProxyError('denied')
            # Privacy is inferred from the actual Evaluator admission, never
            # from a caller's claim or a path containing the word "private".
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            private = False
            if 'evaluator_task_transports' in tables:
                private = db.execute('SELECT 1 FROM evaluator_task_transports p '
                    'JOIN controller_task_admissions a ON a.intent=p.intent WHERE a.task=?',
                    (task['task_instance_id'],)).fetchone() is not None
            if request['phase'] != ('protected' if private else 'dev'):
                raise ProxyError('denied')
            admitted = self.store._one(db, 'SELECT authorization FROM controller_source_admissions WHERE campaign=? AND subject=?',
                (task['campaign_id'],task['subject_digest']))
            config = _load(admitted[0])['config']
            if (digest_jcs(config) != request['config_digest'] or request['model_identity'] !=
                    {k:config.get(k) for k in ('model_id','model_manifest_digest','tokenizer_hashes')}):
                raise ProxyError('denied')
            cancellation = db.execute('SELECT 1 FROM formal_campaign_cancellations WHERE campaign=?',
                (task['campaign_id'],)).fetchone() if 'formal_campaign_cancellations' in tables else None
            if cancellation:
                raise ProxyError('cancelled')
            prior = db.execute('SELECT request_digest FROM runtime_inference_attempts WHERE run_id=? AND round_index=?',
                (request['run_id'], request['round_index'])).fetchone()
            if prior:
                # Returning an original reservation would authorize redispatch.
                # Recovery uses only the original evidence, never this endpoint.
                raise ProxyError('inference_already_spent' if prior[0] == request['digest'] else 'version_conflict')
            attempts = db.execute('SELECT round_index,response_digest FROM runtime_inference_attempts '
                'WHERE run_id=? ORDER BY round_index', (request['run_id'],)).fetchall()
            if ([r[0] for r in attempts] != list(range(request['round_index']))
                    or any(r[1] is None for r in attempts)):
                raise ProxyError('inference_original_unresolved')
            deadline = min(_parse(run['deadline']), _parse(run['approval_lease_expiry']))
            if approval['expires_at'] is not None:
                deadline = min(deadline, _parse(approval['expires_at']))
            value = {'kind':'ProxyRuntimeInferenceReserved','request_digest':request['digest'],
                'deployment_epoch':self.store.deployment_epoch,'run_id':request['run_id'],
                'round_index':request['round_index'],'fencing_token':run['fence'],
                'phase':request['phase'],'deadline':_stamp(deadline),'reserved_at':_stamp(_now()),
                'redispatch_allowed':False,'qualification_issued':False,'request':request}
            value['digest'] = digest_jcs(value)
            db.execute('INSERT INTO runtime_inference_attempts VALUES(?,?,?,?,NULL,NULL)',
                (request['run_id'], request['round_index'], request['digest'], canonical_json_line(value)))
            return value

    def complete(self, request):
        if (type(request) is not dict or set(request) != {'kind','request_digest','response_digest','deadline'}
                or request['kind'] != 'RuntimeInferenceCompletion'
                or any(type(request[k]) is not str or not DIGEST.fullmatch(request[k])
                       for k in ('request_digest','response_digest'))):
            raise ProxyError('invalid_args')
        with self.store._transaction() as db:
            row = self.store._one(db, 'SELECT response_digest FROM runtime_inference_attempts WHERE request_digest=?',
                (request['request_digest'],))
            if row[0] is not None and row[0] != request['response_digest']:
                raise ProxyError('version_conflict')
            # Cancellation/revocation does not erase evidence of a response that
            # already happened; it prevents the next reserve and all late tools.
            db.execute('UPDATE runtime_inference_attempts SET response_digest=?,completed_at=? '
                'WHERE request_digest=? AND response_digest IS NULL',
                (request['response_digest'], _stamp(_now()), request['request_digest']))
            return {'kind':'ProxyRuntimeInferenceRecorded','request_digest':request['request_digest'],
                    'response_digest':request['response_digest'],'redispatch_allowed':False}
