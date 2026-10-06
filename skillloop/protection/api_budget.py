"""Durable monetary reservations. Unknown delivery retains its full charge."""
import sqlite3
from decimal import Decimal,ROUND_CEILING
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4
from skillloop.protocol import digest_jcs

class APIBudget:
    def __init__(self,path:Path,*,input_rate:str,output_rate:str,limit_rmb:str='10.00'):
        self.path=path;self.input=Decimal(input_rate);self.output=Decimal(output_rate);self.limit=Decimal(limit_rmb)
        if not all(v.is_finite() for v in (self.input,self.output,self.limit)) or min(self.input,self.output)<0 or not 0<self.limit<=10:
            raise ValueError('invalid_api_rates_or_limit')
        self.limit_micro=int(self.limit*1000000)
        binding=digest_jcs({'input_rate':input_rate,'output_rate':output_rate,'limit_rmb':limit_rmb})
        with self.connect() as db:
            db.executescript('''BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE IF NOT EXISTS reservations(key TEXT PRIMARY KEY,reserved_micro INTEGER NOT NULL,
                charged_micro INTEGER NOT NULL,state TEXT NOT NULL,input_tokens INTEGER,output_tokens INTEGER);''')
            old=db.execute('SELECT value FROM metadata WHERE key=?',('binding',)).fetchone()
            if old and old[0]!=binding:raise ValueError('api_budget_identity_changed')
            db.execute('INSERT OR IGNORE INTO metadata VALUES(?,?)',('binding',binding))
    def connect(self):return sqlite3.connect(self.path,timeout=10)
    def price(self,input_tokens,output_tokens):
        if any(type(v) is not int or v<0 for v in (input_tokens,output_tokens)):raise ValueError('invalid_token_count')
        return int((input_tokens*self.input+output_tokens*self.output).to_integral_value(rounding=ROUND_CEILING))
    def reserve(self,key,input_tokens,output_tokens):
        charge=self.price(input_tokens,output_tokens)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM reservations WHERE key=?',(key,)).fetchone():raise ValueError('api_request_already_reserved')
            used=db.execute('SELECT COALESCE(SUM(charged_micro),0) FROM reservations').fetchone()[0]
            if used+charge>self.limit_micro:raise ValueError('api_cost_cap_exceeded')
            db.execute('INSERT INTO reservations VALUES(?,?,?, ?,NULL,NULL)',(key,charge,charge,'reserved'))
        return charge
    def finish(self,key,input_tokens,output_tokens):
        charge=self.price(input_tokens,output_tokens)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT reserved_micro,state FROM reservations WHERE key=?',(key,)).fetchone()
            if old is None or old[1]!='reserved':raise ValueError('api_reservation_state')
            if charge>old[0]:raise ValueError('api_returned_usage_exceeds_reservation')
            db.execute('UPDATE reservations SET charged_micro=?,state=?,input_tokens=?,output_tokens=? WHERE key=?',
                (charge,'complete',input_tokens,output_tokens,key))
        return charge
    def spent_micro(self):
        with self.connect() as db:return db.execute('SELECT COALESCE(SUM(charged_micro),0) FROM reservations').fetchone()[0]


class ScopedAPIBudget:
    """Apply a bounded campaign ceiling over the existing shared reservations table.

    The legacy APIBudget identity remains bound to its existing configured cap
    (currently RMB 10). This wrapper validates that identity, then atomically
    enforces the explicitly authorized campaign ceiling without changing the
    ledger metadata or creating a second ledger.
    """

    def __init__(self, path: Path, *, input_rate: str, output_rate: str,
                 limit_rmb: str, legacy_limit_rmb: str = '10.00',
                 scope_id: str = 'm6-markdown-refunds-api-v1'):
        self.legacy = APIBudget(path, input_rate=input_rate,
            output_rate=output_rate, limit_rmb=legacy_limit_rmb)
        self.limit_micro = int(Decimal(limit_rmb) * 1_000_000)
        if not Decimal(limit_rmb).is_finite() or not 0 < self.limit_micro <= 50_000_000:
            raise ValueError('invalid_scoped_api_limit')
        if scope_id != 'm6-markdown-refunds-api-v1' or self.limit_micro != 50_000_000:
            raise ValueError('invalid_scoped_api_identity')
        self.scope_id = scope_id
        with self.legacy.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS campaign_caps(scope TEXT PRIMARY KEY,limit_micro INTEGER NOT NULL,baseline_micro INTEGER NOT NULL,event_id TEXT NOT NULL,created_at TEXT NOT NULL)')
            row = db.execute('SELECT limit_micro,baseline_micro,event_id FROM campaign_caps WHERE scope=?',
                (scope_id,)).fetchone()
            if row is None:
                baseline = db.execute('SELECT COALESCE(SUM(charged_micro),0) FROM reservations').fetchone()[0]
                event_id = 'm6-api-cap-' + uuid4().hex
                created_at = datetime.now(timezone.utc).isoformat()
                db.execute('INSERT INTO campaign_caps VALUES(?,?,?,?,?)',
                    (scope_id, self.limit_micro, baseline, event_id, created_at))
                self.baseline_micro, self.event_id = baseline, event_id
            else:
                if row[0] != self.limit_micro:
                    raise ValueError('scoped_api_cap_changed')
                self.baseline_micro, self.event_id = row[1], row[2]

    def reserve(self, key, input_tokens, output_tokens):
        if not key.startswith('m6-joint-api-'):
            raise ValueError('scoped_api_request_id')
        charge = self.legacy.price(input_tokens, output_tokens)
        with self.legacy.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM reservations WHERE key=?', (key,)).fetchone():
                raise ValueError('api_request_already_reserved')
            used = db.execute('SELECT COALESCE(SUM(charged_micro),0) FROM reservations').fetchone()[0]
            if used + charge > self.limit_micro:
                raise ValueError('scoped_api_cost_cap_exceeded')
            db.execute('INSERT INTO reservations VALUES(?,?,?, ?,NULL,NULL)',
                (key, charge, charge, 'reserved'))
        return charge

    def finish(self, key, input_tokens, output_tokens):
        charge = self.legacy.price(input_tokens, output_tokens)
        with self.legacy.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT reserved_micro,state FROM reservations WHERE key=?', (key,)).fetchone()
            if old is None or old[1] != 'reserved':
                raise ValueError('api_reservation_state')
            if charge > old[0]:
                raise ValueError('api_returned_usage_exceeds_reservation')
            db.execute('UPDATE reservations SET charged_micro=?,state=?,input_tokens=?,output_tokens=? WHERE key=?',
                (charge, 'complete', input_tokens, output_tokens, key))
        return charge

    def spent_micro(self):
        return self.legacy.spent_micro()
