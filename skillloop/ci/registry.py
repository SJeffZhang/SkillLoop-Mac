"""Durable local generation fencing; demonstrates M8 races without GitHub writes."""
import json,sqlite3
from pathlib import Path
from skillloop.protocol import digest_jcs

class LocalRegistry:
    def __init__(self,path: Path):
        self.path=path
        with sqlite3.connect(path) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.executescript('''CREATE TABLE IF NOT EXISTS projects(project TEXT PRIMARY KEY,generation INTEGER,head TEXT,config TEXT);
                CREATE TABLE IF NOT EXISTS triggers(key TEXT PRIMARY KEY,project TEXT,generation INTEGER,campaign TEXT);
                CREATE TABLE IF NOT EXISTS receipts(campaign TEXT PRIMARY KEY,digest TEXT,body TEXT);''')
    def trigger(self,project,head,config,reason='source',prior_attestation=None):
        if reason not in {'source','configuration','renewal'}:raise ValueError('trigger_reason')
        if reason=='renewal' and not prior_attestation:raise ValueError('renewal_requires_prior')
        key=digest_jcs([project,head,config,reason,prior_attestation])
        with sqlite3.connect(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT generation,campaign FROM triggers WHERE key=?',(key,)).fetchone()
            if old:return {'generation':old[0],'campaign':old[1],'deduplicated':True}
            if reason=='renewal':
                prior=db.execute('SELECT t.project FROM receipts r JOIN triggers t ON r.campaign=t.campaign WHERE r.digest=?',(prior_attestation,)).fetchone()
                if prior!=(project,):raise ValueError('renewal_prior_not_verified')
            row=db.execute('SELECT generation FROM projects WHERE project=?',(project,)).fetchone()
            gen=row[0]+1 if row else 1;campaign='local-'+key[7:31]
            db.execute('INSERT OR REPLACE INTO projects VALUES(?,?,?,?)',(project,gen,head,config))
            db.execute('INSERT INTO triggers VALUES(?,?,?,?)',(key,project,gen,campaign))
            return {'generation':gen,'campaign':campaign,'deduplicated':False}
    def complete(self,project,head,config,generation,campaign,decision):
        with sqlite3.connect(self.path) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT generation,head,config FROM projects WHERE project=?',(project,)).fetchone()
            if row!=(generation,head,config):raise ValueError('stale_generation')
            known=db.execute('SELECT generation,campaign FROM triggers WHERE project=? AND generation=?',(project,generation)).fetchone()
            if known!=(generation,campaign):raise ValueError('unknown_campaign')
            digest=digest_jcs(decision);prior=db.execute('SELECT digest FROM receipts WHERE campaign=?',(campaign,)).fetchone()
            if prior and prior[0]!=digest:raise ValueError('immutable_receipt')
            db.execute('INSERT OR IGNORE INTO receipts VALUES(?,?,?)',(campaign,digest,json.dumps(decision)))
            return digest

    def verify_current(self,project,head,config,generation,campaign,decision):
        """Read the exact generation without committing a qualification receipt.

        GitHub transport can fail or return an unknown result. A pre-write
        identity fence must not record a locally completed campaign merely
        because a remote Check was still pending.
        """
        with sqlite3.connect(self.path) as db:
            db.execute('BEGIN')
            row=db.execute('SELECT generation,head,config FROM projects WHERE project=?',(project,)).fetchone()
            if row!=(generation,head,config):raise ValueError('stale_generation')
            known=db.execute('SELECT generation,campaign FROM triggers WHERE project=? AND generation=?',(project,generation)).fetchone()
            if known!=(generation,campaign):raise ValueError('unknown_campaign')
            prior=db.execute('SELECT digest FROM receipts WHERE campaign=?',(campaign,)).fetchone()
            if prior and prior[0]!=digest_jcs(decision):raise ValueError('immutable_receipt')
            return digest_jcs(decision)
