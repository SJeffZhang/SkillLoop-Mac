"""Bounded complete logical identity of an actual consistent SQLite export."""
import hashlib

from skillloop.protocol import canonical_json_line, digest_bytes


def snapshot_content_digest(db, within_budget):
    schemas=[list(row) for row in db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")]
    if len(schemas)>256:raise ValueError('snapshot_schema_capacity')
    identity=hashlib.sha256();identity.update(canonical_json_line(schemas))
    identity.update(canonical_json_line({'user_version':db.execute('PRAGMA user_version').fetchone()[0],
        'application_id':db.execute('PRAGMA application_id').fetchone()[0]}))
    rows_seen=0;bytes_seen=0
    for kind,name,_,_ in schemas:
        if kind!='table':continue
        within_budget();rows=[]
        quoted='"'+name.replace('"','""')+'"'
        for row in db.execute('SELECT * FROM '+quoted):
            within_budget();values=[];rows_seen+=1
            if rows_seen>131072:raise ValueError('snapshot_row_capacity')
            for cell in row:
                if isinstance(cell,bytes):
                    bytes_seen+=len(cell);values.append({'blob':digest_bytes(cell),'bytes':len(cell)})
                else:
                    if isinstance(cell,str):bytes_seen+=len(cell.encode('utf-8'))
                    values.append({'type':type(cell).__name__,'value':cell})
            if bytes_seen>268435456:raise ValueError('snapshot_logical_capacity')
            rows.append(digest_bytes(canonical_json_line(values)))
        identity.update(canonical_json_line({'table':name,'rows':sorted(rows)}))
    return 'sha256:'+identity.hexdigest()
