"""Import offline address-lease journals from fabric agents."""
import hashlib,json

def import_page(db,page_id,rows,received_at):
    db.execute('CREATE TABLE IF NOT EXISTS lease_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS lease_rows (page_id TEXT,line_no INTEGER,agent TEXT,tenant TEXT,node TEXT,address TEXT,start INTEGER,expires INTEGER,PRIMARY KEY(page_id,line_no))')
    keys={'agent','tenant','node','address','start','expires'}
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!=keys or not isinstance(r['start'],int) or not isinstance(r['expires'],int) or r['start']>=r['expires'] for r in rows):raise ValueError('invalid_lease_page')
    digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    old=db.execute('SELECT digest FROM lease_pages WHERE id=?',(page_id,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('lease_page_conflict')
        return {'status':'replayed','rows':len(rows)}
    with db:
        db.execute('INSERT INTO lease_pages VALUES (?,?,?)',(page_id,digest,received_at))
        for i,r in enumerate(rows,1):db.execute('INSERT INTO lease_rows VALUES (?,?,?,?,?,?,?,?)',(page_id,i,r['agent'],r['tenant'],r['node'],r['address'],r['start'],r['expires']))
    return {'status':'captured','rows':len(rows)}
