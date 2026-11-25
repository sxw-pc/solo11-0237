"""Offline cooling-loop flow and temperature meter pages."""
import hashlib,json

def import_page(db,page_id,rows,received_at):
    db.execute('CREATE TABLE IF NOT EXISTS cooling_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS cooling_rows (page_id TEXT,line_no INTEGER,meter TEXT,loop TEXT,tick INTEGER,flow_lpm INTEGER,temp_c INTEGER,PRIMARY KEY(page_id,line_no))')
    keys={'meter','loop','tick','flow_lpm','temp_c'}
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!=keys or not isinstance(r['tick'],int) or not isinstance(r['flow_lpm'],int) or not isinstance(r['temp_c'],int) or r['flow_lpm']<0 for r in rows):raise ValueError('invalid_cooling_page')
    digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    old=db.execute('SELECT digest FROM cooling_pages WHERE id=?',(page_id,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('cooling_page_conflict')
        return {'status':'replayed','rows':len(rows)}
    with db:
        db.execute('INSERT INTO cooling_pages VALUES (?,?,?)',(page_id,digest,received_at))
        for i,r in enumerate(rows,1):db.execute('INSERT INTO cooling_rows VALUES (?,?,?,?,?,?,?)',(page_id,i,r['meter'],r['loop'],r['tick'],r['flow_lpm'],r['temp_c']))
    return {'status':'captured','rows':len(rows)}
