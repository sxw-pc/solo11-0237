"""Capture immutable offline inventory pages from two management agents."""
import hashlib,json

def import_page(db,page_id,rows,received_at):
    db.execute('CREATE TABLE IF NOT EXISTS hardware_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS hardware_rows (page_id TEXT,line_no INTEGER,agent_id TEXT,card_cert TEXT,serial_tail TEXT,rack TEXT,cpu INTEGER,PRIMARY KEY(page_id,line_no))')
    keys={'agent_id','card_cert','serial_tail','rack','cpu'}
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!=keys or not isinstance(r['cpu'],int) or r['cpu']<=0 for r in rows):raise ValueError('invalid_hardware_page')
    digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    old=db.execute('SELECT digest FROM hardware_pages WHERE id=?',(page_id,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('hardware_page_conflict')
        return {'status':'replayed','rows':len(rows)}
    with db:
        db.execute('INSERT INTO hardware_pages VALUES (?,?,?)',(page_id,digest,received_at))
        for i,r in enumerate(rows,1):db.execute('INSERT INTO hardware_rows VALUES (?,?,?,?,?,?,?)',(page_id,i,r['agent_id'],r['card_cert'],r['serial_tail'],r['rack'],r['cpu']))
    return {'status':'captured','rows':len(rows)}
