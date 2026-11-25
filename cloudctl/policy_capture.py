"""Import offline ordered firewall-policy pages."""
import hashlib,json

def import_page(db,page_id,rows,received_at):
    db.execute('CREATE TABLE IF NOT EXISTS policy_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS policy_rows (page_id TEXT,line_no INTEGER,rule_id TEXT,priority INTEGER,src_prefix TEXT,dst_port INTEGER,action TEXT,PRIMARY KEY(page_id,line_no))')
    keys={'rule_id','priority','src_prefix','dst_port','action'}
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!=keys or not isinstance(r['priority'],int) or not isinstance(r['dst_port'],int) or r['action'] not in ('allow','deny') for r in rows):raise ValueError('invalid_policy_page')
    digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    old=db.execute('SELECT digest FROM policy_pages WHERE id=?',(page_id,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('policy_page_conflict')
        return {'status':'replayed','rows':len(rows)}
    with db:
        db.execute('INSERT INTO policy_pages VALUES (?,?,?)',(page_id,digest,received_at))
        for i,r in enumerate(rows,1):db.execute('INSERT INTO policy_rows VALUES (?,?,?,?,?,?,?)',(page_id,i,r['rule_id'],r['priority'],r['src_prefix'],r['dst_port'],r['action']))
    return {'status':'captured','rows':len(rows)}
