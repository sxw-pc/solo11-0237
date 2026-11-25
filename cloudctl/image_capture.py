"""Import offline machine-image registry manifest pages."""
import hashlib,json

def import_page(db,page_id,rows,received_at):
    db.execute('CREATE TABLE IF NOT EXISTS image_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS image_rows (page_id TEXT,line_no INTEGER,image TEXT,base TEXT,digest TEXT,signer TEXT,abi TEXT,built_at INTEGER,PRIMARY KEY(page_id,line_no))')
    keys={'image','base','digest','signer','abi','built_at'}
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!=keys or not isinstance(r['built_at'],int) or not r['image'] or not r['digest'] for r in rows):raise ValueError('invalid_image_page')
    digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    old=db.execute('SELECT digest FROM image_pages WHERE id=?',(page_id,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('image_page_conflict')
        return {'status':'replayed','rows':len(rows)}
    with db:
        db.execute('INSERT INTO image_pages VALUES (?,?,?)',(page_id,digest,received_at))
        for i,r in enumerate(rows,1):db.execute('INSERT INTO image_rows VALUES (?,?,?,?,?,?,?,?)',(page_id,i,r['image'],r['base'],r['digest'],r['signer'],r['abi'],r['built_at']))
    return {'status':'captured','rows':len(rows)}
