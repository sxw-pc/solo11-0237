"""Import offline machine-image registry manifest pages and supply-chain evidence.

Captured originals are append-only: manifest pages, image file byte digests,
builder sign-offs and revocation notices are never overwritten or deleted.
Every record is idempotent by its commit id so a crashed or retried import
recovers the original result instead of applying twice.
"""
import hashlib,json

PAGE_KEYS={'image','base','digest','signer','abi','built_at'}

def _ensure_evidence(db):
    db.execute('CREATE TABLE IF NOT EXISTS image_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS image_rows (page_id TEXT,line_no INTEGER,image TEXT,base TEXT,digest TEXT,signer TEXT,abi TEXT,built_at INTEGER,PRIMARY KEY(page_id,line_no))')
    db.execute('CREATE TABLE IF NOT EXISTS image_files (id TEXT PRIMARY KEY,name TEXT NOT NULL,digest TEXT NOT NULL,recorded_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS signoffs (id TEXT PRIMARY KEY,digest TEXT NOT NULL,signer TEXT NOT NULL,signed_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS revocations (id TEXT PRIMARY KEY,signer TEXT NOT NULL,revoked_at INTEGER NOT NULL,received_at INTEGER NOT NULL,quarantined TEXT NOT NULL)')

def _ensure_machines(db):
    db.execute('CREATE TABLE IF NOT EXISTS machine_states (machine TEXT PRIMARY KEY,permit TEXT,digest TEXT,chain TEXT,loaded_at INTEGER,status TEXT NOT NULL,migration_owed INTEGER NOT NULL DEFAULT 0)')
    db.execute('CREATE TABLE IF NOT EXISTS machine_history (seq INTEGER PRIMARY KEY AUTOINCREMENT,machine TEXT NOT NULL,at INTEGER,kind TEXT NOT NULL,detail TEXT NOT NULL)')

def import_page(db,page_id,rows,received_at):
    _ensure_evidence(db)
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!=PAGE_KEYS or not isinstance(r['built_at'],int) or not r['image'] or not r['digest'] for r in rows):raise ValueError('invalid_image_page')
    digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    old=db.execute('SELECT digest FROM image_pages WHERE id=?',(page_id,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('image_page_conflict')
        return {'status':'replayed','rows':len(rows)}
    with db:
        db.execute('INSERT INTO image_pages VALUES (?,?,?)',(page_id,digest,received_at))
        for i,r in enumerate(rows,1):db.execute('INSERT INTO image_rows VALUES (?,?,?,?,?,?,?,?)',(page_id,i,r['image'],r['base'],r['digest'],r['signer'],r['abi'],r['built_at']))
    return {'status':'captured','rows':len(rows)}

def record_file(db,file_id,name,digest,recorded_at):
    """Record the byte digest of an image file; resending the same file replays the original result."""
    _ensure_evidence(db)
    if not file_id or not name or not digest or not isinstance(recorded_at,int):raise ValueError('invalid_image_file')
    old=db.execute('SELECT name,digest,recorded_at FROM image_files WHERE id=?',(file_id,)).fetchone()
    if old:
        if (old[0],old[1],old[2])!=(name,digest,recorded_at):raise ValueError('image_file_conflict')
        return {'status':'replayed','digest':old[1]}
    with db:db.execute('INSERT INTO image_files VALUES (?,?,?,?)',(file_id,name,digest,recorded_at))
    return {'status':'recorded','digest':digest}

def record_signoff(db,signoff_id,digest,signer,signed_at):
    """Record a builder sign-off binding an image digest to its signer at a signing time."""
    _ensure_evidence(db)
    if not signoff_id or not digest or not signer or not isinstance(signed_at,int):raise ValueError('invalid_signoff')
    old=db.execute('SELECT digest,signer,signed_at FROM signoffs WHERE id=?',(signoff_id,)).fetchone()
    if old:
        if (old[0],old[1],old[2])!=(digest,signer,signed_at):raise ValueError('signoff_conflict')
        return {'status':'replayed','digest':old[0]}
    with db:db.execute('INSERT INTO signoffs VALUES (?,?,?,?)',(signoff_id,digest,signer,signed_at))
    return {'status':'recorded','digest':digest}

def _chain_revoked_by(db,chain,signer,revoked_at):
    for digest in chain:
        for row_signer,built_at in db.execute('SELECT DISTINCT signer,built_at FROM image_rows WHERE digest=?',(digest,)):
            if row_signer==signer and revoked_at<=built_at:return True
    return False

def record_revocation(db,notice_id,signer,revoked_at,received_at):
    """Record a revocation notice. Already-booted machines whose loaded digest chain
    it invalidates are marked quarantined with a customer-migration obligation;
    their permits and load receipts are kept as committed facts."""
    _ensure_evidence(db);_ensure_machines(db)
    if not notice_id or not signer or not isinstance(revoked_at,int) or not isinstance(received_at,int):raise ValueError('invalid_revocation')
    old=db.execute('SELECT signer,revoked_at,received_at,quarantined FROM revocations WHERE id=?',(notice_id,)).fetchone()
    if old:
        if (old[0],old[1],old[2])!=(signer,revoked_at,received_at):raise ValueError('revocation_conflict')
        return {'status':'replayed','signer':old[0],'quarantined':json.loads(old[3])}
    quarantined=[]
    for machine,chain in db.execute("SELECT machine,chain FROM machine_states WHERE status IN ('running','serving')"):
        if _chain_revoked_by(db,json.loads(chain),signer,revoked_at):quarantined.append(machine)
    with db:
        db.execute('INSERT INTO revocations VALUES (?,?,?,?,?)',(notice_id,signer,revoked_at,received_at,json.dumps(quarantined)))
        for machine in quarantined:
            db.execute("UPDATE machine_states SET status='quarantined',migration_owed=1 WHERE machine=?",(machine,))
            db.execute('INSERT INTO machine_history(machine,at,kind,detail) VALUES (?,?,?,?)',(machine,received_at,'quarantined',json.dumps({'notice':notice_id,'signer':signer},sort_keys=True)))
    return {'status':'recorded','signer':signer,'quarantined':quarantined}
