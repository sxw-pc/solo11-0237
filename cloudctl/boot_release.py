"""Boot permits bound to the closed, evidence-backed image lineage chain.

A permit is issued only when the requested image resolves to one unambiguous
digest whose whole base-layer chain is captured, every layer carries a file
byte digest and a builder sign-off, and no layer's signer was revoked before
its build time. The permit binds the full digest chain and the client-required
compatible interface; a tag or a signer string never stands in for bytes.
Blocked attempts commit nothing, so a retry after the evidence arrives
re-evaluates from scratch.
"""
import json

def _ensure(db):
    db.execute('CREATE TABLE IF NOT EXISTS image_rows (page_id TEXT,line_no INTEGER,image TEXT,base TEXT,digest TEXT,signer TEXT,abi TEXT,built_at INTEGER,PRIMARY KEY(page_id,line_no))')
    db.execute('CREATE TABLE IF NOT EXISTS image_files (id TEXT PRIMARY KEY,name TEXT NOT NULL,digest TEXT NOT NULL,recorded_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS signoffs (id TEXT PRIMARY KEY,digest TEXT NOT NULL,signer TEXT NOT NULL,signed_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS revocations (id TEXT PRIMARY KEY,signer TEXT NOT NULL,revoked_at INTEGER NOT NULL,received_at INTEGER NOT NULL,quarantined TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS boot_permits (id TEXT PRIMARY KEY,image TEXT NOT NULL,digest TEXT NOT NULL,abi TEXT NOT NULL,chain TEXT NOT NULL,layers TEXT NOT NULL,issued_at INTEGER)')

def _rows_for(db,image):
    return db.execute('SELECT image,base,digest,signer,abi,built_at FROM image_rows WHERE image=? ORDER BY built_at DESC,page_id,line_no',(image,)).fetchall()

def _resolve_chain(db,image):
    """Resolve image name to its closed dependency chain (top first), or an error."""
    rows=_rows_for(db,image)
    if not rows:return None,{'reason':'unknown_image'}
    if len({r[2] for r in rows})>1:return None,{'reason':'ambiguous_image','layer':image}
    chain=[];visited=set();current=rows[0]
    while True:
        digest=current[2]
        if digest in visited:return None,{'reason':'cycle','layer':current[0]}
        visited.add(digest)
        chain.append({'image':current[0],'base':current[1],'digest':digest,'signer':current[3],'abi':current[4],'built_at':current[5]})
        base=current[1]
        if not base:return chain,None
        base_rows=_rows_for(db,base)
        if not base_rows:return None,{'reason':'missing_layer','layer':base}
        if len({r[2] for r in base_rows})>1:return None,{'reason':'ambiguous_layer','layer':base}
        current=base_rows[0]

def _layer_problem(db,layer):
    if not db.execute('SELECT 1 FROM image_files WHERE digest=?',(layer['digest'],)).fetchone():return 'missing_file'
    if not db.execute('SELECT 1 FROM signoffs WHERE digest=? AND signer=? AND signed_at>=?',(layer['digest'],layer['signer'],layer['built_at'])).fetchone():return 'missing_signoff'
    if db.execute('SELECT 1 FROM revocations WHERE signer=? AND revoked_at<=?',(layer['signer'],layer['built_at'])).fetchone():return 'revoked_signer'
    return None

def issue(db,permit_id,image,abi=None,issued_at=None):
    _ensure(db)
    old=db.execute('SELECT image,digest,abi,chain,layers,issued_at FROM boot_permits WHERE id=?',(permit_id,)).fetchone()
    if old:
        if old[0]!=image or (abi is not None and old[2]!=abi):raise ValueError('boot_permit_conflict')
        return {'decision':'issued','permit':permit_id,'image':old[0],'digest':old[1],'abi':old[2],'chain':json.loads(old[3]),'layers':json.loads(old[4]),'issued_at':old[5],'replayed':True}
    chain,error=_resolve_chain(db,image)
    if error:return {'decision':'blocked','image':image,**error}
    if abi is not None and chain[0]['abi']!=abi:return {'decision':'blocked','image':image,'reason':'abi_mismatch','expected':abi,'actual':chain[0]['abi']}
    for layer in chain:
        problem=_layer_problem(db,layer)
        if problem:return {'decision':'blocked','image':image,'reason':problem,'layer':layer['image'],'digest':layer['digest']}
    bound_abi=abi if abi is not None else chain[0]['abi']
    digests=[layer['digest'] for layer in chain]
    with db:db.execute('INSERT INTO boot_permits VALUES (?,?,?,?,?,?,?)',(permit_id,image,chain[0]['digest'],bound_abi,json.dumps(digests),json.dumps(chain,sort_keys=True),issued_at))
    return {'decision':'issued','permit':permit_id,'image':image,'digest':chain[0]['digest'],'abi':bound_abi,'chain':digests,'layers':chain,'issued_at':issued_at}
