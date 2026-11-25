"""Provisional boot permit from latest captured machine image."""

def issue(db,permit_id,image):
    db.execute('CREATE TABLE IF NOT EXISTS image_rows (page_id TEXT,line_no INTEGER,image TEXT,base TEXT,digest TEXT,signer TEXT,abi TEXT,built_at INTEGER,PRIMARY KEY(page_id,line_no))')
    db.execute('CREATE TABLE IF NOT EXISTS boot_permits (id TEXT PRIMARY KEY,image TEXT,digest TEXT,abi TEXT)')
    row=db.execute('SELECT digest,abi,signer FROM image_rows WHERE image=? ORDER BY built_at DESC LIMIT 1',(image,)).fetchone()
    if not row or row[2]!='trusted':return {'decision':'blocked','image':image}
    with db:db.execute('INSERT INTO boot_permits VALUES (?,?,?,?)',(permit_id,image,row[0],row[1]))
    return {'decision':'issued','digest':row[0],'abi':row[1]}
