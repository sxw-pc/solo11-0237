"""Real-machine measured-load receipts, quarantine, rollback and service-open records.

A signed permit alone never counts as a running version: a machine serves the
workload only after a measured-load receipt proves it loaded exactly the digest
chain its permit binds, and that chain is still qualified under every
revocation captured so far. Receipts, state transitions and recovery (rollback)
records are append-only, so late manifest pages or notices never silently
delete running tasks or completed processing records. Every step recovers by
its commit id after a power loss or retry.
"""
import json

def _ensure(db):
    db.execute('CREATE TABLE IF NOT EXISTS image_rows (page_id TEXT,line_no INTEGER,image TEXT,base TEXT,digest TEXT,signer TEXT,abi TEXT,built_at INTEGER,PRIMARY KEY(page_id,line_no))')
    db.execute('CREATE TABLE IF NOT EXISTS revocations (id TEXT PRIMARY KEY,signer TEXT NOT NULL,revoked_at INTEGER NOT NULL,received_at INTEGER NOT NULL,quarantined TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS boot_permits (id TEXT PRIMARY KEY,image TEXT NOT NULL,digest TEXT NOT NULL,abi TEXT NOT NULL,chain TEXT NOT NULL,layers TEXT NOT NULL,issued_at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS load_receipts (id TEXT PRIMARY KEY,machine TEXT NOT NULL,permit TEXT,digest TEXT NOT NULL,chain TEXT NOT NULL,loaded_at INTEGER NOT NULL,decision TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS machine_states (machine TEXT PRIMARY KEY,permit TEXT,digest TEXT,chain TEXT,loaded_at INTEGER,status TEXT NOT NULL,migration_owed INTEGER NOT NULL DEFAULT 0)')
    db.execute('CREATE TABLE IF NOT EXISTS machine_history (seq INTEGER PRIMARY KEY AUTOINCREMENT,machine TEXT NOT NULL,at INTEGER,kind TEXT NOT NULL,detail TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS service_opens (id TEXT PRIMARY KEY,machine TEXT NOT NULL,opened_at INTEGER NOT NULL)')

def _revoked_digest(db,chain):
    for digest in chain:
        for signer,built_at in db.execute('SELECT DISTINCT signer,built_at FROM image_rows WHERE digest=?',(digest,)):
            if db.execute('SELECT 1 FROM revocations WHERE signer=? AND revoked_at<=?',(signer,built_at)).fetchone():return digest
    return None

def _history(db,machine,at,kind,detail):
    db.execute('INSERT INTO machine_history(machine,at,kind,detail) VALUES (?,?,?,?)',(machine,at,kind,json.dumps(detail,sort_keys=True)))

def _set_state(db,machine,permit_id,chain,loaded_at,status,migration_owed):
    db.execute('INSERT OR REPLACE INTO machine_states(machine,permit,digest,chain,loaded_at,status,migration_owed) VALUES (?,?,?,?,?,?,?)',(machine,permit_id,chain[0],json.dumps(chain),loaded_at,status,migration_owed))

def record_load(db,receipt_id,machine,permit_id,chain,loaded_at):
    """Record a machine's measured-load receipt. The loaded digest chain must equal
    the chain the permit binds; a machine that loads anything else, or a chain
    invalidated by a captured revocation, is quarantined until it re-proves."""
    _ensure(db)
    if not receipt_id or not machine or not isinstance(chain,list) or not chain or any(not isinstance(d,str) or not d for d in chain) or not isinstance(loaded_at,int):raise ValueError('invalid_load_receipt')
    old=db.execute('SELECT machine,permit,digest,chain,loaded_at,decision FROM load_receipts WHERE id=?',(receipt_id,)).fetchone()
    if old:
        if (old[0],old[1],old[2],json.loads(old[3]),old[4])!=(machine,permit_id,chain[0],list(chain),loaded_at):raise ValueError('load_receipt_conflict')
        return {'decision':old[5],'receipt':receipt_id,'machine':machine,'digest':old[2],'chain':json.loads(old[3]),'replayed':True}
    permit=db.execute('SELECT chain FROM boot_permits WHERE id=?',(permit_id,)).fetchone() if permit_id else None
    if not permit:decision='no_permit'
    elif json.loads(permit[0])!=list(chain):decision='chain_mismatch'
    elif _revoked_digest(db,chain):decision='quarantined'
    else:decision='running'
    prev=db.execute('SELECT status,digest FROM machine_states WHERE machine=?',(machine,)).fetchone()
    with db:
        db.execute('INSERT INTO load_receipts VALUES (?,?,?,?,?,?,?)',(receipt_id,machine,permit_id,chain[0],json.dumps(chain),loaded_at,decision))
        if decision=='running':
            kind='loaded' if not prev else 'recovered' if prev[0]=='quarantined' else 'reloaded'
            _set_state(db,machine,permit_id,chain,loaded_at,'running',0)
            _history(db,machine,loaded_at,kind,{'receipt':receipt_id,'permit':permit_id,'chain':list(chain),'previous_digest':prev[1] if prev else None})
        else:
            _set_state(db,machine,permit_id,chain,loaded_at,'quarantined',1)
            _history(db,machine,loaded_at,'quarantined',{'receipt':receipt_id,'permit':permit_id,'chain':list(chain),'reason':decision})
    return {'decision':decision,'receipt':receipt_id,'machine':machine,'digest':chain[0],'chain':list(chain)}

def open_service(db,open_id,machine,opened_at):
    """Open a proven machine to customer traffic; recoverable by its commit id."""
    _ensure(db)
    if not open_id or not machine or not isinstance(opened_at,int):raise ValueError('invalid_service_open')
    old=db.execute('SELECT machine,opened_at FROM service_opens WHERE id=?',(open_id,)).fetchone()
    if old:
        if (old[0],old[1])!=(machine,opened_at):raise ValueError('service_open_conflict')
        return {'decision':'serving','open':open_id,'machine':machine,'replayed':True}
    state=db.execute('SELECT status FROM machine_states WHERE machine=?',(machine,)).fetchone()
    if not state or state[0]!='running':return {'decision':'not_running','machine':machine}
    with db:
        db.execute('INSERT INTO service_opens VALUES (?,?,?)',(open_id,machine,opened_at))
        db.execute("UPDATE machine_states SET status='serving' WHERE machine=?",(machine,))
        _history(db,machine,opened_at,'opened',{'open':open_id})
    return {'decision':'serving','open':open_id,'machine':machine}

def status(db,machine):
    _ensure(db)
    row=db.execute('SELECT permit,digest,chain,loaded_at,status,migration_owed FROM machine_states WHERE machine=?',(machine,)).fetchone()
    if not row:return {'machine':machine,'status':'unknown'}
    return {'machine':machine,'permit':row[0],'digest':row[1],'chain':json.loads(row[2]),'loaded_at':row[3],'status':row[4],'migration_owed':bool(row[5])}

def history(db,machine):
    _ensure(db)
    return [{'at':at,'kind':kind,'detail':json.loads(detail)} for at,kind,detail in db.execute('SELECT at,kind,detail FROM machine_history WHERE machine=? ORDER BY seq',(machine,))]
