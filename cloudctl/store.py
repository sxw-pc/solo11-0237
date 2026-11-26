import json,sqlite3
from contextlib import contextmanager
SCHEMA="""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS demands(id TEXT PRIMARY KEY,app TEXT,start INTEGER,end INTEGER,minimum INTEGER,burst INTEGER,cpu INTEGER,version INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS commitments(demand TEXT PRIMARY KEY,units INTEGER,forecast_version INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS forecasts(app TEXT,version INTEGER,peak INTEGER,observed INTEGER,PRIMARY KEY(app,version));
CREATE TABLE IF NOT EXISTS proposal_forecast(demand TEXT PRIMARY KEY,forecast_version INTEGER,units INTEGER,assessed INTEGER);
CREATE TABLE IF NOT EXISTS releases(demand TEXT PRIMARY KEY,at INTEGER,reason TEXT);
CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,kind TEXT,zone TEXT,cpu INTEGER,ready INTEGER,healthy INTEGER);
CREATE TABLE IF NOT EXISTS provisions(id TEXT PRIMARY KEY,kind TEXT,zone TEXT,requested INTEGER,deadline INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS machine_types(kind TEXT PRIMARY KEY,cpu INTEGER,warmup INTEGER,cost INTEGER);
CREATE TABLE IF NOT EXISTS placements(demand TEXT,node TEXT,replica INTEGER,status TEXT,PRIMARY KEY(demand,replica));
CREATE TABLE IF NOT EXISTS drains(node TEXT PRIMARY KEY,generation INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS drain_moves(node TEXT,generation INTEGER,demand TEXT,replica INTEGER,destination TEXT,PRIMARY KEY(node,generation,demand,replica));
CREATE TABLE IF NOT EXISTS zone_rules(app TEXT PRIMARY KEY,min_zones INTEGER);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,subject TEXT,decision TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS hardware_page_blobs(page_id TEXT PRIMARY KEY,content BLOB,byte_digest TEXT NOT NULL,captured_minute INTEGER,received_at INTEGER,original_result TEXT);
CREATE TABLE IF NOT EXISTS hardware_page_conflicts(seq INTEGER PRIMARY KEY AUTOINCREMENT,page_id TEXT,seen_at INTEGER,old_digest TEXT,new_digest TEXT,detail TEXT);
CREATE TABLE IF NOT EXISTS rack_photos(photo_id TEXT PRIMARY KEY,page_id TEXT,rack TEXT,digest TEXT NOT NULL,captured_minute INTEGER,shows_full_serial INTEGER NOT NULL DEFAULT 0,visible_serial TEXT,summary TEXT);
CREATE TABLE IF NOT EXISTS serial_sightings(seq INTEGER PRIMARY KEY AUTOINCREMENT,page_id TEXT,line_no INTEGER,agent_id TEXT,serial_full TEXT,serial_visible TEXT,serial_tail TEXT,source TEXT,observed_minute INTEGER,digest TEXT);
CREATE TABLE IF NOT EXISTS card_replacement_orders(order_id TEXT PRIMARY KEY,old_card_cert TEXT,new_card_cert TEXT,old_agent_id TEXT,new_agent_id TEXT,chassis_serial TEXT,issued_minute INTEGER,digest TEXT,payload TEXT);
CREATE TABLE IF NOT EXISTS evidence_artifacts(artifact_id TEXT PRIMARY KEY,kind TEXT,reference TEXT,digest TEXT,minute INTEGER,payload TEXT);
CREATE TABLE IF NOT EXISTS attestations(attestation_id TEXT PRIMARY KEY,nonce TEXT NOT NULL UNIQUE,agent_id TEXT,chassis_serial TEXT,cpu INTEGER NOT NULL,rack TEXT,at_minute INTEGER NOT NULL,digest TEXT,payload TEXT);
CREATE TABLE IF NOT EXISTS used_nonces(nonce TEXT PRIMARY KEY,attestation_id TEXT,used_at INTEGER);
CREATE TABLE IF NOT EXISTS chassis_entities(chassis_id TEXT PRIMARY KEY,serial_full TEXT UNIQUE,rack TEXT,cpu INTEGER,proof_level TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active',primary_agent TEXT,created_minute INTEGER,source TEXT);
CREATE TABLE IF NOT EXISTS agent_identity_bindings(agent_id TEXT PRIMARY KEY,card_cert TEXT,chassis_id TEXT,identity_status TEXT NOT NULL,attested_cpu INTEGER,rack TEXT,updated_minute INTEGER);
CREATE TABLE IF NOT EXISTS quarantined_agents(agent_id TEXT PRIMARY KEY,at_minute INTEGER,reason TEXT,active INTEGER NOT NULL DEFAULT 1,restored_minute INTEGER);
CREATE TABLE IF NOT EXISTS chassis_interpretations(interpretation_id TEXT PRIMARY KEY,scene TEXT NOT NULL,kind TEXT NOT NULL,physical_chassis INTEGER NOT NULL,physical_cpu INTEGER NOT NULL,provable_cpu INTEGER NOT NULL,status TEXT NOT NULL,basis TEXT,missing_evidence TEXT);
CREATE TABLE IF NOT EXISTS interpretation_members(interpretation_id TEXT,agent_id TEXT,chassis_id TEXT,PRIMARY KEY(interpretation_id,agent_id));
CREATE TABLE IF NOT EXISTS capacity_certificates_v2(certificate_id TEXT PRIMARY KEY,series TEXT NOT NULL,version INTEGER NOT NULL,claimed_cpu INTEGER NOT NULL,interpretation_id TEXT,interpretation_kind TEXT,basis TEXT NOT NULL,supersedes TEXT,issued_minute INTEGER,kind TEXT);
CREATE TABLE IF NOT EXISTS certificate_dependencies(certificate_id TEXT,ref_kind TEXT,ref_id TEXT,digest TEXT,PRIMARY KEY(certificate_id,ref_kind,ref_id));
CREATE TABLE IF NOT EXISTS certificate_obligations(obligation_id TEXT PRIMARY KEY,old_certificate_id TEXT NOT NULL,new_certificate_id TEXT,claimed_cpu INTEGER,covered_cpu INTEGER,shortfall_cpu INTEGER NOT NULL,status TEXT NOT NULL,created_minute INTEGER,fulfilled_by TEXT,fulfilled_minute INTEGER,note TEXT);
CREATE TABLE IF NOT EXISTS chassis_installs(reference TEXT PRIMARY KEY,chassis_id TEXT,node_id TEXT,serial_full TEXT,cpu INTEGER,rack TEXT,status TEXT,minute INTEGER,detail TEXT);
CREATE TABLE IF NOT EXISTS purchase_orders(po_id TEXT PRIMARY KEY,serial_full TEXT,model TEXT,minute INTEGER,detail TEXT);
CREATE TABLE IF NOT EXISTS resource_usage(seq INTEGER PRIMARY KEY AUTOINCREMENT,chassis_id TEXT,kind TEXT,reference TEXT,minute INTEGER,UNIQUE(chassis_id,kind,reference));
CREATE TABLE IF NOT EXISTS migration_todos(todo_id TEXT PRIMARY KEY,from_agent TEXT NOT NULL,to_agent TEXT,chassis_id TEXT,demand TEXT,replica INTEGER,node TEXT,reason TEXT,status TEXT NOT NULL DEFAULT 'pending',created_minute INTEGER,UNIQUE(demand,replica));
"""
def ensure(db):
    """Idempotently create every table/index on an open connection."""
    db.executescript(SCHEMA)
    db.commit()
def table_exists(db,name):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone() is not None
def init(path):
    db=sqlite3.connect(path)
    try:db.executescript(SCHEMA)
    finally:db.close()
@contextmanager
def tx(path):
    db=sqlite3.connect(path);db.row_factory=sqlite3.Row
    try:db.execute('BEGIN IMMEDIATE');yield db;db.commit()
    except Exception:db.rollback();raise
    finally:db.close()
def one(db,q,a=()):
    r=db.execute(q,a).fetchone();return dict(r) if r else None
def many(db,q,a=()):return [dict(r) for r in db.execute(q,a)]
def event(db,kind,subject,decision,evidence):
    db.execute('INSERT INTO events(kind,subject,decision,evidence) VALUES(?,?,?,?)',(kind,subject,decision,json.dumps(evidence,sort_keys=True)))
    return {'subject':subject,'decision':decision,'evidence':evidence}
