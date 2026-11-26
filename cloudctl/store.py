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
"""
from .lease_capture import SCHEMA as ADDRESS_SCHEMA, _SCHEMA_VERSION
SCHEMA = SCHEMA + '\n' + ADDRESS_SCHEMA
def init(path):
    db=sqlite3.connect(path)
    try:
        db.executescript(SCHEMA)
        db.execute('PRAGMA user_version=%d' % _SCHEMA_VERSION)
        db.commit()
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
