"""Capture detector telemetry pages and preserve field evidence.

Two ordering clocks are kept for every piece of intake evidence:

* ``occurred_at`` -- the minute at which the physical fact happened
  (detector tick, valve position, person exit, ...);
* ``received_at`` -- the minute at which the system received the record.

The auto-increment ``response_ledger.seq`` is the true arrival/capture order.
Late-arriving facts therefore keep their early occurrence time without being
allowed to rewrite decisions that were already taken before they arrived.
"""
import hashlib
import json


LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS intake_submissions (
    ref TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    result_json TEXT,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS response_ledger (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    ref TEXT,
    subject TEXT,
    occurred_at INTEGER,
    received_at INTEGER,
    payload_json TEXT
);
"""


def ensure_ledger(db):
    db.executescript(LEDGER_SCHEMA)


def canonical_digest(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')
    ).hexdigest()


def ledger_append(db, kind, payload=None, ref=None, subject=None,
                  occurred_at=None, received_at=None):
    """Append one immutable evidence entry in arrival (capture) order."""
    ensure_ledger(db)
    cur = db.execute(
        'INSERT INTO response_ledger (kind,ref,subject,occurred_at,received_at,payload_json)'
        ' VALUES (?,?,?,?,?,?)',
        (kind, ref, subject, occurred_at, received_at,
         json.dumps(payload or {}, sort_keys=True, default=str)),
    )
    return cur.lastrowid


def accept_record(db, ref, kind, payload, at, received_at=None, subject=None, write=None):
    """Idempotent intake for numbered records.

    Same ``ref`` + same content replays the stored result without adding a
    ledger entry.  Same ``ref`` + different content raises ``<kind>_conflict``
    and leaves the original record untouched.  New records are inserted by
    ``write(db)`` together with the intake/ledger rows in one transaction.
    """
    ensure_ledger(db)
    received_at = at if received_at is None else received_at
    digest = canonical_digest({'kind': kind, 'payload': payload})
    old = db.execute(
        'SELECT digest,result_json FROM intake_submissions WHERE ref=?', (ref,)
    ).fetchone()
    if old is not None:
        if old[0] != digest:
            raise ValueError('%s_conflict' % kind)
        result = json.loads(old[1]) if old[1] else {}
        result.update({'status': 'idempotent', 'ref': ref})
        return result
    result = {}
    with db:
        if write is not None:
            result = write(db) or {}
        ledger_append(
            db, kind, payload=payload, ref=ref, subject=subject,
            occurred_at=at, received_at=received_at,
        )
        db.execute(
            'INSERT INTO intake_submissions (ref,kind,digest,result_json,received_at)'
            ' VALUES (?,?,?,?,?)',
            (ref, kind, digest, json.dumps(result, sort_keys=True, default=str), received_at),
        )
    result.update({'status': 'recorded', 'ref': ref})
    return result


def ledger_entries(db, order='arrival'):
    """Return ledger rows as dicts in arrival order or physical occurrence order."""
    ensure_ledger(db)
    if order == 'occurrence':
        sql = ('SELECT seq,kind,ref,subject,occurred_at,received_at,payload_json'
               ' FROM response_ledger ORDER BY occurred_at IS NULL, occurred_at,'
               ' seq')
    else:
        sql = ('SELECT seq,kind,ref,subject,occurred_at,received_at,payload_json'
               ' FROM response_ledger ORDER BY seq')
    cur = db.execute(sql)
    cols = [c[0] for c in cur.description]
    out = []
    for row in cur.fetchall():
        item = dict(zip(cols, row))
        item['payload'] = json.loads(item.pop('payload_json') or '{}')
        out.append(item)
    return out


def import_page(db, page_id, rows, received_at):
    db.execute('CREATE TABLE IF NOT EXISTS alarm_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS alarm_rows (page_id TEXT,line_no INTEGER,detector TEXT,zone TEXT,tick INTEGER,smoke INTEGER,heat INTEGER,PRIMARY KEY(page_id,line_no))')
    keys = {'detector', 'zone', 'tick', 'smoke', 'heat'}
    if not isinstance(rows, list) or any(not isinstance(r, dict) or set(r) != keys or not all(isinstance(r[k], int) for k in ('tick', 'smoke', 'heat')) or r['smoke'] < 0 for r in rows):
        raise ValueError('invalid_alarm_page')
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    old = db.execute('SELECT digest FROM alarm_pages WHERE id=?', (page_id,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('alarm_page_conflict')
        return {'status': 'replayed'}
    ensure_ledger(db)
    last_tick = max((r['tick'] for r in rows), default=None)
    with db:
        db.execute('INSERT INTO alarm_pages VALUES (?,?,?)', (page_id, digest, received_at))
        for i, r in enumerate(rows, 1):
            db.execute('INSERT INTO alarm_rows VALUES (?,?,?,?,?,?,?)', (page_id, i, r['detector'], r['zone'], r['tick'], r['smoke'], r['heat']))
        ledger_append(
            db, 'alarm_page', payload={'page_id': page_id, 'rows': rows},
            ref=page_id, subject=page_id, occurred_at=last_tick,
            received_at=received_at,
        )
    return {'status': 'captured'}
