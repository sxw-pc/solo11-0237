"""Capture detector telemetry pages."""
import hashlib
import json


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
    with db:
        db.execute('INSERT INTO alarm_pages VALUES (?,?,?)', (page_id, digest, received_at))
        for i, r in enumerate(rows, 1):
            db.execute('INSERT INTO alarm_rows VALUES (?,?,?,?,?,?,?)', (page_id, i, r['detector'], r['zone'], r['tick'], r['smoke'], r['heat']))
    return {'status': 'captured'}
