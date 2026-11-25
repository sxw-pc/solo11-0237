"""Capture site clock reports."""
import hashlib
import json


def import_page(db, page_id, rows, received_at):
    db.execute('CREATE TABLE IF NOT EXISTS clock_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS clock_rows (page_id TEXT,line_no INTEGER,site TEXT,source TEXT,sampled_tick INTEGER,reported_minute INTEGER,PRIMARY KEY(page_id,line_no))')
    keys = {'site', 'source', 'sampled_tick', 'reported_minute'}
    if not isinstance(rows, list) or any(not isinstance(r, dict) or set(r) != keys or not isinstance(r['sampled_tick'], int) or not isinstance(r['reported_minute'], int) for r in rows):
        raise ValueError('invalid_clock_page')
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    old = db.execute('SELECT digest FROM clock_pages WHERE id=?', (page_id,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('clock_page_conflict')
        return {'status': 'replayed'}
    with db:
        db.execute('INSERT INTO clock_pages VALUES (?,?,?)', (page_id, digest, received_at))
        for i, r in enumerate(rows, 1):
            db.execute('INSERT INTO clock_rows VALUES (?,?,?,?,?,?)', (page_id, i, r['site'], r['source'], r['sampled_tick'], r['reported_minute']))
    return {'status': 'captured'}
