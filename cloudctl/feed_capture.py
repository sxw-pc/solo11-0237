"""Capture signed-off power source telemetry pages."""
import hashlib
import json


def import_page(db, page_id, rows, received_at):
    db.execute('CREATE TABLE IF NOT EXISTS feed_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS feed_rows (page_id TEXT,line_no INTEGER,bus TEXT,source TEXT,tick INTEGER,voltage INTEGER,available_kw INTEGER,PRIMARY KEY(page_id,line_no))')
    keys = {'bus', 'source', 'tick', 'voltage', 'available_kw'}
    if not isinstance(rows, list) or any(not isinstance(r, dict) or set(r) != keys or not all(isinstance(r[k], int) for k in ('tick', 'voltage', 'available_kw')) or r['available_kw'] < 0 for r in rows):
        raise ValueError('invalid_feed_page')
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    old = db.execute('SELECT digest FROM feed_pages WHERE id=?', (page_id,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('feed_page_conflict')
        return {'status': 'replayed', 'rows': len(rows)}
    with db:
        db.execute('INSERT INTO feed_pages VALUES (?,?,?)', (page_id, digest, received_at))
        for i, r in enumerate(rows, 1):
            db.execute('INSERT INTO feed_rows VALUES (?,?,?,?,?,?,?)', (page_id, i, r['bus'], r['source'], r['tick'], r['voltage'], r['available_kw']))
    return {'status': 'captured', 'rows': len(rows)}
