"""Provisional site maintenance window admission."""


def open_window(db, site, node, freeze_until, at):
    db.execute('CREATE TABLE IF NOT EXISTS maintenance_windows (site TEXT,node TEXT,at INTEGER,freeze_until INTEGER,decision TEXT)')
    try:
        row = db.execute('SELECT MAX(reported_minute) FROM clock_rows WHERE site=?', (site,)).fetchone()
    except __import__('sqlite3').OperationalError:
        row = None
    decision = 'open' if row and row[0] is not None and row[0] >= freeze_until else 'hold'
    with db:
        db.execute('INSERT INTO maintenance_windows VALUES (?,?,?,?,?)', (site, node, at, freeze_until, decision))
    return {'site': site, 'node': node, 'decision': decision}
