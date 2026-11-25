"""Provisional node power permission from source telemetry."""


def energize(db, node, bus, source, draw_kw, at):
    db.execute('CREATE TABLE IF NOT EXISTS power_permits (node TEXT,bus TEXT,source TEXT,draw_kw INTEGER,at INTEGER,decision TEXT)')
    try:
        row = db.execute('SELECT voltage,available_kw FROM feed_rows WHERE bus=? AND source=? ORDER BY tick DESC LIMIT 1', (bus, source)).fetchone()
    except __import__('sqlite3').OperationalError:
        row = None
    decision = 'permit' if row and row[0] >= 220 and row[1] >= draw_kw else 'hold'
    with db:
        db.execute('INSERT INTO power_permits VALUES (?,?,?,?,?,?)', (node, bus, source, draw_kw, at, decision))
    return {'node': node, 'bus': bus, 'source': source, 'decision': decision}
