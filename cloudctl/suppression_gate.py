"""Provisional suppression authorization from detector telemetry."""


def release(db, zone, at):
    db.execute('CREATE TABLE IF NOT EXISTS suppression_releases (zone TEXT,at INTEGER,decision TEXT,detector TEXT)')
    try:
        row = db.execute('SELECT detector,smoke,heat FROM alarm_rows WHERE zone=? ORDER BY tick DESC LIMIT 1', (zone,)).fetchone()
    except __import__('sqlite3').OperationalError:
        row = None
    decision = 'release' if row and row[1] >= 80 and row[2] >= 50 else 'hold'
    with db:
        db.execute('INSERT INTO suppression_releases VALUES (?,?,?,?)', (zone, at, decision, row[0] if row else None))
    return {'zone': zone, 'decision': decision}
