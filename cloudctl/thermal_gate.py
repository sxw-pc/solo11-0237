"""Provisional cooling release from captured loop measurements."""

def release(db,loop,at):
    db.execute('CREATE TABLE IF NOT EXISTS thermal_releases (loop TEXT,at INTEGER,flow_lpm INTEGER,temp_c INTEGER)')
    try:row=db.execute('SELECT flow_lpm,temp_c FROM cooling_rows WHERE loop=? ORDER BY tick DESC LIMIT 1',(loop,)).fetchone()
    except __import__('sqlite3').OperationalError:row=None
    if not row or row[0]<80 or row[1]>30:return {'decision':'hold','loop':loop}
    with db:db.execute('INSERT INTO thermal_releases VALUES (?,?,?,?)',(loop,at,row[0],row[1]))
    return {'decision':'released','loop':loop,'flow_lpm':row[0]}
