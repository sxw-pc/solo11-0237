"""Provisional endpoint route from latest imported address lease."""

def publish(db,tenant,at):
    db.execute('CREATE TABLE IF NOT EXISTS endpoint_routes (tenant TEXT,address TEXT,node TEXT,at INTEGER)')
    try:row=db.execute('SELECT address,node FROM lease_rows WHERE tenant=? AND start<=? AND expires>? ORDER BY start DESC LIMIT 1',(tenant,at,at)).fetchone()
    except __import__('sqlite3').OperationalError:row=None
    if not row:return {'decision':'no_route','tenant':tenant}
    with db:db.execute('INSERT INTO endpoint_routes VALUES (?,?,?,?)',(tenant,row[0],row[1],at))
    return {'decision':'published','tenant':tenant,'address':row[0],'node':row[1]}
