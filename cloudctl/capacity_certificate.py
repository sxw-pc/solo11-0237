"""Provisional capacity certificate from management-agent inventory rows."""

def issue(db,certificate_id):
    db.execute('CREATE TABLE IF NOT EXISTS capacity_certificates (id TEXT PRIMARY KEY,claimed_cpu INTEGER NOT NULL,agent_count INTEGER NOT NULL)')
    rows=db.execute('SELECT agent_id,MAX(cpu) FROM hardware_rows GROUP BY agent_id').fetchall()
    total=sum(x[1] for x in rows)
    with db:db.execute('INSERT INTO capacity_certificates VALUES (?,?,?)',(certificate_id,total,len(rows)))
    return {'certificate_id':certificate_id,'claimed_cpu':total,'agent_count':len(rows)}
