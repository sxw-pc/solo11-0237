"""Minimal typed offline recovery-material intake for a stateful tenant."""
import hashlib,json

def schema(db):
    db.execute('CREATE TABLE IF NOT EXISTS recovery_material (artifact TEXT PRIMARY KEY,replica TEXT NOT NULL,kind TEXT NOT NULL,source_writer TEXT NOT NULL,epoch INTEGER NOT NULL,confirmed_seq INTEGER NOT NULL,recorded_at INTEGER NOT NULL,digest TEXT NOT NULL)')

def import_material(db,artifact,replica,kind,source_writer,epoch,confirmed_seq,recorded_at,rows):
    schema(db)
    if kind not in ('mirror','snapshot','log') or not isinstance(rows,list) or any(not isinstance(x,int) or x<0 for x in (epoch,confirmed_seq,recorded_at)) or not source_writer:raise ValueError('invalid_recovery_material')
    digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    old=db.execute('SELECT digest FROM recovery_material WHERE artifact=?',(artifact,)).fetchone()
    if old:
        if old[0]!=digest:raise ValueError('recovery_material_conflict')
        return {'status':'replayed','confirmed_seq':confirmed_seq}
    with db:db.execute('INSERT INTO recovery_material VALUES (?,?,?,?,?,?,?,?)',(artifact,replica,kind,source_writer,epoch,confirmed_seq,recorded_at,digest))
    return {'status':'captured','confirmed_seq':confirmed_seq}

def certified_seq(db,replica):
    schema(db)
    row=db.execute('SELECT COALESCE(MAX(confirmed_seq),0) FROM recovery_material WHERE replica=?',(replica,)).fetchone()
    return row[0]
