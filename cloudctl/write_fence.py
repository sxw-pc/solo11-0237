"""Provisional write authority after typed offline state recovery."""
from .data_recovery import certified_seq

def claim(db,replica,required_seq,new_epoch,target_writer,at):
    db.execute('CREATE TABLE IF NOT EXISTS writer_fences (replica TEXT PRIMARY KEY,fence_id TEXT NOT NULL,epoch INTEGER NOT NULL,required_seq INTEGER NOT NULL,target_writer TEXT NOT NULL,issued_at INTEGER NOT NULL)')
    if certified_seq(db,replica)<required_seq:return {'decision':'state_incomplete','replica':replica}
    old=db.execute('SELECT epoch FROM writer_fences WHERE replica=?',(replica,)).fetchone()
    if old and new_epoch<=old[0]:return {'decision':'stale_epoch','replica':replica}
    fence_id=f'{replica}:{new_epoch}'
    with db:db.execute('INSERT OR REPLACE INTO writer_fences VALUES (?,?,?,?,?,?)',(replica,fence_id,new_epoch,required_seq,target_writer,at))
    return {'decision':'granted','replica':replica,'fence_id':fence_id,'epoch':new_epoch}
