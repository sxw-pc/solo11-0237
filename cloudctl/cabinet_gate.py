"""Provisional cabinet release copied from a shared loop ticket."""
from .thermal_gate import release


def permit(db, cabinet, supply_loop, at):
    db.execute('CREATE TABLE IF NOT EXISTS cabinet_permits (cabinet TEXT, supply_loop TEXT, at INTEGER, decision TEXT)')
    ticket = release(db, supply_loop, at)
    decision = 'permit' if ticket['decision'] == 'released' else 'hold'
    with db:
        db.execute('INSERT INTO cabinet_permits VALUES (?,?,?,?)', (cabinet, supply_loop, at, decision))
    return {'cabinet': cabinet, 'decision': decision, 'loop': supply_loop}
