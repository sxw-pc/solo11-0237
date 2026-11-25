from .store import one,many,event
def catalog(db,r):
    if min(r['cpu'],r['warmup'],r['cost'])<=0:return event(db,'catalog',r['kind'],'invalid_machine',{})
    db.execute('INSERT OR REPLACE INTO machine_types VALUES(?,?,?,?)',(r['kind'],r['cpu'],r['warmup'],r['cost']))
    return event(db,'catalog',r['kind'],'available',{'cpu':r['cpu'],'cost':r['cost']})
def plan(db,r):
    choices=many(db,'SELECT * FROM machine_types WHERE cpu>=? AND warmup+?<=? ORDER BY cost,kind',(r.get('cpu',1),r['requested'],r['deadline']))
    kind=r['kind']
    if kind=='auto':
        if not choices:return event(db,'plan',r['id'],'no_eligible_machine',{})
        kind=choices[0]['kind']
    if r['requested']>=r['deadline']:return event(db,'plan',r['id'],'warmup_too_late',{})
    if one(db,'SELECT * FROM provisions WHERE id=?',(r['id'],)):
        return event(db,'plan',r['id'],'idempotent',{})
    db.execute('INSERT INTO provisions VALUES(?,?,?,?,?,?)',(r['id'],kind,r['zone'],r['requested'],r['deadline'],'pending'))
    return event(db,'plan',r['id'],'planned',{'kind':kind})
def ready(db,r):
    plan=one(db,'SELECT * FROM provisions WHERE id=?',(r['plan'],))
    if not plan:return event(db,'ready',r['id'],'missing_plan',{})
    if r['at']>plan['deadline'] or not r['healthy']:
        db.execute('UPDATE provisions SET status=? WHERE id=?',('failed',r['plan']))
        return event(db,'ready',r['id'],'failed_warmup',{})
    if r['kind']!=plan['kind'] or r['zone']!=plan['zone']:
        return event(db,'ready',r['id'],'wrong_machine',{})
    db.execute('INSERT OR REPLACE INTO nodes VALUES(?,?,?,?,?,?)',(r['id'],r['kind'],r['zone'],r['cpu'],r['at'],1))
    db.execute('UPDATE provisions SET status=? WHERE id=?',('ready',r['plan']))
    return event(db,'ready',r['id'],'available',{'cpu':r['cpu']})
def register(db,r):
    db.execute('INSERT OR REPLACE INTO nodes VALUES(?,?,?,?,?,?)',(r['id'],r['kind'],r['zone'],r['cpu'],r['ready'],int(r['healthy'])))
    return event(db,'register',r['id'],'available' if r['healthy'] else 'failed',{})
def fail(db,r):
    node=one(db,'SELECT * FROM nodes WHERE id=?',(r['id'],))
    if not node:return event(db,'fail',r['id'],'missing',{})
    db.execute('UPDATE nodes SET healthy=0 WHERE id=?',(r['id'],))
    affected=many(db,'SELECT demand FROM placements WHERE node=? AND status=?',(r['id'],'active'))
    db.execute('UPDATE placements SET status=? WHERE node=?',('at_risk',r['id']))
    return event(db,'fail',r['id'],'isolated',{'affected':[x['demand'] for x in affected]})
