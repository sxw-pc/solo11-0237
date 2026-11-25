from .store import one,many,event
def zone_rule(db,r):
    if r['min_zones']<1:return event(db,'zone_rule',r['app'],'invalid',{})
    db.execute('INSERT OR REPLACE INTO zone_rules VALUES(?,?)',(r['app'],r['min_zones']))
    return event(db,'zone_rule',r['app'],'recorded',{})
def place(db,r):
    demand=one(db,'SELECT * FROM demands WHERE id=?',(r['demand'],));node=one(db,'SELECT * FROM nodes WHERE id=?',(r['node'],))
    if not demand or demand['status']!='committed' or not node or not node['healthy']:
        return event(db,'place',r['demand'],'unavailable',{})
    existing=many(db,'SELECT p.node,n.zone FROM placements p JOIN nodes n ON n.id=p.node WHERE p.demand=? AND p.status=?',(r['demand'],'active'))
    rule=one(db,'SELECT min_zones FROM zone_rules WHERE app=?',(demand['app'],))
    if rule and len(existing)<rule['min_zones'] and node['zone'] in [x['zone'] for x in existing]:
        return event(db,'place',r['demand'],'zone_conflict',{'zone':node['zone']})
    if len(existing)>=demand['minimum']:return event(db,'place',r['demand'],'already_satisfied',{})
    db.execute('INSERT INTO placements VALUES(?,?,?,?)',(r['demand'],r['node'],r['replica'],'active'))
    return event(db,'place',r['demand'],'placed',{'node':r['node'],'zone':node['zone']})
def drain(db,r):
    node=one(db,'SELECT * FROM nodes WHERE id=?',(r['id'],))
    if not node:return event(db,'drain',r['id'],'missing',{})
    hosted=many(db,'SELECT * FROM placements WHERE node=? AND status=?',(r['id'],'active'))
    for p in hosted:
        d=one(db,'SELECT * FROM demands WHERE id=?',(p['demand'],))
        alternatives=many(db,'SELECT * FROM nodes WHERE id<>? AND healthy=1 AND cpu>=?',(r['id'],d['cpu']))
        if not alternatives:return event(db,'drain',r['id'],'blocked_placement',{'demand':d['id']})
    generation=(one(db,'SELECT generation FROM drains WHERE node=?',(r['id'],)) or {}).get('generation',0)+1
    db.execute('INSERT OR REPLACE INTO drains VALUES(?,?,?)',(r['id'],generation,'planned'))
    return event(db,'drain',r['id'],'planned',{'generation':generation,'count':len(hosted)})
def complete(db,r):
    drain=one(db,'SELECT * FROM drains WHERE node=?',(r['id'],))
    if not drain or drain['generation']!=r['generation']:
        return event(db,'complete',r['id'],'stale_plan',{})
    if not r['success']:
        db.execute('UPDATE drains SET status=? WHERE node=?',('rolled_back',r['id']))
        return event(db,'complete',r['id'],'rolled_back',{})
    db.execute('UPDATE placements SET status=? WHERE node=?',('migrated',r['id']))
    db.execute('UPDATE nodes SET healthy=0 WHERE id=?',(r['id'],))
    db.execute('UPDATE drains SET status=? WHERE node=?',('complete',r['id']))
    return event(db,'complete',r['id'],'drained',{})
