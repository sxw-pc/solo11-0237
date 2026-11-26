from .store import one,many,event
from .supply import node_physical_scope,physical_used_on_scope
def zone_rule(db,r):
    if r['min_zones']<1:return event(db,'zone_rule',r['app'],'invalid',{})
    db.execute('INSERT OR REPLACE INTO zone_rules VALUES(?,?)',(r['app'],r['min_zones']))
    return event(db,'zone_rule',r['app'],'recorded',{})
def place(db,r):
    demand=one(db,'SELECT * FROM demands WHERE id=?',(r['demand'],));node=one(db,'SELECT * FROM nodes WHERE id=?',(r['node'],))
    if not demand or demand['status']!='committed' or not node or not node['healthy']:
        return event(db,'place',r['demand'],'unavailable',{})
    if node['ready']>demand['start']:
        return event(db,'place',r['demand'],'node_not_ready_for_start',{'ready':node['ready'],'start':demand['start']})
    existing=many(db,'SELECT p.node,n.zone FROM placements p JOIN nodes n ON n.id=p.node WHERE p.demand=? AND p.status=?',(r['demand'],'active'))
    rule=one(db,'SELECT min_zones FROM zone_rules WHERE app=?',(demand['app'],))
    if rule and len(existing)<rule['min_zones'] and node['zone'] in [x['zone'] for x in existing]:
        return event(db,'place',r['demand'],'zone_conflict',{'zone':node['zone']})
    committed=one(db,'SELECT units FROM commitments WHERE demand=?',(r['demand'],))['units']
    if len(existing)>=committed:return event(db,'place',r['demand'],'already_satisfied',{})
    used=one(db,'SELECT COALESCE(SUM(d.cpu),0) n FROM placements p JOIN demands d ON d.id=p.demand WHERE p.node=? AND p.status=?',(r['node'],'active'))['n']
    if used+demand['cpu']>node['cpu']:return event(db,'place',r['demand'],'node_capacity_exhausted',{'used':used,'capacity':node['cpu']})
    # Entity scope: agent ids that are aliases of one proven chassis share
    # its physical CPU, so the same silicon cannot be filled twice.
    scope_id,scope_cpu=node_physical_scope(db,r['node'])
    if scope_id and scope_id!=r['node']:
        physical_used=physical_used_on_scope(db,scope_id,r['node'])
        if physical_used+demand['cpu']>scope_cpu:
            return event(db,'place',r['demand'],'physical_chassis_capacity_exhausted',
                         {'chassis':scope_id,'used':physical_used,'capacity':scope_cpu,
                          'requested':demand['cpu'],'node':r['node']})
    db.execute('INSERT INTO placements VALUES(?,?,?,?)',(r['demand'],r['node'],r['replica'],'active'))
    return event(db,'place',r['demand'],'placed',{'node':r['node'],'zone':node['zone']})
def drain(db,r):
    node=one(db,'SELECT * FROM nodes WHERE id=?',(r['id'],))
    if not node:return event(db,'drain',r['id'],'missing',{})
    hosted=many(db,'SELECT * FROM placements WHERE node=? AND status=?',(r['id'],'active'))
    planned=[];reserved={}
    for p in hosted:
        d=one(db,'SELECT * FROM demands WHERE id=?',(p['demand'],))
        alternatives=many(db,'SELECT * FROM nodes WHERE id<>? AND healthy=1 AND cpu>=? ORDER BY id',(r['id'],d['cpu']))
        rule=one(db,'SELECT min_zones FROM zone_rules WHERE app=?',(d['app'],))
        other_zones={x['zone'] for x in many(db,'SELECT n.zone FROM placements p JOIN nodes n ON n.id=p.node WHERE p.demand=? AND p.replica<>? AND p.status=?',(d['id'],p['replica'],'active'))}
        candidates=[]
        for n in alternatives:
            if n['ready']>d['start']:continue
            used=one(db,'SELECT COALESCE(SUM(d.cpu),0) n FROM placements p JOIN demands d ON d.id=p.demand WHERE p.node=? AND p.status=?',(n['id'],'active'))['n']
            if used+reserved.get(n['id'],0)+d['cpu']>n['cpu']:continue
            if rule and len(other_zones)<rule['min_zones'] and n['zone'] in other_zones:continue
            candidates.append(n)
        if not candidates:return event(db,'drain',r['id'],'blocked_placement',{'demand':d['id'],'replica':p['replica']})
        planned.append((d['id'],p['replica'],candidates[0]['id']))
        reserved[candidates[0]['id']]=reserved.get(candidates[0]['id'],0)+d['cpu']
    generation=(one(db,'SELECT generation FROM drains WHERE node=?',(r['id'],)) or {}).get('generation',0)+1
    db.execute('INSERT OR REPLACE INTO drains VALUES(?,?,?)',(r['id'],generation,'planned'))
    db.executemany('INSERT INTO drain_moves VALUES(?,?,?,?,?)',[(r['id'],generation,*move) for move in planned])
    return event(db,'drain',r['id'],'planned',{'generation':generation,'moves':planned})
def complete(db,r):
    drain=one(db,'SELECT * FROM drains WHERE node=?',(r['id'],))
    if not drain or drain['generation']!=r['generation'] or drain['status']!='planned':
        return event(db,'complete',r['id'],'stale_plan',{})
    if not r['success']:
        db.execute('UPDATE drains SET status=? WHERE node=?',('rolled_back',r['id']))
        return event(db,'complete',r['id'],'rolled_back',{})
    moves=many(db,'SELECT demand,replica,destination FROM drain_moves WHERE node=? AND generation=?',(r['id'],r['generation']))
    incoming={}
    for move in moves:
        dest=one(db,'SELECT * FROM nodes WHERE id=?',(move['destination'],))
        if not dest or not dest['healthy']:
            db.execute('UPDATE drains SET status=? WHERE node=?',('rolled_back',r['id']))
            return event(db,'complete',r['id'],'replacement_failed',{'destination':move['destination']})
        original=one(db,'SELECT status FROM placements WHERE demand=? AND replica=? AND node=?',(move['demand'],move['replica'],r['id']))
        if not original or original['status']!='active':
            db.execute('UPDATE drains SET status=? WHERE node=?',('rolled_back',r['id']))
            return event(db,'complete',r['id'],'source_changed',{'demand':move['demand']})
        demand=one(db,'SELECT cpu FROM demands WHERE id=?',(move['demand'],))
        start=one(db,'SELECT start FROM demands WHERE id=?',(move['demand'],))['start']
        if dest['ready']>start:
            db.execute('UPDATE drains SET status=? WHERE node=?',('rolled_back',r['id']))
            return event(db,'complete',r['id'],'replacement_not_ready_for_start',{'destination':dest['id'],'ready':dest['ready'],'start':start})
        incoming[dest['id']]=incoming.get(dest['id'],0)+demand['cpu']
        used=one(db,'SELECT COALESCE(SUM(d.cpu),0) n FROM placements p JOIN demands d ON d.id=p.demand WHERE p.node=? AND p.status=?',(dest['id'],'active'))['n']
        if used+incoming[dest['id']]>dest['cpu']:
            db.execute('UPDATE drains SET status=? WHERE node=?',('rolled_back',r['id']))
            return event(db,'complete',r['id'],'replacement_capacity_exhausted',{'destination':dest['id'],'used':used,'incoming':incoming[dest['id']]})
    for move in moves:
        db.execute('UPDATE placements SET node=? WHERE demand=? AND replica=? AND node=?',(move['destination'],move['demand'],move['replica'],r['id']))
    db.execute('UPDATE nodes SET healthy=0 WHERE id=?',(r['id'],))
    db.execute('UPDATE drains SET status=? WHERE node=?',('complete',r['id']))
    return event(db,'complete',r['id'],'drained',{})
def recover(db,r):
    placement=one(db,'SELECT * FROM placements WHERE demand=? AND replica=?',(r['demand'],r['replica']))
    node=one(db,'SELECT * FROM nodes WHERE id=?',(r['destination'],))
    demand=one(db,'SELECT * FROM demands WHERE id=?',(r['demand'],))
    if not demand or demand['status']!='committed':
        return event(db,'recover',r['demand'],'demand_inactive',{})
    if not placement or placement['status']!='at_risk':
        return event(db,'recover',r['demand'],'not_at_risk',{})
    if not node or not node['healthy'] or node['cpu']<demand['cpu']:
        return event(db,'recover',r['demand'],'replacement_unavailable',{})
    if node['ready']>demand['start']:
        return event(db,'recover',r['demand'],'replacement_not_ready_for_start',{'ready':node['ready'],'start':demand['start']})
    used=one(db,'SELECT COALESCE(SUM(d.cpu),0) n FROM placements p JOIN demands d ON d.id=p.demand WHERE p.node=? AND p.status=?',(r['destination'],'active'))['n']
    if used+demand['cpu']>node['cpu']:
        return event(db,'recover',r['demand'],'replacement_capacity_exhausted',{'used':used})
    other_zones={x['zone'] for x in many(db,'SELECT n.zone FROM placements p JOIN nodes n ON n.id=p.node WHERE p.demand=? AND p.replica<>? AND p.status=?',(r['demand'],r['replica'],'active'))}
    rule=one(db,'SELECT min_zones FROM zone_rules WHERE app=?',(demand['app'],))
    if rule and len(other_zones)<rule['min_zones'] and node['zone'] in other_zones:
        return event(db,'recover',r['demand'],'zone_conflict',{})
    db.execute('UPDATE placements SET node=?,status=? WHERE demand=? AND replica=?',(r['destination'],'active',r['demand'],r['replica']))
    return event(db,'recover',r['demand'],'restored',{'replica':r['replica'],'node':r['destination']})
