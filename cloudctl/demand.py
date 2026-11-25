from .store import one,many,event
def forecast(db,r):
    old=one(db,'SELECT MAX(version) v FROM forecasts WHERE app=?',(r['app'],))['v'] or 0
    if r['version']!=old+1:return event(db,'forecast',r['app'],'stale_version',{'expected':old+1})
    db.execute('INSERT INTO forecasts VALUES(?,?,?,?)',(r['app'],r['version'],r['peak'],r['at']))
    affected=many(db,'SELECT d.id FROM demands d WHERE d.app=? AND d.status=?',(r['app'],'proposed'))
    return event(db,'forecast',r['app'],'recorded',{'affected':[x['id'] for x in affected]})
def commit(db,r):
    if one(db,'SELECT * FROM demands WHERE id=?',(r['id'],)):
        return event(db,'commit',r['id'],'idempotent',{})
    if r['start']>=r['end'] or r['minimum']>r['burst'] or r['minimum']<1:
        return event(db,'commit',r['id'],'invalid_contract',{})
    latest=one(db,'SELECT version,peak FROM forecasts WHERE app=? ORDER BY version DESC LIMIT 1',(r['app'],))
    if not latest:return event(db,'commit',r['id'],'missing_forecast',{})
    available=sum(n['cpu'] for n in many(db,'SELECT cpu FROM nodes WHERE healthy=1 AND ready<=?',(r['start'],)))
    other=one(db,'SELECT COALESCE(SUM(c.units*d.cpu),0) n FROM commitments c JOIN demands d ON d.id=c.demand WHERE c.status=? AND d.start<? AND d.end>?',('active',r['end'],r['start']))['n']
    needed=r['minimum']*r['cpu']
    if needed+other>available:return event(db,'commit',r['id'],'capacity_shortfall',{'need':needed,'available':available-other})
    db.execute('INSERT INTO demands VALUES(?,?,?,?,?,?,?,?,?)',(r['id'],r['app'],r['start'],r['end'],r['minimum'],r['burst'],r['cpu'],1,'committed'))
    db.execute('INSERT INTO commitments VALUES(?,?,?,?)',(r['id'],r['minimum'],latest['version'],'active'))
    return event(db,'commit',r['id'],'committed',{'forecast_version':latest['version'],'units':r['minimum']})
def gap(db,r):
    available=sum(x['cpu'] for x in many(db,'SELECT cpu FROM nodes WHERE healthy=1 AND ready<=?',(r['start'],)))
    warming=sum(x['cpu'] for x in many(db,'SELECT cpu FROM nodes WHERE healthy=1 AND ready>? AND ready<=?',(r['start'],r['end'])))
    need=r['units']*r['cpu']
    reason='none' if available>=need else 'warmup' if available+warming>=need else 'total_capacity'
    return event(db,'gap',r['app'],reason,{'needed':need,'ready':available,'warming':warming})
def release(db,r):
    d=one(db,'SELECT * FROM demands WHERE id=?',(r['id'],))
    if not d:return event(db,'release',r['id'],'missing',{})
    if d['status']=='terminated':return event(db,'release',r['id'],'idempotent',{})
    db.execute('INSERT INTO releases VALUES(?,?,?)',(r['id'],r['at'],r['reason']))
    db.execute('UPDATE demands SET status=? WHERE id=?',('terminated',r['id']))
    db.execute('UPDATE commitments SET status=? WHERE demand=?',('released',r['id']))
    return event(db,'release',r['id'],'released',{'provision_plans_retained':True})
