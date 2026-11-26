from .store import one,many,event
from .supply import available_cpu,warming_cpu
def forecast(db,r):
    old=one(db,'SELECT MAX(version) v FROM forecasts WHERE app=?',(r['app'],))['v'] or 0
    if r['version']!=old+1:return event(db,'forecast',r['app'],'stale_version',{'expected':old+1})
    db.execute('INSERT INTO forecasts VALUES(?,?,?,?)',(r['app'],r['version'],r['peak'],r['at']))
    affected=many(db,'SELECT d.id FROM demands d WHERE d.app=? AND d.status=?',(r['app'],'proposed'))
    for item in affected:
        d=one(db,'SELECT * FROM demands WHERE id=?',(item['id'],))
        units=max(d['minimum'],min(d['burst'],r['peak']))
        db.execute('UPDATE proposal_forecast SET forecast_version=?,units=?,assessed=? WHERE demand=?',(r['version'],units,r['at'],d['id']))
    return event(db,'forecast',r['app'],'recorded',{'affected':[x['id'] for x in affected]})
def propose(db,r):
    if one(db,'SELECT id FROM demands WHERE id=?',(r['id'],)):
        return event(db,'propose',r['id'],'idempotent',{})
    latest=one(db,'SELECT version,peak FROM forecasts WHERE app=? ORDER BY version DESC LIMIT 1',(r['app'],))
    if not latest:return event(db,'propose',r['id'],'missing_forecast',{})
    if r['start']>=r['end'] or r['minimum']<1 or r['minimum']>r['burst']:
        return event(db,'propose',r['id'],'invalid_contract',{})
    units=max(r['minimum'],min(r['burst'],latest['peak']))
    db.execute('INSERT INTO demands VALUES(?,?,?,?,?,?,?,?,?)',(r['id'],r['app'],r['start'],r['end'],r['minimum'],r['burst'],r['cpu'],1,'proposed'))
    db.execute('INSERT INTO proposal_forecast VALUES(?,?,?,?)',(r['id'],latest['version'],units,r.get('at',0)))
    return event(db,'propose',r['id'],'proposed',{'forecast_version':latest['version'],'units':units})
def activate(db,r):
    d=one(db,'SELECT * FROM demands WHERE id=?',(r['id'],))
    proposal=one(db,'SELECT * FROM proposal_forecast WHERE demand=?',(r['id'],))
    if not d or d['status']!='proposed' or not proposal:
        return event(db,'activate',r['id'],'not_proposed',{})
    available=available_cpu(db,d['start'])
    other=one(db,'SELECT COALESCE(SUM(c.units*x.cpu),0) n FROM commitments c JOIN demands x ON x.id=c.demand WHERE c.status=? AND x.start<? AND x.end>?',('active',d['end'],d['start']))['n']
    if other+proposal['units']*d['cpu']>available:
        return event(db,'activate',r['id'],'capacity_shortfall',{'available':available-other})
    db.execute('INSERT INTO commitments VALUES(?,?,?,?)',(d['id'],proposal['units'],proposal['forecast_version'],'active'))
    db.execute('UPDATE demands SET status=?,version=version+1 WHERE id=?',('committed',d['id']))
    return event(db,'activate',r['id'],'committed',{'forecast_version':proposal['forecast_version'],'units':proposal['units']})
def commit(db,r):
    old=one(db,'SELECT * FROM demands WHERE id=?',(r['id'],))
    if old:
        same=all(old[key]==r[key] for key in ('app','start','end','minimum','burst','cpu'))
        return event(db,'commit',r['id'],'idempotent' if same else 'contract_conflict',{})
    if r['start']>=r['end'] or r['minimum']>r['burst'] or r['minimum']<1:
        return event(db,'commit',r['id'],'invalid_contract',{})
    latest=one(db,'SELECT version,peak FROM forecasts WHERE app=? ORDER BY version DESC LIMIT 1',(r['app'],))
    if not latest:return event(db,'commit',r['id'],'missing_forecast',{})
    available=available_cpu(db,r['start'])
    other=one(db,'SELECT COALESCE(SUM(c.units*d.cpu),0) n FROM commitments c JOIN demands d ON d.id=c.demand WHERE c.status=? AND d.start<? AND d.end>?',('active',r['end'],r['start']))['n']
    units=max(r['minimum'],min(r['burst'],latest['peak']))
    needed=units*r['cpu']
    if needed+other>available:return event(db,'commit',r['id'],'capacity_shortfall',{'need':needed,'available':available-other})
    db.execute('INSERT INTO demands VALUES(?,?,?,?,?,?,?,?,?)',(r['id'],r['app'],r['start'],r['end'],r['minimum'],r['burst'],r['cpu'],1,'committed'))
    db.execute('INSERT INTO commitments VALUES(?,?,?,?)',(r['id'],units,latest['version'],'active'))
    return event(db,'commit',r['id'],'committed',{'forecast_version':latest['version'],'units':units})
def gap(db,r):
    available=available_cpu(db,r['start'])
    warming=warming_cpu(db,r['start'],r['end'])
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
    db.execute('UPDATE placements SET status=? WHERE demand=? AND status=?',('released',r['id'],'active'))
    return event(db,'release',r['id'],'released',{'provision_plans_retained':True})
