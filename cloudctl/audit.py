from .store import one,many,event
def inspect(db,r):
    demand=one(db,'SELECT * FROM demands WHERE id=?',(r['id'],))
    if not demand:return event(db,'audit',r['id'],'missing',{})
    commitment=one(db,'SELECT * FROM commitments WHERE demand=?',(r['id'],))
    placed=many(db,'SELECT p.replica,p.node,n.healthy,n.zone FROM placements p JOIN nodes n ON n.id=p.node WHERE p.demand=? AND p.status=?',(r['id'],'active'))
    live=[x for x in placed if x['healthy']]
    decision='released' if commitment['status']=='released' else 'fulfilled' if len(live)>=commitment['units'] else 'underplaced'
    return event(db,'audit',r['id'],decision,{'forecast_version':commitment['forecast_version'],'committed_units':commitment['units'],'live_replicas':[x['replica'] for x in live],'zones':sorted({x['zone'] for x in live})})
