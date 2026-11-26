import argparse,json,sys
from . import store,demand,supply,rebalance,audit,data_residency
OPS={'demand.forecast':demand.forecast,'demand.propose':demand.propose,'demand.activate':demand.activate,'demand.commit':demand.commit,'demand.gap':demand.gap,'demand.release':demand.release,'demand.audit':audit.inspect,'node.catalog':supply.catalog,'node.plan':supply.plan,'node.ready':supply.ready,'node.register':supply.register,'node.fail':supply.fail,'capacity.zone_rule':rebalance.zone_rule,'capacity.place':rebalance.place,'capacity.drain':rebalance.drain,'capacity.complete':rebalance.complete,'capacity.recover':rebalance.recover}
OPS.update(data_residency.ACTION_ALIASES)
def execute(path,r):
    with store.tx(path) as db:
        if r['action'] in OPS:return OPS[r['action']](db,r)
        fn=data_residency.resolve_action(r['action'])
        if fn is not None:return fn(db,r)
        raise ValueError('unknown action')
def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['init','demo','demand','node','capacity','data','residency','data_residency','compliance','license']);p.add_argument('operation',nargs='?');p.add_argument('--db',default='state.sqlite');p.add_argument('--fixture');a=p.parse_args();store.init(a.db)
    if a.command=='init':print(json.dumps({'status':'initialized'}));return
    if not a.fixture and a.command!='demo':p.error('--fixture required')
    requests=json.load(open(a.fixture or 'fixtures/demo.json',encoding='utf-8'))
    prefixes={'data':('data.','residency.','data_residency.','compliance.','license.'),
              'residency':('residency.','data.','data_residency.','compliance.','license.'),
              'data_residency':('data_residency.','residency.','data.','compliance.','license.'),
              'compliance':('compliance.','residency.','data.','data_residency.','license.'),
              'license':('license.','residency.','data.','data_residency.','compliance.')}
    allowed=prefixes.get(a.command,(a.command+'.',))
    for r in requests if isinstance(requests,list) else [requests]:
        if a.command!='demo' and not r['action'].startswith(allowed):raise ValueError('wrong subsystem command')
        for prerequisite in r.get('setup',[]):execute(a.db,prerequisite)
        print(json.dumps(execute(a.db,r),ensure_ascii=False,default=str))
if __name__=='__main__':
    try:main()
    except (ValueError,KeyError) as e:print(json.dumps({'error':str(e)}),file=sys.stderr);sys.exit(2)
