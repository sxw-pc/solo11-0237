import argparse,json,sys
from . import store,demand,supply,rebalance
OPS={'demand.forecast':demand.forecast,'demand.commit':demand.commit,'demand.gap':demand.gap,'demand.release':demand.release,'node.plan':supply.plan,'node.ready':supply.ready,'node.register':supply.register,'node.fail':supply.fail,'capacity.zone_rule':rebalance.zone_rule,'capacity.place':rebalance.place,'capacity.drain':rebalance.drain,'capacity.complete':rebalance.complete}
def execute(path,r):
    with store.tx(path) as db:
        if r['action'] not in OPS:raise ValueError('unknown action')
        return OPS[r['action']](db,r)
def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['init','demo','demand','node','capacity']);p.add_argument('--db',default='state.sqlite');p.add_argument('--fixture');a=p.parse_args();store.init(a.db)
    if a.command=='init':print(json.dumps({'status':'initialized'}));return
    if not a.fixture and a.command!='demo':p.error('--fixture required')
    requests=json.load(open(a.fixture or 'fixtures/demo.json',encoding='utf-8'))
    for r in requests if isinstance(requests,list) else [requests]:
        if a.command!='demo' and r['action'].split('.')[0]!=a.command:raise ValueError('wrong subsystem command')
        print(json.dumps(execute(a.db,r),ensure_ascii=False))
if __name__=='__main__':
    try:main()
    except (ValueError,KeyError) as e:print(json.dumps({'error':str(e)}),file=sys.stderr);sys.exit(2)
