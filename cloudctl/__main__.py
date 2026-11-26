import argparse,json,sys
from . import store,demand,supply,rebalance,audit,lease_capture,route_publish
def _lease_import(db,r):
    return lease_capture.import_page(db,r['page_id'],r['rows'],r['received_at'])
OPS={'demand.forecast':demand.forecast,'demand.propose':demand.propose,'demand.activate':demand.activate,'demand.commit':demand.commit,'demand.gap':demand.gap,'demand.release':demand.release,'demand.audit':audit.inspect,'node.catalog':supply.catalog,'node.plan':supply.plan,'node.ready':supply.ready,'node.register':supply.register,'node.fail':supply.fail,'capacity.zone_rule':rebalance.zone_rule,'capacity.place':rebalance.place,'capacity.drain':rebalance.drain,'capacity.complete':rebalance.complete,'capacity.recover':rebalance.recover,
     'lease.import_page':_lease_import,'lease.import':_lease_import,'lease.confirm':lease_capture.confirm_lease,'lease.ack':lease_capture.confirm_lease,'lease.register_agent':lease_capture.register_agent,'lease.agent':lease_capture.register_agent,'lease.neighbor_cache':lease_capture.record_neighbor_cache,'lease.neighbors':lease_capture.record_neighbor_cache,'lease.terminate':lease_capture.terminate_tenant,'lease.calibrate_clock':lease_capture.calibrate_clock,'lease.receipt':lease_capture.save_receipt,'lease.save_receipt':lease_capture.save_receipt,'lease.step':lease_capture.record_step,
     'address.publish':lambda db,r:route_publish.publish(db,r['tenant'],r.get('at')),'route.publish':lambda db,r:route_publish.publish(db,r['tenant'],r.get('at')),
     'address.conflicts':lambda db,r:route_publish.conflict_report(db,r.get('at'),r.get('domain'),r.get('address')),'address.check':lambda db,r:route_publish.conflict_report(db,r.get('at')),'address.occupancy':lambda db,r:route_publish.conflict_report(db,r.get('at')),'address.detect_conflicts':lambda db,r:route_publish.detect_conflicts(db,r.get('at')),
     'address.assess_risks':lambda db,r:route_publish.assess_risks(db,r.get('at')),'address.risks':lambda db,r:route_publish.assess_risks(db,r.get('at')),
     'address.prepare_handoff':route_publish.prepare_handoff,'address.prepare':route_publish.prepare_handoff,'address.handoff':route_publish.prepare_handoff,
     'address.receipt':lease_capture.save_receipt,'address.agent_receipt':lease_capture.save_receipt,
     'address.commit_handoff':lambda db,r:route_publish.commit_handoff(db,r.get('handoff_id') or r.get('id'),r.get('at')),'address.commit':lambda db,r:route_publish.commit_handoff(db,r.get('handoff_id') or r.get('id'),r.get('at')),
     'address.complete_handoff':lambda db,r:route_publish.commit_handoff(db,r.get('handoff_id') or r.get('id'),r.get('at')),
     'address.recover':lambda db,r:route_publish.recover_handoff(db,r.get('handoff_id'),r.get('at')),'address.reopen':lambda db,r:route_publish.reopen(db,r.get('handoff_id')),
     'address.readdress':route_publish.readdress_fix,'address.renumber':route_publish.readdress_fix,'address.fix_readdress':route_publish.readdress_fix,
     'address.isolate':route_publish.isolation_fix,'address.isolation':route_publish.isolation_fix,'address.fix_isolation':route_publish.isolation_fix,
     'address.repair':route_publish.repair_conflict,'address.resolve':route_publish.repair_conflict,
     'address.probe':route_publish.probe_address,'address.provision_domain':route_publish.provision_domain,'address.isolation_receipt':route_publish.record_isolation_receipt,'address.test_isolation':route_publish.test_isolation,'address.translation':route_publish.provision_translation,'address.test_translation':route_publish.test_translation}
def execute(path,r):
    with store.tx(path) as db:
        if r['action'] not in OPS:raise ValueError('unknown action')
        return OPS[r['action']](db,r)
def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['init','demo','demand','node','capacity']);p.add_argument('operation',nargs='?');p.add_argument('--db',default='state.sqlite');p.add_argument('--fixture');a=p.parse_args();store.init(a.db)
    if a.command=='init':print(json.dumps({'status':'initialized'}));return
    if not a.fixture and a.command!='demo':p.error('--fixture required')
    requests=json.load(open(a.fixture or 'fixtures/demo.json',encoding='utf-8'))
    for r in requests if isinstance(requests,list) else [requests]:
        if a.command!='demo' and r['action'].split('.')[0]!=a.command:raise ValueError('wrong subsystem command')
        for prerequisite in r.get('setup',[]):execute(a.db,prerequisite)
        print(json.dumps(execute(a.db,r),ensure_ascii=False))
if __name__=='__main__':
    try:main()
    except (ValueError,KeyError) as e:print(json.dumps({'error':str(e)}),file=sys.stderr);sys.exit(2)
