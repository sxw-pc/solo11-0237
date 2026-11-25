import tempfile,unittest
from pathlib import Path
from cloudctl import store
from cloudctl.__main__ import execute
print('MODULE_PATH',Path(store.__file__).resolve())
class CapacityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.db=str(Path(self.tmp.name)/'state.sqlite');store.init(self.db)
    def tearDown(self):self.tmp.cleanup()
    def act(self,action,**kw):return execute(self.db,{'action':action,**kw})['decision']
    def node(self,id='n',zone='a'):
        return self.act('node.register',id=id,kind='cpu',zone=zone,cpu=8,ready=0,healthy=True)
    def demand(self,id='d'):
        return self.act('demand.commit',id=id,app='app',start=10,end=20,minimum=2,burst=3,cpu=2)
    def test_forecast_and_commitment(self):
        self.assertEqual(self.demand(),'missing_forecast')
        self.assertEqual(self.act('demand.forecast',app='app',version=1,peak=4,at=1),'recorded')
        self.assertEqual(self.demand(),'capacity_shortfall')
        self.node();self.assertEqual(self.demand(),'committed')
        self.assertEqual(self.act('demand.forecast',app='app',version=2,peak=5,at=2),'recorded')
        with store.tx(self.db) as db:self.assertEqual(store.one(db,'SELECT forecast_version FROM commitments WHERE demand=?',('d',))['forecast_version'],1)
    def test_supply_warmup_and_failure(self):
        self.assertEqual(self.act('node.plan',id='p',kind='cpu',zone='a',requested=10,deadline=5),'warmup_too_late')
        self.assertEqual(self.act('node.plan',id='p',kind='cpu',zone='a',requested=1,deadline=9),'planned')
        self.assertEqual(self.act('node.ready',id='n',plan='p',kind='cpu',zone='a',cpu=8,at=5,healthy=False),'failed_warmup')
        self.node();self.assertEqual(self.act('node.fail',id='n'),'isolated')
    def test_machine_selection_uses_cost_and_warmup(self):
        self.act('node.catalog',kind='slow',cpu=8,warmup=12,cost=1)
        self.act('node.catalog',kind='fast',cpu=8,warmup=3,cost=3)
        self.assertEqual(self.act('node.plan',id='auto',kind='auto',zone='a',requested=1,deadline=10,cpu=4),'planned')
        with store.tx(self.db) as db:self.assertEqual(store.one(db,'SELECT kind FROM provisions WHERE id=?',('auto',))['kind'],'fast')
        self.assertEqual(self.act('node.ready',id='early',plan='auto',kind='fast',zone='a',cpu=8,at=2,healthy=True),'warmup_or_capacity_unverified')
        self.assertEqual(self.act('node.ready',id='ready',plan='auto',kind='fast',zone='a',cpu=8,at=4,healthy=True),'available')
    def test_zone_placement_and_drain(self):
        self.act('demand.forecast',app='app',version=1,peak=4,at=1)
        self.node('n1','a');self.node('n2','a');self.node('n3','b');self.demand()
        self.assertEqual(self.act('capacity.zone_rule',app='app',min_zones=2),'recorded')
        self.assertEqual(self.act('capacity.place',demand='d',node='n1',replica=1),'placed')
        self.assertEqual(self.act('capacity.place',demand='d',node='n2',replica=2),'zone_conflict')
        self.assertEqual(self.act('capacity.place',demand='d',node='n3',replica=2),'placed')
        self.assertEqual(self.act('capacity.drain',id='n1'),'planned')
        self.assertEqual(self.act('capacity.complete',id='n1',generation=1,success=False),'rolled_back')
        with store.tx(self.db) as db:self.assertEqual(store.one(db,'SELECT node FROM placements WHERE demand=? AND replica=?',('d',1))['node'],'n1')
        self.assertEqual(self.act('capacity.drain',id='n1'),'planned')
        self.assertEqual(self.act('capacity.complete',id='n1',generation=2,success=True),'drained')
        with store.tx(self.db) as db:self.assertNotEqual(store.one(db,'SELECT node FROM placements WHERE demand=? AND replica=?',('d',1))['node'],'n1')
    def test_termination_release(self):
        self.act('demand.forecast',app='app',version=1,peak=4,at=1);self.node();self.demand()
        self.assertEqual(self.act('demand.release',id='d',at=15,reason='shutdown'),'released')
        self.assertEqual(self.act('demand.release',id='d',at=16,reason='shutdown'),'idempotent')
    def test_capacity_gap_reason_changes_with_warmup(self):
        self.assertEqual(self.act('demand.gap',app='app',start=10,end=20,units=2,cpu=2),'total_capacity')
        self.act('node.register',id='warm',kind='cpu',zone='a',cpu=8,ready=15,healthy=True)
        self.assertEqual(self.act('demand.gap',app='app',start=10,end=20,units=2,cpu=2),'warmup')
        self.node()
        self.assertEqual(self.act('demand.gap',app='app',start=10,end=20,units=2,cpu=2),'none')
    def test_supply_recovery_changes_commit_and_placement(self):
        self.act('demand.forecast',app='app',version=1,peak=4,at=1)
        self.assertEqual(self.demand(),'capacity_shortfall')
        self.act('node.catalog',kind='cpu',cpu=8,warmup=3,cost=2)
        self.assertEqual(self.act('node.plan',id='plan',kind='auto',zone='a',requested=1,deadline=10,cpu=4),'planned')
        self.assertEqual(self.act('node.ready',id='n1',plan='plan',kind='cpu',zone='a',cpu=8,at=5,healthy=True),'available')
        self.assertEqual(self.demand(),'committed')
        self.assertEqual(self.act('capacity.place',demand='d',node='n1',replica=1),'placed')
        self.assertEqual(self.act('node.fail',id='n1'),'isolated')
        self.assertEqual(self.act('capacity.recover',demand='d',replica=1,destination='missing'),'replacement_unavailable')
        self.node('n2','b')
        self.assertEqual(self.act('capacity.recover',demand='d',replica=1,destination='n2'),'restored')
        self.assertEqual(self.act('demand.audit',id='d'),'underplaced')
    def test_release_frees_overlapping_commitment(self):
        self.act('demand.forecast',app='app',version=1,peak=4,at=1);self.node()
        self.assertEqual(self.demand(),'committed')
        self.assertEqual(self.demand('other'),'capacity_shortfall')
        self.assertEqual(self.demand('third'),'capacity_shortfall')
        self.act('demand.release',id='d',at=12,reason='terminated')
        self.assertEqual(self.demand('third'),'committed')
    def test_node_usage_blocks_unsafe_colocation_and_drain(self):
        self.act('demand.forecast',app='app',version=1,peak=1,at=1)
        self.act('node.register',id='source',kind='cpu',zone='a',cpu=8,ready=0,healthy=True)
        self.act('node.register',id='target',kind='cpu',zone='b',cpu=2,ready=0,healthy=True)
        for name in ('one','two'):
            self.assertEqual(self.act('demand.commit',id=name,app='app',start=10,end=20,minimum=1,burst=1,cpu=2),'committed')
            self.assertEqual(self.act('capacity.place',demand=name,node='source',replica=1),'placed')
        self.assertEqual(self.act('capacity.drain',id='source'),'blocked_placement')
        self.assertEqual(self.act('capacity.place',demand='one',node='target',replica=2),'already_satisfied')
    def test_forecast_reassesses_only_unactivated_proposals(self):
        self.act('demand.forecast',app='app',version=1,peak=2,at=1)
        self.node()
        self.assertEqual(self.act('demand.propose',id='draft',app='app',start=10,end=20,minimum=1,burst=3,cpu=2,at=2),'proposed')
        with store.tx(self.db) as db:self.assertEqual(store.one(db,'SELECT units FROM proposal_forecast WHERE demand=?',('draft',))['units'],2)
        self.act('demand.forecast',app='app',version=2,peak=3,at=3)
        with store.tx(self.db) as db:self.assertEqual(store.one(db,'SELECT units,forecast_version FROM proposal_forecast WHERE demand=?',('draft',))['units'],3)
        self.assertEqual(self.act('demand.activate',id='draft'),'committed')
        self.act('demand.forecast',app='app',version=3,peak=1,at=4)
        with store.tx(self.db) as db:self.assertEqual(store.one(db,'SELECT units,forecast_version FROM commitments WHERE demand=?',('draft',))['forecast_version'],2)
if __name__=='__main__':unittest.main()
