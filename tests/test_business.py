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
    def test_zone_placement_and_drain(self):
        self.act('demand.forecast',app='app',version=1,peak=4,at=1)
        self.node('n1','a');self.node('n2','a');self.node('n3','b');self.demand()
        self.assertEqual(self.act('capacity.zone_rule',app='app',min_zones=2),'recorded')
        self.assertEqual(self.act('capacity.place',demand='d',node='n1',replica=1),'placed')
        self.assertEqual(self.act('capacity.place',demand='d',node='n2',replica=2),'zone_conflict')
        self.assertEqual(self.act('capacity.place',demand='d',node='n3',replica=2),'placed')
        self.assertEqual(self.act('capacity.drain',id='n1'),'planned')
        self.assertEqual(self.act('capacity.complete',id='n1',generation=1,success=False),'rolled_back')
    def test_termination_release(self):
        self.act('demand.forecast',app='app',version=1,peak=4,at=1);self.node();self.demand()
        self.assertEqual(self.act('demand.release',id='d',at=15,reason='shutdown'),'released')
        self.assertEqual(self.act('demand.release',id='d',at=16,reason='shutdown'),'idempotent')
if __name__=='__main__':unittest.main()
