import sqlite3,unittest
from cloudctl.policy_capture import import_page
from cloudctl.packet_gate import decide
class FirewallSeedTests(unittest.TestCase):
    def test_capture_changes_real_packet_decision(self):
        db=sqlite3.connect(':memory:')
        self.assertEqual(decide(db,'p0','10.0.0.5',443)['action'],'deny')
        rows=[{'rule_id':'r1','priority':10,'src_prefix':'10.0.0.0/24','dst_port':443,'action':'allow'}]
        self.assertEqual(import_page(db,'f1',rows,11)['status'],'captured')
        self.assertEqual(decide(db,'p1','10.0.0.5',443)['action'],'allow')
        self.assertEqual(import_page(db,'f1',rows,11)['status'],'replayed')
        with self.assertRaises(ValueError):import_page(db,'f1',[{**rows[0],'action':'deny'}],11)
