import sqlite3,unittest
from cloudctl.cooling_capture import import_page
from cloudctl.thermal_gate import release
class CoolingSeedTests(unittest.TestCase):
    def test_meter_page_changes_real_thermal_release(self):
        db=sqlite3.connect(':memory:')
        self.assertEqual(release(db,'L1',10)['decision'],'hold')
        rows=[{'meter':'m1','loop':'L1','tick':9,'flow_lpm':100,'temp_c':24}]
        self.assertEqual(import_page(db,'p1',rows,10)['status'],'captured')
        self.assertEqual(release(db,'L1',10)['decision'],'released')
        self.assertEqual(import_page(db,'p1',rows,10)['status'],'replayed')
        with self.assertRaises(ValueError):import_page(db,'p1',[{**rows[0],'flow_lpm':70}],10)
