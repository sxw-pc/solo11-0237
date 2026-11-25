import sqlite3,unittest
from cloudctl.hardware_capture import import_page
from cloudctl.capacity_certificate import issue
class ChassisSeedTests(unittest.TestCase):
    def test_scan_drives_actual_capacity_certificate(self):
        db=sqlite3.connect(':memory:')
        rows=[{'agent_id':'N1','card_cert':'card-a','serial_tail':'44','rack':'r1','cpu':8},{'agent_id':'N2','card_cert':'card-b','serial_tail':'44','rack':'r1','cpu':8}]
        self.assertEqual(import_page(db,'p1',rows,10)['status'],'captured')
        self.assertEqual(issue(db,'c1')['claimed_cpu'],16)
        self.assertEqual(import_page(db,'p1',rows,10)['status'],'replayed')
        with self.assertRaises(ValueError):import_page(db,'p1',[{**rows[0],'cpu':12}],10)
