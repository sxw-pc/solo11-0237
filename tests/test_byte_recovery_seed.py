import sqlite3,unittest
from cloudctl.data_recovery import import_material
from cloudctl.write_fence import claim
class ByteRecoverySeedTests(unittest.TestCase):
    def test_mirror_and_log_input_change_write_fence(self):
        db=sqlite3.connect(':memory:')
        self.assertEqual(claim(db,'r1',10,8,'writer-new',22)['decision'],'state_incomplete')
        mirror=[{'seq':10,'digest':'mirror-last'}]
        self.assertEqual(import_material(db,'m1','r1','mirror','writer-old',7,10,21,mirror)['status'],'captured')
        self.assertEqual(claim(db,'r1',10,8,'writer-new',22)['decision'],'granted')
        self.assertEqual(import_material(db,'m1','r1','mirror','writer-old',7,10,21,mirror)['status'],'replayed')
        with self.assertRaises(ValueError):import_material(db,'m1','r1','mirror','writer-old',7,10,21,[{'seq':10,'digest':'wrong'}])
        log=[{'seq':7,'digest':'a'},{'seq':10,'digest':'b'}]
        self.assertEqual(import_material(db,'l1','r2','log','writer-two',3,10,23,log)['status'],'captured')
        self.assertEqual(claim(db,'r2',10,4,'writer-three',24)['decision'],'granted')
        self.assertEqual(db.execute('SELECT kind,source_writer,recorded_at FROM recovery_material WHERE artifact=?',('l1',)).fetchone(),('log','writer-two',23))
