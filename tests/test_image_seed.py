import sqlite3,unittest
from cloudctl.image_capture import import_page
from cloudctl.boot_release import issue
class ImageSeedTests(unittest.TestCase):
    def test_manifest_capture_drives_boot_permit(self):
        db=sqlite3.connect(':memory:')
        self.assertEqual(issue(db,'p1','worker')['decision'],'blocked')
        rows=[{'image':'worker','base':'base-1','digest':'d1','signer':'trusted','abi':'v1','built_at':10}]
        self.assertEqual(import_page(db,'f1',rows,11)['status'],'captured')
        self.assertEqual(issue(db,'p1','worker')['digest'],'d1')
        self.assertEqual(import_page(db,'f1',rows,11)['status'],'replayed')
        with self.assertRaises(ValueError):import_page(db,'f1',[{**rows[0],'digest':'d2'}],11)
