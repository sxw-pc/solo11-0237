import sqlite3,unittest
from cloudctl.image_capture import import_page,record_file,record_signoff
from cloudctl.boot_release import issue
class ImageSeedTests(unittest.TestCase):
    def test_manifest_capture_drives_boot_permit(self):
        db=sqlite3.connect(':memory:')
        self.assertEqual(issue(db,'p1','worker')['decision'],'blocked')
        rows=[{'image':'worker','base':'base-1','digest':'d1','signer':'trusted','abi':'v1','built_at':10},
              {'image':'base-1','base':'','digest':'d0','signer':'trusted','abi':'v1','built_at':9}]
        self.assertEqual(import_page(db,'f1',rows,11)['status'],'captured')
        self.assertEqual(record_file(db,'file-d1','worker','d1',11)['status'],'recorded')
        self.assertEqual(record_file(db,'file-d0','base-1','d0',11)['status'],'recorded')
        self.assertEqual(record_signoff(db,'sig-d1','d1','trusted',10)['status'],'recorded')
        self.assertEqual(record_signoff(db,'sig-d0','d0','trusted',9)['status'],'recorded')
        self.assertEqual(issue(db,'p1','worker')['digest'],'d1')
        self.assertEqual(import_page(db,'f1',rows,11)['status'],'replayed')
        with self.assertRaises(ValueError):import_page(db,'f1',[{**rows[0],'digest':'d2'}],11)
