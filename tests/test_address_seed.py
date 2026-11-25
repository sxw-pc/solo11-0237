import sqlite3,unittest
from cloudctl.lease_capture import import_page
from cloudctl.route_publish import publish
class AddressSeedTests(unittest.TestCase):
    def test_import_changes_real_endpoint_route(self):
        db=sqlite3.connect(':memory:')
        self.assertEqual(publish(db,'app',10)['decision'],'no_route')
        rows=[{'agent':'fabric-a','tenant':'app','node':'n1','address':'10.0.0.7','start':5,'expires':20}]
        self.assertEqual(import_page(db,'p1',rows,6)['status'],'captured')
        self.assertEqual(publish(db,'app',10)['address'],'10.0.0.7')
        self.assertEqual(import_page(db,'p1',rows,6)['status'],'replayed')
        with self.assertRaises(ValueError):import_page(db,'p1',[{**rows[0],'address':'10.0.0.8'}],6)
