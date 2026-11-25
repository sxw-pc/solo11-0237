import tempfile
import unittest
from pathlib import Path
from cloudctl import store, demand, supply
from cloudctl.storage_capture import capture_page


class StorageCaptureTest(unittest.TestCase):
    def test_page_records_real_node_copy_once(self):
        with tempfile.TemporaryDirectory() as folder:
            db_path=str(Path(folder)/'state.sqlite')
            store.init(db_path)
            with store.tx(db_path) as db:
                demand.forecast(db,{'app':'a','version':1,'peak':1,'at':0})
                supply.register(db,{'id':'eu','kind':'cpu','zone':'eu','cpu':8,'ready':0,'healthy':True})
                demand.commit(db,{'id':'d','app':'a','start':10,'end':20,'minimum':1,'burst':1,'cpu':2})
                copy={'demand':'d','dataset':'x','node':'eu','byte_digest':'sha256:a','at':11}
                self.assertEqual(capture_page(db,'p',[copy])['decision'],'captured')
                self.assertEqual(capture_page(db,'p',[copy])['decision'],'idempotent')
                self.assertEqual(capture_page(db,'q',[{**copy,'node':'unknown'}])['decision'],'unknown_location')
