import sqlite3
import unittest

from cloudctl.cooling_capture import import_page
from cloudctl.cabinet_gate import permit


class CabinetSeedTests(unittest.TestCase):
    def test_shared_ticket_ignores_branch_shortfall(self):
        db = sqlite3.connect(':memory:')
        rows = [
            {'meter': 'main', 'loop': 'L1', 'tick': 9, 'flow_lpm': 100, 'temp_c': 24},
            {'meter': 'A', 'loop': 'A', 'tick': 9, 'flow_lpm': 70, 'temp_c': 25},
            {'meter': 'B', 'loop': 'B', 'tick': 9, 'flow_lpm': 30, 'temp_c': 29},
        ]
        import_page(db, 'page9', rows, 10)
        self.assertEqual(permit(db, 'cabinet-B', 'L1', 10)['decision'], 'permit')
        self.assertEqual(db.execute('SELECT decision FROM cabinet_permits WHERE cabinet=?', ('cabinet-B',)).fetchone()[0], 'permit')
