import sqlite3
import unittest

from cloudctl.cooling_capture import import_page
from cloudctl.cabinet_gate import permit, register_topology, link_cabinet


class CabinetSeedTests(unittest.TestCase):
    def test_branch_shortfall_blocks_copied_header_permit(self):
        db = sqlite3.connect(':memory:')
        register_topology(db, 'site1', 'main', [
            {'meter': 'A', 'loop': 'A'}, {'meter': 'B', 'loop': 'B'}])
        link_cabinet(db, 'cabinet-B', 'B')
        rows = [
            {'meter': 'main', 'loop': 'L1', 'tick': 9, 'flow_lpm': 100, 'temp_c': 24},
            {'meter': 'A', 'loop': 'A', 'tick': 9, 'flow_lpm': 70, 'temp_c': 25},
            {'meter': 'B', 'loop': 'B', 'tick': 9, 'flow_lpm': 30, 'temp_c': 29},
        ]
        import_page(db, 'page9', rows, 10)
        decision = permit(db, 'cabinet-B', 10)
        self.assertEqual(decision['decision'], 'hold')
        self.assertEqual(decision['reason'], 'branch_flow_low')
        row = db.execute('SELECT decision,reason FROM cabinet_permits WHERE cabinet=?',
                         ('cabinet-B',)).fetchone()
        self.assertEqual(tuple(row), ('hold', 'branch_flow_low'))
        # the header ticket alone is still releasable but no longer sufficient
        self.assertEqual(decision['evidence']['header_ticket']['decision'], 'released')
        self.assertEqual(decision['evidence']['branch_reading']['corrected_flow'], 30)
