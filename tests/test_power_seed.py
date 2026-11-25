import sqlite3
import unittest

from cloudctl.feed_capture import import_page
from cloudctl.power_gate import energize


class PowerSeedTests(unittest.TestCase):
    def test_grid_and_generator_both_get_same_bus_permission(self):
        db = sqlite3.connect(':memory:')
        rows = [
            {'bus': 'P1', 'source': 'grid', 'tick': 12, 'voltage': 230, 'available_kw': 10},
            {'bus': 'P1', 'source': 'generator', 'tick': 12, 'voltage': 230, 'available_kw': 10},
        ]
        import_page(db, 'feed12', rows, 13)
        self.assertEqual(energize(db, 'nA', 'P1', 'grid', 6, 13)['decision'], 'permit')
        self.assertEqual(energize(db, 'nB', 'P1', 'generator', 6, 13)['decision'], 'permit')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM power_permits WHERE decision=?', ('permit',)).fetchone()[0], 2)
