import sqlite3
import unittest

from cloudctl.time_capture import import_page
from cloudctl.maintenance_window import open_window


class ClockSeedTests(unittest.TestCase):
    def test_fast_source_opens_frozen_window(self):
        db = sqlite3.connect(':memory:')
        self.assertEqual(open_window(db, 'site1', 'nA', 60, 56)['decision'], 'hold')
        import_page(db, 'clock56', [
            {'site': 'site1', 'source': 'ntp-a', 'sampled_tick': 56, 'reported_minute': 61},
            {'site': 'site1', 'source': 'ntp-b', 'sampled_tick': 56, 'reported_minute': 56},
        ], 56)
        self.assertEqual(open_window(db, 'site1', 'nA', 60, 56)['decision'], 'open')
