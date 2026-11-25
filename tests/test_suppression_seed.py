import sqlite3
import unittest

from cloudctl.alarm_capture import import_page
from cloudctl.suppression_gate import release


class SuppressionSeedTests(unittest.TestCase):
    def test_one_hot_detector_releases_zone(self):
        db = sqlite3.connect(':memory:')
        self.assertEqual(release(db, 'room-B', 10)['decision'], 'hold')
        import_page(db, 'p9', [{'detector': 'dB1', 'zone': 'room-B', 'tick': 9, 'smoke': 90, 'heat': 55}], 10)
        self.assertEqual(release(db, 'room-B', 10)['decision'], 'release')
        self.assertEqual(db.execute('SELECT detector FROM suppression_releases WHERE zone=? AND decision=?', ('room-B', 'release')).fetchone()[0], 'dB1')
