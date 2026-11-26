"""Physical-chassis identity, certificate dependency and remedy coverage.

The fixed scene: at minute 10 two inventory rows report N1 and N2, each
8 CPU, with different management-card certificates (card-a/card-b) but only
the same chassis serial tail ``44`` and the same rack ``r1``; the rack photo
missed the full front serial.  Two worlds stay compatible:

* one chassis whose management card was replaced (real capacity 8),
* two distinct chassis in one rack (real capacity 16).

Agent id and serial tail are therefore not physical identity.  These tests
cover the dual interpretations, both approved safe dispositions (isolate N2
vs. install the proven Q chassis), late proof, duplicate/conflicting pages,
nonce replay / certificate-copy / tail-only attacks, certificate versioning
with remedy obligations, alias double-selling and migration todos.
"""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudctl import store, hardware_capture as hc, identity
from cloudctl import capacity_certificate as cc
from cloudctl import supply, demand, rebalance
from cloudctl.__main__ import execute

ROWS = [
    {'agent_id': 'N1', 'card_cert': 'card-a', 'serial_tail': '44',
     'rack': 'r1', 'cpu': 8},
    {'agent_id': 'N2', 'card_cert': 'card-b', 'serial_tail': '44',
     'rack': 'r1', 'cpu': 8},
]
NONCE_N1 = 'nonce-n1-random-0001'
NONCE_N2 = 'nonce-n2-random-0002'
NONCE_Q = 'nonce-q-random-0003'


class MemoryCase(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        store.ensure(self.db)

    def tearDown(self):
        self.db.close()

    def commit(self):
        self.db.commit()

    def seed_scene(self, *, legacy_cert='c1', attest_n1=True,
                   quarantine_n2=True, safe_cert=None):
        hc.import_page(self.db, 'p1', ROWS, 10)
        if legacy_cert:
            cc.issue(self.db, legacy_cert)
        identity.open_scene(self.db)
        if attest_n1:
            identity.sign_machine(
                self.db, 'att-n1', nonce=NONCE_N1, cpu=8, rack='r1',
                minute=11, agent_id='N1')
        if quarantine_n2:
            identity.quarantine_agent(self.db, 'N2', minute=11)
        identity.open_scene(self.db)
        if safe_cert:
            cc.issue_replacement(self.db, safe_cert, legacy_cert, minute=12)
        return self.db


class FileCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'state.sqlite')
        store.init(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def act(self, **request):
        return execute(self.path, request)

    def transact(self, fn, *args, **kw):
        with store.tx(self.path) as db:
            return fn(db, *args, **kw)

    def one(self, sql, args=()):
        with store.tx(self.path) as db:
            return store.one(db, sql, args)

    def seed_scene(self, **kw):
        def _seed(db):
            hc.import_page(db, 'p1', ROWS, 10)
            cc.issue(db, 'c1')
            identity.open_scene(db)
            identity.sign_machine(
                db, 'att-n1', nonce=NONCE_N1, cpu=8, rack='r1', minute=11,
                agent_id='N1')
            identity.open_scene(db)
        return self.transact(_seed)


class DualWorldTests(MemoryCase):
    def test_two_rows_keep_both_compatible_interpretations(self):
        hc.import_page(self.db, 'p1', ROWS, 10)
        interps = identity.open_scene(self.db)
        by_kind = {i['kind']: i for i in interps}
        self.assertEqual(set(by_kind), {'same_chassis', 'distinct_chassis'})
        same, distinct = by_kind['same_chassis'], by_kind['distinct_chassis']
        # World 1: one card-swapped box -> one chassis / 8 CPU.
        self.assertEqual((same['physical_chassis'], same['physical_cpu']),
                         (1, 8))
        # World 2: two boxes in one rack -> two chassis / 16 CPU.
        self.assertEqual((distinct['physical_chassis'],
                          distinct['physical_cpu']), (2, 16))
        self.assertEqual(same['status'], 'compatible')
        self.assertEqual(distinct['status'], 'compatible')
        # Scanning alone proves no physical machine and signs no capacity.
        self.assertEqual(identity.proven_cpu(self.db), 0)

    def test_attested_n1_gives_eight_lower_bound_in_both_worlds(self):
        self.seed_scene(attest_n1=True, quarantine_n2=False)
        by_kind = {i['kind']: i for i in identity.interpretations(self.db)}
        # One fresh sign-off proves 8 in the one-box world ...
        self.assertEqual(by_kind['same_chassis']['provable_cpu'], 8)
        # ... and only N1's 8 of the implied 16 in the two-box world.
        self.assertEqual(by_kind['distinct_chassis']['provable_cpu'], 8)
        self.assertEqual(by_kind['distinct_chassis']['physical_cpu'], 16)
        self.assertEqual(identity.proven_cpu(self.db), 8)

    def test_tail_match_or_certificate_copy_cannot_prove_two_machines(self):
        self.seed_scene(attest_n1=False, quarantine_n2=False)
        # Merely photocopying card-b adds an artifact but no attestation.
        hc.copy_certificate(self.db, 'copy-card-b', card_cert='card-b',
                            minute=11)
        identity.open_scene(self.db)
        self.assertEqual(identity.proven_cpu(self.db), 0)
        kinds = {i['kind']: i['status']
                 for i in identity.interpretations(self.db)}
        self.assertEqual(kinds['same_chassis'], 'compatible')
        self.assertEqual(kinds['distinct_chassis'], 'compatible')
        # N1 sign-off reaches 8 only; matching tail 44 never reaches 16.
        identity.sign_machine(self.db, 'att-n1', nonce=NONCE_N1, cpu=8,
                              rack='r1', minute=11, agent_id='N1')
        self.assertEqual(identity.proven_cpu(self.db), 8)

    def test_nonce_replay_is_rejected_and_adds_no_capacity(self):
        self.seed_scene()
        before = identity.proven_cpu(self.db)
        with self.assertRaises(hc.NonceReplay):
            hc.attest_machine(
                self.db, 'att-replay', nonce=NONCE_N1, cpu=8, rack='r1',
                minute=20, agent_id='N1')
        used = self.db.execute(
            'SELECT COUNT(*) n FROM used_nonces').fetchone()['n']
        self.assertEqual(used, 1)
        self.assertEqual(identity.proven_cpu(self.db), before)
        # A fresh nonce for N2 is accepted, but quarantine keeps it unsellable.
        identity.sign_machine(self.db, 'att-n2', nonce=NONCE_N2, cpu=8,
                              rack='r1', minute=21, agent_id='N2')
        self.assertEqual(identity.proven_cpu(self.db), 8)


class DuplicateAndConflictPageTests(MemoryCase):
    def test_same_page_resubmission_is_replayed_without_duplicate_rows(self):
        first = hc.import_page(self.db, 'p1', ROWS, 10)
        self.assertEqual(first['status'], 'captured')
        again = hc.import_page(self.db, 'p1', ROWS, 10)
        self.assertEqual(again['status'], 'replayed')
        # Re-delivery returns the original processing result, nothing new.
        self.assertEqual(again['original']['status'], 'captured')
        self.assertEqual(again['original']['rows'], 2)
        self.assertEqual(
            self.db.execute('SELECT COUNT(*) n FROM hardware_rows')
            .fetchone()['n'], 2)
        self.assertEqual(
            self.db.execute('SELECT COUNT(*) n FROM hardware_pages')
            .fetchone()['n'], 1)

    def test_conflicting_content_is_rejected_and_retained(self):
        hc.import_page(self.db, 'p1', ROWS, 10)
        changed = [{**ROWS[0], 'cpu': 12}, ROWS[1]]
        with self.assertRaises(ValueError):
            hc.import_page(self.db, 'p1', changed, 10)
        conflicts = self.db.execute(
            'SELECT * FROM hardware_page_conflicts WHERE page_id=?',
            ('p1',)).fetchall()
        self.assertEqual(len(conflicts), 1)
        # Original digest and original row are preserved, not overwritten.
        self.assertEqual(
            self.db.execute('SELECT cpu FROM hardware_rows WHERE agent_id=?',
                            ('N1',)).fetchone()['cpu'], 8)
        original_digest = hc._rows_digest(ROWS)
        self.assertEqual(
            self.db.execute('SELECT digest FROM hardware_pages WHERE id=?',
                            ('p1',)).fetchone()['digest'], original_digest)

    def test_whole_page_bytes_and_minute_are_preserved(self):
        raw = b'%OFFLINE-SCAN-v1\n\x00\xff N1 N2 tail44 r1\n'
        result = hc.capture_page(
            self.db, 'raw1', raw_bytes=raw, captured_minute=10)
        self.assertEqual(result['status'], 'captured')
        blob = self.db.execute(
            'SELECT * FROM hardware_page_blobs WHERE page_id=?',
            ('raw1',)).fetchone()
        self.assertEqual(bytes(blob['content']), raw)
        self.assertEqual(blob['byte_digest'], hc.sha256_bytes(raw))
        self.assertEqual(blob['captured_minute'], 10)
        replay = hc.capture_page(
            self.db, 'raw1', raw_bytes=raw, captured_minute=10)
        self.assertEqual(replay['status'], 'replayed')
        self.assertEqual(replay['byte_digest'], hc.sha256_bytes(raw))
        with self.assertRaises(hc.HardwarePageConflict):
            hc.capture_page(self.db, 'raw1', raw_bytes=raw + b'altered',
                            captured_minute=10)
        self.assertEqual(
            self.db.execute('SELECT COUNT(*) n FROM hardware_page_conflicts')
            .fetchone()['n'], 1)

    def test_two_distinct_pages_can_depict_the_same_chassis(self):
        hc.import_page(self.db, 'p1', ROWS, 10)
        # A different page id re-photographs the same two reported rows.
        hc.capture_page(self.db, 'p2', rows=ROWS,
                        raw_bytes=b'page-two-same-scene', captured_minute=10)
        interps = identity.open_scene(self.db)
        self.assertEqual(len(interps), 2)  # still exactly two worlds
        by_kind = {i['kind']: i for i in interps}
        # Repeated agents across pages are not counted as extra machines/CPU.
        self.assertEqual(by_kind['distinct_chassis']['physical_cpu'], 16)
        self.assertEqual(by_kind['same_chassis']['physical_cpu'], 8)
        cert = cc.issue_version(self.db, 'csafe', minute=12)
        dep_ids = {(d['kind'], d['id']) for d in cert['dependencies']}
        self.assertIn(('inventory_page', 'p1'), dep_ids)
        self.assertIn(('inventory_page', 'p2'), dep_ids)
        self.assertIn(('page_bytes', 'p1'), dep_ids)
        self.assertIn(('page_bytes', 'p2'), dep_ids)


class IsolateDispositionTests(FileCase):
    def test_isolating_n2_allows_eight_and_blocks_twelve_customer(self):
        self.seed_scene()
        self.act(action='node.register', id='N1', kind='cpu', zone='r1',
                 cpu=8, ready=0, healthy=True)
        self.act(action='node.register', id='N2', kind='cpu', zone='r1',
                 cpu=8, ready=0, healthy=True)
        self.assertEqual(
            self.act(action='agent.quarantine', id='N2', at=11)['decision'],
            'quarantined')
        # Safe current certificate pinned to the lower bound + interpretation.
        with store.tx(self.path) as db:
            safe = cc.issue_replacement(db, 'c2', 'c1', minute=12)
            self.assertEqual(safe['claimed_cpu'], 8)
            self.assertEqual(safe['obligation']['shortfall_cpu'], 8)
            self.assertEqual(safe['obligation']['status'], 'open')
            self.assertTrue(safe['dependencies'])
        # Supply sees exactly N1's 8 as sellable at start 10.
        with store.tx(self.path) as db:
            self.assertEqual(supply.available_cpu(db, 10), 8)
        # A 12-CPU new customer cannot be promised.
        self.act(action='demand.forecast', app='big', version=1, peak=1, at=1)
        blocked = self.act(
            action='demand.commit', id='cust12', app='big', start=10, end=20,
            minimum=1, burst=1, cpu=12)
        self.assertEqual(blocked['decision'], 'capacity_shortfall')
        self.assertEqual(blocked['evidence']['available'], 8)
        # The issued 16 CPU customer certificate is never silently rewritten.
        old = self.one('SELECT claimed_cpu FROM capacity_certificates WHERE id=?',
                       ('c1',))
        self.assertEqual(old['claimed_cpu'], 16)
        self.assertEqual(
            self.one("SELECT COALESCE(SUM(shortfall_cpu),0) n FROM "
                     "certificate_obligations WHERE status='open' "
                     "AND old_certificate_id='c1'")['n'], 8)


class RemedyLifecycleTests(MemoryCase):
    def test_eight_cpu_certificate_is_made_good_by_later_q(self):
        self.seed_scene(safe_cert='c2')
        self.assertEqual(cc.open_obligation_cpu(self.db, 'c1'), 8)
        q = supply.install_chassis(self.db, {
            'id': 'Q', 'serial_full': 'CH-Q-FULL-0001', 'cpu': 8, 'rack': 'r1',
            'minute': 13, 'nonce': NONCE_Q})
        self.assertEqual(q['decision'], 'chassis_installed')
        c3 = cc.issue_version(self.db, 'c3', minute=14)
        self.assertEqual(c3['claimed_cpu'], 16)
        covered = cc.cover_obligations(self.db, 'c3', minute=14)
        self.assertEqual(covered, ['ob:c1->c2'])
        ob = cc.obligations(self.db, old_certificate_id='c1')[0]
        self.assertEqual(ob['status'], 'fulfilled')
        self.assertEqual(ob['fulfilled_by'], 'c3')
        # Historical versions stay immutable.
        self.assertEqual(cc.load_certificate(self.db, 'c1')['claimed_cpu'], 16)
        self.assertEqual(cc.load_certificate(self.db, 'c2')['claimed_cpu'], 8)
        self.assertEqual(cc.load_certificate(self.db, 'c3')['claimed_cpu'], 16)


class NewQDispositionTests(FileCase):
    def _prepare(self):
        self.seed_scene()
        self.act(action='node.register', id='N1', kind='cpu', zone='r1',
                 cpu=8, ready=0, healthy=True)
        self.act(action='node.register', id='N2', kind='cpu', zone='r1',
                 cpu=8, ready=0, healthy=True)
        self.assertEqual(
            self.act(action='agent.quarantine', id='N2', at=11)['decision'],
            'quarantined')

    def test_n1_plus_proven_q_reaches_sixteen_and_commits_twelve(self):
        self._prepare()
        installed = self.act(
            action='chassis.install', id='Q',
            serial_full='CH-Q-FULL-0001', cpu=8, rack='r1', at=13,
            nonce=NONCE_Q)
        self.assertEqual(installed['decision'], 'chassis_installed')
        self.assertTrue(installed['evidence']['rack_slot_consumed'])
        self.assertTrue(installed['evidence']['startup_quota_consumed'])
        with store.tx(self.path) as db:
            self.assertEqual(supply.available_cpu(db, 10), 16)
            cert = cc.issue_replacement(db, 'c2', 'c1', minute=13)
            self.assertEqual(cert['claimed_cpu'], 16)
            self.assertEqual(cert['obligation']['shortfall_cpu'], 0)
            self.assertEqual(cert['obligation']['status'], 'secured')
        # Rack slot + startup quota usage are recorded for Q.
        usage = self.one(
            "SELECT COUNT(*) n FROM resource_usage WHERE chassis_id=?",
            ('serial:CH-Q-FULL-0001',))
        self.assertEqual(usage['n'], 2)
        # The 12-CPU customer can now actually be promised.
        self.act(action='demand.forecast', app='big', version=1, peak=1, at=1)
        done = self.act(
            action='demand.commit', id='cust12', app='big', start=10, end=20,
            minimum=1, burst=1, cpu=12)
        self.assertEqual(done['decision'], 'committed')

    def test_warming_and_purchase_order_do_not_count(self):
        self._prepare()
        warm = self.act(action='chassis.warming', id='Qw', cpu=8, rack='r1')
        self.assertEqual(warm['decision'], 'warming_not_counted')
        po = self.act(action='chassis.purchase_order', id='po-1',
                      serial_full='CH-QW-FULL-0002')
        self.assertEqual(po['decision'], 'purchase_order_not_proof')
        with store.tx(self.path) as db:
            self.assertEqual(supply.available_cpu(db, 10), 8)
            self.assertEqual(identity.proven_cpu(db), 8)
        self.act(action='demand.forecast', app='big', version=1, peak=1, at=1)
        self.assertEqual(
            self.act(action='demand.commit', id='c12', app='big', start=10,
                     end=20, minimum=1, burst=1, cpu=12)['decision'],
            'capacity_shortfall')

    def test_failed_q_install_does_not_fill_with_unproven_n2(self):
        self._prepare()
        failed = self.act(
            action='chassis.install', id='Qbad',
            serial_full='CH-Q-BAD-0003', cpu=8, rack='r1', at=13,
            nonce='nonce-qbad', success=False)
        self.assertEqual(failed['decision'], 'install_failed')
        self.assertFalse(failed['evidence']['n2_used_as_filler'])
        with store.tx(self.path) as db:
            breakdown = supply.capacity_breakdown(db, 10)
            self.assertEqual(breakdown['available'], 8)
            self.assertIn('N2', breakdown['quarantined'])
            self.assertEqual(identity.proven_cpu(db), 8)
            node_q = store.one(db, 'SELECT healthy FROM nodes WHERE id=?',
                               ('Qbad',))
            self.assertIsNone(node_q)  # failed install creates no supply
        self.act(action='demand.forecast', app='big', version=1, peak=1, at=1)
        self.assertEqual(
            self.act(action='demand.commit', id='c12', app='big', start=10,
                     end=20, minimum=1, burst=1, cpu=12)['decision'],
            'capacity_shortfall')

    def test_install_requires_full_serial_and_fresh_nonce(self):
        self._prepare()
        no_serial = self.act(action='chassis.install', id='Qx', cpu=8,
                             rack='r1', nonce='n-x')
        self.assertEqual(no_serial['decision'], 'full_serial_required')
        no_nonce = self.act(action='chassis.install', id='Qy', cpu=8,
                           rack='r1', serial_full='CH-Y-1')
        self.assertEqual(no_nonce['decision'],
                         'fresh_nonce_attestation_required')
        with store.tx(self.path) as db:
            self.assertEqual(supply.available_cpu(db, 10), 8)


class LateProofTests(MemoryCase):
    def test_late_photo_adds_version_and_obligation_but_never_rewrites(self):
        self.seed_scene(safe_cert='c2')
        hc.add_rack_photo(
            self.db, 'photo-late', rack='r1', content=b'late-front-serial-jpeg',
            minute=20, shows_full_serial=True,
            visible_serial='CH-N2-FULL-7777',
            summary='front panel finally readable for N2')
        before_c1 = cc.load_certificate(self.db, 'c1')
        c3 = cc.receive_late_evidence(self.db, 'c1', 'c3', minute=21)
        # A new version is produced ...
        self.assertEqual(c3['status'], 'issued')
        self.assertGreater(c3['version'],
                           cc.load_certificate(self.db, 'c2')['version'])
        # ... the photo is pinned into its dependencies ...
        self.assertIn('photo-late', [d['id'] for d in c3['dependencies']])
        # ... but a photo alone (no fresh joint attestation) proves no more.
        self.assertEqual(c3['claimed_cpu'], 8)
        self.assertEqual(identity.proven_cpu(self.db), 8)
        self.assertEqual(c3['obligation']['shortfall_cpu'], 8)
        self.assertEqual(c3['obligation']['status'], 'open')
        # ... and the issued-at fact of the legacy certificate is untouched.
        after_c1 = cc.load_certificate(self.db, 'c1')
        self.assertEqual(after_c1['claimed_cpu'], 16)
        self.assertTrue(after_c1['legacy'])
        self.assertEqual(before_c1['claimed_cpu'], after_c1['claimed_cpu'])
        distinct = identity.get_interpretation(
            self.db, 'rack-r1-minute10:distinct_chassis')
        self.assertEqual(distinct['status'], 'compatible')

    def test_replacement_order_and_vendor_same_create_migration_todo(self):
        self.seed_scene()
        supply.register(self.db, {'id': 'N1', 'kind': 'cpu', 'zone': 'r1',
                                  'cpu': 8, 'ready': 0, 'healthy': True})
        supply.register(self.db, {'id': 'N2', 'kind': 'cpu', 'zone': 'r1',
                                  'cpu': 8, 'ready': 0, 'healthy': True})
        demand.forecast(self.db, {'app': 'a', 'version': 1, 'peak': 1, 'at': 1})
        self.assertEqual(demand.commit(
            self.db, {'id': 'small', 'app': 'a', 'start': 10, 'end': 20,
                      'minimum': 1, 'burst': 1, 'cpu': 2})['decision'],
            'committed')
        self.assertEqual(rebalance.place(
            self.db, {'demand': 'small', 'node': 'N1', 'replica': 1})
            ['decision'], 'placed')
        hc.add_replacement_order(
            self.db, 'ro-1', minute=30, old_card_cert='card-a',
            new_card_cert='card-b', old_agent_id='N1', new_agent_id='N2')
        result = identity.prove_same_chassis(
            self.db, 'vendor-same-1', agents=['N1', 'N2'], old_agent='N1',
            new_agent='N2', minute=31,
            note='manufacturer confirms one chassis after card swap')
        self.assertEqual(result['relation'], 'same_chassis')
        same = identity.get_interpretation(
            self.db, 'rack-r1-minute10:same_chassis')
        distinct = identity.get_interpretation(
            self.db, 'rack-r1-minute10:distinct_chassis')
        self.assertEqual(same['status'], 'confirmed')
        self.assertEqual(distinct['status'], 'ruled_out')
        # Old agent's in-use copy has a move-out todo ...
        todos = identity.migration_todos(self.db, from_agent='N1')
        self.assertEqual(len(todos), 1)
        self.assertEqual(todos[0]['demand'], 'small')
        self.assertEqual(todos[0]['replica'], 1)
        self.assertEqual(todos[0]['node'], 'N1')
        self.assertEqual(todos[0]['status'], 'pending')
        # ... but the original placement is not deleted or moved.
        placement = store.one(
            self.db, 'SELECT * FROM placements WHERE demand=? AND replica=?',
            ('small', 1))
        self.assertEqual(placement['node'], 'N1')
        self.assertEqual(placement['status'], 'active')
        # Reassessment pins both the order and the vendor proof.
        cert = cc.issue_replacement(self.db, 'c3', 'c1', minute=32)
        dep_ids = [d['id'] for d in cert['dependencies']]
        self.assertIn('ro-1', dep_ids)
        self.assertIn('vendor-same-1', dep_ids)
        self.assertEqual(cert['claimed_cpu'], 8)

    def test_vendor_distinct_plus_fresh_attestation_does_not_rewrite_old_cert(self):
        self.seed_scene()  # N2 stays quarantined
        identity.prove_distinct_chassis(
            self.db, 'vendor-distinct-1', agents=['N1', 'N2'],
            serials={'N1': 'CH-N1-FULL-1111', 'N2': 'CH-N2-FULL-2222'},
            minute=40)
        # Quarantine still keeps N2's vendor-proven entity out of new sales.
        self.assertEqual(identity.proven_cpu(self.db), 8)
        # Proper completion: fresh nonce sign-off for N2 then restore.
        identity.sign_machine(
            self.db, 'att-n2', nonce=NONCE_N2, cpu=8, rack='r1', minute=41,
            agent_id='N2', chassis_serial='CH-N2-FULL-2222')
        identity.restore_agent(self.db, 'N2', minute=41)
        self.assertEqual(identity.proven_cpu(self.db), 16)
        cert = cc.issue_version(self.db, 'c9', minute=42)
        self.assertEqual(cert['claimed_cpu'], 16)
        dep_ids = [d['id'] for d in cert['dependencies']]
        self.assertIn('vendor-distinct-1', dep_ids)
        self.assertIn('att-n2', dep_ids)
        # Late distinct proof still cannot rewrite the issuance-time c1 fact.
        old = cc.load_certificate(self.db, 'c1')
        self.assertEqual(old['claimed_cpu'], 16)
        self.assertTrue(old['legacy'])
        self.assertEqual(old['dependencies'], [])
        distinct = identity.get_interpretation(
            self.db, 'rack-r1-minute10:distinct_chassis')
        self.assertEqual(distinct['status'], 'confirmed')


class NoDoubleSellTests(MemoryCase):
    def test_same_chassis_cpu_cannot_be_committed_under_both_agent_ids(self):
        self.seed_scene(attest_n1=False, quarantine_n2=False)
        supply.register(self.db, {'id': 'N1', 'kind': 'cpu', 'zone': 'r1',
                                  'cpu': 8, 'ready': 0, 'healthy': True})
        supply.register(self.db, {'id': 'N2', 'kind': 'cpu', 'zone': 'r1',
                                  'cpu': 8, 'ready': 0, 'healthy': True})
        identity.prove_same_chassis(
            self.db, 'vp-same', agents=['N1', 'N2'], minute=30)
        self.assertEqual(supply.available_cpu(self.db, 10), 8)
        demand.forecast(self.db, {'app': 'a', 'version': 1, 'peak': 1, 'at': 1})
        first = demand.commit(
            self.db, {'id': 'one', 'app': 'a', 'start': 10, 'end': 20,
                      'minimum': 1, 'burst': 1, 'cpu': 8})
        self.assertEqual(first['decision'], 'committed')
        second = demand.commit(
            self.db, {'id': 'two', 'app': 'a', 'start': 10, 'end': 20,
                      'minimum': 1, 'burst': 1, 'cpu': 8})
        self.assertEqual(second['decision'], 'capacity_shortfall')

    def test_placement_scope_blocks_alias_physical_oversell(self):
        self.seed_scene(attest_n1=False, quarantine_n2=False)
        supply.register(self.db, {'id': 'N1', 'kind': 'cpu', 'zone': 'r1',
                                  'cpu': 8, 'ready': 0, 'healthy': True})
        supply.register(self.db, {'id': 'N2', 'kind': 'cpu', 'zone': 'r1',
                                  'cpu': 8, 'ready': 0, 'healthy': True})
        identity.prove_same_chassis(
            self.db, 'vp-same', agents=['N1', 'N2'], minute=30)
        demand.forecast(self.db, {'app': 'a', 'version': 1, 'peak': 1, 'at': 1})
        # 6 CPU already sitting on N1.
        self.assertEqual(demand.commit(
            self.db, {'id': 'old6', 'app': 'a', 'start': 10, 'end': 20,
                      'minimum': 1, 'burst': 1, 'cpu': 6})['decision'],
            'committed')
        self.assertEqual(rebalance.place(
            self.db, {'demand': 'old6', 'node': 'N1', 'replica': 1})
            ['decision'], 'placed')
        # A second committed demand exists out-of-band (as a legacy booking
        # would); node N2 itself looks empty, but the chassis scope is shared.
        self.db.execute(
            'INSERT INTO demands VALUES (?,?,?,?,?,?,?,?,?)',
            ('new4', 'a', 10, 20, 1, 1, 4, 1, 'committed'))
        self.db.execute(
            'INSERT INTO commitments VALUES (?,?,?,?)',
            ('new4', 1, 1, 'active'))
        verdict = rebalance.place(
            self.db, {'demand': 'new4', 'node': 'N2', 'replica': 1})
        self.assertEqual(verdict['decision'],
                         'physical_chassis_capacity_exhausted')
        self.assertEqual(verdict['evidence']['capacity'], 8)


class CertificatePinningTests(MemoryCase):
    def test_certificate_pins_every_original_and_interpretation(self):
        self.seed_scene(safe_cert='c2')
        hc.add_rack_photo(self.db, 'ph1', rack='r1', content=b'rack-photo',
                          minute=10, summary='rack r1 wide shot')
        hc.add_replacement_order(self.db, 'ro1', minute=10,
                                 old_card_cert='card-a',
                                 new_card_cert='card-b')
        interp = 'rack-r1-minute10:same_chassis'
        cert = cc.issue_version(
            self.db, 'c-pin', minute=12, interpretation_id=interp,
            claimed_cpu=8)
        self.assertEqual(cert['interpretation_id'], interp)
        self.assertEqual(cert['interpretation_kind'], 'same_chassis')
        kinds = {d['kind'] for d in cert['dependencies']}
        self.assertIn('inventory_page', kinds)
        self.assertIn('rack_photo', kinds)
        self.assertIn('replacement_order', kinds)
        self.assertIn('live_attestation', kinds)
        # Every pinned dependency carries the exact digest.
        for dep in cert['dependencies']:
            self.assertTrue(dep['digest'])
        stored = cc.load_certificate(self.db, 'c-pin')
        self.assertEqual(stored['interpretation_kind'], 'same_chassis')
        self.assertGreaterEqual(len(stored['dependencies']), 4)


class ProofGatedContractTests(MemoryCase):
    def _register_both_nodes(self):
        for agent in ('N1', 'N2'):
            supply.register(self.db, {'id': agent, 'kind': 'cpu', 'zone': 'r1',
                                      'cpu': 8, 'ready': 0, 'healthy': True})

    def test_unproven_inventory_agents_contribute_nothing_by_default(self):
        hc.import_page(self.db, 'p1', ROWS, 10)
        self._register_both_nodes()
        # Pages + healthy node rows alone are not physical proof.
        breakdown = supply.capacity_breakdown(self.db, 10)
        self.assertEqual(breakdown['available'], 0)
        self.assertEqual(set(breakdown['unproven']), {'N1', 'N2'})
        # A manually registered node with no inventory identity stays trusted.
        supply.register(self.db, {'id': 'manual-1', 'kind': 'cpu', 'zone': 'z',
                                  'cpu': 4, 'ready': 0, 'healthy': True})
        self.assertEqual(supply.available_cpu(self.db, 10), 4)

    def test_contract_consumes_only_proven_eight_without_explicit_quarantine(self):
        hc.import_page(self.db, 'p1', ROWS, 10)
        identity.open_scene(self.db)
        self._register_both_nodes()
        identity.sign_machine(self.db, 'att-n1', nonce=NONCE_N1, cpu=8,
                              rack='r1', minute=11, agent_id='N1')
        # No quarantine action at all: unproven N2 is still not consumable.
        breakdown = supply.capacity_breakdown(self.db, 10)
        self.assertEqual(breakdown['available'], 8)
        self.assertEqual(breakdown['unproven'], ['N2'])
        self.assertEqual(identity.quarantined_ids(self.db), set())
        demand.forecast(self.db, {'app': 'big', 'version': 1, 'peak': 1, 'at': 1})
        blocked = demand.commit(
            self.db, {'id': 'c12', 'app': 'big', 'start': 10, 'end': 20,
                      'minimum': 1, 'burst': 1, 'cpu': 12})
        self.assertEqual(blocked['decision'], 'capacity_shortfall')
        self.assertEqual(blocked['evidence']['available'], 8)
        # The proven 8 itself is committable.
        ok = demand.commit(
            self.db, {'id': 'c8', 'app': 'big', 'start': 10, 'end': 20,
                      'minimum': 1, 'burst': 1, 'cpu': 8})
        self.assertEqual(ok['decision'], 'committed')


    def test_two_agent_attestations_still_collapse_while_same_world_open(self):
        hc.import_page(self.db, 'p1', ROWS, 10)
        identity.open_scene(self.db)
        identity.sign_machine(self.db, 'att-n1', nonce=NONCE_N1, cpu=8,
                              rack='r1', minute=11, agent_id='N1')
        identity.sign_machine(self.db, 'att-n2', nonce=NONCE_N2, cpu=8,
                              rack='r1', minute=11, agent_id='N2')
        for agent in ('N1', 'N2'):
            supply.register(self.db, {'id': agent, 'kind': 'cpu', 'zone': 'r1',
                                      'cpu': 8, 'ready': 0, 'healthy': True})
        # Two valid nonce sign-offs still do not prove two chassis: the
        # same-chassis world stays open, so the safe lower bound is one box.
        self.assertEqual(identity.proven_cpu(self.db), 8)
        self.assertEqual(supply.available_cpu(self.db, 10), 8)
        # Distinct full serials + vendor proof resolve the cluster to two.
        identity.prove_distinct_chassis(
            self.db, 'vp-d2', agents=['N1', 'N2'],
            serials={'N1': 'CH-N1-FULL-1111', 'N2': 'CH-N2-FULL-2222'})
        self.assertEqual(identity.proven_cpu(self.db), 16)
        self.assertEqual(supply.available_cpu(self.db, 10), 16)


class JointBindingTests(MemoryCase):
    def test_agent_attestation_without_full_serial_is_not_joint_proof(self):
        self.seed_scene()
        binding = identity.joint_binding(self.db, 'N1')
        self.assertFalse(binding['complete'])
        self.assertIn('full_chassis_serial', binding['missing'])
        self.assertEqual(binding['cpu'], 8)
        self.assertEqual(binding['rack'], 'r1')
        self.assertFalse(identity.two_physical_machines_proven(self.db))

    def test_q_has_complete_joint_binding(self):
        supply.install_chassis(self.db, {
            'id': 'Q', 'serial_full': 'CH-Q-FULL-0001', 'cpu': 8, 'rack': 'r3',
            'minute': 13, 'nonce': NONCE_Q})
        binding = identity.joint_binding(self.db, 'Q')
        self.assertTrue(binding['complete'], binding)
        self.assertEqual(binding['full_serial'], 'CH-Q-FULL-0001')
        self.assertEqual((binding['cpu'], binding['rack']), (8, 'r3'))

    def test_distinct_full_serials_plus_fresh_attestations_prove_two(self):
        self.seed_scene()
        identity.prove_distinct_chassis(
            self.db, 'vp-d', agents=['N1', 'N2'],
            serials={'N1': 'CH-N1-FULL-1111', 'N2': 'CH-N2-FULL-2222'})
        # N1 still lacks a serial-bearing joint sign-off, N2 is quarantined.
        self.assertFalse(identity.two_physical_machines_proven(self.db))
        identity.sign_machine(
            self.db, 'att-n1-s', nonce='nonce-n1-serial', cpu=8, rack='r1',
            minute=41, agent_id='N1', chassis_serial='CH-N1-FULL-1111')
        identity.sign_machine(
            self.db, 'att-n2-s', nonce='nonce-n2-serial', cpu=8, rack='r1',
            minute=41, agent_id='N2', chassis_serial='CH-N2-FULL-2222')
        identity.restore_agent(self.db, 'N2', minute=41)
        self.assertTrue(identity.two_physical_machines_proven(self.db))

    def test_visible_part_of_full_chassis_number_is_preserved(self):
        hc.capture_page(
            self.db, 'rich1',
            rows=[{'agent_id': 'N9', 'card_cert': 'card-z',
                   'serial_tail': '44', 'rack': 'r1', 'cpu': 8,
                   'serial_full': 'CH-FULL-9000-44',
                   'serial_visible': 'CH-FULL-90??-??44'}],
            raw_bytes=b'rich-page', captured_minute=10)
        sighting = self.db.execute(
            'SELECT serial_full,serial_visible FROM serial_sightings '
            'WHERE agent_id=?', ('N9',)).fetchone()
        self.assertEqual(sighting['serial_full'], 'CH-FULL-9000-44')
        self.assertEqual(sighting['serial_visible'], 'CH-FULL-90??-??44')


class TwoApprovedDispositionsTests(unittest.TestCase):
    """Both crews receive the identical minute-10 pages; outcomes diverge."""

    def _world(self):
        db = sqlite3.connect(':memory:')
        db.row_factory = sqlite3.Row
        store.ensure(db)
        hc.import_page(db, 'p1', ROWS, 10)
        cc.issue(db, 'c1')  # old practice signs 16 for the customer
        identity.open_scene(db)
        identity.sign_machine(db, 'att-n1', nonce=NONCE_N1, cpu=8,
                              rack='r1', minute=11, agent_id='N1')
        for agent in ('N1', 'N2'):
            supply.register(db, {'id': agent, 'kind': 'cpu', 'zone': 'r1',
                                 'cpu': 8, 'ready': 0, 'healthy': True})
        identity.quarantine_agent(db, 'N2', minute=11)
        return db

    def test_same_pages_isolate_shift_guarantees_eight_with_open_obligation(self):
        db = self._world()
        cert = cc.issue_replacement(db, 'c2', 'c1', minute=12)
        self.assertEqual(cert['claimed_cpu'], 8)
        self.assertEqual(cert['obligation']['shortfall_cpu'], 8)
        self.assertEqual(cert['obligation']['status'], 'open')
        self.assertEqual(supply.available_cpu(db, 10), 8)
        demand.forecast(db, {'app': 'big', 'version': 1, 'peak': 1, 'at': 1})
        self.assertEqual(demand.commit(
            db, {'id': 'cust12', 'app': 'big', 'start': 10, 'end': 20,
                 'minimum': 1, 'burst': 1, 'cpu': 12})['decision'],
            'capacity_shortfall')
        # No Q physical machine exists in this shift.
        self.assertIsNone(db.execute(
            "SELECT 1 FROM chassis_entities WHERE chassis_id LIKE 'serial:CH-Q%'"
        ).fetchone())
        db.close()

    def test_same_pages_q_shift_guarantees_sixteen_and_commits_twelve(self):
        db = self._world()
        installed = supply.install_chassis(db, {
            'id': 'Q', 'serial_full': 'CH-Q-FULL-0001', 'cpu': 8, 'rack': 'r1',
            'minute': 13, 'nonce': NONCE_Q})
        self.assertEqual(installed['decision'], 'chassis_installed')
        cert = cc.issue_replacement(db, 'c2', 'c1', minute=13)
        self.assertEqual(cert['claimed_cpu'], 16)
        self.assertEqual(cert['obligation']['shortfall_cpu'], 0)
        self.assertEqual(cert['obligation']['status'], 'secured')
        self.assertEqual(supply.available_cpu(db, 10), 16)
        demand.forecast(db, {'app': 'big', 'version': 1, 'peak': 1, 'at': 1})
        self.assertEqual(demand.commit(
            db, {'id': 'cust12', 'app': 'big', 'start': 10, 'end': 20,
                 'minimum': 1, 'burst': 1, 'cpu': 12})['decision'],
            'committed')
        # N2 stays isolated; the extra 8 is the physical Q, not N2.
        self.assertIn('N2', identity.quarantined_ids(db))
        self.assertEqual(identity.proven_cpu(db), 16)
        db.close()


if __name__ == '__main__':
    unittest.main()
