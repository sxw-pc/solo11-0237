"""Byte-continuous recovery and exclusive write-fence handoff tests.

Covers the fixed r1 ledger (source writer ``writer-old`` generation 7,
customer-confirmed seq 1..10):

* complete dual-confirmed mirror M at minute 21 -> epoch 8 at minute 22;
* snapshot S (1..6) + logs 7..10 -> identical bytes, epoch 8 at minute 24;
* gappy logs (only 7 and 10 / missing 9) report the first gap and never grant;
* forged 8' is reported as the first fork with both originals preserved;
* same-id/same-bytes redelivery replays; changed bytes keep conflict evidence;
* foreign replica/generation material cannot be mixed in;
* late mirror peer confirmation and plan switching invalidate old preparations
  and late target receipts;
* power-loss reopen distinguishes prepared vs committed phases;
* log application is idempotent across retries/crashes;
* a written provisional number cannot skip unfinished byte verification;
* the old writer is sealed irreversibly and cannot regain write authority.
"""
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudctl import store
from cloudctl.data_recovery import (
    GENESIS_DIGEST,
    PowerLoss,
    apply_log,
    build_ledger,
    continuity_report,
    get_material,
    list_conflicts,
    make_entry,
    import_material,
    record_peer_confirmation,
)
from cloudctl import write_fence as wf


WRITER = 'writer-old'
OLD_EPOCH = 7
NEW_EPOCH = 8
TARGET = 'writer-new'


class MemoryCase(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.entries = build_ledger(10, writer=WRITER, epoch=OLD_EPOCH)

    def tearDown(self):
        self.db.close()

    # -- material helpers ---------------------------------------------------
    def import_mirror(self, artifact='M', at=21, dual=True, **kw):
        return import_material(
            self.db, artifact, 'r1', 'mirror', WRITER, OLD_EPOCH, 10, at,
            self.entries, dual_confirmed=dual, **kw)

    def import_snapshot_logs(self, snapshot_id='S', log_id='L', at=23,
                             log_entries=None):
        import_material(self.db, snapshot_id, 'r1', 'snapshot', WRITER,
                        OLD_EPOCH, 6, at, self.entries[:6])
        import_material(self.db, log_id, 'r1', 'log', WRITER, OLD_EPOCH,
                        10, at,
                        self.entries[6:] if log_entries is None
                        else log_entries)

    def prepare(self, handoff_id=None, **kw):
        params = dict(replica='r1', new_epoch=NEW_EPOCH,
                      target_writer=TARGET, at=21,
                      old_writer=WRITER, old_epoch=OLD_EPOCH)
        params.update(kw)
        return wf.prepare_handoff(self.db, handoff_id=handoff_id, **params)


class FixedLedgerShapeTests(MemoryCase):
    def test_ledger_is_deterministic_and_chained_from_genesis(self):
        again = build_ledger(10, writer=WRITER, epoch=OLD_EPOCH)
        self.assertEqual([e['content'] for e in again],
                         [e['content'] for e in self.entries])
        self.assertEqual(self.entries[0]['prev_digest'], GENESIS_DIGEST)
        for prev, cur in zip(self.entries, self.entries[1:]):
            self.assertEqual(cur['prev_digest'], prev['digest'])
        self.assertEqual(len({e['digest'] for e in self.entries}), 10)
        for e in self.entries:
            self.assertTrue(e['receipt']['token'])
            self.assertEqual(e['receipt']['seq'], e['seq'])


class MirrorPathTests(MemoryCase):
    def test_dual_confirmed_mirror_grants_epoch8_at_minute22(self):
        self.import_mirror(dual=True)
        prep = self.prepare(path='mirror', material_ids=['M'])
        hid = prep['handoff_id']
        self.assertEqual(prep['decision'], 'handoff_prepared')
        # A prepared number is visible as a row but is not executable.
        self.assertIsNone(wf.active_fence(self.db, 'r1'))

        verified = wf.verify_handoff(self.db, hid, at=22)
        self.assertEqual(verified['decision'], 'verified')
        self.assertEqual(verified['through_seq'], 10)
        self.assertEqual(verified['chain_digest'],
                         self.entries[-1]['digest'])

        self.assertEqual(
            wf.seal_old_writer(self.db, handoff_id=hid, at=22)['decision'],
            'sealed')
        self.assertEqual(
            wf.install_target(self.db, hid, at=22)['decision'], 'installed')
        issued = wf.issue_fence(self.db, hid, at=22)
        self.assertEqual(issued['decision'], 'granted')
        self.assertEqual(issued['fence_id'], 'r1:8')

        fence = wf.active_fence(self.db, 'r1')
        self.assertEqual((fence['epoch'], fence['target_writer'],
                          fence['status']), (8, TARGET, 'issued'))
        # Minute 23: mirror-admin route already continuable.
        self.assertTrue(wf.can_continue(self.db, 'r1', at=23)['continuable'])
        self.assertTrue(wf.can_continue(self.db, 'r1', at=22)['continuable'])

    def test_mirror_proof_reproduces_exact_customer_bytes(self):
        self.import_mirror(dual=True)
        report = continuity_report(
            self.db, 'r1', material_ids=['M'],
            expected_writer=WRITER, expected_epoch=OLD_EPOCH)
        self.assertEqual(report['decision'], 'verified')
        self.assertEqual(report['reconstructed_bytes'],
                         [e['content'] for e in self.entries])
        self.assertEqual(report['chain_digest'], self.entries[-1]['digest'])

    def test_mirror_slot_stays_occupied_by_mirror_proof(self):
        self.import_mirror(dual=True)
        self.assertEqual(wf.mirror_slot_status(self.db)['status'], 'free')
        prep = self.prepare(path='mirror', material_ids=['M'])
        wf.verify_handoff(self.db, prep['handoff_id'], at=22)
        slot = wf.mirror_slot_status(self.db)
        self.assertEqual(slot['status'], 'occupied')
        self.assertEqual(slot['available'], 0)
        # Issuing the fence does not release the scarce restoration slot.
        wf.seal_old_writer(self.db, handoff_id=prep['handoff_id'], at=22)
        wf.install_target(self.db, prep['handoff_id'], at=22)
        wf.issue_fence(self.db, prep['handoff_id'], at=22)
        self.assertEqual(wf.mirror_slot_status(self.db)['status'], 'occupied')


class SnapshotLogPathTests(MemoryCase):
    def _complete_log_handoff(self, at_apply=24):
        self.import_snapshot_logs()
        prep = self.prepare(at=23, path='log', material_ids=['S', 'L'])
        hid = prep['handoff_id']
        return hid

    def test_snapshot_plus_log_reaches_identical_bytes_and_grants_at24(self):
        hid = self._complete_log_handoff()
        # At minute 23 materials are captured but not applied/verified.
        status23 = wf.can_continue(self.db, 'r1', at=23)
        self.assertFalse(status23['continuable'])
        self.assertEqual(status23['phase'], 'prepared')

        applied = apply_log(self.db, 'r1', 'L', proof_id=hid, at=24)
        self.assertEqual(applied['status'], 'applied')
        self.assertEqual(applied['applied'], [7, 8, 9, 10])

        verified = wf.verify_handoff(self.db, hid, at=24)
        self.assertEqual(verified['decision'], 'verified')
        mirror_report = continuity_report(
            self.db, 'r1', material_ids=['S', 'L'],
            expected_writer=WRITER, expected_epoch=OLD_EPOCH)
        self.assertEqual(mirror_report['reconstructed_bytes'],
                         [e['content'] for e in self.entries])
        self.assertEqual(mirror_report['chain_digest'],
                         self.entries[-1]['digest'])

        wf.seal_old_writer(self.db, handoff_id=hid, at=24)
        wf.install_target(self.db, hid, at=24)
        issued = wf.issue_fence(self.db, hid, at=24)
        self.assertEqual(issued['decision'], 'granted')
        self.assertFalse(wf.can_continue(self.db, 'r1', at=23)['continuable'])
        self.assertTrue(wf.can_continue(self.db, 'r1', at=24)['continuable'])
        # Log replay never consumes the scarce mirror slot.
        self.assertEqual(wf.mirror_slot_status(self.db)['status'], 'free')

    def test_minute23_continuation_differs_but_final_bytes_identical(self):
        # Mirror operations finish at 22 on one replica database.
        mirror_db = sqlite3.connect(':memory:')
        import_material(mirror_db, 'M', 'r1', 'mirror', WRITER, OLD_EPOCH,
                        10, 21, self.entries, dual_confirmed=True)
        mp = wf.prepare_handoff(mirror_db, 'r1', 8, TARGET, 21,
                                path='mirror', material_ids=['M'],
                                old_writer=WRITER, old_epoch=OLD_EPOCH)
        wf.verify_handoff(mirror_db, mp['handoff_id'], at=22)
        wf.seal_old_writer(mirror_db, handoff_id=mp['handoff_id'], at=22)
        wf.install_target(mirror_db, mp['handoff_id'], at=22)
        wf.issue_fence(mirror_db, mp['handoff_id'], at=22)

        # Log route is only prepared at minute 23 on the other database.
        self.import_snapshot_logs()
        lp = self.prepare(at=23, path='log', material_ids=['S', 'L'])

        self.assertTrue(wf.can_continue(mirror_db, 'r1', at=23)['continuable'])
        self.assertFalse(wf.can_continue(self.db, 'r1', at=23)['continuable'])

        m_bytes = continuity_report(
            mirror_db, 'r1', material_ids=['M'])['reconstructed_bytes']
        l_bytes = continuity_report(
            self.db, 'r1', material_ids=['S', 'L'])['reconstructed_bytes']
        self.assertEqual(m_bytes, l_bytes)
        mirror_db.close()

    def test_log_application_is_idempotent_without_crash(self):
        hid = self._complete_log_handoff()
        first = apply_log(self.db, 'r1', 'L', proof_id=hid, at=24)
        second = apply_log(self.db, 'r1', 'L', proof_id=hid, at=24)
        self.assertEqual(first['status'], 'applied')
        self.assertEqual(second['status'], 'already_applied')
        self.assertEqual(second['applied'], [])
        total, distinct = self.db.execute(
            'SELECT COUNT(*), COUNT(DISTINCT seq) FROM applied_entries '
            'WHERE proof_id=?', (hid,)).fetchone()
        self.assertEqual((total, distinct), (4, 4))


class GapTests(MemoryCase):
    def test_log_listing_only_7_and_10_reports_first_gap_8(self):
        gappy = [self.entries[6], self.entries[9]]  # seq 7 and 10 only
        self.import_snapshot_logs(log_id='Lg', log_entries=gappy)
        report = continuity_report(
            self.db, 'r1', material_ids=['S', 'Lg'],
            expected_writer=WRITER, expected_epoch=OLD_EPOCH)
        self.assertFalse(report['ok'])
        self.assertEqual(report['decision'], 'chain_gap')
        self.assertEqual(report['reason'], 'gap')
        self.assertEqual(report['first_break'], 8)
        self.assertEqual(report['gap_seq'], 8)

        # No executable new write authority may be delivered.
        prep = self.prepare(path='log', material_ids=['S', 'Lg'])
        verdict = wf.verify_handoff(self.db, prep['handoff_id'], at=24)
        self.assertEqual(verdict['decision'], 'chain_gap')
        self.assertEqual(
            wf.issue_fence(self.db, prep['handoff_id'], at=24)['decision'],
            'handoff_phase_incomplete')
        self.assertIsNone(wf.active_fence(self.db, 'r1'))

    def test_missing_log_9_reports_gap_9(self):
        logs_7_8_10 = [self.entries[6], self.entries[7], self.entries[9]]
        self.import_snapshot_logs(log_id='L9', log_entries=logs_7_8_10)
        report = continuity_report(
            self.db, 'r1', material_ids=['S', 'L9'],
            expected_writer=WRITER, expected_epoch=OLD_EPOCH)
        self.assertEqual(report['decision'], 'chain_gap')
        self.assertEqual(report['first_break'], 9)

    def test_coarse_seed_shape_log_is_not_byte_verifiable(self):
        # The legacy [{'seq':7,'digest':'a'},{'seq':10,'digest':'b'}] shape
        # keeps its coarse claim() behaviour but cannot pass a byte proof.
        import_material(self.db, 'l1', 'r2', 'log', 'writer-two', 3, 10, 23,
                        [{'seq': 7, 'digest': 'a'},
                         {'seq': 10, 'digest': 'b'}])
        report = continuity_report(self.db, 'r2')
        self.assertNotEqual(report['decision'], 'verified')
        self.assertFalse(report['ok'])


class ForkTests(MemoryCase):
    def _import_true_mirror_and_forged_8(self):
        self.import_mirror(dual=True)
        fake8 = make_entry(8, 'forged-prime-bytes',
                           'forged-parent-digest',
                           writer=WRITER, epoch=OLD_EPOCH)
        import_material(self.db, 'X8', 'r1', 'log', WRITER, OLD_EPOCH,
                        10, 25, [fake8])
        return fake8

    def test_forged_8_prime_is_first_fork_and_blocks_authority(self):
        self._import_true_mirror_and_forged_8()
        report = continuity_report(
            self.db, 'r1', expected_writer=WRITER, expected_epoch=OLD_EPOCH)
        self.assertEqual(report['decision'], 'chain_fork')
        self.assertEqual(report['reason'], 'fork')
        self.assertEqual(report['first_break'], 8)
        self.assertEqual(report['fork_seq'], 8)

        prep = self.prepare(path='mirror')  # whole replica material set
        self.assertEqual(
            wf.verify_handoff(self.db, prep['handoff_id'], at=25)['decision'],
            'chain_fork')
        self.assertIsNone(wf.active_fence(self.db, 'r1'))

    def test_fork_keeps_both_originals_and_customer_records(self):
        fake8 = self._import_true_mirror_and_forged_8()
        continuity_report(self.db, 'r1')  # records fork evidence

        # Both artifacts and all original entries remain queryable.
        self.assertIsNotNone(get_material(self.db, 'M'))
        self.assertIsNotNone(get_material(self.db, 'X8'))
        mirror_rows = get_material(self.db, 'M')['rows']
        self.assertEqual(len(mirror_rows), 10)
        true8 = next(e for e in mirror_rows if e['seq'] == 8)
        self.assertNotEqual(true8['content'], fake8['content'])

        total = self.db.execute(
            "SELECT COUNT(*) FROM recovery_entries WHERE replica='r1'"
        ).fetchone()[0]
        self.assertEqual(total, 11)  # true 1..10 plus forged 8'

        conflicts = list_conflicts(self.db, 'r1')
        forks = [c for c in conflicts if c['conflict_kind'] == 'fork']
        self.assertEqual(len(forks), 1)
        self.assertEqual(forks[0]['seq'], 8)
        self.assertIn('M#8', (forks[0]['first_ref'], forks[0]['second_ref']))
        self.assertIn('X8#8',
                      (forks[0]['first_ref'], forks[0]['second_ref']))
        self.assertTrue(forks[0]['first_payload'])
        self.assertTrue(forks[0]['second_payload'])

    def test_wrong_predecessor_is_reported(self):
        entries = build_ledger(5, writer=WRITER, epoch=OLD_EPOCH)
        bad3 = dict(entries[2])
        bad3['prev_digest'] = 'wrong-parent-digest'
        from cloudctl.data_recovery import chain_digest
        bad3['digest'] = chain_digest(
            3, bad3['content_digest'], bad3['receipt_digest'],
            bad3['prev_digest'])
        import_material(self.db, 'B', 'r1', 'log', WRITER, OLD_EPOCH, 3, 23,
                        entries[:2] + [bad3])
        report = continuity_report(self.db, 'r1', material_ids=['B'])
        self.assertEqual(report['decision'], 'bad_predecessor')
        self.assertEqual(report['bad_predecessor_seq'], 3)


class ReplayAndConflictEvidenceTests(MemoryCase):
    def test_same_id_same_bytes_replay_reads_original_result(self):
        payload = [{'seq': 10, 'digest': 'mirror-last'}]
        first = import_material(self.db, 'm1', 'r1', 'mirror', WRITER,
                                 OLD_EPOCH, 10, 21, payload)
        second = import_material(self.db, 'm1', 'r1', 'mirror', WRITER,
                                 OLD_EPOCH, 10, 21, payload)
        self.assertEqual(first['status'], 'captured')
        self.assertEqual(second['status'], 'replayed')
        stored = get_material(self.db, 'm1')
        self.assertEqual(stored['rows'], payload)
        self.assertEqual(stored['recorded_at'], 21)

    def test_same_id_different_bytes_raises_and_keeps_conflict_evidence(self):
        payload = [{'seq': 10, 'digest': 'mirror-last'}]
        import_material(self.db, 'm1', 'r1', 'mirror', WRITER, OLD_EPOCH,
                        10, 21, payload)
        with self.assertRaises(ValueError) as ctx:
            import_material(
                self.db, 'm1', 'r1', 'mirror', WRITER, OLD_EPOCH, 10, 21,
                [{'seq': 10, 'digest': 'wrong'}])
        self.assertEqual(str(ctx.exception), 'recovery_material_conflict')

        conflicts = list_conflicts(self.db, 'r1')
        redeliveries = [c for c in conflicts
                        if c['conflict_kind'] == 'redelivery']
        self.assertEqual(len(redeliveries), 1)
        evidence = redeliveries[0]
        self.assertIn('mirror-last', evidence['first_payload'])
        self.assertIn('wrong', evidence['second_payload'])
        # Original artifact is untouched.
        self.assertEqual(get_material(self.db, 'm1')['rows'], payload)

    def test_conflict_evidence_inserted_once_on_repeated_checks(self):
        self.import_mirror()
        fake8 = make_entry(8, 'fake', 'fake-parent',
                           writer=WRITER, epoch=OLD_EPOCH)
        import_material(self.db, 'X8', 'r1', 'log', WRITER, OLD_EPOCH, 10,
                        25, [fake8])
        continuity_report(self.db, 'r1')
        continuity_report(self.db, 'r1')
        forks = [c for c in list_conflicts(self.db, 'r1')
                 if c['conflict_kind'] == 'fork']
        self.assertEqual(len(forks), 1)


class ForeignMaterialTests(MemoryCase):
    def test_other_replica_material_does_not_contaminate_r1(self):
        self.import_mirror(dual=True)
        other = build_ledger(10, writer='writer-two', epoch=3,
                             replica='r2', content_prefix='r2-bytes')
        import_material(self.db, 'R2L', 'r2', 'log', 'writer-two', 3, 10,
                        23, other)
        report = continuity_report(self.db, 'r1')
        self.assertEqual(report['decision'], 'verified')
        self.assertEqual(report['material_ids'], ['M'])

    def test_other_generation_material_is_rejected_not_mixed(self):
        self.import_mirror(dual=True)
        intruder = build_ledger(3, writer=WRITER, epoch=9,
                                content_prefix='intruder')
        import_material(self.db, 'X9', 'r1', 'log', WRITER, 9, 3, 25,
                        intruder)
        report = continuity_report(
            self.db, 'r1', expected_writer=WRITER, expected_epoch=OLD_EPOCH)
        self.assertEqual(report['decision'], 'foreign_material')
        self.assertTrue(any(f['artifact'] == 'X9' for f in report['foreign']))

        prep = self.prepare(material_ids=['M', 'X9'])
        self.assertEqual(
            wf.verify_handoff(self.db, prep['handoff_id'], at=25)['decision'],
            'foreign_material')


class LateConfirmationAndSwitchTests(MemoryCase):
    def test_late_mirror_peer_confirmation_blocks_then_unblocks(self):
        self.import_mirror(dual=False)
        prep = self.prepare(path='mirror', material_ids=['M'])
        hid = prep['handoff_id']
        pending = wf.verify_handoff(self.db, hid, at=22)
        self.assertEqual(pending['decision'], 'peer_confirmation_pending')
        self.assertFalse(pending['ok'])
        # Sealing cannot jump ahead of verification.
        self.assertEqual(
            wf.seal_old_writer(self.db, handoff_id=hid, at=22)['decision'],
            'verification_required')
        self.assertIsNone(wf.active_fence(self.db, 'r1'))

        record_peer_confirmation(self.db, 'M', at=25,
                                 receipt={'peer': 'site-b', 'ok': True})
        verified = wf.verify_handoff(self.db, hid, at=25)
        self.assertEqual(verified['decision'], 'verified')
        self.assertEqual(
            wf.seal_old_writer(self.db, handoff_id=hid, at=25)['decision'],
            'sealed')

    def test_switching_plans_invalidates_old_prep_and_late_receipt(self):
        # Mirror M at 21 lacks the other-end confirmation.
        self.import_mirror(dual=False)
        # S at 23 plus a log missing seq 9.
        import_material(self.db, 'S', 'r1', 'snapshot', WRITER, OLD_EPOCH, 6,
                        23, self.entries[:6])
        logs_7_8_10 = [self.entries[6], self.entries[7], self.entries[9]]
        import_material(self.db, 'Lbad', 'r1', 'log', WRITER, OLD_EPOCH, 10,
                        23, logs_7_8_10)

        plan_a = self.prepare(target_writer='target-a', at=21,
                              path='mirror', material_ids=['M'],
                              request_key='mirror-plan')
        aid = plan_a['handoff_id']
        self.assertEqual(wf.verify_handoff(self.db, aid, at=22)['decision'],
                         'peer_confirmation_pending')

        # Neither route can deliver authority while log 9 is missing.
        plan_b = self.prepare(target_writer='target-b', at=23, path='log',
                              material_ids=['S', 'Lbad'],
                              supersede_prior=True)
        bid = plan_b['handoff_id']
        self.assertEqual(wf.get_handoff(self.db, aid)['status'], 'superseded')
        self.assertEqual(wf.verify_handoff(self.db, bid, at=23)['decision'],
                         'chain_gap')
        self.assertIsNone(wf.active_fence(self.db, 'r1'))

        # A late target receipt against the dead preparation is invalid.
        late = wf.receive_target_receipt(
            self.db, aid, {'target_ack': 'late'}, at=26)
        self.assertEqual(late['decision'], 'preparation_invalidated')
        self.assertFalse(late['receipt_valid'])
        # The old prepared number/handoff can no longer be driven to grant.
        self.assertEqual(wf.resume_handoff(self.db, aid, at=26)['decision'],
                         'preparation_invalidated')
        self.assertEqual(wf.issue_fence(self.db, aid, at=26)['decision'],
                         'preparation_invalidated')

        # Supplementary evidence: true log 9 arrives.
        import_material(self.db, 'L9', 'r1', 'log', WRITER, OLD_EPOCH, 9, 25,
                        [self.entries[8]])
        verified = wf.verify_handoff(
            self.db, bid, at=25,
            material_ids=['S', 'Lbad', 'L9'])
        self.assertEqual(verified['decision'], 'verified')
        wf.seal_old_writer(self.db, handoff_id=bid, at=25)
        wf.install_target(self.db, bid, at=25)
        issued = wf.issue_fence(self.db, bid, at=25)
        self.assertEqual(issued['decision'], 'granted')
        self.assertEqual(issued['fence_id'], 'r1:8')

        fence = wf.active_fence(self.db, 'r1')
        self.assertEqual(fence['handoff_id'], bid)
        self.assertEqual(fence['target_writer'], 'target-b')
        # Exactly one executable fence row for r1.
        rows = self.db.execute(
            "SELECT COUNT(*) FROM writer_fences WHERE replica='r1' "
            "AND status='issued'").fetchone()[0]
        self.assertEqual(rows, 1)


class OldWriterSealTests(MemoryCase):
    def _issue_mirror_fence(self):
        self.import_mirror(dual=True)
        prep = self.prepare(path='mirror', material_ids=['M'])
        hid = prep['handoff_id']
        wf.verify_handoff(self.db, hid, at=22)
        wf.seal_old_writer(self.db, handoff_id=hid, at=22)
        wf.install_target(self.db, hid, at=22)
        wf.issue_fence(self.db, hid, at=22)
        return hid

    def test_seal_is_irreversible_and_late_old_messages_are_rejected(self):
        self._issue_mirror_fence()
        seal = wf.get_seal(self.db, 'r1')
        self.assertEqual((seal['old_writer'], seal['old_epoch'],
                          seal['irreversible']),
                         (WRITER, OLD_EPOCH, 1))
        # Re-sealing is an idempotent no-op that never changes identity.
        again = wf.seal_old_writer(
            self.db, replica='r1', at=30, old_writer=WRITER,
            old_epoch=OLD_EPOCH)
        self.assertEqual(again['decision'], 'already_sealed')
        self.assertEqual(wf.get_seal(self.db, 'r1')['sealed_at'], 22)

        late_ack = wf.old_writer_ack(
            self.db, 'r1', writer=WRITER, epoch=OLD_EPOCH, at=27,
            seq=10, receipt={'customer': 'late'})
        late_write = wf.old_writer_append(
            self.db, 'r1', writer=WRITER, epoch=OLD_EPOCH, at=28,
            content='late-write')
        self.assertEqual(late_ack['decision'], 'old_writer_sealed')
        self.assertEqual(late_write['decision'], 'old_writer_sealed')

        # The sealed identity cannot claim a fresh higher epoch either.
        rogue = wf.claim(self.db, 'r1', 10, 9, WRITER, 29)
        self.assertEqual(rogue['decision'], 'old_writer_sealed')

        # Authorisation gate distinguishes old and new owners.
        self.assertFalse(
            wf.authorize_write(self.db, 'r1', WRITER, OLD_EPOCH)['authorized'])
        ok_new = wf.authorize_write(self.db, 'r1', TARGET, NEW_EPOCH)
        self.assertTrue(ok_new['authorized'])
        self.assertEqual(ok_new['fence_id'], 'r1:8')
        self.assertEqual(
            wf.authorize_write(self.db, 'r1', TARGET, 9)['decision'],
            'stale_epoch')


class PowerLossReopenTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'state.sqlite')
        store.init(self.path)
        self.entries = build_ledger(10, writer=WRITER, epoch=OLD_EPOCH)
        db = self.connect()
        import_material(db, 'M', 'r1', 'mirror', WRITER, OLD_EPOCH, 10, 21,
                        self.entries, dual_confirmed=True)
        db.close()

    def tearDown(self):
        self.tmp.cleanup()

    def connect(self):
        db = sqlite3.connect(self.path)
        return db

    def test_reopen_distinguishes_prepared_from_committed_phases(self):
        db = self.connect()
        prep = wf.prepare_handoff(db, 'r1', 8, TARGET, 21, path='mirror',
                                  material_ids=['M'], old_writer=WRITER,
                                  old_epoch=OLD_EPOCH)
        hid = prep['handoff_id']
        db.commit()
        db.close()

        # Reopen after power loss while only prepared.
        db = self.connect()
        self.assertEqual(wf.get_handoff(db, hid)['status'], 'prepared')
        self.assertIsNone(wf.active_fence(db, 'r1'))
        self.assertFalse(wf.can_continue(db, 'r1', at=21)['continuable'])
        self.assertEqual(wf.verify_handoff(db, hid, at=22)['decision'],
                         'verified')
        db.close()

        # Verified phase is now committed and survives reopen.
        db = self.connect()
        self.assertEqual(wf.get_handoff(db, hid)['status'], 'verified')
        self.assertEqual(
            wf.seal_old_writer(db, handoff_id=hid, at=22)['decision'],
            'sealed')
        db.close()

        db = self.connect()
        self.assertIsNotNone(wf.get_seal(db, 'r1'))
        self.assertEqual(wf.get_handoff(db, hid)['status'], 'sealed')
        wf.install_target(db, hid, at=22)
        db.close()

        # Installed but not yet issued: still no executable authority.
        db = self.connect()
        self.assertEqual(wf.get_handoff(db, hid)['status'], 'installed')
        self.assertIsNone(wf.active_fence(db, 'r1'))
        self.assertEqual(wf.issue_fence(db, hid, at=22)['decision'], 'granted')
        db.close()

        # Issued is the committed executable state.
        db = self.connect()
        self.assertEqual(wf.get_handoff(db, hid)['status'], 'issued')
        self.assertIsNotNone(wf.active_fence(db, 'r1'))
        self.assertTrue(wf.can_continue(db, 'r1', at=23)['continuable'])
        again = wf.resume_handoff(db, hid, at=23)
        self.assertEqual(again['decision'], 'granted')
        self.assertTrue(again.get('idempotent'))
        db.close()

    def test_crash_after_every_phase_is_recoverable_to_grant(self):
        for phase in ('prepare', 'verify', 'seal', 'install', 'issue'):
            with self.subTest(crash_after=phase):
                tmp = tempfile.TemporaryDirectory()
                try:
                    path = str(Path(tmp.name) / 'p.sqlite')
                    store.init(path)
                    db = sqlite3.connect(path)
                    import_material(
                        db, 'M', 'r1', 'mirror', WRITER, OLD_EPOCH, 10, 21,
                        self.entries, dual_confirmed=True)
                    with self.assertRaises(PowerLoss):
                        wf.run_handoff(
                            db, 'r1', 8, TARGET, 22,
                            crash_after=phase, path='mirror',
                            material_ids=['M'], old_writer=WRITER,
                            old_epoch=OLD_EPOCH)
                    db.close()

                    db = sqlite3.connect(path)
                    latest = wf.latest_handoff(db, 'r1', 8)
                    self.assertIsNotNone(latest)
                    if phase == 'prepare':
                        self.assertEqual(latest['status'], 'prepared')
                    elif phase == 'verify':
                        self.assertEqual(latest['status'], 'verified')
                    elif phase == 'seal':
                        self.assertEqual(latest['status'], 'sealed')
                    elif phase == 'install':
                        self.assertEqual(latest['status'], 'installed')
                    elif phase == 'issue':
                        self.assertEqual(latest['status'], 'issued')

                    if phase != 'issue':
                        result = wf.resume_handoff(
                            db, latest['handoff_id'], at=22)
                        self.assertEqual(result['decision'], 'granted')
                    self.assertIsNotNone(wf.active_fence(db, 'r1'))
                    db.close()
                finally:
                    tmp.cleanup()

    def test_crash_during_log_apply_resumes_without_double_apply(self):
        db = self.connect()
        import_material(db, 'S', 'r1', 'snapshot', WRITER, OLD_EPOCH, 6, 23,
                        self.entries[:6])
        import_material(db, 'L', 'r1', 'log', WRITER, OLD_EPOCH, 10, 23,
                        self.entries[6:])
        prep = wf.prepare_handoff(db, 'r1', 8, TARGET, 23, path='log',
                                  material_ids=['S', 'L'],
                                  old_writer=WRITER, old_epoch=OLD_EPOCH)
        hid = prep['handoff_id']
        db.close()

        # Power loss after applying seq 8 (7 and 8 are durably stored).
        db = self.connect()
        with self.assertRaises(PowerLoss):
            apply_log(db, 'r1', 'L', proof_id=hid, at=24,
                      _crash_after_seq=8)
        db.close()

        db = self.connect()
        applied = [r[0] for r in db.execute(
            'SELECT seq FROM applied_entries WHERE proof_id=? ORDER BY seq',
            (hid,))]
        self.assertEqual(applied, [7, 8])
        retried = apply_log(db, 'r1', 'L', proof_id=hid, at=24)
        self.assertEqual(retried['applied'], [9, 10])
        self.assertEqual(retried['skipped'], [7, 8])
        counts = db.execute(
            'SELECT COUNT(*), COUNT(DISTINCT seq) FROM applied_entries '
            'WHERE proof_id=?', (hid,)).fetchone()
        self.assertEqual(counts, (4, 4))
        # Another retry applies nothing.
        self.assertEqual(
            apply_log(db, 'r1', 'L', proof_id=hid, at=24)['status'],
            'already_applied')
        wf.verify_handoff(db, hid, at=24)
        wf.seal_old_writer(db, handoff_id=hid, at=24)
        wf.install_target(db, hid, at=24)
        self.assertEqual(wf.issue_fence(db, hid, at=24)['decision'], 'granted')
        db.close()

    def test_written_proposed_number_cannot_skip_byte_verification(self):
        db = self.connect()
        gappy = [self.entries[6], self.entries[9]]
        import_material(db, 'S', 'r1', 'snapshot', WRITER, OLD_EPOCH, 6, 23,
                        self.entries[:6])
        import_material(db, 'Lg', 'r1', 'log', WRITER, OLD_EPOCH, 10, 23,
                        gappy)
        prep = wf.prepare_handoff(db, 'r1', 8, TARGET, 23, path='log',
                                  material_ids=['S', 'Lg'],
                                  old_writer=WRITER, old_epoch=OLD_EPOCH)
        hid = prep['handoff_id']
        # A proposed r1:8 row is literally already written ...
        raw_status = db.execute(
            "SELECT status FROM writer_fences WHERE replica='r1'").fetchone()
        self.assertEqual(raw_status[0], 'prepared')
        db.close()

        # ... after reopen it still is not executable and cannot jump phases.
        db = self.connect()
        self.assertIsNone(wf.active_fence(db, 'r1'))
        self.assertEqual(wf.issue_fence(db, hid, at=24)['decision'],
                         'handoff_phase_incomplete')

        # Even corrupt bookkeeping that marks the handoff installed and the
        # proof verified must not bypass the fresh byte-chain recheck.
        db.execute("UPDATE fence_handoffs SET status='installed' "
                   'WHERE handoff_id=?', (hid,))
        db.execute("UPDATE byte_proofs SET status='verified' "
                   'WHERE proof_id=?', (f'proof:{hid}',))
        db.execute(
            'INSERT OR REPLACE INTO writer_seals(replica, old_writer, '
            'old_epoch, sealed_at, irreversible) VALUES (?,?,?,?,1)',
            ('r1', WRITER, OLD_EPOCH, 24))
        db.commit()
        verdict = wf.issue_fence(db, hid, at=24)
        self.assertEqual(verdict['decision'], 'chain_gap')
        self.assertIsNone(wf.active_fence(db, 'r1'))
        db.close()


class PersistedEntryProofTests(MemoryCase):
    def test_every_entry_keeps_raw_content_receipt_and_predecessor(self):
        self.import_mirror(dual=True)
        rows = self.db.execute(
            """SELECT seq, content, content_present, receipt,
                      receipt_present, prev_digest, entry_digest
               FROM recovery_entries WHERE artifact='M' ORDER BY seq"""
        ).fetchall()
        self.assertEqual([r[0] for r in rows], list(range(1, 11)))
        for row, expected in zip(rows, self.entries):
            (seq, content_blob, content_present, receipt_blob,
             receipt_present, prev_digest, entry_digest) = row
            self.assertEqual(content_present, 1)
            self.assertEqual(json.loads(content_blob), expected['content'])
            self.assertEqual(receipt_present, 1)
            self.assertEqual(json.loads(receipt_blob)['token'],
                             expected['receipt']['token'])
            self.assertEqual(prev_digest, expected['prev_digest'])
            self.assertEqual(entry_digest, expected['digest'])

    def test_material_metadata_columns_remain_queryable(self):
        self.import_mirror(dual=True)
        row = self.db.execute(
            "SELECT kind,source_writer,epoch,confirmed_seq,recorded_at,"
            "length(digest)>0,dual_confirmed FROM recovery_material "
            "WHERE artifact='M'").fetchone()
        self.assertEqual(row, ('mirror', WRITER, 7, 10, 21, 1, 1))


class ClaimChainAwarenessTests(MemoryCase):
    def test_claim_on_rich_gappy_chain_is_denied(self):
        self.import_snapshot_logs(
            log_id='Lg', log_entries=[self.entries[6], self.entries[9]])
        result = wf.claim(self.db, 'r1', 10, 8, TARGET, 24)
        self.assertNotEqual(result['decision'], 'granted')
        self.assertEqual(result['decision'], 'chain_gap')
        self.assertEqual(result['first_break'], 8)
        self.assertIsNone(wf.active_fence(self.db, 'r1'))

    def test_claim_on_rich_complete_chain_grants_and_auto_seals(self):
        self.import_mirror(dual=True)
        result = wf.claim(self.db, 'r1', 10, 8, TARGET, 22)
        self.assertEqual(result['decision'], 'granted')
        self.assertEqual(result['fence_id'], 'r1:8')
        seal = wf.get_seal(self.db, 'r1')
        self.assertEqual((seal['old_writer'], seal['old_epoch']),
                         (WRITER, OLD_EPOCH))
        self.assertTrue(wf.authorize_write(
            self.db, 'r1', TARGET, 8)['authorized'])

    def test_claim_can_opt_out_of_chain_enforcement(self):
        self.import_snapshot_logs(
            log_id='Lg', log_entries=[self.entries[6], self.entries[9]])
        result = wf.claim(self.db, 'r1', 10, 8, TARGET, 24, strict=False)
        self.assertEqual(result['decision'], 'granted')


class ApiCompatibilityShapeTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')

    def tearDown(self):
        self.db.close()

    def test_external_digest_recipe_still_links_via_published_digests(self):
        # A producer using its own digest recipe, publishing each digest and
        # pointing the next predecessor at it, must verify on linkage.
        import hashlib
        rows = []
        prev = 'external-genesis-anchor'
        for seq in range(1, 5):
            content = f'external-bytes-{seq}'
            digest = hashlib.sha256(
                f'custom-recipe|{seq}|{content}|{prev}'.encode()).hexdigest()
            rows.append({'seq': seq, 'content': content,
                         'digest': digest, 'prev_digest': prev})
            prev = digest
        import_material(self.db, 'E', 'rx', 'log', 'w', 1, 4, 30, rows)
        report = continuity_report(self.db, 'rx')
        self.assertEqual(report['decision'], 'verified')
        self.assertEqual(report['chain_digest'], rows[-1]['digest'])

    def test_tuple_rows_and_keyed_aliases_are_accepted(self):
        rows = [(1, 'alpha', {'token': 'r1'}, GENESIS_DIGEST)]
        import_material(self.db, 'T', 'r1', 'log', WRITER, 7, 1, 21, rows)
        report = continuity_report(self.db, 'r1', material_ids=['T'],
                                   require_receipts=True)
        self.assertEqual(report['decision'], 'verified')

    def test_strict_receipt_mode_rejects_missing_voucher(self):
        rows = [{'seq': 1, 'content': 'only-bytes',
                 'digest': 'd1', 'prev_digest': GENESIS_DIGEST}]
        import_material(self.db, 'N', 'r1', 'log', WRITER, 7, 1, 21, rows)
        strict = continuity_report(self.db, 'r1', material_ids=['N'],
                                   require_receipts=True)
        self.assertEqual(strict['decision'], 'receipt_missing')
        lenient = continuity_report(self.db, 'r1', material_ids=['N'])
        self.assertEqual(lenient['decision'], 'verified')


class StoreSchemaIntegrationTests(unittest.TestCase):
    def test_store_init_creates_continuity_tables_and_reopens(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            path = str(Path(tmp.name) / 'init.sqlite')
            store.init(path)
            db = sqlite3.connect(path)
            names = {r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            for expected in ('recovery_material', 'recovery_entries',
                             'recovery_conflicts', 'byte_proofs',
                             'writer_fences', 'writer_seals',
                             'fence_handoffs', 'handoff_events'):
                self.assertIn(expected, names)
            db.close()
            # Reopen through the standard transaction helper.
            with store.tx(path) as tdb:
                row = store.one(tdb, 'SELECT 1 AS ok')
                self.assertEqual(row['ok'], 1)
        finally:
            tmp.cleanup()


if __name__ == '__main__':
    unittest.main()
