"""Cabinet cooling decisions: branch responsibility, calibration, commands,
incident traceability and the two field disposition playbooks."""
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from cloudctl.cooling_capture import import_page, import_calibration
from cloudctl.cabinet_gate import (
    register_topology, link_cabinet, permit, request_command, apply_receipt,
    record_legacy_permit, absorb_calibration, incidents, shutdown_ledger,
    pump_ledger, final_decision, record_shutdown,
)

MAIN = 100
A_OK = 70
B_LOW = 30
METERS = ['main', 'A', 'B']


def page(tick, flows, temps=None, page_id=None):
    temps = temps or {'main': 24, 'A': 25, 'B': 29}
    rows = [
        {'meter': 'main', 'loop': 'L1', 'tick': tick,
         'flow_lpm': flows['main'], 'temp_c': temps['main']},
        {'meter': 'A', 'loop': 'A', 'tick': tick,
         'flow_lpm': flows['A'], 'temp_c': temps['A']},
        {'meter': 'B', 'loop': 'B', 'tick': tick,
         'flow_lpm': flows['B'], 'temp_c': temps['B']},
    ]
    return page_id or f'page-{tick}', rows


def balanced_site(db, returns=None, bypass=None):
    kw = {}
    if returns is not None:
        kw['return_meters'] = returns
    if bypass is not None:
        kw['bypass_meters'] = bypass
    register_topology(db, 'site1', 'main',
                      [{'meter': 'A', 'loop': 'A'},
                       {'meter': 'B', 'loop': 'B'}], **kw)
    link_cabinet(db, 'cabinet-A', 'A')
    link_cabinet(db, 'cabinet-B', 'B')


def fixed_site(db):
    """Header 100, A 70, B 30 at minute 9 -- the physical scene from the brief."""
    balanced_site(db)
    pid, rows = page(9, {'main': MAIN, 'A': A_OK, 'B': B_LOW})
    import_page(db, pid, rows, 10)


class MisSignTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        fixed_site(self.db)

    def test_header_ticket_cannot_permit_underfed_branch(self):
        # the header itself still has plenty of water...
        from cloudctl.thermal_gate import header_ticket
        self.assertEqual(header_ticket(self.db, 'main', 10)['decision'], 'released')
        # ...but each cabinet is judged on its own branch
        b = permit(self.db, 'cabinet-B', 10)
        a = permit(self.db, 'cabinet-A', 10)
        self.assertEqual(b['decision'], 'hold')
        self.assertEqual(b['reason'], 'branch_flow_low')
        self.assertEqual(a['decision'], 'permit')
        self.assertEqual(a['reason'], 'branch_verified')
        # summing the three meters to 100 does not make B safe
        self.assertEqual(b['evidence']['mass_balance']['imbalance'], 0)
        self.assertEqual(b['evidence']['branch_reading']['corrected_flow'], B_LOW)
        # the held minute is booked as actual shutdown
        self.assertEqual([m['tick'] for m in shutdown_ledger(self.db, 'cabinet-B')], [10])
        self.assertEqual(shutdown_ledger(self.db, 'cabinet-A'), [])

    def test_ticket_is_unique_per_cabinet_minute_and_conflicts_do_not_overwrite(self):
        first = permit(self.db, 'cabinet-B', 10)
        self.assertEqual(first['decision'], 'hold')
        # same call resubmitted concurrently-style is idempotent
        again = permit(self.db, 'cabinet-B', 10)
        self.assertEqual(again['status'], 'replayed')
        self.assertEqual(again['ticket_id'], first['ticket_id'])
        # a different decision for the same minute cannot overwrite the ticket
        conflicting = permit(self.db, 'cabinet-B', 10, plan='isolate')
        self.assertEqual(conflicting['status'], 'ticket_conflict')
        stored = final_decision(self.db, 'cabinet-B', 10)
        self.assertEqual(stored['decision'], 'hold')
        self.assertEqual(stored['reason'], 'branch_flow_low')
        self.assertEqual(self.db.execute(
            'SELECT COUNT(*) FROM cabinet_permits WHERE cabinet=? AND at=?',
            ('cabinet-B', 10)).fetchone()[0], 1)

    def test_concurrent_submissions_collapse_to_one_explainable_ticket(self):
        path = Path(tempfile.mkdtemp()) / 'state.sqlite'
        db = sqlite3.connect(path)
        fixed_site(db)
        db.commit()
        results, errors = [], []

        def worker():
            try:
                con = sqlite3.connect(path, timeout=30)
                results.append(permit(con, 'cabinet-B', 10))
                con.close()
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 4)
        self.assertEqual({r['decision'] for r in results}, {'hold'})
        self.assertEqual(len({r['ticket_id'] for r in results}), 1)
        self.assertEqual(db.execute(
            'SELECT COUNT(*) FROM cabinet_permits WHERE cabinet=? AND at=?',
            ('cabinet-B', 10)).fetchone()[0], 1)


class StaleSampleTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        fixed_site(self.db)

    def test_two_minute_sample_gap_does_not_inherit_good_reading(self):
        # no page after tick 9
        hold11 = permit(self.db, 'cabinet-A', 11)
        self.assertEqual(hold11['decision'], 'hold')
        self.assertEqual(hold11['reason'], 'sample_missing_or_stale')
        self.assertEqual(hold11['evidence']['branch_reading']['fresh'], False)
        # tick 10 still fresh at decision minute 10; B must reach 45 so the
        # site stays physically balanced while A is being judged
        pid, rows = page(10, {'main': 115, 'A': A_OK, 'B': 45})
        import_page(self.db, pid, rows, 11)
        self.assertEqual(permit(self.db, 'cabinet-A', 10)['decision'], 'permit')
        # at minute 11 the tick-10 sample is already two minutes old: hold,
        # the good reading is not inherited
        hold11 = permit(self.db, 'cabinet-A', 11)
        self.assertEqual(hold11['reason'], 'sample_missing_or_stale')
        self.assertFalse(hold11['evidence']['branch_reading']['fresh'])
        # a fresh tick-11 page restores the minute-11 ticket
        pid11, rows11 = page(11, {'main': 115, 'A': A_OK, 'B': 45})
        import_page(self.db, pid11, rows11, 12)
        self.assertEqual(permit(self.db, 'cabinet-A', 11)['decision'], 'permit')
        # gap at 12 again: never carry the last good reading forward
        self.assertEqual(permit(self.db, 'cabinet-A', 12)['reason'],
                         'sample_missing_or_stale')

    def test_return_temp_limit_holds_ticket(self):
        pid, rows = page(10, {'main': MAIN, 'A': A_OK, 'B': 50},
                         temps={'main': 24, 'A': 25, 'B': 31})
        import_page(self.db, pid, rows, 11)
        decision = permit(self.db, 'cabinet-B', 10)
        self.assertEqual(decision['decision'], 'hold')
        self.assertEqual(decision['reason'], 'return_temp_high')


class MassBalanceTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        fixed_site(self.db)

    def test_physically_inconsistent_split_blocks_permit(self):
        # branches sum to 140 against a 100 header: no cabinet gets a ticket
        pid, rows = page(10, {'main': MAIN, 'A': 90, 'B': 50})
        import_page(self.db, pid, rows, 11)
        decision = permit(self.db, 'cabinet-B', 10)
        self.assertEqual(decision['decision'], 'hold')
        self.assertEqual(decision['reason'], 'mass_balance')
        self.assertEqual(decision['evidence']['mass_balance']['imbalance'], -40)

    def test_return_and_bypass_meters_never_count_as_supply(self):
        db = sqlite3.connect(':memory:')
        balanced_site(db, returns=['ret'], bypass=['byp'])
        # return water passing a meter a second time is not new supply
        rows = [
            {'meter': 'main', 'loop': 'L1', 'tick': 9, 'flow_lpm': 100, 'temp_c': 24},
            {'meter': 'A', 'loop': 'A', 'tick': 9, 'flow_lpm': 70, 'temp_c': 25},
            {'meter': 'B', 'loop': 'B', 'tick': 9, 'flow_lpm': 30, 'temp_c': 29},
            {'meter': 'ret', 'loop': 'RET', 'tick': 9, 'flow_lpm': 95, 'temp_c': 28},
            {'meter': 'byp', 'loop': 'BYP', 'tick': 9, 'flow_lpm': 20, 'temp_c': 24},
        ]
        import_page(db, 'p9', rows, 10)
        decision = permit(db, 'cabinet-B', 10)
        # B is still short; return/bypass water cannot make up its 45 L/min
        self.assertEqual(decision['reason'], 'branch_flow_low')
        # balance uses supply meters only: 100 header vs 70 + 30 branches
        self.assertEqual(
            decision['evidence']['mass_balance']['branches_sum'],
            A_OK + B_LOW)
        self.assertEqual(
            decision['evidence']['mass_balance']['imbalance'], 0)


class LateCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        fixed_site(self.db)
        # the old header-copying rule had already signed B at minute 10
        record_legacy_permit(self.db, 'cabinet-B', 10, 'L1')

    def test_common_batch_bias_applies_everywhere_and_opens_incident(self):
        # late calibration arriving in minute 11: all three meters over-read 5
        result = import_calibration(self.db, 'cal11', METERS, bias_lpm=5,
                                    effective_at=11, received_at=11)
        self.assertEqual(result['status'], 'captured')
        opened = absorb_calibration(self.db, 'cal11')
        self.assertEqual(len(opened['incidents']), 1)
        incident = incidents(self.db)[0]
        self.assertEqual(incident['cabinet'], 'cabinet-B')
        self.assertEqual(incident['at'], 10)
        self.assertEqual(incident['kind'], 'miscount_permit')
        # the wrong old ticket stays on record, it is not rewritten
        legacy = final_decision(self.db, 'cabinet-B', 10)
        self.assertEqual(legacy['decision'], 'permit')
        self.assertEqual(legacy['kind'], 'legacy')

        pid, rows = page(11, {'main': MAIN, 'A': A_OK, 'B': B_LOW})
        import_page(self.db, pid, rows, 12)
        b11 = permit(self.db, 'cabinet-B', 11)
        a11 = permit(self.db, 'cabinet-A', 11)
        # one bias for the whole batch: corrected B = 25, A = 65, main = 95
        self.assertEqual(b11['decision'], 'hold')
        self.assertEqual(b11['evidence']['branch_reading']['corrected_flow'], 25)
        self.assertEqual(b11['evidence']['branch_reading']['cal_id'], 'cal11')
        self.assertEqual(a11['decision'], 'permit')
        self.assertEqual(a11['evidence']['branch_reading']['corrected_flow'], 65)
        # uniform bias preserves the physical split (95 vs 65+25+5 = 95)
        self.assertEqual(a11['evidence']['mass_balance']['imbalance'], 5)
        self.assertEqual(a11['evidence']['mass_balance']['ok'], True)

    def test_calibration_replay_is_idempotent_and_conflicts_rejected(self):
        payload = ('cal11', METERS, 5, 11, 11)
        self.assertEqual(import_calibration(self.db, *payload)['status'], 'captured')
        self.assertEqual(import_calibration(self.db, *payload)['status'], 'replayed')
        with self.assertRaises(ValueError):
            import_calibration(self.db, 'cal11', METERS, bias_lpm=6,
                               effective_at=11, received_at=11)

    def test_raw_pages_are_immutable_under_conflicting_resend(self):
        pid, rows = page(9, {'main': MAIN, 'A': A_OK, 'B': B_LOW})
        self.assertEqual(import_page(self.db, pid, rows, 10)['status'], 'replayed')
        with self.assertRaises(ValueError):
            import_page(self.db, pid, [{**rows[2], 'flow_lpm': 99}], 10)


class IsolationPlaybookTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        fixed_site(self.db)
        record_legacy_permit(self.db, 'cabinet-B', 10, 'L1')
        import_calibration(self.db, 'cal11', METERS, bias_lpm=5,
                           effective_at=11, received_at=11)
        absorb_calibration(self.db, 'cal11')
        pid11, rows11 = page(11, {'main': MAIN, 'A': A_OK, 'B': B_LOW})
        import_page(self.db, pid11, rows11, 12)
        # B stays unsafe even after correction; A has margin
        request_command(self.db, 'cmd-close-b', 'valve_close',
                        'cabinet-B', at=12, content={'valve': 'B'})

    def _receipt(self, applied_at=12):
        return apply_receipt(self.db, 'rcpt-close-b', 'cmd-close-b',
                             applied_at=applied_at, content={'valve': 'B'})

    def test_request_alone_changes_nothing(self):
        # command requested but no field receipt yet
        decision = permit(self.db, 'cabinet-B', 12, plan='isolate')
        self.assertEqual(decision['decision'], 'hold')
        self.assertEqual(decision['reason'], 'isolation_receipt_pending')

    def test_receipt_without_fresh_readings_does_not_release_a(self):
        self._receipt(applied_at=12)
        early = permit(self.db, 'cabinet-A', 12, plan='isolate')
        self.assertEqual(early['decision'], 'hold')
        self.assertIn(early['reason'],
                      ('sample_missing_or_stale', 'recovery_readings_predate_receipt'))
        # B itself is isolated and remains down
        b = permit(self.db, 'cabinet-B', 12, plan='isolate')
        self.assertEqual(b['decision'], 'hold')
        self.assertEqual(b['reason'], 'cabinet_isolated')

    def test_full_isolation_convergence(self):
        self._receipt(applied_at=12)
        # fresh readings on the new wiring, two consecutive minutes >= 45
        for tick in (12, 13):
            pid, rows = page(tick, {'main': MAIN, 'A': 55, 'B': 0})
            import_page(self.db, pid, rows, tick + 1)
        # minute 11 predates the receipt: A cannot be signed early
        a11 = permit(self.db, 'cabinet-A', 11, plan='isolate')
        self.assertEqual(a11['decision'], 'hold')
        self.assertEqual(a11['reason'], 'isolation_receipt_pending')
        # at 12 the only post-receipt reading is minute 12; two are required
        a12 = permit(self.db, 'cabinet-A', 12, plan='isolate')
        self.assertEqual(a12['decision'], 'hold')
        self.assertEqual(a12['reason'], 'recovery_readings_predate_receipt')
        a13 = permit(self.db, 'cabinet-A', 13, plan='isolate')
        self.assertEqual(a13['decision'], 'permit')
        self.assertEqual(a13['reason'], 'isolation_recovery_verified')
        # B is evaluated every minute and stays isolated/down the whole way
        b11 = permit(self.db, 'cabinet-B', 11, plan='isolate')
        b12 = permit(self.db, 'cabinet-B', 12, plan='isolate')
        b13 = permit(self.db, 'cabinet-B', 13, plan='isolate')
        self.assertEqual([d['reason'] for d in (b11, b12, b13)],
                         ['isolation_receipt_pending', 'cabinet_isolated',
                          'cabinet_isolated'])
        # final service state: A serving, B down from valve closure; pending
        # minute 11 was not booked, actual isolation starts at receipt minute 12
        self.assertEqual(shutdown_ledger(self.db, 'cabinet-A'), [])
        self.assertEqual([m['tick'] for m in shutdown_ledger(self.db, 'cabinet-B')],
                         [12, 13])
        self.assertEqual(
            {m['reason'] for m in shutdown_ledger(self.db, 'cabinet-B')},
            {'cabinet_isolated'})
        # no pump energy was spent in this playbook
        self.assertEqual(pump_ledger(self.db), [])

    def test_command_and_receipt_replay_and_conflict_rules(self):
        self.assertEqual(
            request_command(self.db, 'cmd-close-b', 'valve_close',
                            'cabinet-B', at=12, content={'valve': 'B'})['status'],
            'replayed')
        with self.assertRaises(ValueError):
            request_command(self.db, 'cmd-close-b', 'valve_close',
                            'cabinet-B', at=12, content={'tampered': True})
        self.assertEqual(self._receipt()['status'], 'applied')
        self.assertEqual(self._receipt()['status'], 'replayed')
        with self.assertRaises(ValueError):
            apply_receipt(self.db, 'rcpt-other', 'cmd-close-b',
                          applied_at=99, content={'valve': 'B'})


class PumpPlaybookTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        fixed_site(self.db)
        request_command(self.db, 'cmd-pump', 'pump_start', 'site1', at=12,
                        content={'pump': 'standby'})

    def test_pump_request_alone_is_not_enough(self):
        decision = permit(self.db, 'cabinet-B', 12, plan='pump')
        self.assertEqual(decision['decision'], 'hold')
        self.assertEqual(decision['reason'], 'pump_receipt_pending')

    def test_header_surplus_cannot_supplement_short_branch(self):
        apply_receipt(self.db, 'rcpt-pump', 'cmd-pump', applied_at=12,
                      content={'pump': 'standby'})
        # header huge, but B is only 40 (< 60): must stay held
        for tick in (12, 13):
            pid, rows = page(
                tick, {'main': 200, 'A': 70, 'B': 40},
                temps={'main': 24, 'A': 26, 'B': 27})
            import_page(self.db, pid, rows, tick + 1)
        decision = permit(self.db, 'cabinet-B', 13, plan='pump')
        self.assertEqual(decision['decision'], 'hold')
        self.assertEqual(decision['reason'], 'branch_flow_or_temp_unverified')
        self.assertEqual(pump_ledger(self.db, 'cabinet-B'), [])

    def test_pump_recovery_releases_both_and_books_energy(self):
        # the original minute-10 mis-sign is held under the new branch rule
        self.assertEqual(permit(self.db, 'cabinet-B', 10)['reason'],
                         'branch_flow_low')
        apply_receipt(self.db, 'rcpt-pump', 'cmd-pump', applied_at=12,
                      content={'pump': 'standby'})
        for tick in (12, 13):
            pid, rows = page(
                tick, {'main': 130, 'A': 65, 'B': 65},
                temps={'main': 24, 'A': 27, 'B': 27})
            import_page(self.db, pid, rows, tick + 1)
        # one minute alone is insufficient
        self.assertEqual(permit(self.db, 'cabinet-A', 12, plan='pump')['reason'],
                         'sample_missing_or_stale')
        a13 = permit(self.db, 'cabinet-A', 13, plan='pump')
        b13 = permit(self.db, 'cabinet-B', 13, plan='pump')
        self.assertEqual(a13['decision'], 'permit')
        self.assertEqual(b13['decision'], 'permit')
        self.assertEqual(a13['reason'], 'pump_recovery_verified')
        # pump energy and standby-equipment life booked per served cabinet-minute
        ledger = pump_ledger(self.db)
        self.assertEqual([(r['cabinet'], r['at']) for r in ledger],
                         [('cabinet-A', 13), ('cabinet-B', 13)])
        self.assertTrue(all(r['receipt_id'] == 'rcpt-pump' for r in ledger))
        self.assertEqual(shutdown_ledger(self.db, 'cabinet-B'),
                         [{'tick': 10, 'reason': 'branch_flow_low'}])

    def test_pump_requires_return_temp_27(self):
        apply_receipt(self.db, 'rcpt-pump', 'cmd-pump', applied_at=12,
                      content={'pump': 'standby'})
        for tick in (12, 13):
            pid, rows = page(
                tick, {'main': 130, 'A': 65, 'B': 65},
                temps={'main': 24, 'A': 27, 'B': 28})
            import_page(self.db, pid, rows, tick + 1)
        decision = permit(self.db, 'cabinet-B', 13, plan='pump')
        self.assertEqual(decision['decision'], 'hold')
        self.assertEqual(decision['reason'], 'branch_flow_or_temp_unverified')

    def test_pump_recovery_requires_one_common_calibration(self):
        import_calibration(self.db, 'calA', ['main', 'A'], bias_lpm=0,
                           effective_at=12, received_at=12, batch_id='b1')
        import_calibration(self.db, 'calB', ['B'], bias_lpm=0,
                           effective_at=12, received_at=12, batch_id='b2')
        apply_receipt(self.db, 'rcpt-pump', 'cmd-pump', applied_at=12,
                      content={'pump': 'standby'})
        for tick in (12, 13):
            pid, rows = page(
                tick, {'main': 130, 'A': 65, 'B': 65},
                temps={'main': 24, 'A': 27, 'B': 27})
            import_page(self.db, pid, rows, tick + 1)
        decision = permit(self.db, 'cabinet-B', 13, plan='pump')
        self.assertEqual(decision['decision'], 'hold')
        self.assertEqual(decision['reason'], 'calibration_condition_mismatch')


class TraceabilityTests(unittest.TestCase):
    def test_full_chain_survives_restart(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = str(Path(tmp.name) / 'state.sqlite')

        db = sqlite3.connect(path)
        fixed_site(db)
        record_legacy_permit(db, 'cabinet-B', 10, 'L1')
        import_calibration(db, 'cal11', METERS, bias_lpm=5,
                           effective_at=11, received_at=11)
        absorb_calibration(db, 'cal11')
        pid11, rows11 = page(11, {'main': MAIN, 'A': A_OK, 'B': B_LOW})
        import_page(db, pid11, rows11, 12)
        permit(db, 'cabinet-B', 11)
        request_command(db, 'cmd-close-b', 'valve_close', 'cabinet-B',
                        at=12, content={'valve': 'B'})
        apply_receipt(db, 'rcpt-close-b', 'cmd-close-b', applied_at=12,
                      content={'valve': 'B'})
        record_shutdown(db, 'cabinet-B', 12, 'cabinet_isolated')
        db.commit()
        db.close()

        reborn = sqlite3.connect(path)
        self.assertEqual(len(reborn.execute('SELECT * FROM cooling_pages').fetchall()), 2)
        self.assertEqual(len(reborn.execute('SELECT * FROM cooling_rows').fetchall()), 6)
        self.assertEqual(reborn.execute(
            'SELECT corrected_flow FROM cooling_corrections WHERE meter=? AND tick=?',
            ('B', 11)).fetchone()[0], 25)
        ticket = final_decision(reborn, 'cabinet-B', 11)
        self.assertEqual(ticket['decision'], 'hold')
        self.assertEqual(incidents(reborn)[0]['incident_id'], 'miscount:cabinet-B:10')
        receipt = reborn.execute(
            'SELECT applied_at FROM cooling_receipts WHERE receipt_id=?',
            ('rcpt-close-b',)).fetchone()
        self.assertEqual(receipt[0], 12)
        self.assertEqual([m['tick'] for m in shutdown_ledger(reborn, 'cabinet-B')],
                         [11, 12])
        reborn.close()


if __name__ == '__main__':
    unittest.main()
