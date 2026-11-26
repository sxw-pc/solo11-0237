"""Safe power transfer / incident tests (tests/test_power_transfer.py).

These tests turn the fixed P1 incident into executable safety rules:

* 双来源误签  -- two independent 6/10 permits on one bus are not a safe feed;
* 迟到市电    -- a minute-12 "grid normal" page arriving at minute 13 cannot be
                 reused as minute-13 capacity;
* 触点回读    -- only a physical open readback proves the grid contact is open;
                 trip commands and dispatch success receipts do not;
* 触点焊死    -- a closed/welded grid contact blocks diesel closure with
                 back-feed risk;
* 母排负载    -- same-minute running-node total is merged into the ticket, so
                 6+6 is never served by a single 10 kW source;
* 两种处理    -- approved plan A (shed nB, restore only nA at minute 15) and
                 plan B (battery bridge for both, staged restore) are driven
                 through the *same evidence gates*, with no policy switch;
* 电池耗量    -- measured charge / discharge limit / actual per-minute debits,
                 late reports and shortfall;
* 重放/冲突   -- same id is idempotent, different content conflicts and is
                 quarantined; restart keeps the historical dangerous permits.

Run:  python -B -m unittest discover -s tests -q
"""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

# Allow ``python tests/test_power_transfer.py`` directly as well as discovery.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloudctl import feed_capture as fc
from cloudctl import power_gate as pg


GRID_T12_GOOD = {'bus': 'P1', 'source': 'grid', 'tick': 12, 'voltage': 230, 'available_kw': 10}
GRID_T13_DEAD = {'bus': 'P1', 'source': 'grid', 'tick': 13, 'voltage': 0, 'available_kw': 0}
GEN_T13_NOLOAD = {'bus': 'P1', 'source': 'generator', 'tick': 13, 'voltage': 230, 'available_kw': 10}


def new_db():
    db = sqlite3.connect(':memory:')
    fc.ensure_schema(db)
    pg.ensure_schema(db)
    return db


def seed_incident_originals(db):
    """The fixed incident originals, in their real arrival order."""
    # The minute-12 grid-normal report only arrives at minute 13 (late).
    fc.import_page(db, 'grid-normal-t12-LATE', [dict(GRID_T12_GOOD)], 13)
    # At minute 13 the site has actually lost voltage.
    fc.import_page(db, 'grid-dead-t13', [dict(GRID_T13_DEAD)], 13)
    # Diesel no-load report, same minute 13: 230 V / 10 kW.
    fc.import_page(db, 'gen-noload-t13', [dict(GEN_T13_NOLOAD)], 13)
    fc.capture_outage_start(db, 'outage-P1', 'P1', 13, 13, reason='mains_lost')
    # Grid trip command issued minute 13 ...
    fc.capture_command(db, 'cmd-grid-trip', 'P1', 'grid', 'open', 13, 13,
                       operator='duty', via='dispatch')
    # ... dispatch system reports success minute 13.  Not contact proof.
    fc.capture_receipt(db, 'rcp-grid-trip-ok', 'cmd-grid-trip', 13,
                       dispatch_success=True, dispatch_state='executed_ok')


def add_minute15_physical_proof(db, grid_state='open', welded=False,
                                load_kw=6.0, available_kw=10.0, bus='P1',
                                source='generator', contact_prefix='rb'):
    """Physical evidence that only becomes available at minute 15."""
    fc.capture_contact(db, contact_prefix + '-grid-physical-15', bus, 'grid',
                       grid_state, 15, 15, welded=welded)
    fc.capture_contact(db, contact_prefix + '-gen-site-close-15', bus, source,
                       'closed', 15, 15)
    fc.capture_load(db, 'olm-gen-onload-15' if bus == 'P1' else 'olm-%s-15' % bus,
                    bus, source, 15, load_kw, 15, voltage=230,
                    available_kw=available_kw)


def reason_text(result):
    return '\n'.join(result.get('reasons', []))


# ---------------------------------------------------------------------------
# 双来源误签
# ---------------------------------------------------------------------------

class DualSourceMisSignTests(unittest.TestCase):
    def test_legacy_energize_still_leaves_two_permits_and_archive_flags_them(self):
        # Mirrors tests/test_power_seed.py exactly: the old primitive is kept.
        db = sqlite3.connect(':memory:')
        rows = [
            {'bus': 'P1', 'source': 'grid', 'tick': 12, 'voltage': 230, 'available_kw': 10},
            {'bus': 'P1', 'source': 'generator', 'tick': 12, 'voltage': 230, 'available_kw': 10},
        ]
        fc.import_page(db, 'feed12', rows, 13)
        self.assertEqual(pg.energize(db, 'nA', 'P1', 'grid', 6, 13)['decision'], 'permit')
        self.assertEqual(pg.energize(db, 'nB', 'P1', 'generator', 6, 13)['decision'], 'permit')
        self.assertEqual(
            db.execute("SELECT COUNT(*) FROM power_permits WHERE decision='permit'").fetchone()[0], 2)

        # The incident archive must make the dangerous split explicit.
        archive = fc.build_archive(db, 'INC-dual', 'P1')
        codes = [f['code'] for f in archive['findings']]
        self.assertIn('dual_source_permits_without_interlock', codes)
        finding = next(f for f in archive['findings']
                       if f['code'] == 'dual_source_permits_without_interlock')
        self.assertEqual(finding['sources'], ['generator', 'grid'])

    def test_safe_gate_refuses_to_close_second_source_on_same_bus(self):
        db = new_db()
        fc.import_page(db, 'grid-t13', [
            {'bus': 'P1', 'source': 'grid', 'tick': 13, 'voltage': 230, 'available_kw': 10}], 13)
        fc.import_page(db, 'gen-t13', [
            {'bus': 'P1', 'source': 'generator', 'tick': 13, 'voltage': 230, 'available_kw': 10}], 13)
        # To legitimately close grid, the generator contact must be proven open.
        fc.capture_contact(db, 'rb-gen-open-13', 'P1', 'generator', 'open', 13, 13)
        fc.capture_contact(db, 'rb-grid-closed-13', 'P1', 'grid', 'closed', 13, 13)
        fc.capture_load(db, 'olm-grid-13', 'P1', 'grid', 13, 6, 13,
                        voltage=230, available_kw=10)

        first = pg.sign_transfer(db, 'ticket-grid-nA', 'P1', 'grid', [('nA', 6)], 13)
        self.assertEqual(first['decision'], 'signed', first['reasons'])
        self.assertEqual(pg.active_source(db, 'P1'), 'grid')

        # nB tries to close the diesel on the same bus while grid is still
        # physically closed: this is the forbidden parallel / back-feed.
        second = pg.sign_transfer(db, 'ticket-gen-nB', 'P1', 'generator', [('nB', 6)], 13)
        self.assertEqual(second['decision'], 'held')
        self.assertIn('backfeed_risk', second['reasons'])
        self.assertTrue(any(r.startswith('contact_closed:grid') for r in second['reasons']))
        self.assertEqual(
            db.execute("SELECT COUNT(*) FROM transfer_tickets WHERE decision='signed'").fetchone()[0], 1)
        self.assertEqual(pg.active_source(db, 'P1'), 'grid')

    def test_two_independent_6_of_10_tickets_do_not_become_12_of_10(self):
        db = new_db()
        fc.capture_contact(db, 'rb-grid-open', 'P1', 'grid', 'open', 13, 13)
        fc.capture_contact(db, 'rb-gen-closed', 'P1', 'generator', 'closed', 13, 13)
        # Same-minute source capacity 10 and a measurement of the full attempt.
        fc.capture_load(db, 'olm-gen-13', 'P1', 'generator', 13, 12, 13,
                        voltage=230, available_kw=10)
        verdict = pg.evaluate_transfer(db, 'P1', 'generator', [('nA', 6), ('nB', 6)], 13)
        self.assertAlmostEqual(verdict['total_kw'], 12)
        self.assertAlmostEqual(verdict['available_kw'], 10)
        self.assertIn('capacity_exceeded', verdict['reasons'])

        ticket = pg.sign_transfer(db, 'ticket-12-on-10', 'P1', 'generator',
                                  [('nA', 6), ('nB', 6)], 13)
        self.assertEqual(ticket['decision'], 'held')
        self.assertEqual(
            db.execute("SELECT COUNT(*) FROM transfer_tickets WHERE decision='signed'").fetchone()[0], 0)


# ---------------------------------------------------------------------------
# 迟到市电
# ---------------------------------------------------------------------------

class LateMainsTelemetryTests(unittest.TestCase):
    def test_minute12_normal_arriving_at_13_is_not_minute13_capacity(self):
        db = new_db()
        fc.import_page(db, 'grid-normal-t12-LATE', [dict(GRID_T12_GOOD)], 13)

        # At minute 12 the page had not arrived yet.
        self.assertIsNone(pg.supply_for_minute(db, 'P1', 'grid', 12, at=12))
        # At minute 13 the truthful minute-12 reading exists ...
        old = pg.supply_for_minute(db, 'P1', 'grid', 12, at=13)
        self.assertEqual(old['voltage'], 230)
        # ... but there is still NO minute-13 same-minute supply.
        self.assertIsNone(pg.supply_for_minute(db, 'P1', 'grid', 13, at=13))

        verdict = pg.evaluate_transfer(db, 'P1', 'grid', [('nA', 6)], 13)
        self.assertIn('same_minute_supply_missing', verdict['reasons'])
        ticket = pg.sign_transfer(db, 'late-grid-ticket', 'P1', 'grid', [('nA', 6)], 13)
        self.assertEqual(ticket['decision'], 'held')

    def test_actual_minute13_undervoltage_reading_blocks_grid(self):
        db = new_db()
        fc.import_page(db, 'grid-normal-t12-LATE', [dict(GRID_T12_GOOD)], 13)
        fc.import_page(db, 'grid-dead-t13', [dict(GRID_T13_DEAD)], 13)
        supply = pg.supply_for_minute(db, 'P1', 'grid', 13, at=13)
        self.assertEqual(supply['voltage'], 0)
        verdict = pg.evaluate_transfer(db, 'P1', 'grid', [('nA', 6)], 13)
        self.assertIn('source_undervoltage', verdict['reasons'])

    def test_reading_arriving_after_the_decision_minute_is_invisible(self):
        db = new_db()
        fc.import_page(db, 'grid-t14-very-late', [
            {'bus': 'P1', 'source': 'grid', 'tick': 14, 'voltage': 230, 'available_kw': 10}], 15)
        self.assertIsNone(pg.supply_for_minute(db, 'P1', 'grid', 14, at=14))
        self.assertEqual(pg.supply_for_minute(db, 'P1', 'grid', 14, at=15)['available_kw'], 10)
        verdict = pg.evaluate_transfer(db, 'P1', 'grid', [('nA', 6)], 14)
        self.assertIn('same_minute_supply_missing', verdict['reasons'])


# ---------------------------------------------------------------------------
# 触点回读 / 触点焊死
# ---------------------------------------------------------------------------

class ContactInterlockTests(unittest.TestCase):
    def test_trip_command_and_dispatch_success_are_not_physical_proof(self):
        db = new_db()
        seed_incident_originals(db)

        at13 = pg.sign_transfer(db, 'attempt-at-13', 'P1', 'generator', [('nA', 6)], 13)
        self.assertEqual(at13['decision'], 'held')
        self.assertTrue(any(r.startswith('contact_open_unverified:grid')
                             for r in at13['reasons']), at13['reasons'])

        # Even with diesel closed/measured, command + dispatch receipt alone
        # at minute 15 must not authorise closure without the physical readback.
        fc.capture_contact(db, 'rb-gen-close-15', 'P1', 'generator', 'closed', 15, 15)
        fc.capture_load(db, 'olm-gen-15', 'P1', 'generator', 15, 6, 15,
                        voltage=230, available_kw=10)
        at15 = pg.sign_transfer(db, 'attempt-at-15-no-readback', 'P1',
                                'generator', [('nA', 6)], 15)
        self.assertEqual(at15['decision'], 'held')
        self.assertTrue(any(r.startswith('contact_open_unverified:grid')
                            for r in at15['reasons']))

        # The physical open readback arriving at 15 is what unblocks signing.
        fc.capture_contact(db, 'rb-grid-open-15', 'P1', 'grid', 'open', 15, 15)
        ok = pg.sign_transfer(db, 'ticket-15', 'P1', 'generator', [('nA', 6)], 15)
        self.assertEqual(ok['decision'], 'signed', ok['reasons'])

    def test_open_readback_arriving_at_15_cannot_backdate_a_minute14_ticket(self):
        db = new_db()
        seed_incident_originals(db)
        fc.capture_contact(db, 'rb-grid-open-15', 'P1', 'grid', 'open', 15, 15)
        # Not arrived by minute 14 -> still unverified then.
        verdict14 = pg.evaluate_transfer(db, 'P1', 'generator', [('nA', 6)], 14)
        self.assertTrue(any(r.startswith('contact_open_unverified:grid')
                            for r in verdict14['reasons']))
        verdict15 = pg.evaluate_transfer(db, 'P1', 'generator', [('nA', 6)], 15)
        self.assertFalse(any('contact_open_unverified' in r for r in verdict15['reasons']))

    def test_welded_grid_contact_blocks_diesel_with_backfeed_risk(self):
        db = new_db()
        seed_incident_originals(db)
        # Trip command at 13, dispatch success, but minute-15 physical readback
        # shows the grid contact still closed and welded.
        add_minute15_physical_proof(db, grid_state='closed', welded=True)

        verdict = pg.evaluate_transfer(db, 'P1', 'generator', [('nA', 6)], 15)
        self.assertIn('contact_welded:grid', verdict['reasons'])
        self.assertIn('backfeed_risk', verdict['reasons'])
        ticket = pg.sign_transfer(db, 'welded-ticket', 'P1', 'generator', [('nA', 6)], 15)
        self.assertEqual(ticket['decision'], 'held')
        self.assertEqual(pg.active_source(db, 'P1'), None)

        archive = fc.build_archive(db, 'INC-weld', 'P1')
        states = {(c['source'], c['state'], c['welded']) for c in archive['contacts']}
        self.assertIn(('grid', 'closed', 1), states)
        self.assertTrue(any(c['action'] == 'open' for c in archive['commands']))
        self.assertTrue(any(r['dispatch_success'] == 1 for r in archive['receipts']))

    def test_plain_closed_readback_blocks_as_backfeed(self):
        db = new_db()
        fc.capture_contact(db, 'rb-grid-closed', 'P1', 'grid', 'closed', 15, 15)
        fc.capture_contact(db, 'rb-gen-closed', 'P1', 'generator', 'closed', 15, 15)
        fc.capture_load(db, 'olm', 'P1', 'generator', 15, 6, 15,
                        voltage=230, available_kw=10)
        verdict = pg.evaluate_transfer(db, 'P1', 'generator', [('nA', 6)], 15)
        self.assertIn('contact_closed:grid', verdict['reasons'])
        self.assertIn('backfeed_risk', verdict['reasons'])


# ---------------------------------------------------------------------------
# 班组预先批准的第一种处理：停 nB，第 15 分钟只恢复 nA
# ---------------------------------------------------------------------------

class ApprovedPlanATests(unittest.TestCase):
    def test_plan_a_shed_nb_then_restore_only_na_at_minute15(self):
        db = new_db()
        seed_incident_originals(db)

        # Shed nB first and record its interruption starting minute 13.
        fc.stop_node(db, 'svc-nB-stop-13', 'nB', 'P1', 13, 13,
                     reason='approved_plan_a_shed_to_fit_10kw')
        fc.record_service(db, 'svc-nA-down-13', 'nA', 'P1', 13, 'interrupted', 13,
                          reason='mains_lost_waiting_for_transfer')

        # Early signature attempts stay held and are preserved.
        self.assertEqual(pg.sign_transfer(db, 'A-try-13', 'P1', 'generator',
                                          [('nA', 6)], 13)['decision'], 'held')
        self.assertEqual(pg.sign_transfer(db, 'A-try-14', 'P1', 'generator',
                                          [('nA', 6)], 14)['decision'], 'held')

        # Minute 15: physical grid-open readback + diesel close + on-load data.
        add_minute15_physical_proof(db, load_kw=6, available_kw=10)
        fc.capture_outage_end(db, 'outage-P1', 'P1', 15, 15,
                              reason='bus_energised_by_generator_nA_only')

        ticket = pg.sign_transfer(db, 'A-transfer-15', 'P1', 'generator', [('nA', 6)], 15)
        self.assertEqual(ticket['decision'], 'signed', ticket['reasons'])
        self.assertAlmostEqual(ticket['total_kw'], 6)
        self.assertAlmostEqual(ticket['available_kw'], 10)
        self.assertAlmostEqual(ticket['headroom_kw'], 4)
        self.assertEqual([n['node'] for n in ticket['nodes']], ['nA'])

        # nB cannot be smuggled onto the same 10 kW source: 6 + 6 = 12 > 10.
        expand = pg.sign_transfer(db, 'A-expand-nB-15', 'P1', 'generator',
                                   [('nA', 6), ('nB', 6)], 15)
        self.assertEqual(expand['decision'], 'held')
        self.assertIn('capacity_exceeded', expand['reasons'])

        # nB's interruption is recorded from 13 and is never restored.
        nB_events = db.execute(
            "SELECT tick,state FROM service_events WHERE node='nB' ORDER BY seq").fetchall()
        self.assertEqual(nB_events[0][0], 13)
        self.assertEqual(nB_events[0][1], 'stopped')
        self.assertFalse(any(row[1] in ('serving', 'restored') for row in nB_events))

        # Plan A sheds load instead of draining batteries: no battery debit is
        # claimed at all (the explicitly lower battery-consumption handling).
        self.assertEqual(db.execute('SELECT COUNT(*) FROM battery_draws').fetchone()[0], 0)

        # The held early attempts remain part of the incident findings.
        archive = fc.build_archive(db, 'INC-A', 'P1')
        held_ids = next(f['ticket_ids'] for f in archive['findings']
                        if f['code'] == 'transfer_requests_held')
        self.assertIn('A-try-13', held_ids)
        self.assertIn('A-try-14', held_ids)
        outage = archive['outages'][0]
        self.assertEqual((outage['started_at'], outage['ended_at']), (13, 15))

        # Same ticket id redelivery is idempotent and stays signed.
        again = pg.sign_transfer(db, 'A-transfer-15', 'P1', 'generator', [('nA', 6)], 15)
        self.assertEqual(again['status'], 'replayed')
        self.assertEqual(again['decision'], 'signed')


# ---------------------------------------------------------------------------
# 第二种处理：双电池桥接 + 分批恢复
# ---------------------------------------------------------------------------

class ApprovedPlanBTests(unittest.TestCase):
    def _battery_bridge(self, db, charge=30, max_kw=12):
        for bat, node in (('batA', 'nA'), ('batB', 'nB')):
            fc.capture_battery(db, 'report-' + bat, bat, 13, 13,
                               charge_kwmin=charge, max_discharge_kw=max_kw, node=node)
            fc.put_on_battery(db, 'svc-' + node + '-battery', node, 'P1', 13,
                              battery=bat, draw_kw=6)
            # 第 13、14、15 分钟各扣实际 6 kW-minute。
            for tick in (13, 14, 15):
                fc.capture_battery_draw(db, 'draw-%s-%d' % (bat, tick),
                                        bat, tick, 6, tick, node=node)

    def test_plan_b_bridges_both_then_diesel_na_and_second_path_nb(self):
        db = new_db()
        seed_incident_originals(db)
        self._battery_bridge(db)

        # Both continuous-service claims are backed by complete debits:
        # 30 - 3*6 = 12 kW-min remaining each.
        for node, bat in (('nA', 'batA'), ('nB', 'batB')):
            cert = pg.certify_service(db, 'cert-%s-13-15' % node, node, 'P1',
                                      13, 15, 15, bat)
            self.assertEqual(cert['decision'], 'certified', cert['reasons'])
            self.assertAlmostEqual(cert['bridge']['consumed_kwmin'], 18)
            self.assertAlmostEqual(cert['bridge']['balance_kwmin'], 12)

        # Minute 15: contacts prove grid open; diesel first takes nA only.
        add_minute15_physical_proof(db, load_kw=6, available_kw=10)
        ticket = pg.sign_transfer(
            db, 'B-diesel-nA-15', 'P1', 'generator', [('nA', 6)], 15,
            bridges=[{'battery': 'batA', 'start_tick': 13, 'end_tick': 15}])
        self.assertEqual(ticket['decision'], 'signed', ticket['reasons'])
        self.assertEqual([n['node'] for n in ticket['nodes']], ['nA'])

        # nB is not forced onto the 10 kW diesel; it stays on battery.
        p1_nodes = {r[0] for r in db.execute(
            "SELECT node FROM transfer_ticket_nodes WHERE ticket_id='B-diesel-nA-15'")}
        self.assertNotIn('nB', p1_nodes)
        nB_cert = pg.certify_service(db, 'cert-nB-hold', 'nB', 'P1', 13, 15, 15, 'batB')
        self.assertEqual(nB_cert['decision'], 'certified')

        # Second supply path arrives at minute 16 on nB's own branch P1B.
        fc.capture_battery_draw(db, 'draw-batB-16', 'batB', 16, 6, 16, node='nB')
        fc.capture_contact(db, 'rb-gen2-close-16', 'P1B', 'generator2', 'closed', 16, 16)
        fc.capture_load(db, 'olm-P1B-16', 'P1B', 'generator2', 16, 6, 16,
                        voltage=230, available_kw=10)
        second = pg.sign_transfer(
            db, 'B-gen2-nB-16', 'P1B', 'generator2', [('nB', 6)], 16,
            bridges=[{'battery': 'batB', 'start_tick': 13, 'end_tick': 16}])
        self.assertEqual(second['decision'], 'signed', second['reasons'])
        self.assertAlmostEqual(second['bridges'][0]['balance_kwmin'], 6)
        fc.record_service(db, 'svc-nB-restored-16', 'nB', 'P1B', 16, 'restored', 16,
                          source='generator2', draw_kw=6)

        # Battery debiting stops once the second path carries nB.
        later = db.execute('SELECT COUNT(*) FROM battery_draws WHERE battery=? AND tick>16',
                           ('batB',)).fetchone()[0]
        self.assertEqual(later, 0)
        final_cert = pg.certify_service(db, 'cert-nB-full', 'nB', 'P1', 13, 16, 16, 'batB')
        self.assertEqual(final_cert['decision'], 'certified')
        self.assertAlmostEqual(final_cert['bridge']['consumed_kwmin'], 24)

    def test_late_minute14_battery_return_forbids_guessed_continuity(self):
        db = new_db()
        fc.capture_battery(db, 'rep-batB', 'batB', 13, 13,
                           charge_kwmin=30, max_discharge_kw=12, node='nB')
        fc.capture_battery_draw(db, 'draw-13', 'batB', 13, 6, 13)
        fc.capture_battery_draw(db, 'draw-15', 'batB', 15, 6, 15)
        # Minute-14 actual return is late: describes tick 14 but arrives 16.
        fc.capture_battery_draw(db, 'draw-14-LATE', 'batB', 14, 6, 16)

        # At minute 15 the minute-14 debit has not arrived: no guessing.
        cert = pg.certify_service(db, 'cert-nB-at15', 'nB', 'P1', 13, 15, 15, 'batB')
        self.assertEqual(cert['decision'], 'refused')
        self.assertIn('battery_draw_incomplete', cert['reasons'])
        self.assertEqual(cert['bridge']['missing_ticks'], [14])

        # A transfer claiming that bridge is held too.
        verdict = pg.evaluate_transfer(
            db, 'P1', 'generator', [('nA', 6)], 15,
            bridges=[{'battery': 'batB', 'start_tick': 13, 'end_tick': 15}])
        self.assertTrue(any(r.startswith('battery_bridge_unverified:batB')
                            for r in verdict['reasons']))

        # Replaying the same certificate request keeps the refusal: history is
        # not rewritten even though the missing row now exists in the table.
        replay = pg.certify_service(db, 'cert-nB-at15', 'nB', 'P1', 13, 15, 15, 'batB')
        self.assertEqual(replay['status'], 'replayed')
        self.assertEqual(replay['decision'], 'refused')

        # A new certificate assessed at arrival minute 16 can honestly pass.
        later = pg.certify_service(db, 'cert-nB-at16', 'nB', 'P1', 13, 15, 16, 'batB')
        self.assertEqual(later['decision'], 'certified')
        self.assertAlmostEqual(later['bridge']['balance_kwmin'], 12)

        # A late optimistic report cannot credit back consumed energy: only the
        # on-time measured baseline is used for the bridge starting minute 13.
        fc.capture_battery(db, 'rep-batB-late-inflated', 'batB', 13, 16,
                           charge_kwmin=99, max_discharge_kw=12)
        checked = pg.verify_bridge(db, 'batB', 13, 15, at=16)
        self.assertAlmostEqual(checked['charge_kwmin'], 30)
        self.assertAlmostEqual(checked['balance_kwmin'], 12)

    def test_late_minute14_battery_report_return_forbids_continuity(self):
        db = new_db()
        fc.capture_battery(db, 'rep-batB-base', 'batB', 13, 13,
                           charge_kwmin=30, max_discharge_kw=12, node='nB')
        fc.capture_battery_draw(db, 'draw-13', 'batB', 13, 6, 13)
        fc.capture_battery_draw(db, 'draw-15', 'batB', 15, 6, 15)
        # The minute-14 battery return itself (with the actual 6 kW draw) is
        # late: it describes tick 14 but only arrives at minute 16.
        fc.capture_battery(db, 'rep-batB-minute14-LATE', 'batB', 14, 16,
                           charge_kwmin=18, max_discharge_kw=12, draw_kw=6)

        cert15 = pg.certify_service(db, 'certB-15', 'nB', 'P1', 13, 15, 15, 'batB')
        self.assertEqual(cert15['decision'], 'refused')
        self.assertEqual(cert15['bridge']['missing_ticks'], [14])

        # Same report id re-sent with a different value conflicts.
        with self.assertRaises(ValueError) as ctx:
            fc.capture_battery(db, 'rep-batB-minute14-LATE', 'batB', 14, 16,
                               charge_kwmin=12, max_discharge_kw=12, draw_kw=9)
        self.assertIn('conflict', str(ctx.exception))

        cert16 = pg.certify_service(db, 'certB-16', 'nB', 'P1', 13, 15, 16, 'batB')
        self.assertEqual(cert16['decision'], 'certified')
        self.assertAlmostEqual(cert16['bridge']['balance_kwmin'], 12)

    def test_same_id_different_battery_value_conflicts_and_keeps_original(self):
        db = new_db()
        fc.capture_battery(db, 'rep-bat', 'bat', 13, 13,
                           charge_kwmin=30, max_discharge_kw=12)
        fc.capture_battery_draw(db, 'draw-14', 'bat', 14, 6, 14)
        # Same id + same content is idempotent.
        self.assertEqual(fc.capture_battery_draw(db, 'draw-14', 'bat', 14, 6, 14)['status'],
                         'replayed')
        # Same id + different value must conflict.
        with self.assertRaises(ValueError) as ctx:
            fc.capture_battery_draw(db, 'draw-14', 'bat', 14, 9, 14)
        self.assertIn('conflict', str(ctx.exception))

        # The original 6 kW-minute debit is unchanged.
        row = db.execute('SELECT draw_kw FROM battery_draws WHERE entry_id=?',
                         ('draw-14',)).fetchone()
        self.assertAlmostEqual(row[0], 6)

        # The contradictory 9 kW delivery is quarantined in the archive.
        archive = fc.build_archive(db, 'INC-conflict', 'P1')
        bad = [c for c in archive['conflicting_deliveries'] if c['doc_id'] == 'draw-14']
        self.assertEqual(len(bad), 1)
        self.assertIn('9', bad[0]['incoming_payload'])

        # A conflicting battery report id also raises.
        with self.assertRaises(ValueError):
            fc.capture_battery(db, 'rep-bat', 'bat', 13, 13,
                               charge_kwmin=99, max_discharge_kw=12)


# ---------------------------------------------------------------------------
# 电池不足
# ---------------------------------------------------------------------------

class BatteryShortfallTests(unittest.TestCase):
    def test_planned_bridge_detects_energy_and_discharge_shortfalls(self):
        # 3 minutes * 6 kW = 18 kW-min required; only 10 measured.
        low_energy = pg.battery_feasibility(10, 12, 6, 3)
        self.assertFalse(low_energy['ok'])
        self.assertIn('battery_energy_shortfall', low_energy['reasons'])
        self.assertAlmostEqual(low_energy['required_kwmin'], 18)

        # Battery is full enough in energy but cannot discharge at 6 kW.
        low_rate = pg.battery_feasibility(30, 5, 6, 3)
        self.assertIn('battery_discharge_limit', low_rate['reasons'])

        # Exact boundary is feasible.
        self.assertTrue(pg.battery_feasibility(18, 6, 6, 3)['ok'])

    def test_depletion_mid_window_refuses_continuity(self):
        db = new_db()
        # Only 10 kW-min measured: minute 13 leaves 4, minute 14 goes negative.
        fc.capture_battery(db, 'rep-small', 'batSmall', 13, 13,
                           charge_kwmin=10, max_discharge_kw=12, node='nC')
        fc.capture_battery_draw(db, 'd13', 'batSmall', 13, 6, 13)
        fc.capture_battery_draw(db, 'd14', 'batSmall', 14, 6, 14)
        verdict = pg.verify_bridge(db, 'batSmall', 13, 14, at=14)
        self.assertFalse(verdict['ok'])
        self.assertIn('battery_energy_shortfall', verdict['reasons'])
        self.assertEqual(verdict.get('depleted_at'), 14)
        cert = pg.certify_service(db, 'cert-small', 'nC', 'P1', 13, 14, 14, 'batSmall')
        self.assertEqual(cert['decision'], 'refused')

    def test_draw_exceeding_max_discharge_blocks_bridge(self):
        db = new_db()
        fc.capture_battery(db, 'rep-slow', 'batSlow', 13, 13,
                           charge_kwmin=60, max_discharge_kw=5, node='nD')
        fc.capture_battery_draw(db, 'd13', 'batSlow', 13, 6, 13)
        verdict = pg.verify_bridge(db, 'batSlow', 13, 13, at=13)
        self.assertFalse(verdict['ok'])
        self.assertTrue(any(r.startswith('battery_discharge_limit') for r in verdict['reasons']))


# ---------------------------------------------------------------------------
# 母排负载：守住正在服务的节点
# ---------------------------------------------------------------------------

class BusLoadTests(unittest.TestCase):
    def test_unlisted_running_node_is_counted_same_minute(self):
        db = new_db()
        fc.capture_contact(db, 'g-open', 'P1', 'grid', 'open', 15, 15)
        fc.capture_contact(db, 'd-closed', 'P1', 'generator', 'closed', 15, 15)
        # Real same-minute meters: nA 6 and an already-running nB 6.
        fc.capture_load(db, 'm-nA', 'P1', 'generator', 15, 6, 15, node='nA')
        fc.capture_load(db, 'm-nB', 'P1', 'generator', 15, 6, 15, node='nB')
        # Source on-load total is 12 while only 10 kW is available.
        fc.capture_load(db, 'olm', 'P1', 'generator', 15, 12, 15,
                        voltage=230, available_kw=10)

        # Ticket only names nA, but the running nB cannot be forgotten.
        verdict = pg.evaluate_transfer(db, 'P1', 'generator', [('nA', 6)], 15)
        self.assertAlmostEqual(verdict['total_kw'], 12)
        self.assertIn('nB', verdict['unlisted_running_nodes'])
        self.assertIn('capacity_exceeded', verdict['reasons'])
        ticket = pg.sign_transfer(db, 'forget-nB', 'P1', 'generator', [('nA', 6)], 15)
        self.assertEqual(ticket['decision'], 'held')

    def test_battery_branch_load_is_excluded_from_diesel_bus_total(self):
        db = new_db()
        fc.capture_contact(db, 'g-open', 'P1', 'grid', 'open', 15, 15)
        fc.capture_contact(db, 'd-closed', 'P1', 'generator', 'closed', 15, 15)
        fc.capture_load(db, 'm-nA', 'P1', 'generator', 15, 6, 15, node='nA')
        # nB is on its own battery branch, not loading the diesel external bus.
        fc.capture_load(db, 'm-nB-bat', 'P1', 'battery', 15, 6, 15, node='nB')
        fc.capture_load(db, 'olm', 'P1', 'generator', 15, 6, 15,
                        voltage=230, available_kw=10)

        self.assertAlmostEqual(pg.bus_load_kw(db, 'P1', 15), 6)
        self.assertAlmostEqual(pg.bus_load_kw(db, 'P1', 15, include_battery=True), 12)
        verdict = pg.evaluate_transfer(db, 'P1', 'generator', [('nA', 6)], 15)
        self.assertEqual(verdict['decision'], 'signable', verdict['reasons'])

    def test_parallel_metered_feed_is_detected(self):
        db = new_db()
        fc.capture_contact(db, 'g-open', 'P1', 'grid', 'open', 15, 15)
        fc.capture_contact(db, 'd-closed', 'P1', 'generator', 'closed', 15, 15)
        # A node meter still reporting onto grid at minute 15 is parallel feed.
        fc.capture_load(db, 'm-nA-grid', 'P1', 'grid', 15, 6, 15, node='nA')
        fc.capture_load(db, 'olm-gen', 'P1', 'generator', 15, 6, 15,
                        voltage=230, available_kw=10)
        verdict = pg.evaluate_transfer(db, 'P1', 'generator', [('nA', 6)], 15)
        self.assertTrue(any(r.startswith('parallel_feed_detected') for r in verdict['reasons']))


# ---------------------------------------------------------------------------
# 重放 / 幂等 / 冲突
# ---------------------------------------------------------------------------

class ReplayAndConflictTests(unittest.TestCase):
    def test_same_id_replay_is_idempotent_and_different_content_conflicts(self):
        db = new_db()

        # Telemetry pages.
        rows = [{'bus': 'P1', 'source': 'grid', 'tick': 13, 'voltage': 230, 'available_kw': 10}]
        self.assertEqual(fc.import_page(db, 'pg1', rows, 13)['status'], 'captured')
        self.assertEqual(fc.import_page(db, 'pg1', rows, 13)['status'], 'replayed')
        with self.assertRaises(ValueError) as ctx:
            fc.import_page(db, 'pg1', [{**rows[0], 'voltage': 229}], 14)
        self.assertEqual(str(ctx.exception), 'feed_page_conflict')

        # Contact readbacks.
        c1 = fc.capture_contact(db, 'rb1', 'P1', 'grid', 'open', 15, 15)
        c2 = fc.capture_contact(db, 'rb1', 'P1', 'grid', 'open', 15, 15)
        self.assertEqual(c2['status'], 'replayed')
        self.assertEqual(c1['seq'], c2['seq'])
        with self.assertRaises(ValueError):
            fc.capture_contact(db, 'rb1', 'P1', 'grid', 'closed', 15, 16)

        # Commands / receipts / outages share the same rule.
        self.assertEqual(fc.capture_command(db, 'cmd1', 'P1', 'grid', 'open', 13)['status'],
                         'captured')
        self.assertEqual(fc.capture_command(db, 'cmd1', 'P1', 'grid', 'open', 13)['status'],
                         'replayed')
        with self.assertRaises(ValueError):
            fc.capture_command(db, 'cmd1', 'P1', 'grid', 'close', 14)
        self.assertEqual(fc.capture_receipt(db, 'rcp1', 'cmd1', 13, True)['status'], 'captured')
        self.assertEqual(fc.capture_receipt(db, 'rcp1', 'cmd1', 13, True)['status'], 'replayed')
        with self.assertRaises(ValueError):
            fc.capture_receipt(db, 'rcp1', 'cmd1', 14, False)
        self.assertEqual(fc.capture_outage_start(db, 'o1', 'P1', 13)['status'], 'captured')
        self.assertEqual(fc.capture_outage_start(db, 'o1', 'P1', 13)['status'], 'replayed')
        with self.assertRaises(ValueError):
            fc.capture_outage_start(db, 'o1', 'P1', 12)

        # Transfer tickets: same request replays the stored decision, a
        # changed request conflicts instead of rewriting the ticket.
        t1 = pg.sign_transfer(db, 'T1', 'P1', 'generator', [('nA', 6)], 15)
        self.assertIn(t1['decision'], ('signed', 'held'))
        t2 = pg.sign_transfer(db, 'T1', 'P1', 'generator', [('nA', 6)], 15)
        self.assertEqual(t2['status'], 'replayed')
        self.assertEqual(t2['decision'], t1['decision'])
        with self.assertRaises(ValueError):
            pg.sign_transfer(db, 'T1', 'P1', 'generator', [('nA', 7)], 15)

    def test_sealed_archive_replay_and_conflict(self):
        db = new_db()
        seed_incident_originals(db)
        first = fc.seal_archive(db, 'INC-1', 'P1', sealed_at=16)
        self.assertEqual(first['status'], 'sealed')
        again = fc.seal_archive(db, 'INC-1', 'P1', sealed_at=16)
        self.assertEqual(again['status'], 'replayed')
        self.assertEqual(again['digest'], first['digest'])

        # New evidence changes the dossier: re-sealing the same incident id
        # conflicts rather than silently replacing the sealed original.
        fc.capture_contact(db, 'late-rb', 'P1', 'grid', 'open', 15, 17)
        with self.assertRaises(ValueError):
            fc.seal_archive(db, 'INC-1', 'P1', sealed_at=17)


# ---------------------------------------------------------------------------
# 重启持久化 + 事故留档
# ---------------------------------------------------------------------------

class RestartAndArchiveTests(unittest.TestCase):
    def test_restart_cannot_erase_dangerous_permits_or_decisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'power-incident.sqlite3')

            db = sqlite3.connect(path)
            fc.import_page(db, 'feed12', [
                {'bus': 'P1', 'source': 'grid', 'tick': 12, 'voltage': 230, 'available_kw': 10},
                {'bus': 'P1', 'source': 'generator', 'tick': 12, 'voltage': 230, 'available_kw': 10},
            ], 13)
            pg.energize(db, 'nA', 'P1', 'grid', 6, 13)
            pg.energize(db, 'nB', 'P1', 'generator', 6, 13)
            seed_incident_originals(db)
            add_minute15_physical_proof(db)
            signed = pg.sign_transfer(db, 'A-transfer-15', 'P1', 'generator', [('nA', 6)], 15)
            self.assertEqual(signed['decision'], 'signed', signed['reasons'])
            sealed = fc.seal_archive(db, 'INC-P1', 'P1', sealed_at=16)
            digest = sealed['digest']
            exported = fc.export_archive_file(db, 'INC-P1', Path(tmp) / 'dossier.json', 'P1')
            db.close()

            # Simulate process restart: a brand new connection to same file.
            db2 = sqlite3.connect(path)
            self.assertEqual(
                db2.execute("SELECT COUNT(*) FROM power_permits WHERE decision='permit'").fetchone()[0],
                2, 'historical dangerous permits must survive restart')
            self.assertEqual(
                db2.execute("SELECT decision FROM transfer_tickets WHERE ticket_id='A-transfer-15'")
                .fetchone()[0], 'signed')
            self.assertEqual(
                db2.execute('SELECT digest FROM incident_archives WHERE incident_id=?',
                            ('INC-P1',)).fetchone()[0], digest)

            archive = fc.build_archive(db2, 'INC-P1', 'P1')
            self.assertTrue(any(f['code'] == 'dual_source_permits_without_interlock'
                                for f in archive['findings']))
            kinds = [a['kind'] for a in archive['arrival_order']]
            # Telemetry pages and physical evidence share one arrival sequence.
            self.assertIn('feed_page', kinds)
            self.assertIn('contact_readback', kinds)
            seqs = [a['seq'] for a in archive['arrival_order']]
            self.assertEqual(seqs, sorted(seqs))
            self.assertEqual(len(seqs), len(set(seqs)))

            # Safety gate still fails closed after restart (welded contact).
            fc.capture_contact(db2, 'rb-grid-weld-after-restart', 'P1', 'grid',
                               'closed', 18, 18, welded=True)
            verdict = pg.evaluate_transfer(db2, 'P1', 'generator', [('nA', 6)], 18)
            self.assertIn('backfeed_risk', verdict['reasons'])
            db2.close()

            dossier = json.loads(Path(exported['path']).read_text(encoding='utf-8'))
            self.assertEqual(dossier['incident_id'], 'INC-P1')
            self.assertEqual(len(dossier['legacy_permits']), 2)

    def test_archive_contains_every_original_class_in_arrival_order(self):
        db = new_db()
        seed_incident_originals(db)
        fc.capture_battery(db, 'repA', 'batA', 13, 13, charge_kwmin=30, max_discharge_kw=12)
        fc.capture_battery_draw(db, 'dA13', 'batA', 13, 6, 13)
        add_minute15_physical_proof(db)
        pg.sign_transfer(db, 'T', 'P1', 'generator', [('nA', 6)], 15)

        archive = fc.build_archive(db, 'INC-full', 'P1')
        self.assertTrue(archive['telemetry_pages'])
        self.assertTrue(archive['contacts'])
        self.assertTrue(archive['commands'])
        self.assertTrue(archive['receipts'])
        self.assertTrue(archive['outages'])
        self.assertTrue(archive['battery_reports'])
        self.assertTrue(archive['battery_draws'])
        self.assertTrue(archive['loads'])
        self.assertTrue(archive['transfer_tickets'])

        # Originals preserve exact reported values.
        gen_page = next(p for p in archive['telemetry_pages'] if p['id'] == 'gen-noload-t13')
        self.assertEqual(gen_page['rows'][0]['voltage'], 230)
        self.assertEqual(gen_page['rows'][0]['available_kw'], 10)
        receipt = archive['receipts'][0]
        self.assertEqual(receipt['dispatch_success'], 1)

        # Unified arrival order is strictly increasing and includes the ticket
        # original itself alongside contacts / telemetry.
        seqs = [item['seq'] for item in archive['arrival_order']]
        self.assertEqual(seqs, sorted(seqs))
        self.assertGreater(len(seqs), 5)
        kinds = [item['kind'] for item in archive['arrival_order']]
        self.assertIn('transfer_ticket', kinds)
        ticket_item = next(item for item in archive['arrival_order']
                           if item['kind'] == 'transfer_ticket')
        self.assertEqual(ticket_item['original']['decision'], 'signed')


class CanonicalFixtureReplayTests(unittest.TestCase):
    FIXTURE = Path(__file__).resolve().parent.parent / 'fixtures' / 'p1_power_transfer.json'

    def test_preserved_incident_fixture_replays_to_approved_plan_a(self):
        doc = json.loads(self.FIXTURE.read_text(encoding='utf-8'))
        db = new_db()

        results = pg.replay_messages(db, doc['messages'])
        tickets = {r['ticket_id']: r for r in results if r.get('ticket_id')}
        for tid in doc['expected']['signed_tickets']:
            self.assertEqual(tickets[tid]['decision'], 'signed', tickets[tid].get('reasons'))
        for tid in doc['expected']['held_tickets']:
            self.assertEqual(tickets[tid]['decision'], 'held')
        self.assertEqual([n['node'] for n in tickets['A-transfer-15']['nodes']],
                         doc['expected']['signed_nodes']['A-transfer-15'])

        # Replaying every preserved original again is fully idempotent and the
        # stored signed/held decisions do not change.
        again = pg.replay_messages(db, doc['messages'])
        again_tickets = {r['ticket_id']: r for r in again if r.get('ticket_id')}
        for tid, result in tickets.items():
            self.assertEqual(again_tickets[tid]['status'], 'replayed')
            self.assertEqual(again_tickets[tid]['decision'], result['decision'])
        self.assertEqual(
            db.execute("SELECT COUNT(*) FROM transfer_tickets").fetchone()[0],
            len(doc['expected']['signed_tickets']) + len(doc['expected']['held_tickets']))

        archive = fc.seal_archive(db, doc['incident_id'], doc['bus'])
        self.assertEqual(archive['status'], 'sealed')
        self.assertTrue(any(f['code'] == 'transfer_requests_held'
                            for f in archive['archive']['findings']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
