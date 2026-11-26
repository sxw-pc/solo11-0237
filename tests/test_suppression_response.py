"""Field suppression response tests for the equipment-room B scenario.

Coverage map (the six required situation families):

* 原有误喷                 -> OriginalFalseDischargeTests / scene accident test
* 共享风道双报警           -> test_shared_duct_pair_is_one_airflow_path
* 两种救险                 -> test_local_a_pod_route / test_full_zone_route /
                             test_the_two_approved_routes_differ
* 人员未离开               -> test_uncleared_b_person_blocks_full_zone_and_can_switch_local
* 阀门未闭合               -> test_open_damper_readback_blocks_even_after_close_command
* 迟到页/迟到回读          -> test_late_pod_readback_cannot_authorize_early_spray /
                             test_late_and_conflicting_pages_never_rewrite_release

Plus physical cylinder readback, dose no-double-counting and evidence ordering.
"""
import json
import sqlite3
import unittest

from cloudctl.alarm_capture import import_page, ledger_entries
from cloudctl import suppression_gate as gate
from cloudctl.suppression_gate import release


def make_db():
    db = sqlite3.connect(':memory:')
    gate.ensure_response_schema(db)
    return db


class SuppressionResponseTestBase(unittest.TestCase):
    def setUp(self):
        self.db = make_db()

    # -- fixed scene -------------------------------------------------------
    def build_scene(self):
        db = self.db
        # Design dose for each selectable space / partition.
        gate.register_space(db, 'pod-A', 6)
        gate.register_space(db, 'A', 8)
        gate.register_space(db, 'B', 12)
        # Cylinder / agent inventories.
        gate.register_cylinder(db, 'C-POD', 'pod-A', 7)   # local A pod stock
        gate.register_cylinder(db, 'C-M1', '*', 12)        # full-zone common bank
        gate.register_cylinder(db, 'C-M2', '*', 8)
        gate.register_cylinder(db, 'C-BX', 'B', 6)        # B-only stock is short
        # Customer equipment that must actually stop before discharge.
        gate.register_equipment(db, 'cab-A1', 'A', 'A cabinet')
        gate.register_equipment(db, 'eq-Ah', 'A', 'A HVAC')
        gate.register_equipment(db, 'eq-B1', 'B', 'B core service')
        # Dampers / isolation points.
        for d, note in (('D-POD', 'A cabinet pod partition'),
                        ('D-AB', 'A/B shared return valve'),
                        ('D-MAIN', 'full zone main valve')):
            gate.register_damper(db, d, note)
        # Detectors: dB1/dB2 share the B inlet of the same return duct.
        gate.register_detector(db, 'dB1', 'B', 'inlet', 'duct-AB-return')
        gate.register_detector(db, 'dB2', 'B', 'inlet', 'duct-AB-return')
        gate.register_detector(db, 'dA1', 'A', 'area')
        # Airflow / source relation: A smoke travels the shared return to B.
        gate.register_airflow(db, 'L-POD', 'pod-A', 'B',
                              duct='duct-AB-return', damper='D-POD', at=8)
        gate.register_airflow(db, 'L-AB', 'A', 'B',
                              duct='duct-AB-return', damper='D-AB', at=8)
        # Rosters at minute 8: A cabinet worker and the B maintenance technician.
        gate.register_person(db, 'worker-A', 'A', 8, name='A electrician')
        gate.register_person(db, 'tech-B', 'B', 8, name='B maintenance')
        # Pre-approved partition plans.
        gate.register_plan(
            db, 'local-A-pod',
            people_spaces=['A'], targets=['pod-A'],
            damper_ids=['D-POD'], equipment_ids=['cab-A1'],
            cylinder_ids=['C-POD'])
        gate.register_plan(
            db, 'full-AB',
            people_spaces=['A', 'B'], targets=['A', 'B'],
            damper_ids=['D-MAIN', 'D-AB'],
            equipment_ids=['cab-A1', 'eq-Ah', 'eq-B1'],
            cylinder_ids=['C-M1', 'C-M2'])
        gate.register_plan(
            db, 'b-only-naive',
            people_spaces=['B'], targets=['B'],
            damper_ids=['D-AB'], equipment_ids=['eq-B1'],
            cylinder_ids=['C-BX'])
        return db

    def prime_alarms(self):
        db = self.db
        import_page(db, 'p9', [
            {'detector': 'dB1', 'zone': 'B', 'tick': 9, 'smoke': 90, 'heat': 55},
        ], 10)
        import_page(db, 'p10', [
            {'detector': 'dB2', 'zone': 'B', 'tick': 10, 'smoke': 85, 'heat': 52},
        ], 10)
        import_page(db, 'pA', [
            {'detector': 'dA1', 'zone': 'A', 'tick': 9, 'smoke': 70, 'heat': 48},
        ], 10)
        gate.report_fire_source(db, 'SRC-A', 'A', 'cabinet-internal-smoke', 9)

    # -- route helpers -----------------------------------------------------
    def prepare_local_ready(self, at_readback=11, readback_received=None):
        db = self.db
        gate.confirm_exit(db, 'worker-A', 'A', 10, 'badge')
        gate.record_shutdown(db, 'cab-A1', 10)
        gate.command_damper(db, 'D-POD', 11)
        gate.readback_damper(db, 'D-POD', 'closed', at_readback,
                             received_at=readback_received)

    def finish_local(self, release_id='LOCAL-1', issue_at=11, final_at=12, amount=7):
        db = self.db
        issued = gate.issue_release(db, release_id, issue_at, name='local-A-pod')
        rb = gate.readback_cylinder(db, release_id, 'C-POD', 'opened', final_at,
                                    released=amount)
        done = gate.finalize_release(db, release_id, final_at)
        return issued, rb, done

    def prepare_full_ready(self):
        db = self.db
        gate.confirm_exit(db, 'worker-A', 'A', 11, 'onsite', by='shift-lead')
        gate.confirm_exit(db, 'tech-B', 'B', 12, 'badge')
        gate.record_shutdown(db, 'cab-A1', 11)
        gate.record_shutdown(db, 'eq-Ah', 11)
        gate.record_shutdown(db, 'eq-B1', 12)
        gate.command_damper(db, 'D-MAIN', 12)
        gate.command_damper(db, 'D-AB', 12)
        gate.readback_damper(db, 'D-MAIN', 'closed', 12)
        gate.readback_damper(db, 'D-AB', 'closed', 12)

    def finish_full(self, release_id='FULL-1', issue_at=13, final_at=14):
        db = self.db
        issued = gate.issue_release(db, release_id, issue_at, name='full-AB')
        gate.readback_cylinder(db, release_id, 'C-M1', 'opened', final_at, released=12)
        gate.readback_cylinder(db, release_id, 'C-M2', 'opened', final_at, released=8)
        done = gate.finalize_release(db, release_id, final_at)
        return issued, done


class OriginalFalseDischargeTests(unittest.TestCase):
    """The original 14-test seed scenario reframed as a false discharge."""

    def test_seed_sequence_writes_provisional_release_and_it_is_an_accident(self):
        db = sqlite3.connect(':memory:')
        gate.ensure_response_schema(db)
        self.assertEqual(release(db, 'room-B', 10)['decision'], 'hold')
        import_page(db, 'p9', [
            {'detector': 'dB1', 'zone': 'room-B', 'tick': 9, 'smoke': 90, 'heat': 55},
        ], 10)
        self.assertEqual(release(db, 'room-B', 10)['decision'], 'release')
        self.assertEqual(
            db.execute(
                'SELECT detector FROM suppression_releases WHERE zone=? AND decision=?',
                ('room-B', 'release')).fetchone()[0],
            'dB1')

        findings = gate.accidents(db)
        self.assertEqual(len(findings), 1)
        accident = findings[0]
        self.assertFalse(accident['safe'])
        self.assertEqual(accident['finding']['classification'],
                         'accidental_early_discharge')
        self.assertIn('roster_unknown:room-B', accident['blockers'])
        self.assertIn('dose_unverified', accident['blockers'])

        # Minute-11 clearance paperwork arrives afterwards ...
        gate.register_person(db, 'late-worker', 'room-B', 11)
        gate.confirm_exit(db, 'late-worker', 'room-B', 11, 'onsite')
        # ... it cannot be seen by a minute-10 decision horizon ...
        self.assertFalse(gate.clearance(db, ['room-B'], 10)['clear'])
        self.assertTrue(gate.clearance(db, ['room-B'], 11)['clear'])
        # ... and the stored accident is never rewritten or duplicated.
        gate._adjudicate_provisional(db, accident['source_rowid'],
                                    'room-B', 10, 'dB1')
        again = gate.accidents(db)
        self.assertEqual(len(again), 1)
        self.assertEqual(json.loads(json.dumps(again[0]['blockers'])),
                         accident['blockers'])
        self.assertFalse(again[0]['safe'])
        raw = db.execute(
            'SELECT decision, detector FROM suppression_releases'
            " WHERE zone='room-B' AND decision='release'").fetchall()
        self.assertEqual(raw, [('release', 'dB1')])


class FixedSceneResponseTests(SuppressionResponseTestBase):

    def test_legacy_gate_still_sprays_occupied_b_and_records_accident(self):
        self.build_scene()
        self.prime_alarms()
        # dB2 is the newest B row (tick 10) and also crosses the threshold,
        # exactly the "dB2 as latest row also writes release" observation.
        self.assertEqual(release(self.db, 'B', 10)['decision'], 'release')
        detector = self.db.execute(
            'SELECT detector FROM suppression_releases WHERE zone=? AND decision=?',
            ('B', 'release')).fetchone()[0]
        self.assertEqual(detector, 'dB2')

        accidents = gate.accidents(self.db)
        self.assertEqual(len(accidents), 1)
        self.assertFalse(accidents[0]['safe'])
        self.assertTrue(any(b == 'person_not_clear:tech-B' for b in accidents[0]['blockers']),
                        accidents[0]['blockers'])
        self.assertTrue(any(b.startswith('damper_readback_missing:')
                            for b in accidents[0]['blockers']))
        # The responsible system issued no safe authorized discharge.
        self.assertEqual(gate.releases(self.db), [])

        # The wrong early spray stays an accident; the subsequent remedy
        # (ventilation, roll call, medical check) is preserved separately and
        # never mutates the accident verdict.
        rem = gate.record_remediation(
            self.db, 'REM-B-1', 'B',
            'ventilate-verify-gas-dispersed-and-account-for-tech-B', 14,
            note='accident response, not clearance backfill')
        self.assertEqual(rem['status'], 'recorded')
        self.assertEqual(len(gate.accidents(self.db)), 1)
        ledger_kinds = [e['kind'] for e in gate.timeline(self.db)]
        self.assertIn('remediation', ledger_kinds)
        self.assertLess(ledger_kinds.index('provisional_release_adjudicated'),
                        ledger_kinds.index('remediation'))

    def test_floor_total_zero_cannot_replace_per_person_b_clearance(self):
        db = self.db
        gate.register_person(db, 'w1', 'B', 8)
        gate.register_person(db, 'w2', 'B', 8)
        gate.record_headcount(db, 'floor-7', 0, 10)
        status = gate.clearance(db, ['B'], 10)
        self.assertFalse(status['clear'])
        self.assertEqual(status['pending'], ['w1', 'w2'])
        # Badge + onsite per-person confirmations are what actually clear B.
        gate.confirm_exit(db, 'w1', 'B', 11, 'badge')
        self.assertFalse(gate.clearance(db, ['B'], 11)['clear'])
        gate.confirm_exit(db, 'w2', 'B', 11, 'onsite', by='fire-warden')
        cleared = gate.clearance(db, ['B'], 11)
        self.assertTrue(cleared['clear'], cleared['pending'])
        self.assertEqual({c['person'] for c in cleared['cleared']}, {'w1', 'w2'})

    def test_shared_duct_pair_is_one_airflow_path_not_two_zone_votes(self):
        self.build_scene()
        self.prime_alarms()
        analysis = gate.analyze_sources(self.db, at=10)

        # Only B has threshold-hot detectors ...
        self.assertEqual(analysis['alarm_zones'], ['B'])
        self.assertEqual(sorted(d['detector'] for d in analysis['hot_detectors']),
                         ['dB1', 'dB2'])
        # ... but both sit on the same shared-return inlet ...
        self.assertEqual(analysis['inlet_groups'],
                         {'duct-AB-return': ['dB1', 'dB2']})
        # ... and the corroborated origin is A, not the alarm-receiving zone.
        self.assertIn('A', analysis['origins'])
        self.assertTrue(any(p['source_space'] == 'A' and p['target_space'] == 'B'
                            and p['corroborated'] for p in analysis['airflow_paths']))

        # Counting both shared-duct heads as votes still cannot spray B:
        verdict = gate.evaluate_plan(self.db, 10, name='b-only-naive')
        self.assertEqual(verdict['decision'], 'hold')
        self.assertIn('person_not_clear:tech-B', verdict['blockers'])
        # B's own stock is short of B design dose as well.
        self.assertFalse(verdict['dose']['sufficient'])

    def test_local_a_pod_route_succeeds_and_keeps_b_in_service(self):
        self.build_scene()
        self.prime_alarms()
        self.prepare_local_ready()

        # The closed physical readback severs the pod -> B shared return path.
        path = gate.airflow_path_status(self.db, 'L-POD', 11)
        self.assertTrue(path['severed'], path['blockers'])

        verdict = gate.evaluate_plan(self.db, 11, name='local-A-pod')
        self.assertEqual(verdict['decision'], 'release', verdict['blockers'])
        self.assertTrue(verdict['dose']['sufficient'])

        issued, rb, done = self.finish_local()
        self.assertEqual(issued['status'], 'issued')
        self.assertEqual(rb['status'], 'recorded')
        self.assertEqual(done['status'], 'released')
        self.assertEqual(done['released_amount'], 7)

        row = gate.get_release(self.db, 'LOCAL-1')
        self.assertEqual(row['status'], 'released')
        self.assertEqual(row['targets'], ['pod-A'])
        self.assertEqual(row['released_amount'], 7)

        # Only the A cabinet was stopped; B equipment keeps running.
        self.assertTrue(gate.shutdown_status(self.db, ['cab-A1'], 12)['stopped'])
        self.assertIn('eq-B1', gate.shutdown_status(self.db, ['eq-B1'], 12)['pending'])

        # B is verified sourceless / ventilation-isolated and stays in service;
        # the A cabinet pays the long manual recovery.
        gate.record_recovery(self.db, 'REC-B-CONTINUE', 'B',
                             'no-source-verified-ventilation-isolated-continue-service',
                             13, service_status='continued', recovery_minutes=0)
        gate.record_recovery(self.db, 'REC-A-CAB', 'cab-A1',
                             'manual-onsite-cabinet-rebuild', 13,
                             service_status='recovered', recovery_minutes=240)
        recovery = self.db.execute(
            'SELECT scope,service_status,recovery_minutes FROM resp_recovery'
            " WHERE kind='recovery' ORDER BY scope").fetchall()
        self.assertEqual([tuple(r) for r in recovery],
                         [('B', 'continued', 0), ('cab-A1', 'recovered', 240)])

    def test_late_pod_readback_cannot_authorize_early_spray(self):
        self.build_scene()
        self.prime_alarms()
        gate.confirm_exit(self.db, 'worker-A', 'A', 10, 'badge')
        gate.record_shutdown(self.db, 'cab-A1', 10)
        gate.command_damper(self.db, 'D-POD', 11)

        # Minute 11 and minute 12: close was commanded, no physical readback yet.
        early = gate.issue_release(self.db, 'LOCAL-LATE', 11, name='local-A-pod')
        self.assertEqual(early['status'], 'held')
        self.assertIn('damper_readback_missing:D-POD', early['blockers'])
        later = gate.issue_release(self.db, 'LOCAL-LATE', 12, name='local-A-pod')
        self.assertEqual(later['status'], 'held')
        self.assertIsNone(gate.get_release(self.db, 'LOCAL-LATE'))

        # The physical closure happened at 11 but the readback only ARRIVES 13.
        gate.readback_damper(self.db, 'D-POD', 'closed', 11, received_at=13)

        at_12 = gate.evaluate_plan(self.db, 12, name='local-A-pod')
        self.assertIn('damper_readback_missing:D-POD', at_12['blockers'])
        self.assertFalse(gate.airflow_path_status(self.db, 'L-POD', 12)['severed'])
        at_13 = gate.evaluate_plan(self.db, 13, name='local-A-pod')
        self.assertEqual(at_13['decision'], 'release', at_13['blockers'])
        self.assertTrue(gate.airflow_path_status(self.db, 'L-POD', 13)['severed'])

        issued = gate.issue_release(self.db, 'LOCAL-LATE', 13, name='local-A-pod')
        self.assertEqual(issued['status'], 'issued')
        gate.readback_cylinder(self.db, 'LOCAL-LATE', 'C-POD', 'opened', 13, released=7)
        done = gate.finalize_release(self.db, 'LOCAL-LATE', 14)
        self.assertEqual(done['status'], 'released')

        # Arrival order preserves held attempts before the late readback before
        # the eventual issue; occurrence order keeps the readback at minute 11.
        arrival = ledger_entries(self.db, order='arrival')
        kinds_refs = [(e['kind'], e['ref']) for e in arrival]
        seq_held12 = next(i for i, e in enumerate(arrival)
                          if e['kind'] == 'release_held'
                          and e['payload'].get('at') == 12)
        seq_rb = next(i for i, e in enumerate(arrival)
                      if e['kind'] == 'damper_readback')
        seq_issued = next(i for i, e in enumerate(arrival)
                          if e['kind'] == 'release_issued'
                          and e['ref'] == 'LOCAL-LATE')
        self.assertLess(seq_held12, seq_rb)
        self.assertLess(seq_rb, seq_issued)
        occurrence = ledger_entries(self.db, order='occurrence')
        rb_entry = next(e for e in occurrence if e['kind'] == 'damper_readback')
        self.assertEqual(rb_entry['occurred_at'], 11)
        self.assertEqual(rb_entry['received_at'], 13)

    def test_full_zone_route_evacuates_every_person_and_records_dose(self):
        self.build_scene()
        self.prime_alarms()
        self.prepare_full_ready()

        verdict = gate.evaluate_plan(self.db, 13, name='full-AB')
        self.assertEqual(verdict['decision'], 'release', verdict['blockers'])
        cleared = {(c['person'], c['space']): c['at']
                   for c in verdict['people']['cleared']}
        self.assertEqual(cleared.get(('worker-A', 'A')), 11)
        self.assertEqual(cleared.get(('tech-B', 'B')), 12)

        issued, done = self.finish_full()
        self.assertEqual(issued['status'], 'issued')
        self.assertEqual(done['status'], 'released')
        self.assertEqual(done['released_amount'], 20)
        row = gate.get_release(self.db, 'FULL-1')
        self.assertEqual(row['targets'], ['A', 'B'])
        self.assertEqual(row['cylinder_ids'], ['C-M1', 'C-M2'])
        self.assertTrue(gate.shutdown_status(
            self.db, ['cab-A1', 'eq-Ah', 'eq-B1'], 13)['stopped'])

        gate.record_recovery(self.db, 'REC-FULL', 'A,B',
                             'full-zone-recharge-and-restore', 18,
                             service_status='recovered', recovery_minutes=300,
                             note='B business interrupted')
        rec = self.db.execute(
            "SELECT recovery_minutes,note FROM resp_recovery WHERE ref='REC-FULL'"
        ).fetchone()
        self.assertEqual(tuple(rec), (300, 'B business interrupted'))

    def test_uncleared_b_person_blocks_full_zone_and_can_switch_to_local(self):
        self.build_scene()
        self.prime_alarms()
        # A side is fully ready ...
        gate.confirm_exit(self.db, 'worker-A', 'A', 10, 'badge')
        gate.record_shutdown(self.db, 'cab-A1', 10)
        gate.command_damper(self.db, 'D-POD', 11)
        gate.readback_damper(self.db, 'D-POD', 'closed', 11)
        # ... full-zone mechanical preconditions are all prepared ...
        gate.record_shutdown(self.db, 'eq-Ah', 11)
        gate.record_shutdown(self.db, 'eq-B1', 11)
        gate.command_damper(self.db, 'D-MAIN', 11)
        gate.readback_damper(self.db, 'D-MAIN', 'closed', 12)
        gate.command_damper(self.db, 'D-AB', 11)
        gate.readback_damper(self.db, 'D-AB', 'closed', 12)
        # ... but tech-B never confirms leaving; a floor total of zero is filed.
        gate.record_headcount(self.db, 'floor-B', 0, 10)
        gate.report_location(self.db, 'tech-B', 'B', 'unknown', 11)

        status = gate.clearance(self.db, ['A', 'B'], 13)
        self.assertFalse(status['clear'])
        self.assertIn('tech-B', status['pending'])
        self.assertIn('tech-B', status['unknown_locations'])
        self.assertEqual(status['floor_headcounts'][0]['total'], 0)
        self.assertTrue(status['floor_counts_are_not_clearance'])

        full = gate.evaluate_plan(self.db, 13, name='full-AB')
        self.assertEqual(full['decision'], 'hold')
        self.assertIn('person_not_clear:tech-B', full['blockers'])
        held = gate.issue_release(self.db, 'FULL-WAIT', 13, name='full-AB')
        self.assertEqual(held['status'], 'held')
        self.assertIsNone(gate.get_release(self.db, 'FULL-WAIT'))

        # The pre-approved alternative remains available: local A-pod spray
        # does not include B personnel/spaces once its partition readback closes.
        local = gate.evaluate_plan(self.db, 12, name='local-A-pod')
        self.assertEqual(local['decision'], 'release', local['blockers'])
        switched = gate.issue_release(self.db, 'LOCAL-SWITCH', 12, name='local-A-pod')
        self.assertEqual(switched['status'], 'issued')

    def test_open_damper_readback_blocks_even_after_close_command(self):
        self.build_scene()
        self.prime_alarms()
        gate.confirm_exit(self.db, 'worker-A', 'A', 10, 'onsite')
        gate.confirm_exit(self.db, 'tech-B', 'B', 10, 'badge')
        for eq in ('cab-A1', 'eq-Ah', 'eq-B1'):
            gate.record_shutdown(self.db, eq, 10)
        # Operator clicks close on the A/B valve at minute 11 ...
        gate.command_damper(self.db, 'D-AB', 11)
        # ... but physical readback still says OPEN.
        gate.readback_damper(self.db, 'D-AB', 'open', 11)
        # Main valve commanded with no independent readback at all.
        gate.command_damper(self.db, 'D-MAIN', 11)

        verdict = gate.evaluate_plan(self.db, 12, name='full-AB')
        self.assertEqual(verdict['decision'], 'hold')
        self.assertIn('damper_not_closed:D-AB', verdict['blockers'])
        self.assertIn('damper_readback_missing:D-MAIN', verdict['blockers'])
        attempted = gate.issue_release(self.db, 'FULL-VALVE', 12, name='full-AB')
        self.assertEqual(attempted['status'], 'held')

        # Main valve readback arrives closed; A/B valve is still physically open,
        # so gas would still cross zones -> remains blocked.
        gate.readback_damper(self.db, 'D-MAIN', 'closed', 12)
        verdict2 = gate.evaluate_plan(self.db, 13, name='full-AB')
        self.assertNotEqual(verdict2['decision'], 'release')
        self.assertIn('damper_not_closed:D-AB', verdict2['blockers'])
        self.assertNotIn('damper_readback_missing:D-MAIN', verdict2['blockers'])
        self.assertIsNone(gate.get_release(self.db, 'FULL-VALVE'))

    def test_cylinder_open_command_needs_independent_application_readback(self):
        self.build_scene()
        self.prepare_local_ready()
        issued = gate.issue_release(self.db, 'LOCAL-CYL', 11, name='local-A-pod')
        self.assertEqual(issued['status'], 'issued')
        # The open command exists, but no physical application readback yet.
        blocked = gate.finalize_release(self.db, 'LOCAL-CYL', 11)
        self.assertEqual(blocked['status'], 'held')
        self.assertIn('cylinder_readback_missing:C-POD', blocked['blockers'])
        # Fault / not-opened readback does not count.
        gate.readback_cylinder(self.db, 'LOCAL-CYL', 'C-POD', 'fault', 12)
        blocked2 = gate.finalize_release(self.db, 'LOCAL-CYL', 12)
        self.assertTrue(any(b.startswith('cylinder_not_opened:C-POD')
                            for b in blocked2['blockers']))
        # Opened but measured amount below design dose does not certify either.
        gate.readback_cylinder(self.db, 'LOCAL-CYL', 'C-POD', 'opened', 12, released=5)
        short = gate.finalize_release(self.db, 'LOCAL-CYL', 12)
        self.assertTrue(any(b.startswith('release_amount_short') for b in short['blockers']))
        # Correct independent readback proves the real release amount.
        gate.readback_cylinder(self.db, 'LOCAL-CYL', 'C-POD', 'opened', 13, released=7)
        done = gate.finalize_release(self.db, 'LOCAL-CYL', 13)
        self.assertEqual(done['status'], 'released')
        self.assertEqual(done['released_amount'], 7)
        # Finalize is idempotent and does not double-consume.
        again = gate.finalize_release(self.db, 'LOCAL-CYL', 14)
        self.assertEqual(again['status'], 'idempotent')
        self.assertEqual(again['released_amount'], 7)

    def test_the_two_approved_routes_have_different_scope_agent_and_recovery(self):
        # --- local route on its own scene/db ---
        local_db = make_db()
        self.db = local_db
        self.build_scene()
        self.prime_alarms()
        self.prepare_local_ready()
        _, _, local_done = self.finish_local()
        gate.record_recovery(local_db, 'R-LOCAL', 'cab-A1', 'long-onsite-repair',
                             20, service_status='recovered', recovery_minutes=240)

        # --- full zone route on a separate scene/db ---
        full_db = make_db()
        self.db = full_db
        self.build_scene()
        self.prime_alarms()
        self.prepare_full_ready()
        _, full_done = self.finish_full()
        gate.record_recovery(full_db, 'R-FULL', 'A,B', 'zone-restore', 20,
                             service_status='recovered', recovery_minutes=300)

        local_rel = gate.get_release(local_db, 'LOCAL-1')
        full_rel = gate.get_release(full_db, 'FULL-1')
        self.assertEqual(local_rel['targets'], ['pod-A'])
        self.assertEqual(full_rel['targets'], ['A', 'B'])
        self.assertLess(local_done['released_amount'], full_done['released_amount'])
        self.assertEqual((local_done['released_amount'], full_done['released_amount']),
                         (7, 20))
        # B equipment is untouched by local but stopped by full.
        self.assertIn('eq-B1',
                      gate.shutdown_status(local_db, ['eq-B1'], 20)['pending'])
        self.assertTrue(gate.shutdown_status(full_db, ['eq-B1'], 20)['stopped'])
        local_minutes = local_db.execute(
            "SELECT recovery_minutes FROM resp_recovery WHERE ref='R-LOCAL'").fetchone()[0]
        full_minutes = full_db.execute(
            "SELECT recovery_minutes FROM resp_recovery WHERE ref='R-FULL'").fetchone()[0]
        self.assertNotEqual(local_minutes, full_minutes)
        self.assertLess(local_minutes, full_minutes)


class DoseProofTests(unittest.TestCase):
    def test_connected_zone_inventories_cannot_double_count_both_claims(self):
        db = make_db()
        gate.register_space(db, 'X', 10)
        gate.register_space(db, 'Y', 10)
        gate.register_cylinder(db, 'CX', 'X', 10)
        gate.register_cylinder(db, 'CY', 'Y', 10)

        self.assertTrue(gate.verify_dose(db, ['X'], ['CX'])['sufficient'])
        self.assertTrue(gate.verify_dose(db, ['Y'], ['CY'])['sufficient'])

        # Summing the neighbour's stock to certify X alone is rejected.
        pooled_x = gate.verify_dose(db, ['X'], ['CX', 'CY'])
        self.assertFalse(pooled_x['sufficient'])
        self.assertIn('foreign_inventory:CY', pooled_x['errors'])

        # One pooled bank cannot back two partition claims at once.
        gate.register_cylinder(db, 'BANK', '*', 20)
        overlap = gate.prove_partitions(db, [
            {'name': 'x-claim', 'targets': ['X'], 'cylinder_ids': ['BANK']},
            {'name': 'y-claim', 'targets': ['Y'], 'cylinder_ids': ['BANK']},
        ])
        self.assertFalse(overlap['proven'])
        self.assertEqual(overlap['code'], 'inventory_double_counted')
        self.assertEqual(overlap['overlap'], ['BANK'])

        # The legitimate combined treatment sums BOTH requirements once and
        # checks the joint physical inventory against that single total.
        combined = gate.verify_dose(db, ['X', 'Y'], ['CX', 'CY'])
        self.assertTrue(combined['sufficient'])
        self.assertEqual((combined['required_dose'], combined['available_dose']), (20, 20))

        # After the combined spray consumes both cylinders, neither side can
        # claim them again.
        gate.register_plan(db, 'xy', people_spaces=[], targets=['X', 'Y'],
                           damper_ids=[], equipment_ids=[],
                           cylinder_ids=['CX', 'CY'])
        issued = gate.issue_release(db, 'XY-1', 5, name='xy')
        self.assertEqual(issued['status'], 'issued', issued)
        gate.readback_cylinder(db, 'XY-1', 'CX', 'opened', 6, released=10)
        gate.readback_cylinder(db, 'XY-1', 'CY', 'opened', 6, released=10)
        self.assertEqual(gate.finalize_release(db, 'XY-1', 6)['status'], 'released')
        again_x = gate.verify_dose(db, ['X'], ['CX'])
        self.assertFalse(again_x['sufficient'])
        self.assertIn('cylinder_spent:CX', again_x['errors'])


class IdempotencyAndLatePageTests(unittest.TestCase):
    def test_page_replay_conflict_and_record_idempotency(self):
        db = make_db()
        rows = [{'detector': 'dB1', 'zone': 'B', 'tick': 9, 'smoke': 90, 'heat': 55}]
        self.assertEqual(import_page(db, 'p1', rows, 10)['status'], 'captured')
        self.assertEqual(import_page(db, 'p1', rows, 10)['status'], 'replayed')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM alarm_rows').fetchone()[0], 1)

        changed = [{'detector': 'dB1', 'zone': 'B', 'tick': 9, 'smoke': 99, 'heat': 55}]
        with self.assertRaises(ValueError) as ctx:
            import_page(db, 'p1', changed, 11)
        self.assertEqual(str(ctx.exception), 'alarm_page_conflict')
        # Original page content survives.
        self.assertEqual(db.execute('SELECT smoke FROM alarm_rows').fetchone()[0], 90)

        gate.register_person(db, 'p', 'B', 8)
        first = gate.confirm_exit(db, 'p', 'B', 10, 'badge', ref='exit-p-10')
        second = gate.confirm_exit(db, 'p', 'B', 10, 'badge', ref='exit-p-10')
        self.assertEqual(first['status'], 'recorded')
        self.assertEqual(second['status'], 'idempotent')
        self.assertEqual(db.execute(
            "SELECT COUNT(*) FROM resp_person_obs WHERE ref='exit-p-10'").fetchone()[0], 1)
        with self.assertRaises(ValueError) as ctx2:
            gate.confirm_exit(db, 'p', 'B', 11, 'onsite', ref='exit-p-10')
        self.assertIn('conflict', str(ctx2.exception))

    def test_late_detector_page_cannot_rewrite_real_release(self):
        db = make_db()
        # Minimal certifiable plan: no people spaces, no dampers/equipment.
        gate.register_space(db, 'S', 5)
        gate.register_cylinder(db, 'C1', 'S', 5)
        gate.register_plan(db, 's-plan', people_spaces=[], targets=['S'],
                           cylinder_ids=['C1'])
        self.assertEqual(import_page(db, 'p-early', [
            {'detector': 'd1', 'zone': 'S', 'tick': 9, 'smoke': 88, 'heat': 51}], 10
        )['status'], 'captured')
        issued = gate.issue_release(db, 'R-REAL', 10, name='s-plan')
        self.assertEqual(issued['status'], 'issued')
        gate.readback_cylinder(db, 'R-REAL', 'C1', 'opened', 11, released=5)
        self.assertEqual(gate.finalize_release(db, 'R-REAL', 11)['status'], 'released')

        before = gate.get_release(db, 'R-REAL')
        # A late, hotter detector page arrives after the real spray.
        late = import_page(db, 'p-late', [
            {'detector': 'd1', 'zone': 'S', 'tick': 12, 'smoke': 140, 'heat': 70}], 13)
        self.assertEqual(late['status'], 'captured')
        after = gate.get_release(db, 'R-REAL')
        self.assertEqual(before['status'], after['status'])
        self.assertEqual(before['released_amount'], after['released_amount'])
        self.assertEqual(before['targets'], after['targets'])
        self.assertEqual(after['issued_at'], 10)
        self.assertEqual(after['finalized_at'], 11)
        # Legacy raw decision history is untouched too.
        self.assertEqual(db.execute(
            'SELECT COUNT(*) FROM resp_releases WHERE release_id=?',
            ('R-REAL',)).fetchone()[0], 1)

    def test_ledger_offers_distinct_arrival_and_occurrence_orders(self):
        db = make_db()
        gate.register_damper(db, 'D1')
        gate.command_damper(db, 'D1', 11)
        # Physical close at 11, arrival 13 -- recorded after a minute-12 check.
        gate.readback_damper(db, 'D1', 'closed', 11, received_at=13)
        gate.evaluate_plan(db, 12, plan={
            'name': 'p', 'people_spaces': [], 'targets': [],
            'damper_ids': ['D1'], 'equipment_ids': [], 'cylinder_ids': []})

        arrival = ledger_entries(db, 'arrival')
        self.assertEqual([e['seq'] for e in arrival],
                         sorted(e['seq'] for e in arrival))
        occurrence = ledger_entries(db, 'occurrence')
        times = [(e['occurred_at'] if e['occurred_at'] is not None else -1)
                 for e in occurrence]
        self.assertEqual(times, sorted(times))
        rb = next(e for e in arrival if e['kind'] == 'damper_readback')
        self.assertEqual((rb['occurred_at'], rb['received_at']), (11, 13))


if __name__ == '__main__':
    unittest.main()
