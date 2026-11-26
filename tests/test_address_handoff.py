"""Cross-agent address occupancy conflict and recoverable endpoint handoff.

Fixed field scene (shared network domain ``V``):

* minute  5, agent ``a`` leases ``10.0.0.7`` to app on ``n1`` until minute 30;
* minute  8, agent ``b`` leases the same ``10.0.0.7`` to beta on ``n2`` until 25;
* minute 10 both paper pages are captured and both clients confirm.

The tests cover the dual-tenant conflict window, the readdress (.8) repair,
the isolated-domain (W + translated external .8) repair, stale neighbour
caches, half-committed file-database reopen, late pages / retransmissions /
termination and clock recalibration history.  The original 14 tests in
``test_address_seed.py`` and ``test_business.py`` continue to pass unchanged.
"""
import os
import sqlite3
import tempfile
import unittest

from cloudctl import lease_capture as lc
from cloudctl import route_publish as rp

DOT7 = '10.0.0.7'
DOT8 = '10.0.0.8'

APP_ROW = {'agent': 'a', 'tenant': 'app', 'node': 'n1', 'address': DOT7,
           'domain': 'V', 'generation': 1, 'start': 5, 'expires': 30}
BETA_ROW = {'agent': 'b', 'tenant': 'beta', 'node': 'n2', 'address': DOT7,
            'domain': 'V', 'generation': 1, 'start': 8, 'expires': 25}
BETA_DOT8_ROW = {'agent': 'b', 'tenant': 'beta', 'node': 'n2', 'address': DOT8,
                 'domain': 'V', 'generation': 2, 'start': 11, 'expires': 40}


def memory_db():
    db = sqlite3.connect(':memory:')
    rp.ensure_schema(db)
    return db


def seed_scene(db, physical=True, confirm=True):
    if physical:
        lc.register_agent(db, 'a', physical_id='PHYS-A-NIC-0')
        lc.register_agent(db, 'b', physical_id='PHYS-B-NIC-0')
    captured_a = lc.import_page(db, 'page-a', [APP_ROW], 10)
    captured_b = lc.import_page(db, 'page-b', [BETA_ROW], 10)
    if confirm:
        lc.confirm_lease(db, 'app', DOT7, at=10, agent='a')
        lc.confirm_lease(db, 'beta', DOT7, at=10, agent='b')
    return captured_a, captured_b


def beta_dot8_evidence(db, probe=True):
    lc.import_page(db, 'page-b-dot8', [BETA_DOT8_ROW], 11)
    lc.confirm_lease(db, 'beta', DOT8, at=11, agent='b')
    if probe:
        rp.probe_address(db, 'beta', DOT8, at=11, ok=True, observed_node='n2')


def v7_endpoints(db):
    return [e for e in rp.active_endpoints(db, domain='V', address=DOT7)]


class OriginalRecordTests(unittest.TestCase):
    def test_rich_originals_are_all_preserved(self):
        db = memory_db()
        seed_scene(db)
        rows = {(r['tenant']): r for r in lc.lease_rows(db, address=DOT7)}
        app = rows['app']
        self.assertEqual(app['agent'], 'a')
        self.assertEqual(app['physical_id'], 'PHYS-A-NIC-0')
        self.assertEqual(app['domain'], 'V')
        self.assertEqual(app['generation'], 1)
        self.assertEqual((app['start'], app['expires']), (5, 30))
        self.assertTrue(app['confirmed'])
        beta = rows['beta']
        self.assertEqual(beta['physical_id'], 'PHYS-B-NIC-0')
        self.assertEqual((beta['start'], beta['expires']), (8, 25))
        self.assertTrue(beta['confirmed'])
        # On-site neighbour cache evidence is preserved verbatim.
        saved = lc.record_neighbor_cache(
            db, 'b', [{'address': DOT7, 'node': 'n2', 'mac': '52:54:00:00:00:02'}],
            at=10, domain='V')
        self.assertEqual(saved['decision'], 'recorded')
        self.assertEqual(lc.neighbor_state(db, 'b', 'V', DOT7), 'fresh')
        # Whole-page digest replay / tamper semantics survive enrichment.
        self.assertEqual(lc.import_page(db, 'page-a', [APP_ROW], 10)['status'], 'replayed')
        tampered = [dict(APP_ROW, node='n9')]
        with self.assertRaises(ValueError):
            lc.import_page(db, 'page-a', tampered, 10)

    def test_same_page_number_from_two_agents_is_two_originals(self):
        db = memory_db()
        # Both agents number their own paper page "1"; that neither collides
        # nor implies a different network domain.
        self.assertEqual(lc.import_page(db, '1', [APP_ROW], 10)['status'], 'captured')
        self.assertEqual(lc.import_page(db, '1', [BETA_ROW], 10)['status'], 'captured')
        self.assertEqual(lc.import_page(db, '1', [APP_ROW], 10)['status'], 'replayed')
        self.assertEqual(len(lc.lease_rows(db, address=DOT7)), 2)
        self.assertEqual(rp.detect_conflicts(db, at=10)[0]['domain'], 'V')


class DualTenantConflictTests(unittest.TestCase):
    def test_reports_actual_conflict_window_and_evidence_agent(self):
        db = memory_db()
        seed_scene(db)
        conflicts = rp.detect_conflicts(db, at=10)
        self.assertEqual(len(conflicts), 1)
        c = conflicts[0]
        self.assertEqual(c['domain'], 'V')
        self.assertEqual(c['address'], DOT7)
        # Actual overlap is max(5,8)=8 .. min(30,25)=25.
        self.assertEqual((c['window_start'], c['window_end']), (8, 25))
        self.assertEqual((c['since'], c['until']), (8, 25))
        self.assertTrue(c['active'])
        self.assertEqual(c['tenants'], ['app', 'beta'])
        self.assertEqual(set(c['nodes']), {'n1', 'n2'})
        self.assertEqual(set(c['agents']), {'a', 'b'})
        self.assertEqual(c['node_by_tenant'], {'app': 'n1', 'beta': 'n2'})
        # b issued the later overlapping grant and must corroborate/supplement.
        self.assertIn('b', c['agents_needing_evidence'])
        self.assertNotIn('a', c['agents_needing_evidence'])
        report = rp.conflict_report(db, at=10)
        self.assertEqual(report['decision'], 'address_conflict')
        self.assertEqual(report['active_conflict_count'], 1)

    def test_exactly_one_executable_endpoint_independent_of_publish_order(self):
        for first, second in (('app', 'beta'), ('beta', 'app')):
            db = memory_db()
            seed_scene(db)
            results = {first: rp.publish(db, first, 10),
                       second: rp.publish(db, second, 10)}
            # app is the deterministic earliest-lease provisional owner.
            self.assertEqual(results['app']['decision'], 'published')
            self.assertEqual(results['beta']['decision'], 'address_conflict')
            self.assertFalse(results['beta'].get('executable', True))
            owners = v7_endpoints(db)
            self.assertEqual(len(owners), 1)
            self.assertEqual(owners[0]['tenant'], 'app')
            self.assertEqual(owners[0]['node'], 'n1')
            # Global invariant: no duplicated executable domain/address keys.
            eps = rp.active_endpoints(db)
            keys = [(e['domain'], e['address']) for e in eps]
            self.assertEqual(len(keys), len(set(keys)))
            # Both publication attempts remain traceable in the route ledger.
            tenants = {r[0] for r in db.execute('SELECT DISTINCT tenant FROM endpoint_routes')}
            self.assertEqual(tenants, {'app', 'beta'})

    def test_cannot_claim_both_reachable_at_minute_ten(self):
        db = memory_db()
        seed_scene(db)
        rp.publish(db, 'app', 10)
        beta = rp.publish(db, 'beta', 10)
        self.assertIn(beta['decision'], ('address_conflict', 'conflict', 'blocked'))
        reachable = rp.reachable_endpoints(db, domain='V', address=DOT7)
        self.assertEqual(len(reachable), 1)
        self.assertEqual(reachable[0]['tenant'], 'app')

    def test_published_duplicate_routes_are_traffic_risk(self):
        db = memory_db()
        # State left by the previous naive publisher: two live routes.
        db.execute("INSERT INTO endpoint_routes(tenant,address,node,at) "
                   "VALUES('app',?,?,?)", (DOT7, 'n1', 10))
        db.execute("INSERT INTO endpoint_routes(tenant,address,node,at) "
                   "VALUES('beta',?,?,?)", (DOT7, 'n2', 10))
        db.commit()
        risks = rp.traffic_risks(db, at=10)
        kinds = {r['kind'] for r in risks}
        self.assertIn('duplicate_published_routes', kinds)
        dup = next(r for r in risks if r['kind'] == 'duplicate_published_routes')
        self.assertEqual(set(dup['nodes']), {'n1', 'n2'})
        self.assertEqual(dup['severity'], 'high')

    def test_conflict_risk_describes_misdelivery_directions(self):
        db = memory_db()
        seed_scene(db)
        report = rp.assess_risks(db, at=10)
        window_risks = [r for r in report['traffic_risks']
                        if r['kind'] == 'overlapping_lease_window']
        self.assertEqual(len(window_risks), 1)
        directions = window_risks[0]['possible_misdelivery']
        intended = {(d['intended_tenant'], d['delivered_node']) for d in directions}
        self.assertIn(('beta', 'n1'), intended)
        self.assertIn(('app', 'n2'), intended)
        # The conclusion is durably recorded.
        self.assertEqual(len(rp.risk_history(db)), 1)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM address_conflicts').fetchone()[0], 1)


class NetworkDomainIsolationTests(unittest.TestCase):
    def test_same_address_in_proven_isolated_domains_is_allowed(self):
        db = memory_db()
        lc.import_page(db, 'pa', [APP_ROW], 10)
        beta_w = dict(BETA_ROW, domain='W')
        lc.import_page(db, 'pb-w', [beta_w], 10)
        rp.provision_domain(db, 'W', isolated_from='V', at=9)
        rp.record_isolation_receipt(db, 'W', 'a', at=10, against_domain='V', probe_ok=1)
        rp.record_isolation_receipt(db, 'W', 'b', at=10, against_domain='V', probe_ok=1)
        rp.test_isolation(db, 'W', at=10, ok=True)
        self.assertIn(('V', 'W'), rp.proven_isolated_domains(db))
        self.assertEqual(rp.detect_conflicts(db, at=10), [])
        app = rp.publish(db, 'app', 10)
        beta = rp.publish(db, 'beta', 10)
        self.assertEqual(app['decision'], 'published')
        self.assertEqual(beta['decision'], 'published')
        keys = {(e['domain'], e['address']): e['tenant'] for e in rp.active_endpoints(db)}
        self.assertEqual(keys[('V', DOT7)], 'app')
        self.assertEqual(keys[('W', DOT7)], 'beta')

    def test_unproven_domain_label_is_warning_not_blanket_conflict(self):
        db = memory_db()
        lc.import_page(db, 'pa', [APP_ROW], 10)
        lc.import_page(db, 'pb-w', [dict(BETA_ROW, domain='W')], 10)
        # No isolation receipts / test: labels alone prove nothing.
        self.assertEqual(rp.detect_conflicts(db, at=10), [])
        report = rp.conflict_report(db, at=10)
        self.assertTrue(report['separation_warnings'])
        self.assertEqual(report['separation_warnings'][0]['kind'],
                         'unproven_domain_separation')


class ReaddressRepairTests(unittest.TestCase):
    def test_prepare_gates_on_new_lease_confirmation_and_live_probe(self):
        db = memory_db()
        seed_scene(db)
        blocked = rp.prepare_readdress(db, id='h', tenant='beta', address=DOT7,
                                       new_address=DOT8, node='n2', at=11)
        self.assertEqual(blocked['decision'], 'blocked')
        self.assertIn('new_lease_missing', blocked['blockers'])
        lc.import_page(db, 'p8', [BETA_DOT8_ROW], 11)
        blocked = rp.prepare_readdress(db, id='h', tenant='beta', address=DOT7,
                                       new_address=DOT8, node='n2', at=11)
        self.assertIn('client_confirmation_missing', blocked['blockers'])
        self.assertIn('address_probe_missing', blocked['blockers'])
        lc.confirm_lease(db, 'beta', DOT8, at=11, agent='b')
        blocked = rp.prepare_readdress(db, id='h', tenant='beta', address=DOT7,
                                       new_address=DOT8, node='n2', at=11)
        self.assertIn('address_probe_missing', blocked['blockers'])
        rp.probe_address(db, 'beta', DOT8, at=11, ok=True)
        ready = rp.prepare_readdress(db, id='h', tenant='beta', address=DOT7,
                                     new_address=DOT8, node='n2', at=11)
        self.assertEqual(ready['decision'], 'prepared')

    def test_stale_neighbor_cache_blocks_completion(self):
        db = memory_db()
        seed_scene(db)
        beta_dot8_evidence(db)
        rp.prepare_readdress(db, id='h1', tenant='beta', address=DOT7,
                             new_address=DOT8, node='n2', at=11)
        lc.save_receipt(db, 'h1', 'a', at=12, steps='all')
        # b applies every fabric step except neighbour-cache invalidation.
        lc.save_receipt(db, 'h1', 'b', at=12, steps=[
            'revoke_old_lease', 'assign_new_address', 'update_client_cache',
            'apply_route'])
        pending = rp.commit_handoff(db, 'h1', at=13)
        self.assertFalse(pending['complete'])
        self.assertEqual(pending['applied_agents'], ['a', 'b'])
        self.assertIn('stale_neighbor_cache', pending['blockers'])
        # A fresh cache entry still pointing .7 at n2 stays dangerous.
        lc.record_neighbor_cache(db, 'b', [{'address': DOT7, 'node': 'n2'}], at=13)
        self.assertIn('stale_neighbor_cache', rp.commit_handoff(db, 'h1', at=13)['blockers'])
        # Invalidating it lets the commit go through.
        lc.invalidate_neighbor(db, agent='b', address=DOT7, at=14, target_node='n2')
        done = rp.commit_handoff(db, 'h1', at=14)
        self.assertEqual(done['decision'], 'completed')

    def test_readdress_fix_moves_beta_to_dot8_and_leaves_app_untouched(self):
        db = memory_db()
        seed_scene(db)
        beta_dot8_evidence(db)
        rp.prepare_readdress(db, id='h1', tenant='beta', address=DOT7,
                             new_address=DOT8, node='n2', at=11)
        for agent in ('a', 'b'):
            lc.save_receipt(db, 'h1', agent, at=12, steps='all')
        done = rp.commit_handoff(db, 'h1', at=14)
        self.assertEqual(done['decision'], 'completed')
        self.assertEqual(done['stop_window']['minutes'], 2)
        eps = {(e['domain'], e['address']): (e['tenant'], e['node'])
               for e in rp.active_endpoints(db)}
        self.assertEqual(eps[('V', DOT7)], ('app', 'n1'))
        self.assertEqual(eps[('V', DOT8)], ('beta', 'n2'))
        # Publishing now resolves each tenant to its unique endpoint.
        self.assertEqual(rp.publish(db, 'app', 15)['address'], DOT7)
        beta = rp.publish(db, 'beta', 15)
        self.assertEqual(beta['address'], DOT8)
        self.assertEqual(beta['node'], 'n2')
        # Old beta .7 route is retained but marked superseded, never deleted.
        old = db.execute(
            "SELECT state FROM endpoint_routes WHERE tenant='beta' AND address=? "
            "ORDER BY rowid", (DOT7,)).fetchall()
        self.assertTrue(old)
        self.assertIn('superseded', [r[0] for r in old])
        self.assertEqual(rp.conflict_report(db, at=15)['open_conflict_count'], 0)

    def test_half_committed_file_reopen_resumes_only_after_both_agents(self):
        tmp = tempfile.TemporaryDirectory()
        path = os.path.join(tmp.name, 'state.sqlite')
        try:
            db = sqlite3.connect(path)
            rp.ensure_schema(db)
            seed_scene(db)
            beta_dot8_evidence(db)
            rp.prepare_readdress(db, id='h1', tenant='beta', address=DOT7,
                                 new_address=DOT8, node='n2', at=11)
            lc.save_receipt(db, 'h1', 'a', at=12, steps='all')
            half = rp.commit_handoff(db, 'h1')
            self.assertEqual(half['decision'], 'half_committed')
            self.assertEqual(half['applied_agents'], ['a'])
            self.assertEqual(half['pending_agents'], ['b'])
            db.close()  # power loss / process restart

            reopened = sqlite3.connect(path)
            state = rp.reopen(reopened, 'h1')
            self.assertEqual(state['status'], 'half_committed')
            self.assertEqual(state['applied_agents'], ['a'])
            self.assertEqual(state['pending_agents'], ['b'])
            # Physical identity of the applied agent survived the restart.
            receipts = state['handoff']['receipts']
            a_receipt = next(r for r in receipts if r['agent'] == 'a')
            self.assertEqual(a_receipt['physical_id'], 'PHYS-A-NIC-0')
            # Recovery cannot finish while b is missing.
            still = rp.recover_handoff(reopened, 'h1', at=13)
            self.assertFalse(still['complete'])
            self.assertEqual(still['pending_agents'], ['b'])
            lc.save_receipt(reopened, 'h1', 'b', at=13, steps='all')
            done = rp.recover_handoff(reopened, 'h1', at=14)
            self.assertEqual(done['decision'], 'completed')
            self.assertEqual(done['applied_agents'], ['a', 'b'])
            self.assertEqual(done['stop_window']['from'], 12)
            self.assertEqual(done['stop_window']['to'], 14)
            keys = [(e['domain'], e['address']) for e in rp.active_endpoints(reopened)]
            self.assertEqual(len(keys), len(set(keys)))
            reopened.close()
        finally:
            tmp.cleanup()

    def test_granular_step_checkpoints_drive_recovery(self):
        db = memory_db()
        seed_scene(db)
        beta_dot8_evidence(db)
        rp.prepare_readdress(db, id='h2', tenant='beta', address=DOT7,
                             new_address=DOT8, node='n2', at=11)
        steps = lc.REQUIRED_STEPS['readdress']
        for step in steps:
            lc.record_step(db, 'h2', 'a', step, at=12)
        h = lc.get_handoff(db, 'h2')
        self.assertEqual(h['applied_agents'], ['a'])
        self.assertEqual(h['pending_agents'], ['b'])
        self.assertFalse(rp.commit_handoff(db, 'h2', at=13)['complete'])
        for step in steps:
            lc.record_step(db, 'h2', 'b', step, at=13)
        done = rp.commit_handoff(db, 'h2', at=14)
        self.assertEqual(done['decision'], 'completed')
        self.assertEqual(rp.publish(db, 'beta', 15)['address'], DOT8)

    def test_bare_agent_receipts_imply_full_apply(self):
        db = memory_db()
        seed_scene(db)
        beta_dot8_evidence(db)
        rp.prepare_readdress(db, id='h3', tenant='beta', address=DOT7,
                             new_address=DOT8, node='n2', at=11)
        # A receipt with no explicit step list is a full application ack,
        # including neighbour-cache invalidation.
        lc.record_receipt(db, 'h3', 'a', at=12)
        lc.record_receipt(db, 'h3', 'b', at=13)
        done = rp.commit_handoff(db, 'h3', at=14)
        self.assertEqual(done['decision'], 'completed')

    def test_positional_natural_repair_call(self):
        db = memory_db()
        seed_scene(db)
        done = rp.repair_readdress(db, 'beta', DOT7, DOT8, at=12, complete_at=14)
        self.assertEqual(done['decision'], 'completed')
        self.assertEqual(rp.current_owner(db, DOT7, 'V')['tenant'], 'app')
        self.assertEqual(rp.current_owner(db, DOT8, 'V')['tenant'], 'beta')


class IsolationRepairTests(unittest.TestCase):
    def _prepared_isolation(self, db, **kw):
        args = dict(id='iso1', tenant='beta', address=DOT7, node='n2', at=11,
                     new_domain='W', external_address=DOT8, translation_slot='slot-w')
        args.update(kw)
        return rp.prepare_isolation(db, **args)

    def test_requires_both_isolation_sides_and_tested_translation(self):
        db = memory_db()
        seed_scene(db)
        rp.provision_domain(db, 'W', isolated_from='V', at=10)
        rp.record_isolation_receipt(db, 'W', 'a', at=11, against_domain='V', probe_ok=1)
        rp.test_isolation(db, 'W', at=11, ok=True)
        rp.provision_translation(db, 'slot-w', external_address=DOT8,
                                 internal_domain='W', internal_address=DOT7,
                                 internal_node='n2', at=11)
        blocked = self._prepared_isolation(db)
        self.assertEqual(blocked['decision'], 'blocked')
        self.assertIn('isolation_receipt_missing', blocked['blockers'])
        self.assertIn('translation_untested', blocked['blockers'])
        # Even if both handoff agent receipts arrive, the missing isolation
        # side keeps the switch uncommittable.
        lc.save_receipt(db, 'iso1', 'a', at=12, steps='all')
        lc.save_receipt(db, 'iso1', 'b', at=12, steps='all')
        not_done = rp.commit_handoff(db, 'iso1', at=13)
        self.assertNotEqual(not_done['decision'], 'completed')
        self.assertIn('isolation_receipt_missing', not_done['blockers'])
        self.assertIn('translation_untested', not_done['blockers'])
        # Supply side b and test the translation table; recovery completes.
        rp.record_isolation_receipt(db, 'W', 'b', at=12, against_domain='V', probe_ok=1)
        rp.test_translation(db, 'slot-w', at=12, ok=True)
        done = rp.commit_handoff(db, 'iso1', at=13)
        self.assertEqual(done['decision'], 'completed')
        self.assertEqual(
            {(e['domain'], e['address']) for e in rp.active_endpoints(db)},
            {('V', DOT7), ('W', DOT7), ('EXT', DOT8)})

    def test_prepare_becomes_ready_after_evidence_completed(self):
        db = memory_db()
        seed_scene(db)
        rp.provision_domain(db, 'W', isolated_from='V', at=10)
        rp.record_isolation_receipt(db, 'W', 'a', at=11, against_domain='V', probe_ok=1)
        rp.record_isolation_receipt(db, 'W', 'b', at=11, against_domain='V', probe_ok=1)
        rp.test_isolation(db, 'W', at=11, ok=True)
        rp.provision_translation(db, 'slot-w', external_address=DOT8,
                                 internal_domain='W', internal_address=DOT7,
                                 internal_node='n2', at=11)
        rp.test_translation(db, 'slot-w', at=11, ok=True)
        ready = self._prepared_isolation(db)
        self.assertEqual(ready['decision'], 'prepared')

    def test_isolation_fix_keeps_internal_dot7_and_uses_domain_and_slot(self):
        db = memory_db()
        seed_scene(db)
        done = rp.isolation_fix(db, id='iso1', at=12, complete_at=15)
        self.assertEqual(done['decision'], 'completed')
        self.assertEqual(done['resources']['network_domains'], 1)
        self.assertEqual(done['resources']['translation_slots'], 1)
        self.assertEqual(done['beta_internal_address'], DOT7)
        eps = {(e['domain'], e['address']): (e['tenant'], e['node'])
               for e in rp.active_endpoints(db)}
        # Both internal .7 endpoints survive, separated by proven domains.
        self.assertEqual(eps[('V', DOT7)], ('app', 'n1'))
        self.assertEqual(eps[('W', DOT7)], ('beta', 'n2'))
        # External path differs: beta is reached via translated .8.
        self.assertEqual(eps[('EXT', DOT8)][0], 'beta')
        beta_route = rp.publish(db, 'beta', 16)
        self.assertEqual(beta_route['address'], DOT8)
        self.assertEqual(beta_route['internal_address'], DOT7)
        self.assertEqual(beta_route['internal_domain'], 'W')
        self.assertEqual(rp.conflict_report(db, at=16)['open_conflict_count'], 0)
        slot = db.execute('SELECT status FROM translation_slots WHERE id=?',
                          ('slot-w-beta',)).fetchone()
        self.assertEqual(slot[0], 'active')

    def test_two_fixes_have_different_address_outage_and_resources(self):
        db_readdress = memory_db()
        seed_scene(db_readdress)
        r_fix = rp.readdress_fix(db_readdress, id='h', at=12, complete_at=14)

        db_isolation = memory_db()
        seed_scene(db_isolation)
        i_fix = rp.isolation_fix(db_isolation, id='i', at=12, complete_at=15)

        self.assertEqual(r_fix['beta_internal_address'], DOT8)
        self.assertEqual(i_fix['beta_internal_address'], DOT7)
        self.assertNotEqual(r_fix['stop_window']['minutes'],
                            i_fix['stop_window']['minutes'])
        self.assertEqual(r_fix['resources']['network_domains'], 0)
        self.assertGreaterEqual(i_fix['resources']['network_domains'], 1)
        self.assertEqual(r_fix['resources']['translation_slots'], 0)
        self.assertEqual(i_fix['resources']['translation_slots'], 1)


class LatePageReplayTerminationTests(unittest.TestCase):
    def test_late_page_and_replay_do_not_regress_completed_route(self):
        db = memory_db()
        seed_scene(db)
        rp.publish(db, 'app', 6)
        rp.readdress_fix(db, id='h1', at=12, complete_at=14)
        rows_before = db.execute('SELECT COUNT(*) FROM endpoint_routes').fetchone()[0]
        # A late paper page re-asserting beta's old .7 lease.
        late = lc.import_page(db, 'late-old-dot7', [BETA_ROW], 20)
        self.assertEqual(late['status'], 'captured')
        again = lc.import_page(db, 'late-old-dot7', [BETA_ROW], 20)
        self.assertEqual(again['status'], 'replayed')
        beta = rp.publish(db, 'beta', 20)
        self.assertEqual(beta['address'], DOT8)
        self.assertEqual(beta['handoff_id'], 'h1')
        # Nothing was deleted; the ledger only grew.
        rows_after = db.execute('SELECT COUNT(*) FROM endpoint_routes').fetchone()[0]
        self.assertGreaterEqual(rows_after, rows_before)
        self.assertTrue(db.execute(
            "SELECT 1 FROM endpoint_routes WHERE handoff_id='h1' LIMIT 1").fetchone())

    def test_termination_withdraws_only_that_tenant_and_keeps_history(self):
        db = memory_db()
        seed_scene(db)
        rp.publish(db, 'app', 10)
        rp.publish(db, 'beta', 10)  # blocked
        result = lc.terminate_tenant(db, 'beta', at=21, reason='tenant_left')
        self.assertEqual(result['decision'], 'terminated')
        self.assertEqual(lc.terminate_tenant(db, 'beta', at=22)['decision'], 'idempotent')
        # beta can no longer publish.
        self.assertEqual(rp.publish(db, 'beta', 22)['decision'], 'tenant_terminated')
        # app's unique .7 endpoint and all original routes survive.
        self.assertEqual(len(v7_endpoints(db)), 1)
        self.assertEqual(v7_endpoints(db)[0]['tenant'], 'app')
        self.assertTrue(db.execute(
            "SELECT 1 FROM endpoint_routes WHERE tenant='beta' LIMIT 1").fetchone())
        # Terminating app must not erase beta's preserved address claim.
        beta_claims_before = len(lc.lease_rows(db, tenant='beta', address=DOT7))
        lc.terminate_tenant(db, 'app', at=22)
        self.assertEqual(len(lc.lease_rows(db, tenant='beta', address=DOT7)),
                         beta_claims_before)
        report = rp.conflict_report(db, at=10)
        self.assertEqual(report['conflict_count'], 1)
        self.assertEqual(set(report['conflicts'][0]['tenants']), {'app', 'beta'})

    def test_terminating_other_tenant_keeps_completed_beta_endpoint(self):
        db = memory_db()
        seed_scene(db)
        rp.isolation_fix(db, id='iso1')
        lc.terminate_tenant(db, 'app', at=20)
        owners = {(e['domain'], e['address']): e['tenant']
                  for e in rp.active_endpoints(db)}
        self.assertEqual(owners[('W', DOT7)], 'beta')
        self.assertEqual(owners[('EXT', DOT8)], 'beta')


class ClockRecalibrationTests(unittest.TestCase):
    def test_reordered_clocks_add_new_conclusion_but_keep_decision_and_history(self):
        db = memory_db()
        seed_scene(db)
        rp.publish(db, 'app', 10)  # executed/programmed app ownership
        first = rp.assess_risks(db, at=10)
        self.assertEqual((first['window_start'], first['window_end']), (8, 25))
        self.assertEqual(first['conflicts'][0]['clock_ranked_owner'], 'app')
        lc.record_misdelivery(db, at=9, domain='V', address=DOT7,
                              intended_tenant='beta', intended_node='n2',
                              delivered_node='n1')
        # True-clock calibration reverses the issuance order.
        lc.calibrate_clock(db, tenant='app', address=DOT7, start=9, at=31)
        lc.calibrate_clock(db, tenant='beta', address=DOT7, start=4, at=31)
        second = rp.assess_risks(db, at=31)
        c = second['conflicts'][0]
        self.assertEqual((c['window_start'], c['window_end']), (9, 25))
        self.assertEqual(c['clock_ranked_owner'], 'beta')
        # The already-made executable decision is not retroactively rewritten.
        self.assertEqual(c['executable_owner'], 'app')
        self.assertEqual(v7_endpoints(db)[0]['tenant'], 'app')
        # Old conclusions, the incident and actions remain queryable.
        history = rp.risk_history(db)
        self.assertEqual(len(history), 2)
        self.assertEqual((history[0]['report']['window_start'],
                          history[0]['report']['window_end']), (8, 25))
        self.assertEqual((history[1]['report']['window_start'],
                          history[1]['report']['window_end']), (9, 25))
        incidents = lc.incident_history(db, address=DOT7)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]['delivered_node'], 'n1')


class ApiSurfaceAndDispatchTests(unittest.TestCase):
    def test_handoff_surface_reachable_from_both_modules(self):
        for name in ('prepare_handoff', 'commit_handoff', 'recover_handoff',
                     'detect_conflicts', 'assess_risks', 'readdress_fix',
                     'isolation_fix', 'reopen'):
            self.assertTrue(callable(getattr(rp, name)), name)
            self.assertTrue(callable(getattr(lc, name)), 'lease_capture.' + name)

    def test_main_execute_dispatch_runs_address_flow_on_file_db(self):
        from cloudctl.__main__ import execute
        tmp = tempfile.TemporaryDirectory()
        path = os.path.join(tmp.name, 'state.sqlite')
        try:
            import cloudctl.store as store
            store.init(path)
            out = execute(path, {'action': 'lease.import_page', 'page_id': 'pa',
                                 'received_at': 10, 'rows': [APP_ROW]})
            self.assertEqual(out['status'], 'captured')
            pub = execute(path, {'action': 'address.publish', 'tenant': 'app', 'at': 10})
            self.assertEqual(pub['decision'], 'published')
            report = execute(path, {'action': 'address.conflicts', 'at': 10})
            self.assertEqual(report['conflict_count'], 0)
        finally:
            tmp.cleanup()


if __name__ == '__main__':
    unittest.main()
