"""End-to-end tests for data residency, license lineage and lawful delivery.

Coverage matrix for the required adversarial cases:

* X 与 Y 限制冲突 (true permission intersection) -> ``test_xy_intersection_...``
* 许可迟到 (late license cannot cure old/late writes) -> ``test_late_license_...``
* 运行中撤销 (revocation while running) -> ``test_revocation_mid_run_...``
* 旧副本删不掉 (undeletable old replica) -> ``test_undeletable_copy_...``
* 匿名化不能复现/换标签 (relabel rejected, proof not reproducible)
  -> ``test_anonymisation_...``
* 跨区恢复点 (cross-region recovery point) -> ``test_cross_region_recovery_point_...``
* 客户已交付旧报告 (delivered report keeps basis + deletion duty)
  -> ``test_old_delivery_...``
* 两区同时申请原始数据 (two jurisdictions request raw data at once)
  -> ``test_two_jurisdictions_...`` / ``test_concurrent_raw_requests_...``
* 控制面断电 (control-plane power loss) -> ``test_power_loss_...``
* 客户取消与许可证撤销并发 (cancel/revoke/deliver race)
  -> ``test_cancel_revoke_deliver_race_...`` and ordered cancellation tests
* 节点迁移/临时缓存/备份 -> guarded drain, transfer temp copies, backup tests.

The acceptance story:

* X is an EU-source medical record whose real bytes are captured only on the
  EU node E; Y is globally usable public parameters.
* North-American node N has spare CPU, but compute capacity never authorises
  moving raw bytes.
* Path 1 (EU-only license): restricted computation finishes on E, a fresh
  de-identified digest/proof is produced and statistics go to the NA
  recipient; raw X and recovery points stay in the EU.
* Path 2 (later cross-border approval for named fields): approved bytes move
  to N's controlled environment, a traceable personal report is generated at
  N and delivered, and every original/temporary copy carries cleanup duty.

The remaining tests cover X/Y conflicts, late licenses, mid-run revocation,
undeletable copies, un-reproducible anonymisation, cross-region recovery
points, immutable old deliveries and two jurisdictions requesting raw data
at once (including threaded contention and cancel/revoke/deliver races).
"""
import json
import tempfile
import threading
import unittest
from pathlib import Path

from cloudctl import store
from cloudctl.__main__ import execute
from cloudctl.storage_capture import capture_page
from cloudctl import data_residency as dr


class ResidencyCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / 'state.sqlite')
        store.init(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    # -- helpers -----------------------------------------------------------
    def call(self, action, **kw):
        return execute(self.db, {'action': action, **kw})

    def decide(self, action, **kw):
        return self.call(action, **kw)['decision']

    def rows(self, sql, args=()):
        with store.tx(self.db) as db:
            return [dict(r) for r in db.execute(sql, args)]

    def row(self, sql, args=()):
        with store.tx(self.db) as db:
            r = db.execute(sql, args).fetchone()
            return dict(r) if r else None

    def capture(self, page='page-x', node='E', at=11, digest='sha256:x',
                demand='dA', dataset='X'):
        with store.tx(self.db) as db:
            return capture_page(db, page, [{
                'demand': demand, 'dataset': dataset, 'node': node,
                'byte_digest': digest, 'at': at}])['decision']

    def seed_world(self, full_report_x=False):
        self.assertEqual(self.decide('residency.jurisdiction', zone='eu', jurisdiction='EU'), 'registered')
        self.assertEqual(self.decide('residency.jurisdiction', zone='na', jurisdiction='NA'), 'registered')
        for nid, zone, cpu in (('E', 'eu', 8), ('B', 'eu', 8), ('N', 'na', 32)):
            self.assertEqual(self.decide('node.register', id=nid, kind='cpu', zone=zone,
                                         cpu=cpu, ready=0, healthy=True), 'available')
        self.assertEqual(self.decide('demand.forecast', app='A', version=1, peak=1, at=0), 'recorded')
        self.assertEqual(self.decide('demand.commit', id='dA', app='A', start=10, end=40,
                                     minimum=1, burst=1, cpu=2), 'committed')
        x_purposes = ['statistics', 'research', 'processing', 'storage', 'backup', 'recovery']
        if full_report_x:
            x_purposes.append('full_report')
        self.assertEqual(self.decide(
            'residency.dataset', id='X', source_party='hospital-eu', jurisdiction='EU',
            sensitivity='medical_record', license_version='eu-1', purposes=x_purposes,
            deidentified_zones=['NA'], delete_after=100), 'registered')
        self.assertEqual(self.decide(
            'residency.dataset', id='Y', source_party='public-parameters', jurisdiction='GLOBAL',
            sensitivity='public', license_version='pub-1', purposes=['*'],
            regions=['*'], deidentified_zones=['*']), 'registered')
        self.assertEqual(self.decide('residency.bind_app', app='A', datasets=['X', 'Y']), 'registered')

    def issue_cross_border_license(self, lid='lic-cb', at=30):
        return self.call(
            'residency.license_issue', id=lid, dataset='X', version=2, at=at,
            purposes=['full_report', 'processing', 'cross_border_processing',
                      'statistics', 'storage'],
            regions=['EU', 'NA'],
            cross_border_fields=['patient_id', 'diagnosis'],
            cross_border_destinations=['NA'], recipient_zones=['NA'],
            deidentified_zones=['*'])

    def eu_stat_artifact(self, plan='plan-eu', at=22, digest_in='sha256:x', node='E'):
        return self.call(
            'residency.anonymize', id='stat-1', plan=plan, dataset='X', datasets=['X', 'Y'],
            input_digest=digest_in, transform='aggregate_statistics',
            spec={'metric': 'diagnosis_count', 'group_by': 'month'},
            node=node, at=at, content='diagnosis_count=42')


class AcceptancePathTests(ResidencyCase):
    def test_eu_only_license_completes_on_eu_and_exports_only_statistics(self):
        self.seed_world()
        # Real bytes of X are captured only on E.
        self.assertEqual(self.capture(), 'captured')
        ing = self.call('residency.ingest_page', page='page-x')
        self.assertEqual(ing['decision'], 'assessed')
        self.assertEqual(ing['evidence']['violations'], [])

        # Compute can be reserved/placed on N: CPU says nothing about bytes.
        self.assertEqual(self.decide('capacity.place', demand='dA', node='N', replica=1), 'placed')
        guard = self.call('residency.guard_placement', demand='dA',
                          datasets=['X', 'Y'], node='N', at=20)
        self.assertEqual(guard['decision'], 'restriction_conflict')

        # A North-American processing plan and a pre-license copy are refused.
        self.assertEqual(self.decide(
            'residency.plan', id='plan-na-naive', app='A', demand='dA',
            inputs=['X', 'Y'], purpose='statistics', target_node='N', at=20), 'planned')
        denied = self.call('residency.plan_authorize', id='plan-na-naive', at=20)
        self.assertEqual(denied['decision'], 'restriction_conflict')
        self.assertEqual(self.decide(
            'residency.transfer', plan='plan-na-naive', dataset='X', digest='sha256:x',
            from_node='E', to_node='N', at=20), 'cross_border_denied')
        self.assertEqual(self.rows(
            "SELECT COUNT(*) c FROM dr_transfers WHERE digest='sha256:x' AND status='transferred'")[0]['c'], 0)

        # Authorised EU plan.
        self.assertEqual(self.decide(
            'residency.plan', id='plan-eu', app='A', demand='dA',
            inputs=['X', 'Y'], purpose='statistics', target_node='E',
            recipient='na-recipient', recipient_zone='NA', at=20), 'planned')
        auth = self.call('residency.plan_authorize', id='plan-eu', at=20)
        self.assertEqual(auth['decision'], 'authorized')
        self.assertEqual(auth['evidence']['snapshot']['X']['version'], 1)

        # Recovery point / backup stays in the EU on B.
        self.assertEqual(self.decide(
            'residency.backup', id='rp-eu', dataset='X', node='B',
            digest='sha256:x', at=21, kind='recovery_point',
            plan='plan-eu', demand='dA'), 'backed_up')

        self.assertEqual(self.decide('residency.run_start', plan='plan-eu', node='E', at=21), 'processing')
        stat = self.eu_stat_artifact()
        self.assertEqual(stat['decision'], 'anonymized')
        new_digest = stat['digest']
        self.assertNotEqual(new_digest, 'sha256:x')
        self.assertEqual(self.decide('residency.verify', digest=new_digest), 'verified')
        self.assertEqual(self.decide('residency.run_finish', plan='plan-eu', at=23), 'completed')

        delivered = self.call('residency.deliver', id='deliv-eu', plan='plan-eu',
                              artifacts=[new_digest], at=24)
        self.assertEqual(delivered['decision'], 'delivered')
        self.assertTrue(delivered['evidence']['lawful'])
        self.assertEqual(delivered['evidence']['basis']['licenses']['X']['version'], 1)
        self.assertEqual(delivered['evidence']['delete_by'], 124)

        # The only bytes that crossed to NA are the derived statistics.
        raw_out = self.rows(
            "SELECT * FROM dr_transfers WHERE digest='sha256:x' AND status IN ('transferred','delivered')")
        self.assertEqual(raw_out, [])
        derived_out = self.rows(
            "SELECT * FROM dr_transfers WHERE digest=? AND status='delivered'", (new_digest,))
        self.assertEqual(len(derived_out), 1)
        self.assertEqual(derived_out[0]['to_zone'], 'NA')

        # Every X copy remains in an EU jurisdiction and live.
        copies = self.rows("SELECT node,jurisdiction,status,kind FROM dr_copies WHERE dataset='X'")
        self.assertTrue(copies)
        self.assertEqual({c['jurisdiction'] for c in copies}, {'EU'})
        self.assertTrue(all(c['status'] == 'live' for c in copies))
        self.assertIn('recovery_point', {c['kind'] for c in copies})

        tr = self.call('residency.trace', plan='plan-eu')
        self.assertEqual(tr['decision'], 'traced')
        self.assertEqual(len(tr['evidence']['violations']), 0)
        self.assertEqual(self.decide('residency.audit'), 'compliant')

        # Event flow was written.
        kinds = {r['kind'] for r in self.rows("SELECT DISTINCT kind FROM events")}
        self.assertIn('residency.delivery', kinds)
        self.assertIn('residency.placement_guard', kinds)

    def test_cross_border_approval_sends_named_bytes_and_traceable_report_to_n(self):
        self.seed_world()
        self.capture()
        self.call('residency.ingest_page', page='page-x')

        # Before approval: N spare CPU is irrelevant and movement is denied.
        self.assertEqual(self.decide(
            'residency.transfer', id='x-pre', dataset='X', digest='sha256:x',
            from_node='E', to_node='N', at=29,
            fields=['patient_id', 'diagnosis']), 'cross_border_denied')

        lic = self.issue_cross_border_license()
        self.assertEqual(lic['decision'], 'issued')

        self.assertEqual(self.decide(
            'residency.plan', id='plan-na', app='A', demand='dA',
            inputs=['X', 'Y'], purpose='full_report', target_node='N',
            recipient='customer-na', recipient_zone='NA', at=31), 'planned')
        auth = self.call('residency.plan_authorize', id='plan-na', at=31)
        self.assertEqual(auth['decision'], 'authorized')
        self.assertEqual(auth['evidence']['snapshot']['X']['version'], 2)

        # Approved field extract gets its own real digest + proof.
        extract = self.call(
            'residency.transform', id='extract-1', kind='field_export', plan='plan-na',
            dataset='X', datasets=['X'], input_digest='sha256:x',
            transform='select_fields', spec={'fields': ['patient_id', 'diagnosis']},
            node='E', at=33, personal=True)
        self.assertEqual(extract['decision'], 'recorded')
        extract_digest = extract['digest']
        self.assertNotEqual(extract_digest, 'sha256:x')

        moved = self.call(
            'residency.transfer', id='x-move', plan='plan-na', dataset='X',
            digest=extract_digest, from_node='E', to_node='N', at=34,
            fields=['patient_id', 'diagnosis'])
        self.assertEqual(moved['decision'], 'transferred')
        self.assertEqual(moved['evidence']['license']['version'], 2)

        n_copy = self.row("SELECT * FROM dr_copies WHERE id=?", (moved['copy_id'],))
        self.assertEqual(n_copy['jurisdiction'], 'NA')
        self.assertEqual(n_copy['lawful'], 1)
        self.assertIn('controlled-env', n_copy['cleanup_owner'])

        self.assertEqual(self.decide('residency.run_start', plan='plan-na', node='N', at=34), 'processing')
        report = self.call(
            'residency.transform', id='report-1', kind='report', plan='plan-na',
            dataset='X', datasets=['X', 'Y'],
            input_digests=[extract_digest, 'sha256:y-params'],
            transform='full_traceable_report',
            spec={'records': ['patient:EU-1/diagnosis', 'patient:EU-2/diagnosis']},
            node='N', at=35, personal=True, traceable=True,
            content='TRACEABLE_REPORT with patient records')
        self.assertEqual(report['decision'], 'recorded')
        self.assertEqual(self.decide('residency.run_finish', plan='plan-na', at=36), 'completed')

        delivered = self.call('residency.deliver', id='deliv-na', plan='plan-na',
                              artifacts=[report['digest']], at=39)
        self.assertEqual(delivered['decision'], 'delivered')
        self.assertEqual(delivered['evidence']['report_kind'], 'traceable_personal_report')
        self.assertTrue(delivered['evidence']['traceable'])

        # Outbound bytes include the personal field extract, unlike path 1.
        personal_egress = self.rows(
            "SELECT * FROM dr_transfers WHERE id='x-move' AND status='transferred'")
        self.assertEqual(len(personal_egress), 1)
        self.assertEqual(json.loads(personal_egress[0]['fields']),
                         ['patient_id', 'diagnosis'])

        # Full raw X is still not cleared for NA; only named fields are.
        full_raw = self.call('residency.raw_request', id='raw-full-na', dataset='X', node='N', at=40)
        self.assertEqual(full_raw['decision'], 'raw_denied')
        field_raw = self.call('residency.raw_request', id='raw-fields-na', dataset='X',
                              node='N', at=40, fields=['diagnosis'])
        self.assertEqual(field_raw['decision'], 'raw_granted')

        # Every original/temporary copy carries cleanup responsibility.
        resp = self.call('residency.responsibilities', plan='plan-na')
        self.assertTrue(resp['evidence']['copies'])
        self.assertTrue(any(c['jurisdiction'] == 'EU' for c in resp['evidence']['copies']))
        self.assertTrue(any(c['jurisdiction'] == 'NA' for c in resp['evidence']['copies']))
        for c in resp['evidence']['copies']:
            self.assertTrue(c['owner'])
        self.assertTrue(self.rows("SELECT * FROM dr_obligations WHERE kind='temporary_copy_cleanup'"))

        tr = self.call('residency.trace', delivery='deliv-na')
        self.assertEqual(tr['decision'], 'traced')
        rep_art = [a for a in tr['evidence']['artifacts'] if a['digest'] == report['digest']][0]
        self.assertTrue(rep_art['traceable'])
        self.assertIn('patient:EU-1', rep_art['spec'])


    def test_two_outcomes_diverge_from_one_shared_start(self):
        # One shared initial world: same X, Y, captured EU bytes, no CB grant.
        self.seed_world()
        self.capture()
        self.call('residency.ingest_page', page='page-x')

        # Branch 1: EU-only restricted computation -> anonymous statistics.
        self.call('residency.plan', id='div-eu', app='A', demand='dA',
                  inputs=['X', 'Y'], purpose='statistics', target_node='E',
                  recipient_zone='NA', at=20)
        self.assertEqual(self.decide('residency.plan_authorize', id='div-eu', at=20), 'authorized')
        self.call('residency.run_start', plan='div-eu', node='E', at=21)
        stat = self.call('residency.anonymize', id='div-stat', plan='div-eu',
                         datasets=['X', 'Y'], input_digest='sha256:x',
                         transform='aggregate_statistics', spec={'m': 'c'}, node='E', at=22)
        self.call('residency.run_finish', plan='div-eu', at=23)
        d_eu = self.call('residency.deliver', id='div-d-eu', plan='div-eu',
                         artifacts=[stat['digest']], at=24)
        self.assertEqual(d_eu['decision'], 'delivered')

        # Branch 2 starts only after later customer/regulator approval.
        self.assertEqual(self.issue_cross_border_license(at=30)['decision'], 'issued')
        self.call('residency.plan', id='div-na', app='A', demand='dA',
                  inputs=['X', 'Y'], purpose='full_report', target_node='N',
                  recipient_zone='NA', at=31)
        self.assertEqual(self.decide('residency.plan_authorize', id='div-na', at=31), 'authorized')
        extract = self.call('residency.transform', id='div-extract', kind='field_export',
                            plan='div-na', datasets=['X'], input_digest='sha256:x',
                            transform='select_fields',
                            spec={'fields': ['patient_id', 'diagnosis']},
                            node='E', at=33, personal=True)
        moved = self.call('residency.transfer', id='div-move', plan='div-na', dataset='X',
                          digest=extract['digest'], from_node='E', to_node='N', at=34,
                          fields=['patient_id', 'diagnosis'])
        self.assertEqual(moved['decision'], 'transferred')
        self.call('residency.run_start', plan='div-na', node='N', at=34)
        report = self.call('residency.transform', id='div-report', kind='report',
                           plan='div-na', datasets=['X', 'Y'],
                           input_digests=[extract['digest'], 'sha256:y'],
                           transform='full_traceable_report',
                           spec={'records': ['p1', 'p2']}, node='N', at=35,
                           personal=True, traceable=True, content='FULL')
        self.call('residency.run_finish', plan='div-na', at=36)
        d_na = self.call('residency.deliver', id='div-d-na', plan='div-na',
                         artifacts=[report['digest']], at=39)
        self.assertEqual(d_na['decision'], 'delivered')

        # Processing nodes differ.
        self.assertEqual(self.row("SELECT target_node FROM dr_plans WHERE id='div-eu'")['target_node'], 'E')
        self.assertEqual(self.row("SELECT target_node FROM dr_plans WHERE id='div-na'")['target_node'], 'N')
        # EU result is non-traceable statistics; NA result is traceable personal.
        self.assertEqual(d_eu['evidence']['report_kind'], 'deidentified_statistics')
        self.assertFalse(d_eu['evidence']['traceable'])
        self.assertEqual(d_na['evidence']['report_kind'], 'traceable_personal_report')
        self.assertTrue(d_na['evidence']['traceable'])
        # Raw X itself never crosses; the named-field extract does.
        self.assertEqual(self.rows(
            "SELECT COUNT(*) c FROM dr_transfers WHERE digest='sha256:x' AND status='transferred'")[0]['c'], 0)
        self.assertEqual(self.row("SELECT status,to_zone FROM dr_transfers WHERE id='div-move'")['status'],
                         'transferred')
        # Traceability rights differ.
        t_eu = self.call('residency.trace', plan='div-eu')['evidence']
        t_na = self.call('residency.trace', plan='div-na')['evidence']
        eu_plan_artifacts = [a for a in t_eu['artifacts'] if a['plan'] == 'div-eu']
        na_plan_artifacts = [a for a in t_na['artifacts'] if a['plan'] == 'div-na']
        self.assertTrue(eu_plan_artifacts and na_plan_artifacts)
        self.assertFalse(any(a['traceable'] for a in eu_plan_artifacts))
        self.assertTrue(any(a['traceable'] for a in na_plan_artifacts))
        # Both branches leave a complete cleanup ledger.
        self.assertTrue(t_eu['obligations'] and t_na['obligations'])


class ConflictAndLicenseTimeTests(ResidencyCase):
    def test_xy_intersection_cannot_be_overridden_by_broad_y_license(self):
        self.seed_world()
        # X forbids marketing and is EU-only; Y permits everything.
        self.assertEqual(self.decide(
            'residency.plan', id='p-mkt', app='A', inputs=['X', 'Y'],
            purpose='marketing', target_node='E', at=20), 'planned')
        denied = self.call('residency.plan_authorize', id='p-mkt', at=20)
        self.assertEqual(denied['decision'], 'restriction_conflict')
        self.assertTrue(any(b.get('dataset') == 'X' and b['reason'] == 'purpose_not_permitted'
                             for b in denied['evidence']['blockers']))

        # Region intersection collapses to EU despite Y being global.
        acc = self.call('residency.access', datasets=['X', 'Y'], at=20,
                        purpose='processing', jurisdiction='NA')
        self.assertEqual(acc['decision'], 'restriction_conflict')
        self.assertEqual(acc['evidence']['regions'], ['EU'])

    def test_late_license_never_cures_old_or_late_arriving_copy(self):
        self.seed_world()
        # Rogue copy physically on N at t=11, observed immediately.
        rogue = self.call('residency.copy', id='rogue-1', dataset='X', node='N',
                          digest='sha256:x', at=11)
        self.assertEqual(rogue['decision'], 'violation_recorded')
        vid = rogue['violation_id']

        # Cross-border approval arrives at t=30.
        self.assertEqual(self.issue_cross_border_license(at=30)['decision'], 'issued')

        # A late capture page (reported after approval) still describes bytes
        # that landed on N at t=12: judged at t=12, still a violation.
        self.assertEqual(self.capture(page='late-page', node='N', at=12,
                                      digest='sha256:x-late'), 'captured')
        late = self.call('residency.ingest_page', page='late-page')
        self.assertEqual(late['decision'], 'violation_recorded')

        aud = self.call('residency.audit')
        self.assertEqual(aud['decision'], 'non_compliant')

        # New movement after the license is clean, but the old tainted copy
        # remains readable and blocks lawful delivery.
        fresh = self.call('residency.copy', id='fresh-na', dataset='X', node='N',
                          digest='sha256:x-new', at=31, kind='temp')
        self.assertEqual(fresh['decision'], 'recorded')

        stat = self.call('residency.anonymize', datasets=['X'], input_digest='sha256:x',
                         transform='aggregate_statistics', spec={}, at=32, node='E')
        blocked = self.call('residency.deliver', id='d-late', datasets=['X'],
                            artifacts=[stat['digest']], zone='NA', at=33)
        self.assertEqual(blocked['decision'], 'unlawful_copy_live')
        self.assertIn('rogue-1', [c['id'] for c in blocked['evidence']['unlawful_copies']])

        # Removing the old copies unblocks delivery but keeps violations.
        before = self.rows("SELECT COUNT(*) c FROM dr_violations")[0]['c']
        self.assertEqual(self.decide('residency.erase', copy_id='rogue-1', at=34), 'deleted')
        late_copy_id = 'cap:late-page:1'
        self.assertEqual(self.decide('residency.erase', copy_id=late_copy_id, at=34), 'deleted')
        delivered = self.call('residency.deliver', id='d-late-2', datasets=['X'],
                              artifacts=[stat['digest']], zone='NA', at=35)
        self.assertEqual(delivered['decision'], 'delivered')
        after = self.rows("SELECT COUNT(*) c FROM dr_violations")[0]['c']
        self.assertEqual(before, after)  # history is immutable
        self.assertTrue(self.row("SELECT remedied FROM dr_violations WHERE id=?", (vid,))['remedied'])

    def test_revocation_mid_run_halts_and_blocks_delivery(self):
        self.seed_world()
        self.capture()
        self.call('residency.ingest_page', page='page-x')
        self.call('residency.plan', id='p-rev', app='A', demand='dA', inputs=['X', 'Y'],
                  purpose='statistics', target_node='E', recipient_zone='NA', at=20)
        self.assertEqual(self.decide('residency.plan_authorize', id='p-rev', at=20), 'authorized')
        self.assertEqual(self.decide('residency.run_start', plan='p-rev', node='E', at=21), 'processing')
        stat = self.eu_stat_artifact(plan='p-rev', at=21)

        lic_id = self.row("SELECT id FROM dr_licenses WHERE dataset='X' AND version=1")['id']
        rev = self.call('residency.license_revoke', id=lic_id, at=22)
        self.assertEqual(rev['decision'], 'revoked')
        self.assertIn('p-rev', rev['evidence']['affected_plans'])
        self.assertTrue(rev['evidence']['cleanup_copies'])

        halted = self.call('residency.run_finish', plan='p-rev', at=23)
        self.assertEqual(halted['decision'], 'halted')
        self.assertTrue(halted['evidence']['violation_id'])

        denied = self.call('residency.deliver', id='d-rev', plan='p-rev',
                           artifacts=[stat['digest']], at=24)
        self.assertEqual(denied['decision'], 'restriction_conflict')
        self.assertEqual(self.row("SELECT state FROM dr_plans WHERE id='p-rev'")['state'], 'halted')

    def test_correction_has_forward_boundary_and_preserves_old_license(self):
        self.seed_world()
        old = self.row("SELECT id,version FROM dr_licenses WHERE dataset='X' ORDER BY version LIMIT 1")
        corr = self.call('residency.license_correct', id=old['id'], at=30,
                         purposes=['statistics', 'processing', 'storage'], regions=['EU'])
        self.assertEqual(corr['decision'], 'corrected')
        old_row = self.row("SELECT state,effective_to FROM dr_licenses WHERE id=?", (old['id'],))
        self.assertEqual(old_row['state'], 'superseded')
        self.assertEqual(old_row['effective_to'], 30)
        new_row = self.row("SELECT version,effective_from,supersedes FROM dr_licenses WHERE id=?",
                           (corr['subject'],))
        self.assertGreater(new_row['version'], old['version'])
        self.assertEqual(new_row['effective_from'], 30)


class CopyIntegrityTests(ResidencyCase):
    def test_undeletable_copy_stays_readable_and_blocks_delivery(self):
        self.seed_world()
        bad = self.call('residency.copy', id='stuck', dataset='X', node='N',
                        digest='sha256:stuck', at=11)
        self.assertEqual(bad['decision'], 'violation_recorded')

        fail = self.call('residency.erase', copy_id='stuck', success=False, at=12)
        self.assertEqual(fail['decision'], 'undeletable')
        self.assertTrue(fail['evidence']['still_readable'])
        self.assertEqual(self.decide('residency.erase', copy_id='stuck', success=False, at=13), 'undeletable')
        crow = self.row("SELECT status,delete_attempts,lawful FROM dr_copies WHERE id='stuck'")
        self.assertEqual(crow['status'], 'delete_failed')
        self.assertEqual(crow['delete_attempts'], 2)
        self.assertEqual(crow['lawful'], 0)

        stat = self.call('residency.anonymize', datasets=['X'], input_digest='sha256:stuck',
                         transform='aggregate_statistics', spec={}, at=14)
        blocked = self.call('residency.deliver', id='d-stuck', datasets=['X'],
                            artifacts=[stat['digest']], zone='NA', at=15)
        self.assertEqual(blocked['decision'], 'unlawful_copy_live')

        self.assertEqual(self.decide('residency.erase', copy_id='stuck', at=16), 'deleted')
        self.assertEqual(self.decide('residency.deliver', id='d-stuck-2', datasets=['X'],
                                     artifacts=[stat['digest']], zone='NA', at=17), 'delivered')
        # The original violation is still on record.
        self.assertTrue(self.rows("SELECT * FROM dr_violations WHERE kind='unauthorized_copy'"))

    def test_anonymisation_must_be_new_bytes_and_reproducible_proof(self):
        self.seed_world()
        # Relabelling the raw digest is rejected and recorded as a violation.
        relabel = self.call('residency.anonymize', datasets=['X'],
                            input_digest='sha256:x', output_digest='sha256:x',
                            transform='anonymize', spec={}, at=20)
        self.assertEqual(relabel['decision'], 'relabel_rejected')
        self.assertTrue(self.rows("SELECT * FROM dr_violations WHERE kind='fake_anonymization_relabel'"))

        # A claimed proof that does not reproduce is rejected/persisted bad.
        bad_proof = self.call('residency.anonymize', datasets=['X'],
                              input_digest='sha256:x', transform='k_anonymity',
                              spec={'k': 5}, proof='sha256:forged', at=21)
        self.assertEqual(bad_proof['decision'], 'proof_mismatch')
        verify_bad = self.call('residency.verify', digest=bad_proof['digest'])
        self.assertEqual(verify_bad['decision'], 'proof_mismatch')
        self.assertFalse(verify_bad['evidence']['reproducible'])

        # A genuine transform verifies and is deterministic.
        a1 = self.call('residency.anonymize', datasets=['X', 'Y'],
                       input_digests=['sha256:x', 'sha256:y'],
                       transform='aggregate_statistics', spec={'metric': 'count'}, at=22)
        self.assertEqual(a1['decision'], 'anonymized')
        again = self.call('residency.anonymize', datasets=['X', 'Y'],
                          input_digests=['sha256:x', 'sha256:y'],
                          transform='aggregate_statistics', spec={'metric': 'count'}, at=23)
        self.assertEqual(again['decision'], 'idempotent')
        self.assertEqual(again['digest'], a1['digest'])
        self.assertEqual(self.decide('residency.verify', digest=a1['digest']), 'verified')
        self.assertNotEqual(a1['digest'], 'sha256:x')

    def test_cross_region_recovery_point_blocks_recovery_until_eu_target(self):
        self.seed_world()
        self.assertEqual(self.decide('capacity.place', demand='dA', node='E', replica=1), 'placed')
        self.assertEqual(self.decide('node.fail', id='E'), 'isolated')

        # A cross-region recovery point observed on N is itself a violation.
        rp = self.call('residency.backup', id='rp-na', dataset='X', node='N',
                       digest='sha256:x-rp', at=15, kind='recovery_point', demand='dA')
        self.assertEqual(rp['decision'], 'violation_recorded')

        blocked = self.call('residency.recover_guarded', demand='dA', replica=1, destination='N')
        self.assertEqual(blocked['decision'], 'recovery_blocked')
        self.assertEqual(self.row("SELECT node,status FROM placements WHERE demand='dA' AND replica=1")['status'],
                         'at_risk')

        restored = self.call('residency.recover_guarded', demand='dA', replica=1, destination='B')
        self.assertEqual(restored['decision'], 'restored')
        self.assertEqual(self.row("SELECT node FROM placements WHERE demand='dA' AND replica=1")['node'], 'B')

    def test_temporary_cache_is_processing_and_governed_by_region(self):
        self.seed_world()
        # A cache of X warmed on N is a temporary copy: EU-only license forbids.
        bad_cache = self.call('residency.copy', id='cache-n', dataset='X', node='N',
                              digest='sha256:x', at=18, kind='cache', plan=None)
        self.assertEqual(bad_cache['decision'], 'violation_recorded')
        self.assertEqual(self.row("SELECT lawful,kind FROM dr_copies WHERE id='cache-n'")['lawful'], 0)
        # Same cache on EU node B is permitted.
        ok_cache = self.call('residency.copy', id='cache-b', dataset='X', node='B',
                             digest='sha256:x', at=18, kind='cache')
        self.assertEqual(ok_cache['decision'], 'recorded')

    def test_guarded_drain_refuses_cross_jurisdiction_destination(self):
        # Self-contained world: E (EU) hosts dA and N (NA) is the only
        # healthy alternative, so capacity drain plans N but residency vetoes.
        self.call('residency.jurisdiction', zone='eu', jurisdiction='EU')
        self.call('residency.jurisdiction', zone='na', jurisdiction='NA')
        self.call('node.register', id='E', kind='cpu', zone='eu', cpu=8, ready=0, healthy=True)
        self.call('node.register', id='N', kind='cpu', zone='na', cpu=32, ready=0, healthy=True)
        self.call('demand.forecast', app='A', version=1, peak=1, at=0)
        self.call('demand.commit', id='dA', app='A', start=10, end=40, minimum=1, burst=1, cpu=2)
        self.call('residency.dataset', id='X', source_party='h', jurisdiction='EU',
                  purposes=['*'], regions=['EU'])
        self.call('residency.bind_app', app='A', datasets=['X'])
        self.assertEqual(self.decide('capacity.place', demand='dA', node='E', replica=1), 'placed')
        self.assertEqual(self.decide('capacity.drain', id='E'), 'planned')
        blocked = self.call('residency.complete_drain_guarded', id='E', generation=1, success=True)
        self.assertEqual(blocked['decision'], 'migration_blocked')
        self.assertEqual(self.row("SELECT node FROM placements WHERE demand='dA' AND replica=1")['node'], 'E')


class DeliveredHistoryTests(ResidencyCase):
    def _deliver_old_report(self):
        self.seed_world()
        self.capture()
        self.call('residency.ingest_page', page='page-x')
        self.call('residency.plan', id='p-old', app='A', demand='dA', inputs=['X', 'Y'],
                  purpose='statistics', target_node='E', recipient_zone='NA', at=20)
        self.call('residency.plan_authorize', id='p-old', at=20)
        self.call('residency.run_start', plan='p-old', node='E', at=21)
        stat = self.eu_stat_artifact(plan='p-old', at=21)
        self.call('residency.run_finish', plan='p-old', at=22)
        return self.call('residency.deliver', id='deliv-old', plan='p-old',
                         artifacts=[stat['digest']], at=24)

    def test_old_delivery_keeps_license_basis_and_deletion_duty(self):
        delivered = self._deliver_old_report()
        self.assertEqual(delivered['decision'], 'delivered')
        basis = delivered['evidence']['basis']
        self.assertEqual(basis['licenses']['X']['version'], 1)
        self.assertEqual(delivered['evidence']['delete_by'], 124)

        lic_id = self.row("SELECT id FROM dr_licenses WHERE dataset='X' AND version=1")['id']
        self.assertEqual(self.decide('residency.license_revoke', id=lic_id, at=30), 'revoked')

        # Immutable old delivery still lawful=1 with the v1 basis.
        drow = self.row("SELECT * FROM dr_deliveries WHERE id='deliv-old'")
        self.assertEqual(drow['lawful'], 1)
        snap = json.loads(drow['license_snapshot'])
        self.assertEqual(snap['licenses']['X']['version'], 1)
        self.assertEqual(drow['deletion_status'], 'pending')

        # A new delivery under the same (now revoked) snapshot is refused.
        stat_digest = json.loads(self.row("SELECT artifacts FROM dr_deliveries WHERE id='deliv-old'")['artifacts'])[0]
        again = self.call('residency.deliver', id='deliv-new', plan='p-old',
                          artifacts=[stat_digest], at=31)
        self.assertEqual(again['decision'], 'restriction_conflict')

        # Fulfilling the deletion obligation updates the historical record.
        obl = self.row("SELECT id FROM dr_obligations WHERE kind='delivered_result_deletion' AND subject='deliv-old'")
        self.assertEqual(self.decide('residency.obligation_complete', obligation_id=obl['id'], at=40), 'deleted')
        self.assertEqual(self.row("SELECT deletion_status FROM dr_deliveries WHERE id='deliv-old'")['deletion_status'],
                         'deleted')

    def test_cancel_before_delivery_blocks_but_delivery_first_stands(self):
        self.seed_world()
        self.call('residency.plan', id='p-c', app='A', inputs=['X', 'Y'],
                  purpose='statistics', target_node='E', at=20)
        self.call('residency.plan_authorize', id='p-c', at=20)
        stat = self.call('residency.anonymize', datasets=['X'], input_digest='sha256:x',
                         transform='aggregate_statistics', spec={}, at=21)
        self.assertEqual(self.decide('residency.plan_cancel', id='p-c', at=22), 'cancelled')
        denied = self.call('residency.deliver', id='d-c', plan='p-c',
                           artifacts=[stat['digest']], at=23)
        self.assertEqual(denied['decision'], 'restriction_conflict')

        # Reverse order: lawful delivery commits first and cannot be undone.
        self.call('residency.plan', id='p-d', app='A', inputs=['X', 'Y'],
                  purpose='statistics', target_node='E', recipient_zone='NA', at=20)
        self.call('residency.plan_authorize', id='p-d', at=20)
        stat2 = self.call('residency.anonymize', datasets=['X'], input_digest='sha256:x2',
                          transform='aggregate_statistics', spec={}, at=21)
        ok = self.call('residency.deliver', id='d-d', plan='p-d',
                       artifacts=[stat2['digest']], at=24)
        self.assertEqual(ok['decision'], 'delivered')
        after = self.call('residency.plan_cancel', id='p-d', at=25)
        self.assertEqual(after['decision'], 'cancelled')
        self.assertEqual(self.row("SELECT state FROM dr_plans WHERE id='p-d'")['state'], 'delivered')
        self.assertEqual(self.row("SELECT lawful FROM dr_deliveries WHERE id='d-d'")['lawful'], 1)


class TwoRegionAndConcurrencyTests(ResidencyCase):
    def test_two_jurisdictions_request_raw_and_migration_simultaneously_on_paper(self):
        self.seed_world()
        eu = self.call('residency.raw_request', id='raw-eu', dataset='X', requester='E-site', node='E', at=15)
        na = self.call('residency.raw_request', id='raw-na', dataset='X', requester='N-site', node='N', at=15)
        self.assertEqual(eu['decision'], 'raw_granted')
        self.assertEqual(na['decision'], 'raw_denied')

        self.call('residency.plan', id='plan-eu-ask', app='A', inputs=['X'],
                  purpose='processing', target_node='E', at=16)
        self.call('residency.plan', id='plan-na-ask', app='A', inputs=['X'],
                  purpose='processing', target_node='N', at=16)
        self.assertEqual(self.decide('residency.plan_authorize', id='plan-eu-ask', at=16), 'authorized')
        self.assertEqual(self.decide('residency.plan_authorize', id='plan-na-ask', at=16), 'restriction_conflict')

    def test_concurrent_raw_requests_leak_no_unauthorised_grant(self):
        self.seed_world()
        n_each = 5
        barrier = threading.Barrier(n_each * 2)
        outcomes = []
        lock = threading.Lock()

        def worker(zone_node, i):
            barrier.wait()
            try:
                res = self.call('residency.raw_request', id='raw-%s-%d' % (zone_node, i),
                                dataset='X', node=zone_node, at=15)
                with lock:
                    outcomes.append((zone_node, res['decision']))
            except Exception as exc:  # pragma: no cover - failure signal
                with lock:
                    outcomes.append((zone_node, 'ERROR:' + repr(exc)))

        threads = []
        for i in range(n_each):
            threads.append(threading.Thread(target=worker, args=('E', i)))
            threads.append(threading.Thread(target=worker, args=('N', i)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(outcomes), n_each * 2)
        self.assertFalse(any(d.startswith('ERROR') for _, d in outcomes), outcomes)
        self.assertTrue(all(d == 'raw_granted' for z, d in outcomes if z == 'E'), outcomes)
        self.assertTrue(all(d == 'raw_denied' for z, d in outcomes if z == 'N'), outcomes)

    def test_concurrent_migration_plans_to_two_regions_move_no_unauthorised_bytes(self):
        self.seed_world()
        self.capture()
        n = 4
        barrier = threading.Barrier(n * 2)
        results = []
        lock = threading.Lock()

        def worker(dest, i):
            barrier.wait()
            try:
                res = self.call('residency.transfer', id='mv-%s-%d' % (dest, i),
                                dataset='X', digest='sha256:x', from_node='E',
                                to_node=dest, at=20)
                with lock:
                    results.append((dest, res['decision']))
            except Exception as exc:  # pragma: no cover
                with lock:
                    results.append((dest, 'ERROR:' + repr(exc)))

        threads = []
        for i in range(n):
            threads.append(threading.Thread(target=worker, args=('B', i)))
            threads.append(threading.Thread(target=worker, args=('N', i)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertFalse(any(d.startswith('ERROR') for _, d in results), results)
        # EU transfers are lawful; every NA migration is denied.
        self.assertTrue(all(d == 'transferred' for z, d in results if z == 'B'), results)
        self.assertTrue(all(d == 'cross_border_denied' for z, d in results if z == 'N'), results)
        self.assertEqual(self.rows(
            "SELECT COUNT(*) c FROM dr_copies WHERE jurisdiction='NA' AND dataset='X' AND lawful=1")[0]['c'], 0)

    def test_cancel_revoke_deliver_race_never_falsely_certifies(self):
        self.seed_world()
        n_trials = 6
        for i in range(n_trials):
            did = 'X%d' % i
            self.call('residency.dataset', id=did, source_party='h', jurisdiction='EU',
                      purposes=['statistics', 'processing', 'storage'],
                      deidentified_zones=['NA'])
            lic_id = self.row("SELECT id FROM dr_licenses WHERE dataset=?", (did,))['id']
            pid = 'race-%d' % i
            self.call('residency.plan', id=pid, app='A%d' % i, inputs=[did],
                      purpose='statistics', target_node='E', recipient_zone='NA', at=20)
            self.call('residency.plan_authorize', id=pid, at=20)
            art = self.call('residency.anonymize', datasets=[did],
                            input_digest='sha256:%d' % i,
                            transform='aggregate_statistics', spec={}, at=21)
            barrier = threading.Barrier(3)
            results = {}

            def deliver():
                barrier.wait()
                results['deliver'] = self.call(
                    'residency.deliver', id='race-d-%d' % i, plan=pid,
                    artifacts=[art['digest']], at=24)['decision']

            def cancel():
                barrier.wait()
                results['cancel'] = self.call('residency.plan_cancel', id=pid, at=22)['decision']

            def revoke():
                barrier.wait()
                results['revoke'] = self.call('residency.license_revoke', id=lic_id, at=22)['decision']

            ts = [threading.Thread(target=deliver), threading.Thread(target=cancel),
                  threading.Thread(target=revoke)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()

            drow = self.row("SELECT lawful FROM dr_deliveries WHERE id=?", ('race-d-%d' % i,))
            state = self.row("SELECT state FROM dr_plans WHERE id=?", (pid,))['state']
            if results['deliver'] == 'delivered':
                self.assertIsNotNone(drow)
                self.assertEqual(drow['lawful'], 1)
                self.assertEqual(state, 'delivered')
            else:
                self.assertIsNone(drow)
                self.assertIn(results['deliver'],
                              ('restriction_conflict', 'unlawful_copy_live'))


class RecoveryAndFacadeTests(ResidencyCase):
    def test_power_loss_reconciles_from_persisted_state(self):
        self.seed_world()
        self.capture()
        self.call('residency.ingest_page', page='page-x')
        self.call('residency.plan', id='p-pl', app='A', demand='dA', inputs=['X', 'Y'],
                  purpose='statistics', target_node='E', recipient_zone='NA', at=20)
        self.call('residency.plan_authorize', id='p-pl', at=20)
        self.call('residency.run_start', plan='p-pl', node='E', at=21)

        # Simulate control-plane loss: only the file survives; a fresh
        # transaction/process reconciles and safely finishes the plan.
        rec = dr.reconcile(self.db, {'plan': 'p-pl'})
        self.assertEqual(rec['decision'], 'reconciled')
        self.assertEqual(rec['evidence']['plans'][0]['safe_state'], 'running')

        stat = self.eu_stat_artifact(plan='p-pl', at=22)
        self.assertEqual(dr.finish_processing(self.db, {'plan': 'p-pl', 'at': 23})['decision'], 'completed')
        self.assertEqual(dr.deliver(self.db, {'id': 'd-pl', 'plan': 'p-pl',
                                              'artifacts': [stat['digest']], 'at': 24})['decision'],
                         'delivered')

    def test_reconcile_flags_plan_halted_after_revocation_horizon(self):
        self.seed_world()
        self.call('residency.plan', id='p-h', app='A', inputs=['X', 'Y'],
                  purpose='statistics', target_node='E', at=20)
        self.call('residency.plan_authorize', id='p-h', at=20)
        lic_id = self.row("SELECT id FROM dr_licenses WHERE dataset='X' AND version=1")['id']
        self.call('residency.license_revoke', id=lic_id, at=22)
        rec = self.call('residency.reconcile', plan='p-h', at=100)
        self.assertEqual(rec['decision'], 'reconciled')
        self.assertEqual(rec['evidence']['plans'][0]['safe_state'], 'halted')

    def test_path_facade_and_dynamic_imports_and_unknown_action(self):
        engine = dr.Residency(self.db)
        out = engine.execute({'action': 'residency.dataset', 'id': 'Z',
                              'source_party': 's', 'jurisdiction': 'EU'})
        self.assertEqual(out['decision'], 'registered')
        # Dynamic attribute compatibility maps nearby vocabulary to ops.
        fn = getattr(dr, 'grant_data_license')
        self.assertTrue(callable(fn))
        with self.assertRaises(ValueError):
            execute(self.db, {'action': 'totally.unknown'})

    def test_cli_data_subsystem_runs_fixture(self):
        import subprocess
        import sys
        import os
        fixture = Path(self.tmp.name) / 'fixture.json'
        fixture.write_text(json.dumps([
            {'action': 'residency.jurisdiction', 'zone': 'eu', 'jurisdiction': 'EU'},
            {'action': 'residency.dataset', 'id': 'X', 'source_party': 'h', 'jurisdiction': 'EU'},
        ]), encoding='utf-8')
        env = dict(os.environ, PYTHONPATH='/workspace')
        proc = subprocess.run(
            [sys.executable, '-B', '-m', 'cloudctl', 'data',
             '--db', self.db, '--fixture', str(fixture)],
            cwd='/workspace', capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [json.loads(x) for x in proc.stdout.strip().splitlines()]
        self.assertEqual([x['decision'] for x in lines], ['registered', 'registered'])


if __name__ == '__main__':
    unittest.main()
