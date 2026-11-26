"""Emergency isolation: rule shadowing, old-connection re-authorization,
the two pre-approved safe handlings, certificate replay and durable audit.

Fixed incident:

* r1 from minute 10 allows 10.0.0.0/24 -> 443 (priority 10);
* at minute 20 the isolation lead signs r2 denying writes from
  10.0.0.128/25 (printed page priority 20);
* customer A is 10.0.0.5, customer B is 10.0.0.200, same network domain;
* cB was established minute 18 under r1 and sends its next write minute 21.

Run:  python -B -m unittest discover -s tests -q
"""
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloudctl import policy_capture as pc
from cloudctl import packet_gate as pg

DOMAIN = 'prod-dc1'
DIGEST_B21 = 'sha256:content-b-seq-21-harmless'


def r1_row(**over):
    row = {'rule_id': 'r1', 'priority': 10, 'src_prefix': '10.0.0.0/24',
           'dst_port': 443, 'action': 'allow', 'issuer': 'netops',
           'domain': DOMAIN, 'effective_at': 10, 'scope': 'new_and_established'}
    row.update(over)
    return row


def r2_row(**over):
    row = {'rule_id': 'r2', 'priority': 20, 'src_prefix': '10.0.0.128/25',
           'dst_port': 443, 'action': 'deny', 'issuer': 'isolation-lead',
           'domain': DOMAIN, 'effective_at': 20, 'authorized': True,
           'signed_at': 20, 'scope': 'write',
           'raw': b'EMERGENCY ISOLATION ORDER r2 10.0.0.128/25 write deny'}
    row.update(over)
    return row


class EmergencyFirewallTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        pc.ensure_schema(self.db)
        pg.ensure_schema(self.db)

    # -- helpers --------------------------------------------------------
    def seed_rules(self, r2_received=20):
        pc.import_page(self.db, 'page-r1', [r1_row()], 10)
        pc.import_page(self.db, 'page-r2', [r2_row()], r2_received)

    def establish_cb(self, seq=7):
        return pg.open_session(self.db, 'cB', '10.0.0.200', 443, at=18,
                               domain=DOMAIN, seq=seq,
                               raw=b'SYN/ACK session original cB')

    # -- page intake: extended fields, replay / conflict ----------------
    def test_01_extended_page_captures_all_original_evidence(self):
        res = pc.import_page(self.db, 'p1', [r1_row(raw=b'R1-RAW')], 11,
                             raw=b'PAGE-BYTES')
        self.assertEqual(res['status'], 'captured')
        row = self.db.execute(
            'SELECT issuer,domain,effective_at,raw_sha256,scope FROM policy_rows'
        ).fetchone()
        self.assertEqual(row[0], 'netops')
        self.assertEqual(row[1], DOMAIN)
        self.assertEqual(row[2], 10)
        self.assertIsNotNone(row[3])
        self.assertEqual(row[4], 'new_and_established')
        page = self.db.execute(
            'SELECT raw_sha256,generation FROM policy_pages WHERE id=?',
            ('p1',)).fetchone()
        self.assertIsNotNone(page[0])
        self.assertEqual(page[1], 1)

    def test_02_same_page_replay_and_changed_content_conflict(self):
        rows = [r1_row()]
        self.assertEqual(pc.import_page(self.db, 'f1', rows, 11)['status'],
                         'captured')
        self.assertEqual(pc.import_page(self.db, 'f1', rows, 11)['status'],
                         'replayed')
        with self.assertRaises(ValueError) as ctx:
            pc.import_page(self.db, 'f1', [r1_row(action='deny')], 11)
        self.assertEqual(str(ctx.exception), 'policy_page_conflict')
        # Changing issuer / raw bytes is also different complete originals.
        pc.import_page(self.db, 'f2', [r2_row()], 20)
        with self.assertRaises(ValueError):
            pc.import_page(self.db, 'f2', [r2_row(issuer='someone-else')], 21)

    # -- rule shadowing -------------------------------------------------
    def test_03_specific_emergency_deny_shadows_broad_allow(self):
        self.seed_rules()
        b = pg.decide(self.db, 'pB', '10.0.0.200', 443, at=21, domain=DOMAIN)
        a = pg.decide(self.db, 'pA', '10.0.0.5', 443, at=21, domain=DOMAIN)
        self.assertEqual(b['action'], 'deny')
        self.assertEqual(b['rule_id'], 'r2')
        self.assertEqual(a['action'], 'allow')
        self.assertEqual(a['rule_id'], 'r1')
        # .20 is inside /24 but outside 10.0.0.128/25: still allowed by r1.
        low = pg.decide(self.db, 'pLow', '10.0.0.20', 443, at=21,
                        domain=DOMAIN)
        self.assertEqual(low['action'], 'allow')
        self.assertEqual(low['rule_id'], 'r1')
        # Addresses outside /24 get the implicit default deny.
        outside = pg.decide(self.db, 'pOut', '10.0.9.9', 443, at=21,
                            domain=DOMAIN)
        self.assertEqual(outside['action'], 'deny')

    def test_04_shadowing_does_not_depend_on_import_or_line_order(self):
        # r2 imported first, r1 second: same overlap outcome.
        db = sqlite3.connect(':memory:')
        pc.import_page(db, 'r2-first', [r2_row()], 20)
        pc.import_page(db, 'r1-later', [r1_row()], 21)
        self.assertEqual(pg.decide(db, 'b', '10.0.0.200', 443, at=21,
                                   domain=DOMAIN)['rule_id'], 'r2')
        self.assertEqual(pg.decide(db, 'a', '10.0.0.5', 443, at=21,
                                   domain=DOMAIN)['action'], 'allow')
        # Both rules on one page with r2 printed first / higher line no.
        db2 = sqlite3.connect(':memory:')
        pc.import_page(db2, 'one-page', [r2_row(), r1_row()], 21)
        self.assertEqual(pg.decide(db2, 'b2', '10.0.0.200', 443, at=21,
                                   domain=DOMAIN)['rule_id'], 'r2')

    def test_05_broad_decoy_deny_cannot_block_customer_a(self):
        self.seed_rules()
        pc.import_page(self.db, 'decoy', [{
            'rule_id': 'r9', 'priority': 1, 'src_prefix': '0.0.0.0/0',
            'dst_port': 443, 'action': 'deny', 'domain': DOMAIN}], 21)
        a = pg.decide(self.db, 'pA2', '10.0.0.5', 443, at=22, domain=DOMAIN)
        self.assertEqual(a['action'], 'allow')
        self.assertEqual(a['rule_id'], 'r1')

    def test_06_domain_separation_is_enforced(self):
        self.seed_rules()
        other = pg.decide(self.db, 'pOth', '10.0.0.5', 443, at=21,
                         domain='management-vlan')
        self.assertEqual(other['action'], 'deny')

    # -- established session + generation switch ------------------------
    def test_07_session_binds_establishment_rule_r1(self):
        pc.import_page(self.db, 'page-r1', [r1_row()], 10)
        res = self.establish_cb()
        self.assertEqual(res['status'], 'established')
        self.assertEqual(res['rule_id'], 'r1')
        row = self.db.execute(
            'SELECT rule_id,generation,status FROM sessions WHERE session_id=?',
            ('cB',)).fetchone()
        self.assertEqual(row[0], 'r1')
        self.assertEqual(row[2], 'open')

    def test_08_old_connection_next_packet_must_reauthorize(self):
        pc.import_page(self.db, 'page-r1', [r1_row()], 10)
        self.establish_cb()
        first = pg.fast_decide(self.db, 'b-19', '10.0.0.200', 443,
                               session_id='cB', seq=8, at=19, domain=DOMAIN)
        self.assertEqual(first['action'], 'allow')
        # Same generation: fast path genuinely reuses its cached allow.
        second = pg.fast_decide(self.db, 'b-19b', '10.0.0.200', 443,
                                session_id='cB', seq=9, at=19, domain=DOMAIN)
        self.assertTrue(second['cache_hit'])
        self.assertEqual(second['action'], 'allow')
        # Emergency page lands: generation switches.
        pc.import_page(self.db, 'page-r2', [r2_row()], 20)
        nxt = pg.fast_decide(self.db, 'b-21', '10.0.0.200', 443,
                             session_id='cB', seq=10, at=21, domain=DOMAIN)
        self.assertEqual(nxt['action'], 'deny')
        self.assertEqual(nxt['rule_id'], 'r2')
        self.assertFalse(nxt['cache_hit'])
        self.assertTrue(nxt['session_stale'])
        # Even a poisoned stale-generation allow cannot bypass isolation.
        for key, ent in list(pg._cache.items()):
            if key[2] == 'cB':
                ent['gen'] = 1
                ent['action'] = 'allow'
        poisoned = pg.fast_decide(self.db, 'b-21b', '10.0.0.200', 443,
                                  session_id='cB', seq=11, at=21,
                                  domain=DOMAIN)
        self.assertEqual(poisoned['action'], 'deny')
        # The ordinary decide path agrees.
        ordinary = pg.decide(self.db, 'b-21c', '10.0.0.200', 443,
                             session_id='cB', seq=12, at=21, domain=DOMAIN)
        self.assertEqual(ordinary['action'], 'deny')

    def test_09_customer_a_keeps_working_throughout(self):
        self.seed_rules()
        pg.open_session(self.db, 'cA', '10.0.0.5', 443, at=12, domain=DOMAIN)
        for minute in (20, 21, 22, 23):
            res = pg.decide(self.db, 'a-%d' % minute, '10.0.0.5', 443,
                            session_id='cA', seq=minute, at=minute,
                            domain=DOMAIN)
            self.assertEqual(res['action'], 'allow', minute)
            self.assertEqual(res['rule_id'], 'r1', minute)

    # -- handling 1: terminate cB ---------------------------------------
    def test_10_shift_one_termination_stops_b_and_keeps_a(self):
        self.seed_rules()
        self.establish_cb()
        term = pg.terminate_session(self.db, 'cB', at=20,
                                   reason='emergency_isolation_order')
        self.assertEqual(term['status'], 'terminated')
        for seq, minute in ((20, 20), (21, 21), (22, 22)):
            res = pg.decide(self.db, 'kill-%d' % seq, '10.0.0.200', 443,
                            session_id='cB', seq=seq, at=minute, domain=DOMAIN)
            self.assertEqual(res['action'], 'deny')
            self.assertEqual(res['reason'], 'session_terminated')
        # A is untouched.
        self.assertEqual(pg.decide(self.db, 'a21', '10.0.0.5', 443, at=21,
                                  domain=DOMAIN)['action'], 'allow')
        # Terminated session is archived.
        archived = pg.terminated(self.db)
        self.assertEqual([t['session_id'] for t in archived], ['cB'])
        # No B allow exists at/after minute 20 in the durable decision table.
        rows = self.db.execute(
            "SELECT action FROM packet_decisions WHERE session_id='cB' "
            "AND at_minute>=20").fetchall()
        self.assertTrue(rows)
        self.assertTrue(all(r[0] == 'deny' for r in rows))

    # -- handling 2: independent inspection exception --------------------
    def _issue_b21_cert(self, **over):
        cert = {'cert_id': 'cert-b21', 'session_id': 'cB', 'seq': 210,
                'content_digest': DIGEST_B21, 'domain': DOMAIN,
                'inspector': 'inspector-wang', 'issued_at': 21}
        cert.update(over)
        return pc.import_certificate(self.db, cert.pop('cert_id'), cert)

    def test_11_shift_two_cert_clears_only_bound_packet(self):
        self.seed_rules()
        self.establish_cb()
        self._issue_b21_cert()
        allowed = pg.decide(self.db, 'b-21', '10.0.0.200', 443,
                            session_id='cB', seq=210, at=21, domain=DOMAIN,
                            content_digest=DIGEST_B21)
        self.assertEqual(allowed['action'], 'allow')
        # Exception is bound on top of the *new* rule r2 / generation 2.
        self.assertEqual(allowed['rule_id'], 'r2')
        self.assertEqual(allowed['certificate_id'], 'cert-b21')
        self.assertEqual(allowed['generation'], 2)
        binding = self.db.execute(
            'SELECT rule_id,generation,packet_id FROM cert_bindings '
            'WHERE cert_id=?', ('cert-b21',)).fetchone()
        self.assertEqual(binding[0], 'r2')
        self.assertEqual(binding[1], 2)
        self.assertEqual(binding[2], 'b-21')
        # Next write has no fresh certificate -> denied again.
        nxt = pg.decide(self.db, 'b-22', '10.0.0.200', 443,
                        session_id='cB', seq=211, at=22, domain=DOMAIN,
                        content_digest='sha256:next')
        self.assertEqual(nxt['action'], 'deny')
        # Inspection capacity / latency is accounted exactly once.
        usage = pg.inspection_usage(self.db)
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0]['cert_id'], 'cert-b21')
        self.assertEqual(usage[0]['latency'], 0)

    def test_12_cert_must_match_content_digest(self):
        self.seed_rules()
        self.establish_cb()
        self._issue_b21_cert()
        bad = pg.decide(self.db, 'b-bad', '10.0.0.200', 443,
                        session_id='cB', seq=210, at=21, domain=DOMAIN,
                        content_digest='sha256:tampered')
        self.assertEqual(bad['action'], 'deny')
        self.assertIn(bad['reason'],
                      ('content_digest_mismatch', 'certificate_unavailable'))

    def test_13_cert_must_match_domain(self):
        self.seed_rules()
        self.establish_cb()
        self._issue_b21_cert()
        bad = pg.decide(self.db, 'b-dom', '10.0.0.200', 443,
                        session_id='cB', seq=210, at=21,
                        domain='staging', content_digest=DIGEST_B21)
        self.assertEqual(bad['action'], 'deny')

    def test_14_late_certificate_cannot_backdate_earlier_packet(self):
        self.seed_rules()
        self.establish_cb()
        # Signed at minute 22, attempted on the minute-21 packet.
        self._issue_b21_cert(issued_at=22, valid_from=22)
        late = pg.decide(self.db, 'b-late', '10.0.0.200', 443,
                         session_id='cB', seq=210, at=21, domain=DOMAIN,
                         content_digest=DIGEST_B21)
        self.assertEqual(late['action'], 'deny')

    def test_15_expired_certificate_does_not_clear(self):
        self.seed_rules()
        self.establish_cb()
        self._issue_b21_cert(issued_at=21, valid_from=21, valid_to=25)
        ok = pg.decide(self.db, 'b-25', '10.0.0.200', 443,
                       session_id='cB', seq=210, at=25, domain=DOMAIN,
                       content_digest=DIGEST_B21)
        self.assertEqual(ok['action'], 'allow')  # boundary valid
        expired = pg.decide(self.db, 'b-26', '10.0.0.200', 443,
                            session_id='cB', seq=212, at=26, domain=DOMAIN,
                            content_digest=DIGEST_B21)
        # seq differs -> no cert anyway; re-use same seq after expiry:
        expired_same = pg.decide(self.db, 'b-26b', '10.0.0.200', 443,
                                session_id='cB', seq=210, at=26,
                                domain=DOMAIN, content_digest=DIGEST_B21)
        self.assertEqual(expired['action'], 'deny')
        self.assertEqual(expired_same['action'], 'deny')

    # -- certificate replay / transfer / duplicate sequence --------------
    def test_16_certificate_replay_cannot_clear_second_packet(self):
        self.seed_rules()
        self.establish_cb()
        self._issue_b21_cert()
        first = pg.decide(self.db, 'b-first', '10.0.0.200', 443,
                          session_id='cB', seq=210, at=21, domain=DOMAIN,
                          content_digest=DIGEST_B21)
        self.assertEqual(first['action'], 'allow')
        # Re-importing the same certificate original is an idempotent replay.
        again = self._issue_b21_cert()
        self.assertEqual(again['status'], 'replayed')
        # Presenting it for another packet (even same sequence) is rejected.
        replay = pg.decide(self.db, 'b-replay', '10.0.0.200', 443,
                           session_id='cB', seq=210, at=21, domain=DOMAIN,
                           content_digest=DIGEST_B21)
        self.assertEqual(replay['action'], 'deny')
        self.assertEqual(replay['reason'],
                         'certificate_replay_to_other_packet')
        # Same certificate on the original packet id stays idempotently allowed.
        same = pg.decide(self.db, 'b-first', '10.0.0.200', 443,
                         session_id='cB', seq=210, at=21, domain=DOMAIN,
                         content_digest=DIGEST_B21)
        self.assertEqual(same['action'], 'allow')
        # Inspection capacity was occupied once, not once per re-decision.
        self.assertEqual(len(pg.inspection_usage(self.db)), 1)

    def test_17_good_result_for_another_session_is_not_transferable(self):
        self.seed_rules()
        self.establish_cb()
        pg.open_session(self.db, 'cC', '10.0.0.201', 443, at=18,
                        domain=DOMAIN)
        self._issue_b21_cert()
        stolen = pg.decide(self.db, 'cC-1', '10.0.0.201', 443,
                           session_id='cC', seq=210, at=21, domain=DOMAIN,
                           content_digest=DIGEST_B21)
        self.assertEqual(stolen['action'], 'deny')

    def test_18_certificate_for_other_sequence_does_not_fit(self):
        self.seed_rules()
        self.establish_cb()
        self._issue_b21_cert()
        other_seq = pg.decide(self.db, 'b-other-seq', '10.0.0.200', 443,
                              session_id='cB', seq=999, at=21, domain=DOMAIN,
                              content_digest=DIGEST_B21)
        self.assertEqual(other_seq['action'], 'deny')

    # -- late r2 page: history survives ----------------------------------
    def test_19_late_r2_page_keeps_old_allow_and_remediation(self):
        pc.import_page(self.db, 'page-r1', [r1_row()], 10)
        self.establish_cb()
        old = pg.decide(self.db, 'b-old', '10.0.0.200', 443,
                        session_id='cB', seq=5, at=19, domain=DOMAIN)
        self.assertEqual(old['action'], 'allow')
        self.assertEqual(old['rule_id'], 'r1')
        # r2 signing page only physically arrives after the old allow ran.
        pc.import_page(self.db, 'page-r2-late', [r2_row()], 22)
        pg.terminate_session(self.db, 'cB', at=22, reason='late_isolation')
        remedy = pg.decide(self.db, 'b-remedy', '10.0.0.200', 443,
                           session_id='cB', seq=6, at=22, domain=DOMAIN)
        self.assertEqual(remedy['action'], 'deny')
        # The executed r1 allow is still in the decision table and timeline.
        row = self.db.execute(
            'SELECT action,rule_id,generation FROM packet_decisions '
            'WHERE packet_id=?', ('b-old',)).fetchone()
        self.assertEqual((row[0], row[1]), ('allow', 'r1'))
        kinds = [(e['action'], e['reason']) for e in
                 pg.history(self.db, session_id='cB')]
        self.assertIn(('allow', 'rule_allow'), kinds)
        self.assertTrue(any(reason == 'session_terminated'
                            for _, reason in kinds))
        explained = pg.explain(self.db, 'b-old')
        self.assertEqual(explained['action'], 'allow')
        self.assertEqual(explained['rule_ref']['page_id'], 'page-r1')

    # -- persistence / power loss ---------------------------------------
    def test_20_reopened_database_explains_every_packet(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, 'fw.sqlite')
        db = sqlite3.connect(path)
        pc.import_page(db, 'page-r1', [r1_row()], 10)
        pc.import_page(db, 'page-r2', [r2_row()], 20)
        pg.open_session(db, 'cB', '10.0.0.200', 443, at=18, domain=DOMAIN)
        pc.import_certificate(db, 'cert-b21', {
            'session_id': 'cB', 'seq': 210, 'content_digest': DIGEST_B21,
            'domain': DOMAIN, 'inspector': 'inspector-wang', 'issued_at': 21})
        allowed = pg.decide(db, 'b-21', '10.0.0.200', 443, session_id='cB',
                            seq=210, at=21, domain=DOMAIN,
                            content_digest=DIGEST_B21)
        self.assertEqual(allowed['action'], 'allow')
        pg.terminate_session  # no-op reference keeps import meaningful
        db.commit()
        db.close()

        reopened = sqlite3.connect(path)
        # Rule shadowing still resolved from durable pages.
        self.assertEqual(pg.decide(reopened, 'a21', '10.0.0.5', 443, at=21,
                                   domain=DOMAIN)['action'], 'allow')
        # Spent certificate cannot be replayed after power loss.
        replay = pg.decide(reopened, 'b-replay', '10.0.0.200', 443,
                           session_id='cB', seq=210, at=21, domain=DOMAIN,
                           content_digest=DIGEST_B21)
        self.assertEqual(replay['action'], 'deny')
        info = pg.explain(reopened, 'b-21')
        self.assertEqual(info['action'], 'allow')
        self.assertEqual(info['certificate_id'], 'cert-b21')
        self.assertEqual(info['rule_ref']['page_id'], 'page-r2')
        self.assertEqual(info['rule_ref']['rule_id'], 'r2')
        self.assertTrue(info['events'])
        reopened.close()

    # -- two filtering agents / propagation ------------------------------
    def test_21_certificate_on_one_agent_is_not_cluster_wide_pass(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, 'agents.sqlite')
        a = sqlite3.connect(path)
        b = sqlite3.connect(path)
        pc.ensure_schema(a)
        pg.register_agent(a, 'filter-a')
        pg.register_agent(b, 'filter-b')
        pc.import_certificate(a, 'cert-x', session_id='cB', seq=1,
                              content_digest='d', domain=DOMAIN,
                              inspector='i', issued_at=21)
        pg.agent_ack(a, 'filter-a', cert_id='cert-x', at=21)
        # b has not acknowledged it yet.
        self.assertFalse(pg.certificate_propagated(b, 'cert-x'))
        pg.agent_ack(b, 'filter-b', cert_id='cert-x', at=21)
        self.assertTrue(pg.certificate_propagated(b, 'cert-x'))
        a.close()
        b.close()

    # -- compatibility facade -------------------------------------------
    def test_22_common_alternative_api_names_are_callable(self):
        self.assertTrue(callable(pc.capture_session))
        self.assertTrue(callable(pc.record_inspection))
        self.assertTrue(callable(pg.establish_session))
        self.assertTrue(callable(pg.kill_session))
        self.assertTrue(callable(pg.fast_decide))
        gate = pg.Gate(self.db)
        self.assertEqual(gate.decide('z', '10.0.0.5', 443)['action'], 'deny')

    # -- adversarial binding / inspector / method checks ------------------
    def test_23_untrusted_or_missing_inspector_cannot_clear(self):
        self.seed_rules()
        self.establish_cb()
        pc.import_certificate(self.db, 'rogue', session_id='cB', seq=210,
                              content_digest=DIGEST_B21, domain=DOMAIN,
                              inspector='mallory', issued_at=21)
        pc.register_inspector(self.db, 'mallory', trusted=0, independent=0)
        bad = pg.decide(self.db, 'b-r', '10.0.0.200', 443, session_id='cB',
                        seq=210, at=21, domain=DOMAIN,
                        content_digest=DIGEST_B21)
        self.assertEqual(bad['action'], 'deny')
        self.assertEqual(bad['reason'], 'inspector_not_trusted')

    def test_24_wrong_bound_values_rejected_but_omitted_context_tolerated(self):
        self.seed_rules()
        self.establish_cb()
        self._issue_b21_cert()
        # A wrong domain is rejected even with the correct digest.
        wrong_domain = pg.decide(self.db, 'b-wd2', '10.0.0.200', 443,
                                 session_id='cB', seq=210, at=21,
                                 domain='other-domain',
                                 content_digest=DIGEST_B21)
        self.assertEqual(wrong_domain['action'], 'deny')
        self.assertEqual(wrong_domain['reason'], 'domain_mismatch')
        # A separate certificate proves omitted optional context is tolerated
        # (compatibility), while sequence binding still applies.
        pc.import_certificate(self.db, 'cert-300', session_id='cB', seq=300,
                              content_digest='H300', domain=DOMAIN,
                              inspector='inspector-wang', issued_at=21)
        omitted = pg.decide(self.db, 'b-300', '10.0.0.200', 443,
                            session_id='cB', seq=300, at=21)
        self.assertEqual(omitted['action'], 'allow')

    def test_25_write_scope_matches_verbs_but_not_reads(self):
        db = sqlite3.connect(':memory:')
        pc.import_page(db, 'p', [
            r1_row(), r2_row()], 20)
        # Explicit write verb is denied by the write-scoped r2.
        post = pg.decide(db, 'post', '10.0.0.200', 443, at=21,
                         domain=DOMAIN, method='POST')
        self.assertEqual(post['action'], 'deny')
        self.assertEqual(post['rule_id'], 'r2')
        # A read verb does not match the write-scoped r2 and falls through r1.
        get = pg.decide(db, 'get', '10.0.0.200', 443, at=21,
                        domain=DOMAIN, method='GET')
        self.assertEqual(get['action'], 'allow')
        self.assertEqual(get['rule_id'], 'r1')

    def test_26_predicates_return_plain_booleans(self):
        self.seed_rules()
        pg.open_session(self.db, 'cB', '10.0.0.200', 443, at=18, domain=DOMAIN)
        self.assertFalse(pg.is_session_terminated(self.db, 'cB'))
        pg.terminate_session(self.db, 'cB', at=20)
        self.assertIs(pg.is_session_terminated(self.db, 'cB'), True)
        self.assertIsInstance(pg.is_session_terminated(self.db, 'cB'), bool)
        denied = pg.decide(self.db, 'z', '10.0.0.200', 443, at=21)
        self.assertFalse(pg.is_allowed(denied))

    def test_27_tuple_page_and_data_kwarg_submit_do_not_crash(self):
        res = pc.import_page(self.db, 't', (r1_row(),), 10)
        self.assertEqual(res['status'], 'captured')
        out = pg.submit_certificate(self.db, data={
            'cert_id': 'c', 'session_id': 's', 'seq': 1,
            'content_digest': 'h', 'inspector': 'i', 'issued_at': 21})
        self.assertIn(out['status'], ('captured', 'replayed'))


def _has_column(db, table, column):
    return column in {r[1] for r in db.execute(
        'PRAGMA table_info(%s)' % table).fetchall()}


if __name__ == '__main__':
    unittest.main()
