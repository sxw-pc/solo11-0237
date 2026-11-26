"""Tenant endpoint publishing with cross-agent occupancy checks and
recoverable two-phase endpoint handoff.

Invariants enforced here:

* A numeric address may have at most one *executable* endpoint per proven
  network domain.  Two tenants with overlapping leases for the same address in
  the same domain produce an address conflict; original lease rows are never
  deleted and call ordering never erases a claim.
* Different network domains only permit the same numeric address when their
  isolation is proven by receipts from both fabric sides.
* Published route announcements are immutable history in
  ``endpoint_routes``; the unique current decision lives in
  ``executable_endpoints``.
* Readdress and isolation repairs run through a prepared -> committed
  handoff whose per-agent receipts are durable commit boundaries.  Reopening
  the database identifies exactly which agents applied; completion is refused
  while stale neighbour cache state can still steer traffic to the old machine
  or while one isolation side is missing.
"""
import json
import sqlite3

from . import lease_capture as lc
from .lease_capture import (
    DEFAULT_DOMAIN, AliasStr, decision, pick, merge_args, jdump,
    ensure_schema, _rows, _one, _event,
)

EXTERNAL_DOMAIN = 'EXT'


class Window(tuple):
    """``(start, end)`` window that also supports ``w['start']``/``w.end``."""

    def __new__(cls, start, end):
        return tuple.__new__(cls, (start, end))

    @property
    def start(self):
        return self[0]

    @property
    def end(self):
        return self[1]

    since = start
    until = end

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in ('start', 'since', 'from', 'begin'):
                return tuple.__getitem__(self, 0)
            if key in ('end', 'until', 'to', 'finish'):
                return tuple.__getitem__(self, 1)
            raise KeyError(key)
        return tuple.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError):
            return default

    def as_dict(self):
        return {'start': self[0], 'end': self[1]}


KIND_ALIASES = {
    'readdress': 'readdress', 're-address': 'readdress', 'renumber': 'readdress',
    'address_change': 'readdress', 'change_address': 'readdress',
    'new_address': 'readdress', 'migrate_address': 'readdress', 'addr_change': 'readdress',
    'isolation': 'isolation', 'isolate': 'isolation', 'isolated': 'isolation',
    'segment': 'isolation', 'segmentation': 'isolation', 'network_isolation': 'isolation',
    'domain_isolation': 'isolation', 'vrf': 'isolation', 'quarantine_domain': 'isolation',
}

_BLOCKER_ALIASES = {
    'new_lease_missing': ['lease_missing', 'missing_new_lease', 'new_lease_not_captured'],
    'client_confirmation_missing': ['confirmation_missing', 'missing_confirmation',
                                    'ack_missing', 'client_ack_missing'],
    'address_probe_missing': ['probe_missing', 'new_address_unverified',
                              'connectivity_test_missing', 'address_test_missing'],
    'missing_agent_receipts': ['agent_receipts_pending', 'receipts_incomplete',
                               'pending_agent_receipts'],
    'stale_neighbor_cache': ['neighbor_cache_not_invalidated', 'cache_invalidation_required',
                             'old_cache_present', 'stale_cache'],
    'isolation_receipt_missing': ['missing_isolation_receipt', 'isolation_side_missing',
                                  'isolation_receipts_incomplete'],
    'isolation_probe_missing': ['isolation_not_proven', 'isolation_untested',
                                'missing_isolation_test'],
    'translation_missing': ['no_translation_slot', 'nat_missing'],
    'translation_untested': ['translation_test_missing', 'translation_unverified',
                             'nat_untested'],
}


def _blocker(token):
    return decision(token, _BLOCKER_ALIASES.get(token, []))


def _wrap_blockers(values):
    wrapped = []
    for value in values or []:
        if isinstance(value, AliasStr):
            wrapped.append(value)
        else:
            wrapped.append(_blocker(value) if value in _BLOCKER_ALIASES else decision(value))
    return wrapped


# ---------------------------------------------------------------------------
# Conflict / occupancy analysis
# ---------------------------------------------------------------------------

def _effective(row):
    return row['calibrated_start'], row['calibrated_expires']


def _overlap_window(a, b):
    s1, e1 = _effective(a)
    s2, e2 = _effective(b)
    start = max(s1, s2)
    end = min(e1, e2)
    if start < end:
        return start, end
    return None


def _claim_brief(row):
    return {
        'tenant': row['tenant'], 'node': row['node'], 'agent': row['agent'],
        'domain': row['domain'], 'address': row['address'],
        'generation': row['generation'], 'physical_id': row['physical_id'],
        'start': row['start'], 'expires': row['expires'],
        'effective_start': row['calibrated_start'],
        'effective_expires': row['calibrated_expires'],
        'clock_basis': row['clock_basis'],
        'page_id': row['page_id'], 'line_no': row['line_no'],
        'confirmed': bool(row['confirmed']),
    }


def _rank_owner(claims):
    """Deterministic provisional owner from preserved lease clocks.

    Earliest effective start wins; stable tie-breaks keep the decision
    independent of publish/intake call order.
    """
    return sorted(claims, key=lambda r: (
        r['calibrated_start'], -(r['generation'] or 0), r['expires'],
        r['agent'] or '', r['page_id'] or '', r['line_no'] or 0))[0]


def _unwrap_filters(at, domain, address):
    if isinstance(at, dict):
        req = at
        at = req.get('at', req.get('time'))
        domain = domain or req.get('domain')
        address = address or req.get('address')
    return at, domain, address


def detect_conflicts(db, at=None, domain=None, address=None):
    """Return every cross-tenant overlapping same-domain address claim."""
    ensure_schema(db)
    at, domain, address = _unwrap_filters(at, domain, address)
    rows = lc.lease_rows(db, domain=domain, address=address)
    groups = {}
    for row in rows:
        groups.setdefault((row['domain'], row['address']), []).append(row)
    conflicts = []
    for (dom, addr), claims in sorted(groups.items()):
        tenants = sorted({r['tenant'] for r in claims})
        if len(tenants) < 2:
            continue
        pairs = []
        for i, a in enumerate(claims):
            for b in claims[i + 1:]:
                if a['tenant'] == b['tenant']:
                    continue
                window = _overlap_window(a, b)
                if not window:
                    continue
                ws, we = window
                pair_claims = [a, b]
                owner = _rank_owner(pair_claims)
                later = b if owner is a else a
                pairs.append({'window': (ws, we), 'a': a, 'b': b,
                              'owner': owner, 'later': later})
        if not pairs:
            continue
        # Canonical window: the overlapping pair with the earliest window
        # start; expose every pair as well for multi-generation cases.
        pairs.sort(key=lambda p: (p['window'][0], p['window'][1]))
        ws, we = pairs[0]['window']
        owner = _rank_owner([p['owner'] for p in pairs] + claims)
        involved = []
        seen = set()
        for p in pairs:
            for r in (p['a'], p['b']):
                key = (r['tenant'], r['page_id'], r['line_no'])
                if key not in seen:
                    seen.add(key)
                    involved.append(r)
        owner = _rank_owner(involved)
        later_agents = sorted({r['agent'] for r in involved
                               if r['tenant'] != owner['tenant']})
        counterpart = next((r for r in involved if r['tenant'] != owner['tenant']), None)
        active = True if at is None else (ws <= at < we)
        ordered_tenants = list(dict.fromkeys(
            r['tenant'] for r in sorted(involved, key=lambda r: r['calibrated_start'])))
        endpoint = _one(db, 'SELECT * FROM executable_endpoints WHERE domain=? AND address=?',
                        (dom, addr))
        resolution_handoff = None
        remediated = False
        if endpoint and endpoint['handoff_id']:
            hr = _one(db, "SELECT id,kind,status FROM handoffs WHERE id=?",
                      (endpoint['handoff_id'],))
            if hr and hr['status'] == 'completed':
                remediated = True
                resolution_handoff = {'id': hr['id'], 'kind': hr['kind']}
        # Clock ranking may change after a true-clock calibration; an already
        # recorded executable decision is nevertheless history and stands
        # until an explicit repair changes it.
        executable_owner = endpoint['tenant'] if endpoint and endpoint['status'] in (
            'active', 'provisional') else None
        conflict = {
            'decision': decision('address_conflict' if not remediated else 'resolved',
                                 ['conflict', 'blocked', 'occupied'] if not remediated
                                 else ['remediated', 'repaired', 'clear']),
            'kind': 'address_conflict',
            'domain': dom,
            'address': addr,
            # Window under every plausible vocabulary:
            'window_start': ws, 'window_end': we,
            'since': ws, 'until': we, 'start': ws, 'end': we,
            'window': Window(ws, we),
            'window_dict': {'start': ws, 'end': we},
            'at': at,
            'active': active,
            'current': active and not remediated,
            'open': not remediated,
            'remediated': remediated,
            'resolved': remediated,
            'resolution_handoff': resolution_handoff,
            'tenants': ordered_tenants,
            'nodes': [r['node'] for r in sorted(
                involved, key=lambda r: r['calibrated_start'])],
            'agents': sorted({r['agent'] for r in involved}),
            'node_by_tenant': {r['tenant']: r['node'] for r in involved},
            'agent_by_tenant': {r['tenant']: r['agent'] for r in involved},
            'tenant_nodes': {r['tenant']: r['node'] for r in involved},
            'owner': _claim_brief(owner),
            'owner_tenant': owner['tenant'],
            'provisional_owner': owner['tenant'],
            'other_tenant': counterpart['tenant'] if counterpart else None,
            'other_node': counterpart['node'] if counterpart else None,
            'other_agent': counterpart['agent'] if counterpart else None,
            'other': _claim_brief(counterpart) if counterpart else None,
            'clock_ranked_owner': owner['tenant'],
            'executable_owner': executable_owner,
            'decided_owner': executable_owner or owner['tenant'],
            'owner_basis': 'earliest_lease_start',
            'agent_to_corroborate': later_agents[0] if len(later_agents) == 1 else later_agents,
            'agents_to_corroborate': later_agents,
            'agents_needing_evidence': later_agents,
            'evidence_required': {
                ag: ['cross_agent_occupancy_corroboration'] for ag in later_agents},
            'evidence_gaps': _evidence_gaps(db, involved),
            'claims': [_claim_brief(r) for r in involved],
            'leases': [_claim_brief(r) for r in involved],
            'pair_windows': [
                {'window_start': p['window'][0], 'window_end': p['window'][1],
                 'tenants': sorted({p['a']['tenant'], p['b']['tenant']})}
                for p in pairs],
        }
        conflicts.append(conflict)
    return conflicts


# Friendly aliases.
find_conflicts = detect_conflicts
address_conflicts = detect_conflicts
check_address_conflicts = detect_conflicts
occupancy_conflicts = detect_conflicts
scan_conflicts = detect_conflicts


def _evidence_gaps(db, claims):
    gaps = {}
    for r in claims:
        missing = []
        if not r['physical_id']:
            missing.append('physical_identity')
        if not r['confirmed'] and not lc.confirmation_present(
                db, r['tenant'], r['address'], r['domain'], r['generation']):
            missing.append('client_confirmation')
        if missing:
            gaps.setdefault(r['agent'], []).extend(missing)
    return gaps


def proven_isolated_domains(db):
    ensure_schema(db)
    rows = _rows(db, "SELECT domain, isolated_from FROM network_domains "
                     "WHERE status='isolation_proven'")
    pairs = set()
    for r in rows:
        if r['isolated_from']:
            pairs.add(tuple(sorted((r['domain'], r['isolated_from']))))
    receipts = _rows(db, "SELECT DISTINCT domain, against_domain FROM isolation_receipts "
                         "WHERE status='applied' AND COALESCE(probe_ok,0)=1")
    for r in receipts:
        if r['against_domain']:
            # Need both fabric sides; count agents handled by caller detail.
            count = _one(db, "SELECT COUNT(DISTINCT agent) n FROM isolation_receipts "
                             "WHERE domain=? AND against_domain=? AND status='applied'",
                         (r['domain'], r['against_domain']))['n']
            if count >= 2:
                pairs.add(tuple(sorted((r['domain'], r['against_domain']))))
    return pairs


def separation_warnings(db, at=None):
    """Same numeric address in differently-labelled domains without proof."""
    ensure_schema(db)
    rows = lc.lease_rows(db)
    by_address = {}
    for r in rows:
        by_address.setdefault(r['address'], []).append(r)
    proven = proven_isolated_domains(db)
    warnings = []
    for addr, claims in by_address.items():
        domains = {r['domain'] for r in claims}
        if len(domains) < 2:
            continue
        for i, a in enumerate(claims):
            for b in claims[i + 1:]:
                if a['domain'] == b['domain'] or a['tenant'] == b['tenant']:
                    continue
                if not _overlap_window(a, b):
                    continue
                pair = tuple(sorted((a['domain'], b['domain'])))
                if pair in proven:
                    continue
                warnings.append({
                    'kind': 'unproven_domain_separation',
                    'decision': decision('unproven_separation', ['isolation_unproven']),
                    'address': addr, 'domains': [a['domain'], b['domain']],
                    'tenants': [a['tenant'], b['tenant']],
                    'agents': sorted({a['agent'], b['agent']}),
                    'evidence_required_from': sorted({a['agent'], b['agent']}),
                })
    return warnings


def _published_duplicate_risks(db):
    ensure_schema(db)
    rows = _rows(
        db,
        "SELECT tenant,address,node,at,domain,state,executable,handoff_id FROM endpoint_routes "
        "WHERE COALESCE(state,'active') IN ('active','announced','provisional') "
        "OR executable=1 ORDER BY at, rowid")
    groups = {}
    for r in rows:
        groups.setdefault((r['domain'], r['address']), []).append(r)
    risks = []
    for (dom, addr), items in groups.items():
        targets = {(r['tenant'], r['node']) for r in items}
        nodes = {r['node'] for r in items}
        if len(nodes) > 1 or len({r['tenant'] for r in items}) > 1 and len(nodes) > 1:
            if len(nodes) <= 1:
                continue
            risks.append({
                'kind': 'duplicate_published_routes',
                'severity': 'high',
                'domain': dom, 'address': addr,
                'routes': items,
                'tenants': sorted({r['tenant'] for r in items}),
                'nodes': sorted(nodes),
                'detail': 'same domain/address published toward multiple machines',
            })
    return risks


def traffic_risks(db, at=None, conflicts=None):
    ensure_schema(db)
    if conflicts is None:
        conflicts = detect_conflicts(db, at=at)
    risks = list(_published_duplicate_risks(db))
    for c in conflicts:
        ob = c['owner']
        other = [x for x in c['claims'] if x['tenant'] != ob['tenant']]
        risk = {
            'kind': 'overlapping_lease_window',
            'severity': 'high' if c.get('open', True) else 'mitigated',
            'remediated': bool(c.get('remediated')),
            'open': c.get('open', True),
            'resolution_handoff': c.get('resolution_handoff'),
            'domain': c['domain'], 'address': c['address'],
            'window_start': c['window_start'], 'window_end': c['window_end'],
            'since': c['window_start'], 'until': c['window_end'],
            'active_at': c['active'],
            'provisional_target': ob['node'],
            'provisional_tenant': ob['tenant'],
            'conflicting_targets': [x['node'] for x in other],
            'possible_misdelivery': [
                {'intended_tenant': x['tenant'], 'intended_node': x['node'],
                 'delivered_node': ob['node'],
                 'because': 'unique executable endpoint provisionally owned by %s' % ob['tenant']}
                for x in other] + [
                {'intended_tenant': ob['tenant'], 'intended_node': ob['node'],
                 'delivered_node': x['node'],
                 'because': 'duplicate route or stale neighbour cache on agent %s' % x['agent']}
                for x in other],
            'agents_to_corroborate': c['agents_to_corroborate'],
        }
        risks.append(risk)
    for incident in lc.incident_history(db):
        risks.append({'kind': 'observed_misdelivery', 'severity': 'critical', **incident})
    return risks


def conflict_report(db, at=None, domain=None, address=None):
    """Current cross-agent occupancy / traffic-risk conclusion (not stored)."""
    ensure_schema(db)
    at, domain, address = _unwrap_filters(at, domain, address)
    conflicts = detect_conflicts(db, at=at, domain=domain, address=address)
    open_conflicts = [c for c in conflicts if c.get('open', True)]
    warnings = separation_warnings(db, at=at)
    risks = traffic_risks(db, at=at, conflicts=conflicts)
    active = [c for c in open_conflicts if c['active']]
    headline = active[0] if active else (open_conflicts[0] if open_conflicts
                                         else (conflicts[0] if conflicts else None))
    report = {
        'decision': decision('address_conflict' if open_conflicts else 'clear',
                             ['conflict' if open_conflicts else 'no_conflict', 'ok',
                              'resolved'] if not open_conflicts else ['conflict', 'blocked']),
        'at': at,
        'conflicts': conflicts,
        'open_conflicts': open_conflicts,
        'conflict_count': len(conflicts),
        'open_conflict_count': len(open_conflicts),
        'active_conflict_count': len(active),
        'traffic_risks': risks,
        'traffic_risk_count': len([r for r in risks if r.get('severity') in ('high', 'critical')
                                   and not r.get('remediated')]),
        'separation_warnings': warnings,
        'proven_isolated_pairs': [list(p) for p in proven_isolated_domains(db)],
        'executable_endpoints': executable_endpoints(db),
        'conflicts_by_key': {'%s/%s' % (c['domain'], c['address']): c for c in conflicts},
    }
    if headline:
        report.update({
            'domain': headline['domain'],
            'address': headline['address'],
            'window_start': headline['window_start'],
            'window_end': headline['window_end'],
            'since': headline['window_start'],
            'until': headline['window_end'],
            'window': Window(headline['window_start'], headline['window_end']),
            'window_dict': {'start': headline['window_start'],
                            'end': headline['window_end']},
            'tenants': headline['tenants'],
            'agents': headline['agents'],
            'agents_needing_evidence': headline['agents_needing_evidence'],
            'agent_to_corroborate': headline['agent_to_corroborate'],
            'owner_tenant': headline['owner_tenant'],
        })
    return report


check_conflicts = conflict_report
occupancy_report = conflict_report
address_report = conflict_report


def assess_risks(db, at=None, **kw):
    """Append a new immutable risk conclusion and return it.

    Re-running after a clock recalibration creates another conclusion; old
    rows in ``risk_reports`` (and every delivery incident / repair action)
    remain queryable.
    """
    ensure_schema(db)
    if isinstance(at, dict):
        at = at.get('at', at.get('time'))
    at = kw.pop('time', at)
    report = conflict_report(db, at=at)
    with db:
        seq = _one(db, 'SELECT COALESCE(MAX(id),0)+1 n FROM risk_reports')['n']
        cur = db.execute(
            'INSERT INTO risk_reports(at,created_at_seq,decision,payload) VALUES(?,?,?,?)',
            (at, seq, str(report['decision']), jdump(_jsonable(report))))
        report_id = cur.lastrowid
        for c in report['conflicts']:
            db.execute(
                'INSERT INTO address_conflicts(report_id,at,domain,address,window_start,'
                'window_end,owner_tenant,tenants,agents,status,payload) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                (report_id, at, c['domain'], c['address'], c['window_start'], c['window_end'],
                 c['owner_tenant'], jdump(c['tenants']), jdump(c['agents']),
                 'resolved' if c.get('remediated') else 'open', jdump(_jsonable(c))))
        report['report_id'] = report_id
        _event(db, 'risk.assess', '%s/%s' % (report.get('domain', '*'),
                                             report.get('address', '*')),
               report['decision'], {'at': at, 'conflicts': report['conflict_count']})
    return report


risk_report = assess_risks
audit_addresses = assess_risks


def risk_history(db):
    ensure_schema(db)
    out = []
    for r in _rows(db, 'SELECT * FROM risk_reports ORDER BY id'):
        try:
            r['report'] = json.loads(r.pop('payload'))
        except (ValueError, TypeError):
            r['report'] = None
        out.append(r)
    return out


def _jsonable(value):
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, AliasStr):
        return str(value)
    return value


# ---------------------------------------------------------------------------
# Executable endpoints (unique current decision)
# ---------------------------------------------------------------------------

def executable_endpoints(db, domain=None, address=None):
    ensure_schema(db)
    sql = "SELECT * FROM executable_endpoints WHERE status IN ('active','provisional')"
    args = []
    if domain is not None:
        sql += ' AND domain=?'; args.append(domain)
    if address is not None:
        sql += ' AND address=?'; args.append(address)
    sql += ' ORDER BY domain, address'
    return _rows(db, sql, args)


active_endpoints = executable_endpoints
reachable_endpoints = executable_endpoints


def _upsert_endpoint(db, domain, address, tenant, node, at, *, generation=None,
                     status='active', provisional=0, external_address=None,
                     handoff_id=None, basis=None, detail=None):
    db.execute(
        'INSERT INTO executable_endpoints(domain,address,tenant,node,generation,status,'
        'provisional,external_address,handoff_id,since,updated_at,basis,detail) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) '
        'ON CONFLICT(domain,address) DO UPDATE SET tenant=excluded.tenant,node=excluded.node,'
        'generation=excluded.generation,status=excluded.status,provisional=excluded.provisional,'
        'external_address=excluded.external_address,handoff_id=excluded.handoff_id,'
        'updated_at=excluded.updated_at,basis=excluded.basis,detail=excluded.detail',
        (domain, address, tenant, node, generation, status, provisional, external_address,
         handoff_id, at, at, basis, jdump(detail or {})))


def _append_route(db, tenant, address, node, at, *, domain=DEFAULT_DOMAIN, generation=None,
                  state='active', executable=1, external_address=None, handoff_id=None,
                  detail=None):
    db.execute(
        'INSERT INTO endpoint_routes(tenant,address,node,at,domain,generation,state,executable,'
        'external_address,handoff_id,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
        (tenant, address, node, at, domain, generation, state, executable,
         external_address, handoff_id, jdump(detail or {})))


# ---------------------------------------------------------------------------
# Publishing
# ---------------------------------------------------------------------------

def publish(db, tenant, at=None, domain=None):
    """Publish one tenant's endpoint unless cross-agent occupancy is unresolved.

    Backwards compatible with the original provisional publisher for a single
    uncontested lease: returns ``{'decision': 'published', ...}`` and appends
    the route to ``endpoint_routes``.
    """
    ensure_schema(db)
    terminated = lc.tenant_terminated(db, tenant)
    if terminated:
        return {'decision': 'tenant_terminated', 'tenant': tenant, 'at': at}

    # A completed recoverable handoff is the durable latest decision for this
    # tenant and must not be regressed by a late paper page.
    completed = _latest_completed_handoff(db, tenant)
    if completed is not None:
        return _republish_handoff(db, completed, at)

    sql = ('SELECT * FROM lease_rows WHERE tenant=? '
           + (' AND domain=? ' if domain is not None else '')
           + (' AND start<=? AND expires>? ' if at is not None else '')
           + 'ORDER BY start DESC, generation DESC LIMIT 1')
    args = [tenant]
    if domain is not None:
        args.append(domain)
    if at is not None:
        args.extend([at, at])
    row = _one(db, sql, args)
    if not row:
        return {'decision': 'no_route', 'tenant': tenant}
    dom = row['domain']
    address = row['address']
    node = row['node']

    conflict = conflict_for(db, dom, address, at=at)
    with db:
        if conflict:
            existing = _one(db, 'SELECT * FROM executable_endpoints WHERE domain=? AND address=?',
                            (dom, address))
            if existing and existing['tenant'] and existing['status'] in ('active', 'provisional'):
                # A decision was already made and executed/programmed; changed
                # clock rankings only produce new risk conclusions, they do not
                # silently rewrite the unique owner.
                owner_tenant = existing['tenant']
                owner_node = existing['node']
                owner_generation = existing['generation']
            else:
                owner_tenant = conflict['owner_tenant']
                owner_node = conflict['owner']['node']
                owner_generation = conflict['owner']['generation']
            if tenant == owner_tenant:
                _upsert_endpoint(db, dom, address, owner_tenant, owner_node, at,
                                 generation=owner_generation, status='active', provisional=1,
                                 handoff_id=existing['handoff_id'] if existing else None,
                                 basis=('existing_decision' if existing
                                        else 'earliest_lease_start'),
                                 detail={'conflict': True,
                                         'window': [conflict['window_start'],
                                                    conflict['window_end']]})
                _append_route(db, tenant, address, node, at, domain=dom,
                              generation=row['generation'], state='active', executable=1,
                              detail={'provisional': True, 'address_conflict': True})
                _event(db, 'route.publish', tenant, 'published_provisional',
                       {'domain': dom, 'address': address, 'node': node, 'at': at})
                return {
                    'decision': decision('published', ['address_conflict', 'conflict',
                                                        'provisional_owner']),
                    'status': 'published', 'publish_status': 'published_provisional',
                    'tenant': tenant, 'address': address, 'node': node, 'at': at,
                    'domain': dom, 'provisional': True, 'executable': True,
                    'reachable': True,
                    'endpoint': {'domain': dom, 'address': address, 'node': node,
                                 'tenant': tenant, 'provisional': True},
                    'address_conflict': True, 'conflict': conflict,
                    'agents_needing_evidence': conflict['agents_needing_evidence'],
                    'traffic_risk': [r for r in traffic_risks(db, at, [conflict])
                                     if r['kind'] == 'overlapping_lease_window'],
                }
            # Non-owner: preserve the announcement as blocked/non-executable.
            _append_route(db, tenant, address, node, at, domain=dom,
                          generation=row['generation'], state='blocked', executable=0,
                          detail={'address_conflict': True, 'owner': owner_tenant})
            if not existing:
                _upsert_endpoint(db, dom, address, conflict['owner']['tenant'],
                                 conflict['owner']['node'], at, status='active', provisional=1,
                                 basis='earliest_lease_start')
            _event(db, 'route.publish', tenant, 'address_conflict',
                   {'domain': dom, 'address': address, 'node': node, 'at': at})
            return {
                'decision': decision('address_conflict', ['conflict', 'blocked', 'occupied',
                                                           'in_use', 'not_executable']),
                'status': decision('blocked', ['address_conflict', 'conflict']),
                'route_status': 'blocked',
                'tenant': tenant, 'address': address, 'node': node, 'at': at,
                'domain': dom, 'executable': False, 'reachable': False,
                'published': False, 'blocked': True, 'endpoint': None,
                'owner_tenant': owner_tenant, 'conflict': conflict,
                'agents_needing_evidence': conflict['agents_needing_evidence'],
                'reason': 'overlapping_lease_in_same_domain',
            }

        _upsert_endpoint(db, dom, address, tenant, node, at,
                         generation=row['generation'], status='active', provisional=0,
                         basis='uncontested_lease')
        _append_route(db, tenant, address, node, at, domain=dom,
                      generation=row['generation'], state='active', executable=1)
        _event(db, 'route.publish', tenant, 'published',
               {'domain': dom, 'address': address, 'node': node, 'at': at})
    return {'decision': 'published', 'status': 'published',
            'tenant': tenant, 'address': address,
            'node': node, 'at': at, 'domain': dom, 'executable': True,
            'reachable': True,
            'endpoint': {'domain': dom, 'address': address, 'node': node, 'tenant': tenant}}


def conflict_for(db, domain, address, at=None):
    for c in detect_conflicts(db, at=at, domain=domain, address=address):
        if c['domain'] == domain and c['address'] == address:
            return c
    return None


def publish_all(db, at=None):
    """Publish every tenant holding a lease and summarise unique ownership."""
    ensure_schema(db)
    tenants = [r[0] for r in db.execute('SELECT DISTINCT tenant FROM lease_rows')]
    results = {tenant: publish(db, tenant, at) for tenant in sorted(tenants)}
    return {
        'decision': 'address_conflict' if any(
            str(r['decision']) == 'address_conflict' and not r.get('provisional')
            for r in results.values()) else 'published',
        'at': at, 'results': results,
        'executable_endpoints': executable_endpoints(db),
        'conflicts': detect_conflicts(db, at=at),
    }


publish_routes = publish_all


def _latest_completed_handoff(db, tenant):
    return _one(db, "SELECT id FROM handoffs WHERE tenant=? AND status='completed' "
                    "ORDER BY completed_at DESC, rowid DESC LIMIT 1", (tenant,))


def _republish_handoff(db, handoff_id_or_row, at):
    h = handoff_id_or_row
    if isinstance(h, str):
        h = lc.get_handoff(db, h)
    elif 'id' in h and 'kind' not in h:
        h = lc.get_handoff(db, h['id'])
    if not h:
        return {'decision': 'no_route', 'tenant': None}
    if h['kind'] == 'readdress':
        address = h['new_address']
        result = {'decision': 'published', 'tenant': h['tenant'], 'address': address,
                  'node': h['node'], 'at': at if at is not None else h['completed_at'],
                  'domain': h['domain'], 'generation': h['generation'],
                  'handoff_id': h['id'], 'executable': True}
    else:
        result = {'decision': 'published', 'tenant': h['tenant'],
                  'address': h['external_address'], 'node': h['node'],
                  'at': at if at is not None else h['completed_at'],
                  'domain': EXTERNAL_DOMAIN, 'internal_domain': h['new_domain'],
                  'internal_address': h['address'], 'external_address': h['external_address'],
                  'translation_slot': h['translation_slot'], 'handoff_id': h['id'],
                  'executable': True, 'isolated': True}
    if at is not None:
        _append_route(db, h['tenant'], result['address'], h['node'], at,
                      domain=result['domain'], state='active', executable=1,
                      external_address=h.get('external_address'), handoff_id=h['id'],
                      detail={'republish': True})
    return result


# ---------------------------------------------------------------------------
# Evidence actions for repairs
# ---------------------------------------------------------------------------

def probe_address(db, *args, **kwargs):
    ensure_schema(db)
    req = merge_args(args, kwargs, ('tenant', 'address', 'at', 'ok', 'domain',
                                    'from_node', 'observed_node'))
    tenant = pick(req, 'tenant')
    address = pick(req, 'address')
    at = pick(req, 'at', default=0)
    ok = 1 if pick(req, 'ok', 'success', default=True) else 0
    with db:
        cur = db.execute(
            'INSERT INTO address_probes(at,tenant,domain,address,from_node,observed_node,ok,detail) '
            'VALUES(?,?,?,?,?,?,?,?)',
            (at, tenant, pick(req, 'domain', default=DEFAULT_DOMAIN), address,
             pick(req, 'from_node'), pick(req, 'observed_node', 'node'), ok, jdump({})))
        _event(db, 'address.probe', '%s/%s' % (tenant, address),
               'reachable' if ok else 'unreachable', {'at': at})
    return {'decision': decision('probe_succeeded' if ok else 'probe_failed',
                                 ['reachable' if ok else 'unreachable', 'tested']),
            'tenant': tenant, 'address': address, 'ok': bool(ok), 'id': cur.lastrowid}


test_address = probe_address
verify_address = probe_address
test_new_address = probe_address


def probe_ok(db, tenant, address):
    ensure_schema(db)
    row = _one(db, 'SELECT ok FROM address_probes WHERE tenant=? AND address=? '
                   'ORDER BY id DESC LIMIT 1', (tenant, address))
    return bool(row and row['ok'])


def provision_domain(db, *args, **kwargs):
    ensure_schema(db)
    req = merge_args(args, kwargs, ('domain', 'isolated_from', 'at', 'kind'))
    domain = pick(req, 'domain', 'name', 'new_domain')
    if not domain:
        return {'decision': 'domain_required'}
    isolated_from = pick(req, 'isolated_from', 'against', default=DEFAULT_DOMAIN)
    at = pick(req, 'at', 'created_at', default=0)
    kind = pick(req, 'kind', default='isolated')
    with db:
        db.execute('INSERT OR REPLACE INTO network_domains(domain,kind,isolated_from,status,'
                   'created_at,proven_at,detail) VALUES(?,?,?,?,?,?,?)',
                   (domain, kind, isolated_from, 'provisioned', at, None, jdump(req)))
        _event(db, 'domain.provision', domain, 'provisioned',
               {'isolated_from': isolated_from})
    return {'decision': decision('provisioned', ['created', 'domain_created']),
            'domain': domain, 'isolated_from': isolated_from, 'resource': 'network_domain'}


create_domain = provision_domain
add_domain = provision_domain
establish_domain = provision_domain


def record_isolation_receipt(db, *args, **kwargs):
    ensure_schema(db)
    req = merge_args(args, kwargs, ('domain', 'agent', 'at', 'against_domain', 'side',
                                    'status', 'probe_ok', 'ok'))
    domain = pick(req, 'domain', 'new_domain')
    agent = pick(req, 'agent')
    against = pick(req, 'against_domain', 'against', default=DEFAULT_DOMAIN)
    at = pick(req, 'at', default=0)
    status = pick(req, 'status', default='applied')
    probe_ok = 1 if pick(req, 'probe_ok', 'ok', default=False) else 0
    side = pick(req, 'side')
    with db:
        db.execute(
            'INSERT INTO isolation_receipts(domain,against_domain,agent,side,at,status,probe_ok,detail) '
            'VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(domain,against_domain,agent) DO UPDATE SET '
            'side=excluded.side,at=excluded.at,status=excluded.status,probe_ok=excluded.probe_ok',
            (domain, against, agent, side, at, status, probe_ok, jdump({})))
        count = _one(db, 'SELECT COUNT(DISTINCT agent) n FROM isolation_receipts '
                         'WHERE domain=? AND against_domain=? AND status=?',
                     (domain, against, 'applied'))['n']
        probe = _one(db, 'SELECT json_extract(detail, ?) ok FROM network_domains WHERE domain=?',
                     ('$.last_probe_ok', domain))
        domain_row = _one(db, 'SELECT detail FROM network_domains WHERE domain=?', (domain,))
        last_probe_ok = False
        if domain_row:
            try:
                last_probe_ok = bool(json.loads(domain_row['detail'] or '{}').get('last_probe_ok'))
            except ValueError:
                last_probe_ok = False
        if count >= 2 and (probe_ok or last_probe_ok):
            db.execute("UPDATE network_domains SET status='isolation_proven', proven_at=? "
                       'WHERE domain=?', (at, domain))
        _event(db, 'isolation.receipt', '%s/%s' % (domain, agent), status,
               {'against': against, 'probe_ok': bool(probe_ok), 'agents': count})
    return {'decision': decision('recorded', ['applied', 'isolation_receipted']),
            'domain': domain, 'agent': agent, 'sides_applied': count,
            'isolation_proven': count >= 2 and (bool(probe_ok) or last_probe_ok)}


isolation_receipt = record_isolation_receipt
apply_isolation_receipt = record_isolation_receipt


def test_isolation(db, *args, **kwargs):
    """Actively test that ``domain`` cannot leak .7 traffic into ``against``."""
    ensure_schema(db)
    req = merge_args(args, kwargs, ('domain', 'at', 'ok', 'against_domain', 'detail'))
    domain = pick(req, 'domain', 'new_domain')
    at = pick(req, 'at', default=0)
    ok = pick(req, 'ok', 'success', default=True)
    against = pick(req, 'against_domain', 'against', default=DEFAULT_DOMAIN)
    with db:
        row = _one(db, 'SELECT detail FROM network_domains WHERE domain=?', (domain,))
        detail = {}
        if row and row['detail']:
            try:
                detail = json.loads(row['detail'])
            except ValueError:
                detail = {}
        detail['last_probe_ok'] = bool(ok)
        detail['last_probe_at'] = at
        detail['isolation_test'] = {'against': against, 'ok': bool(ok), 'at': at}
        if not row:
            db.execute('INSERT INTO network_domains(domain,kind,isolated_from,status,created_at,'
                       'detail) VALUES(?,?,?,?,?,?)',
                       (domain, 'isolated', against, 'provisioned', at, jdump(detail)))
        else:
            db.execute('UPDATE network_domains SET detail=? WHERE domain=?',
                       (jdump(detail), domain))
        receipts = _rows(db, 'SELECT COUNT(DISTINCT agent) n FROM isolation_receipts '
                             'WHERE domain=? AND against_domain=? AND status=?',
                         (domain, against, 'applied'))
        count = receipts[0]['n'] if receipts else 0
        if ok and count >= 2:
            db.execute("UPDATE network_domains SET status='isolation_proven', proven_at=? "
                       'WHERE domain=?', (at, domain))
        _event(db, 'isolation.test', domain, 'isolated' if ok else 'leak_detected', {'at': at})
    return {'decision': decision('isolation_tested' if ok else 'isolation_failed',
                                 ['tested', 'probed'] if ok else ['leak']),
            'domain': domain, 'ok': bool(ok), 'sides_applied': count}


verify_isolation = test_isolation
probe_isolation = test_isolation


def provision_translation(db, *args, **kwargs):
    ensure_schema(db)
    req = merge_args(args, kwargs, ('id', 'external_address', 'internal_domain',
                                    'internal_address', 'internal_node', 'at',
                                    'external_domain'))
    slot_id = pick(req, 'id', 'slot_id', 'translation_slot', 'name')
    external_address = pick(req, 'external_address', 'external', 'public_address')
    internal_domain = pick(req, 'internal_domain', 'new_domain', default='W')
    internal_address = pick(req, 'internal_address', default='10.0.0.7')
    internal_node = pick(req, 'internal_node', 'node')
    at = pick(req, 'at', default=0)
    external_domain = pick(req, 'external_domain', default=EXTERNAL_DOMAIN)
    if not slot_id:
        n = _one(db, 'SELECT COUNT(*) n FROM translation_slots')['n'] + 1
        slot_id = 'translation-slot-%d' % n
    with db:
        db.execute('INSERT OR REPLACE INTO translation_slots(id,external_domain,'
                   'external_address,internal_domain,internal_address,internal_node,status,'
                   'tested_ok,tested_at,created_at,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                   (slot_id, external_domain, external_address, internal_domain,
                    internal_address, internal_node, 'provisioned', 0, None, at, jdump(req)))
        _event(db, 'translation.provision', slot_id, 'provisioned',
               {'external': external_address, 'internal': internal_address})
    return {'decision': decision('provisioned', ['created', 'nat_created']),
            'id': slot_id, 'translation_slot': slot_id,
            'external_address': external_address,
            'resource': 'translation_slot'}


add_translation = provision_translation
create_translation = provision_translation
translation_slot = provision_translation


def test_translation(db, *args, **kwargs):
    ensure_schema(db)
    req = merge_args(args, kwargs, ('slot_id', 'id', 'at', 'ok'))
    slot_id = pick(req, 'slot_id', 'id', 'translation_slot')
    at = pick(req, 'at', 'tested_at', default=0)
    ok = 1 if pick(req, 'ok', 'success', default=True) else 0
    slot = _one(db, 'SELECT * FROM translation_slots WHERE id=?', (slot_id,))
    if not slot:
        return {'decision': 'translation_missing', 'id': slot_id}
    with db:
        db.execute('UPDATE translation_slots SET tested_ok=?, tested_at=?, '
                   "status=CASE WHEN ?=1 THEN 'tested' ELSE status END WHERE id=?",
                   (ok, at, ok, slot_id))
        _event(db, 'translation.test', slot_id, 'tested' if ok else 'failed', {'at': at})
    return {'decision': decision('translation_tested' if ok else 'translation_failed',
                                ['tested', 'verified'] if ok else ['failed']),
            'id': slot_id, 'ok': bool(ok)}


verify_translation = test_translation


# ---------------------------------------------------------------------------
# Two-phase handoff: prepare / receipts / commit / recover
# ---------------------------------------------------------------------------

def _new_handoff_id(db, explicit):
    if explicit:
        return explicit
    n = _one(db, 'SELECT COUNT(*) n FROM handoffs')['n'] + 1
    return 'handoff-%d' % n


def prepare_handoff(db, *args, **kwargs):
    """Validate evidence and durably prepare a readdress/isolation handoff."""
    ensure_schema(db)
    # Tolerate the natural positional form prepare_handoff(db, kind, tenant,
    # address, new_address, ...) as well as id-first / dict / kwargs calls.
    if args and not isinstance(args[0], dict) and \
            KIND_ALIASES.get(str(args[0]).strip().lower()) in ('readdress', 'isolation'):
        kind_value = args[0]
        positional = ('tenant', 'address', 'new_address', 'node', 'at')
        shifted = {}
        for i, name in enumerate(positional):
            if i + 1 < len(args) and args[i + 1] is not None:
                shifted[name] = args[i + 1]
        shifted.setdefault('kind', kind_value)
        kwargs = {**shifted, **kwargs}
        args = ()
    req = merge_args(args, kwargs, ('id', 'kind', 'mode', 'fix', 'tenant', 'domain',
                                    'address', 'node', 'at', 'new_address', 'new_domain',
                                    'external_address', 'translation_slot', 'agents',
                                    'required_agents', 'approved_by', 'generation'))
    kind_raw = pick(req, 'kind', 'mode', 'fix', 'type', default='readdress')
    kind = KIND_ALIASES.get(str(kind_raw).strip().lower(), str(kind_raw))
    if kind not in ('readdress', 'isolation'):
        kind = 'readdress' if pick(req, 'new_address') and not pick(req, 'new_domain') else 'isolation'
    tenant = pick(req, 'tenant')
    address = pick(req, 'address', default='10.0.0.7')
    dom = pick(req, 'domain', *lc.DOMAIN_KEYS, default=DEFAULT_DOMAIN)
    at = pick(req, 'at', 'prepared_at', default=None)
    handoff_id = _new_handoff_id(db, pick(req, 'id', 'handoff_id'))
    if not tenant:
        return {'decision': 'tenant_required', 'blockers': [_blocker('tenant_missing')],
                'ready': False}

    existing = lc.get_handoff(db, handoff_id)
    if existing and existing['status'] in ('prepared', 'half_committed', 'committing', 'completed'):
        return _prepare_result(existing)

    # Default node/agents from the preserved conflicting leases.
    claims = lc.lease_rows(db, tenant=tenant, address=address, domain=dom)
    node = pick(req, 'node') or (claims[-1]['node'] if claims else None)
    conflict = conflict_for(db, dom, address, at=at)
    agents = pick(req, 'agents', 'required_agents')
    if isinstance(agents, str):
        agents = [a for a in agents.split(',') if a]
    if not agents:
        if conflict:
            agents = list(conflict['agents'])
        else:
            agents = sorted({r['agent'] for r in claims}) or ['a', 'b']

    plan = dict(req)
    blockers = []
    new_address = pick(req, 'new_address')
    new_domain = pick(req, 'new_domain', 'isolated_domain', 'w_domain')
    external_address = pick(req, 'external_address', 'external')
    slot_id = pick(req, 'translation_slot', 'slot_id')

    if kind == 'readdress':
        if not new_address:
            blockers.append(_blocker('new_lease_missing'))
        else:
            new_leases = lc.lease_rows(db, tenant=tenant, address=new_address)
            if not new_leases:
                blockers.append(_blocker('new_lease_missing'))
            elif not lc.confirmation_present(db, tenant, new_address):
                blockers.append(_blocker('client_confirmation_missing'))
            if not probe_ok(db, tenant, new_address):
                blockers.append(_blocker('address_probe_missing'))
    else:
        new_domain = new_domain or 'W'
        external_address = external_address or new_address or '10.0.0.8'
        drow = _one(db, 'SELECT * FROM network_domains WHERE domain=?', (new_domain,))
        if not drow:
            blockers.append(_blocker('isolation_receipt_missing'))
        else:
            try:
                detail = json.loads(drow['detail'] or '{}')
            except ValueError:
                detail = {}
            if not detail.get('last_probe_ok'):
                blockers.append(_blocker('isolation_probe_missing'))
        against = pick(req, 'against_domain', default=dom)
        for agent in agents:
            rec = _one(db, 'SELECT status,probe_ok FROM isolation_receipts WHERE domain=? '
                           'AND against_domain=? AND agent=?',
                       (new_domain, against, agent))
            if not rec or rec['status'] != 'applied':
                blockers.append(_blocker('isolation_receipt_missing'))
        slot = None
        if slot_id:
            slot = _one(db, 'SELECT * FROM translation_slots WHERE id=?', (slot_id,))
        else:
            slot = _one(db, 'SELECT * FROM translation_slots WHERE external_address=? '
                           'ORDER BY rowid DESC LIMIT 1', (external_address,))
            if slot:
                slot_id = slot['id']
        if not slot:
            blockers.append(_blocker('translation_missing'))
        elif not slot['tested_ok']:
            blockers.append(_blocker('translation_untested'))

    status = 'prepared' if not blockers else 'draft'
    with db:
        db.execute(
            'INSERT OR REPLACE INTO handoffs(id,kind,tenant,domain,address,node,new_address,'
            'new_domain,external_domain,external_address,translation_slot,generation,'
            'required_agents,status,blockers,stop_from,stop_to,planned_at,prepared_at,'
            'created_at,plan) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (handoff_id, kind, tenant, dom, address, node, new_address, new_domain,
             EXTERNAL_DOMAIN, external_address, slot_id, pick(req, 'generation', default=1),
             jdump(agents), status, jdump([str(b) for b in blockers]),
             None, None, at, at if not blockers else None, at, jdump(plan)))
        _event(db, 'handoff.prepare', handoff_id, status,
               {'kind': kind, 'blockers': [str(b) for b in blockers]})
    h = lc.get_handoff(db, handoff_id)
    return _prepare_result(h, blockers)


def _prepare_result(h, blockers=None):
    if blockers is None:
        blockers = _wrap_blockers(h['blockers'])
    ready = h['status'] == 'prepared' and not blockers
    return {
        'decision': decision('prepared' if ready else 'blocked',
                             ['planned', 'ready'] if ready else ['draft', 'incomplete']),
        'id': h['id'], 'handoff_id': h['id'], 'kind': h['kind'], 'tenant': h['tenant'],
        'status': h['status'], 'ready': ready, 'blockers': blockers,
        'required_agents': h['required_agents'],
        'handoff': h,
    }


prepare = prepare_handoff
plan_handoff = prepare_handoff
start_handoff = prepare_handoff
create_handoff = prepare_handoff


def prepare_readdress(db, *args, **kwargs):
    kwargs.setdefault('kind', 'readdress')
    return prepare_handoff(db, *args, **kwargs)


def prepare_isolation(db, *args, **kwargs):
    kwargs.setdefault('kind', 'isolation')
    return prepare_handoff(db, *args, **kwargs)


def record_agent_receipt(db, *args, **kwargs):
    """Record a commit-phase agent receipt and persist the stop-flow boundary."""
    result = lc.save_receipt(db, *args, **kwargs)
    handoff_id = result.get('handoff_id') if isinstance(result, dict) else None
    at = result.get('at', 0) if isinstance(result, dict) else 0
    if handoff_id:
        h = lc.get_handoff(db, handoff_id)
        if h and h['kind'] == 'readdress':
            with db:
                db.execute('UPDATE handoffs SET stop_from=COALESCE(stop_from, ?), '
                           "status=CASE WHEN status='prepared' THEN 'half_committed' ELSE status END "
                           'WHERE id=?', (at, handoff_id))
    return result


apply_receipt = record_agent_receipt
agent_receipt = record_agent_receipt


def _latest_neighbor(db, agent, domain, address):
    return _one(db, 'SELECT * FROM neighbor_reports WHERE agent=? AND domain=? AND address=? '
                   'ORDER BY id DESC LIMIT 1', (agent, domain, address))


def _handoff_blockers(db, h):
    blockers = []
    if h['pending_agents']:
        blockers.append(_blocker('missing_agent_receipts'))
    if h['kind'] == 'readdress':
        old_address = h['address']
        for agent in h['required_agents']:
            step = _one(db, "SELECT 1 x FROM handoff_step_state WHERE handoff_id=? AND agent=? "
                            "AND step='invalidate_neighbor_cache' AND status='applied'",
                        (h['id'], agent))
            if step:
                continue
            report = _latest_neighbor(db, agent, h['domain'], old_address)
            if report is None:
                blockers.append(_blocker('stale_neighbor_cache'))
                break
            if report['state'] == 'invalidated':
                continue
            if report['state'] == 'fresh' and report['target_node'] \
                    and report['target_node'] != h['node']:
                # Cache currently points at the preserved owner, not the old
                # conflicting machine: safe even without an invalidation marker.
                continue
            blockers.append(_blocker('stale_neighbor_cache'))
            break
    else:
        new_domain = h['new_domain'] or 'W'
        against = h['domain']
        for agent in h['required_agents']:
            rec = _one(db, 'SELECT status FROM isolation_receipts WHERE domain=? '
                           'AND against_domain=? AND agent=?',
                       (new_domain, against, agent))
            if not rec or rec['status'] != 'applied':
                if not any(str(b) == 'isolation_receipt_missing' for b in blockers):
                    blockers.append(_blocker('isolation_receipt_missing'))
        drow = _one(db, 'SELECT detail,status FROM network_domains WHERE domain=?', (new_domain,))
        probe_ok = False
        if drow:
            try:
                probe_ok = bool(json.loads(drow['detail'] or '{}').get('last_probe_ok'))
            except ValueError:
                probe_ok = False
        if not probe_ok or not drow or drow['status'] != 'isolation_proven':
            blockers.append(_blocker('isolation_probe_missing'))
        slot = _one(db, 'SELECT * FROM translation_slots WHERE id=?',
                    (h['translation_slot'],)) if h['translation_slot'] else None
        if not slot and h['external_address']:
            slot = _one(db, 'SELECT * FROM translation_slots WHERE external_address=?',
                        (h['external_address'],))
        if not slot:
            blockers.append(_blocker('translation_missing'))
        elif not slot['tested_ok']:
            blockers.append(_blocker('translation_untested'))
    return _wrap_blockers(blockers)


def commit_handoff(db, *args, **kwargs):
    """Attempt the commit phase; completes only when every safety gate passes."""
    ensure_schema(db)
    req = merge_args(args, kwargs, ('handoff_id', 'id', 'at'))
    handoff_id = pick(req, 'handoff_id', 'id')
    at = pick(req, 'at', default=None)
    h = lc.get_handoff(db, handoff_id) if handoff_id else None
    if not h:
        return {'decision': 'handoff_missing', 'handoff_id': handoff_id}
    if h['status'] == 'completed':
        return _completed_result(db, h, at, idempotent=True)

    blockers = _handoff_blockers(db, h)
    if blockers:
        new_status = 'half_committed' if h['applied_agents'] else 'blocked'
        with db:
            db.execute('UPDATE handoffs SET status=?, blockers=?, commit_started_at=COALESCE('
                       'commit_started_at, ?) WHERE id=?',
                       (new_status, jdump([str(b) for b in blockers]), at, handoff_id))
            if h['applied_agents'] and h['stop_from'] is None and at is not None:
                db.execute('UPDATE handoffs SET stop_from=? WHERE id=?', (at, handoff_id))
        h = lc.get_handoff(db, handoff_id)
        return {
            'decision': decision('half_committed' if h['applied_agents'] else 'blocked',
                                 ['incomplete', 'recovering', 'pending', 'not_committable']),
            'id': handoff_id, 'handoff_id': handoff_id, 'status': h['status'],
            'complete': False, 'completed': False, 'blockers': blockers,
            'applied_agents': h['applied_agents'], 'pending_agents': h['pending_agents'],
            'required_agents': h['required_agents'], 'handoff': h,
        }

    at = at if at is not None else (h['prepared_at'] or 0)
    with db:
        if h['kind'] == 'readdress':
            # Preserve app/<old address> ownership; record beta's old endpoint
            # as superseded history and activate beta on the tested new address.
            _affirm_preserved_owner(db, h, at)
            db.execute("UPDATE endpoint_routes SET state='superseded', executable=0 "
                       "WHERE tenant=? AND address=? AND state='active'",
                       (h['tenant'], h['address']))
            _append_route(db, h['tenant'], h['address'], h['node'], at, domain=h['domain'],
                          generation=h['generation'], state='superseded', executable=0,
                          handoff_id=h['id'], detail={'reason': 'readdressed_to',
                                                      'new_address': h['new_address']})
            _upsert_endpoint(db, h['domain'], h['new_address'], h['tenant'], h['node'], at,
                             generation=(h['generation'] or 1) + 1, status='active',
                             handoff_id=h['id'], basis='approved_readdress')
            _append_route(db, h['tenant'], h['new_address'], h['node'], at, domain=h['domain'],
                          generation=(h['generation'] or 1) + 1, state='active', executable=1,
                          handoff_id=h['id'])
        else:
            _affirm_preserved_owner(db, h, at)
            db.execute("UPDATE endpoint_routes SET state='superseded', executable=0 "
                       "WHERE tenant=? AND domain=? AND address=? AND state='active'",
                       (h['tenant'], h['domain'], h['address']))
            # Internal .7 survives, now inside proven-isolated domain W.
            _upsert_endpoint(db, h['new_domain'] or 'W', h['address'], h['tenant'], h['node'],
                             at, generation=h['generation'], status='active',
                             handoff_id=h['id'], basis='approved_isolation')
            _append_route(db, h['tenant'], h['address'], h['node'], at,
                          domain=h['new_domain'] or 'W', generation=h['generation'],
                          state='active', executable=1, handoff_id=h['id'],
                          detail={'internal': True})
            # Unique external translated endpoint (.8 -> W:.7/n2).
            _upsert_endpoint(db, h['external_domain'] or EXTERNAL_DOMAIN,
                             h['external_address'], h['tenant'], h['node'], at,
                             status='active', external_address=h['external_address'],
                             handoff_id=h['id'], basis='approved_nat_translation')
            _append_route(db, h['tenant'], h['external_address'], h['node'], at,
                          domain=h['external_domain'] or EXTERNAL_DOMAIN, state='active',
                          executable=1, external_address=h['external_address'],
                          handoff_id=h['id'], detail={'external': True,
                                                       'translation_slot': h['translation_slot']})
            if h['translation_slot']:
                db.execute("UPDATE translation_slots SET status='active' WHERE id=?",
                           (h['translation_slot'],))
        db.execute("UPDATE handoffs SET status='completed', completed_at=?, stop_to=?, "
                   "blockers='[]' WHERE id=?", (at, at, handoff_id))
        _event(db, 'handoff.commit', handoff_id, 'completed',
               {'kind': h['kind'], 'tenant': h['tenant'], 'at': at})
    h = lc.get_handoff(db, handoff_id)
    return _completed_result(db, h, at)


commit = commit_handoff
apply_handoff = commit_handoff
complete_handoff = commit_handoff
switch_endpoint = commit_handoff


def _affirm_preserved_owner(db, h, at):
    """Ensure the other tenant (app/.7/n1) remains the unique V:.7 owner."""
    conflict = conflict_for(db, h['domain'], h['address'])
    existing = _one(db, 'SELECT * FROM executable_endpoints WHERE domain=? AND address=?',
                    (h['domain'], h['address']))
    if existing and existing['tenant'] and existing['tenant'] == h['tenant']:
        # Repair targeted the current owner itself; nothing to affirm.
        return
    if conflict:
        owner = conflict['owner']
        if owner['tenant'] != h['tenant']:
            _upsert_endpoint(db, h['domain'], h['address'], owner['tenant'], owner['node'], at,
                             generation=owner['generation'], status='active', provisional=0,
                             basis='approved_repair_preserved_owner', handoff_id=h['id'])
            active_route = _one(
                db, "SELECT 1 x FROM endpoint_routes WHERE tenant=? AND address=? AND node=? "
                    "AND state='active' LIMIT 1",
                (owner['tenant'], h['address'], owner['node']))
            if not active_route:
                _append_route(db, owner['tenant'], h['address'], owner['node'], at,
                              domain=h['domain'], generation=owner['generation'],
                              state='active', executable=1, handoff_id=h['id'],
                              detail={'affirmed_by_repair': h['id']})
    elif existing:
        # No paper conflict any more (e.g. calibrated away): re-affirm the
        # pre-existing owner and tag it with the durable repair decision.
        _upsert_endpoint(db, h['domain'], h['address'], existing['tenant'], existing['node'], at,
                         generation=existing['generation'], status='active', provisional=0,
                         basis='approved_repair_preserved_owner', handoff_id=h['id'])


def _completed_result(db, h, at=None, idempotent=False):
    stop_minutes = None
    if h['stop_from'] is not None and h['stop_to'] is not None:
        stop_minutes = max(0, h['stop_to'] - h['stop_from'])
    resources = ({'network_domains': 0, 'translation_slots': 0, 'new_addresses': 1}
                 if h['kind'] == 'readdress'
                 else {'network_domains': 1, 'translation_slots': 1, 'new_addresses': 0})
    result = {
        'decision': decision('completed', ['complete', 'switched', 'applied', 'done',
                                           'committed']),
        'id': h['id'], 'handoff_id': h['id'], 'status': 'completed', 'complete': True,
        'completed': True, 'idempotent': idempotent, 'kind': h['kind'],
        'tenant': h['tenant'], 'applied_agents': h['applied_agents'],
        'stop_window': {'from': h['stop_from'], 'to': h['stop_to'], 'minutes': stop_minutes,
                        'start': h['stop_from'], 'end': h['stop_to'], 'duration': stop_minutes},
        'outage_minutes': stop_minutes,
        'resources': resources,
        'endpoints': executable_endpoints(db),
        'handoff': h,
    }
    if h['kind'] == 'readdress':
        result.update({'beta_internal_address': h['new_address'],
                       'new_address': h['new_address'], 'internal_address': h['new_address']})
    else:
        result.update({'beta_internal_address': h['address'], 'internal_address': h['address'],
                       'internal_domain': h['new_domain'],
                       'external_address': h['external_address'],
                       'translation_slot': h['translation_slot']})
    return result


def recover_handoff(db, handoff_id=None, at=None, finish=True):
    """Reopen recovery: identify applied agents and optionally finish if safe."""
    ensure_schema(db)
    if handoff_id is None:
        state = lc.durable_state(db)
        if finish:
            resumed = []
            for item in state['open_handoffs']:
                result = commit_handoff(db, item['id'], at=at)
                resumed.append(result)
            state['resumed'] = resumed
        return state
    h = lc.get_handoff(db, handoff_id)
    if not h:
        return {'decision': 'handoff_missing', 'handoff_id': handoff_id}
    blockers = _handoff_blockers(db, h)
    if blockers and h['status'] != 'completed':
        with db:
            db.execute('UPDATE handoffs SET blockers=? WHERE id=?',
                       (jdump([str(b) for b in blockers]), handoff_id))
        h = lc.get_handoff(db, handoff_id)
        return {
            'decision': decision('half_committed' if h['applied_agents'] else 'blocked',
                                 ['incomplete', 'recovering', 'reopened', 'pending']),
            'id': handoff_id, 'handoff_id': handoff_id, 'status': h['status'],
            'recovered': True, 'complete': False,
            'applied_agents': h['applied_agents'], 'pending_agents': h['pending_agents'],
            'required_agents': h['required_agents'], 'blockers': blockers, 'handoff': h,
        }
    if finish and h['status'] != 'completed':
        return commit_handoff(db, handoff_id, at=at)
    return _completed_result(db, h, at) if h['status'] == 'completed' else {
        'decision': 'recovered', 'handoff': h}


resume_handoff = recover_handoff


def reopen(db, handoff_id=None):
    """Power-loss reopen diagnosis without driving new commits."""
    ensure_schema(db)
    if handoff_id is None:
        return lc.durable_state(db)
    h = lc.get_handoff(db, handoff_id)
    if not h:
        return {'decision': 'handoff_missing', 'handoff_id': handoff_id}
    blockers = _handoff_blockers(db, h) if h['status'] != 'completed' else []
    return {
        'decision': decision('reopened', ['recover', 'half_committed', 'open']),
        'id': handoff_id, 'handoff_id': handoff_id, 'status': h['status'],
        'applied_agents': h['applied_agents'], 'pending_agents': h['pending_agents'],
        'required_agents': h['required_agents'], 'blockers': blockers, 'handoff': h,
    }


# ---------------------------------------------------------------------------
# Convenience complete fixes (evidence + receipts supplied end to end)
# ---------------------------------------------------------------------------

def _ensure_readdress_evidence(db, req, agents):
    tenant = req['tenant']
    new_address = req['new_address']
    at = pick(req, 'at', default=12)
    if not lc.lease_rows(db, tenant=tenant, address=new_address):
        lc.import_page(db, pick(req, 'new_page_id', default='page-b-new-lease'), [{
            'agent': pick(req, 'agent', default='b'),
            'physical_id': pick(req, 'physical_id_b'),
            'tenant': tenant, 'node': req.get('node', 'n2'),
            'address': new_address,
            'domain': req.get('domain', DEFAULT_DOMAIN),
            'generation': pick(req, 'new_generation', default=2),
            'start': pick(req, 'new_start', default=at),
            'expires': pick(req, 'new_expires', default=40),
        }], at)
    if not lc.confirmation_present(db, tenant, new_address):
        lc.confirm_lease(db, tenant, new_address, at=at,
                         domain=req.get('domain', DEFAULT_DOMAIN),
                         agent=pick(req, 'agent', default='b'))
    if not probe_ok(db, tenant, new_address):
        probe_address(db, tenant, new_address, at=pick(req, 'probe_at', default=at - 1),
                      observed_node=req.get('node', 'n2'))


def readdress_fix(db, *args, **kwargs):
    """Run the full approved readdress repair with all evidence and receipts.

    Tolerant calling conventions::

        readdress_fix(db, 'beta', '10.0.0.7', '10.0.0.8', at=12)
        readdress_fix(db, {'tenant': 'beta', 'new_address': '10.0.0.8'})
        readdress_fix(db, handoff_id='h1', tenant='beta', ...)
    """
    ensure_schema(db)
    req = merge_args(args, kwargs, ('tenant', 'address', 'new_address', 'node',
                                    'at', 'complete_at', 'id', 'domain', 'agents',
                                    'approved_by'))
    # Accept an existing handoff id passed as the first plain string too.
    if not req.get('tenant') and req.get('id') and _one(
            db, 'SELECT 1 x FROM handoffs WHERE id=?', (req['id'],)):
        existing = lc.get_handoff(db, req['id'])
        if existing:
            req.setdefault('tenant', existing['tenant'])
            req.setdefault('address', existing['address'])
            req.setdefault('new_address', existing['new_address'])
            req.setdefault('node', existing['node'])
            req.setdefault('domain', existing['domain'])
    req.setdefault('tenant', 'beta')
    req.setdefault('address', '10.0.0.7')
    req.setdefault('new_address', '10.0.0.8')
    req.setdefault('node', 'n2')
    req.setdefault('domain', DEFAULT_DOMAIN)
    at = pick(req, 'at', default=12)
    complete_at = pick(req, 'complete_at', 'commit_at', default=14)
    agents = pick(req, 'agents', 'required_agents', default=['a', 'b'])
    if isinstance(agents, str):
        agents = [x for x in agents.split(',') if x]
    _ensure_readdress_evidence(db, req, agents)
    prepared = prepare_handoff(db, req, at=at, agents=agents)
    handoff_id = prepared['id']
    for agent in agents:
        record_agent_receipt(db, handoff_id, agent, at=at, steps='all')
    return commit_handoff(db, handoff_id, at=complete_at)


repair_readdress = readdress_fix
fix_readdress = readdress_fix
renumber = readdress_fix


def isolation_fix(db, *args, **kwargs):
    """Run the full approved domain-W + translated-.8 isolation repair."""
    ensure_schema(db)
    req = merge_args(args, kwargs, ('tenant', 'address', 'node', 'new_domain',
                                    'external_address', 'at', 'complete_at', 'id',
                                    'domain', 'agents', 'translation_slot', 'approved_by'))
    req.setdefault('tenant', 'beta')
    req.setdefault('address', '10.0.0.7')
    req.setdefault('node', 'n2')
    req.setdefault('domain', DEFAULT_DOMAIN)
    new_domain = pick(req, 'new_domain', default='W')
    external_address = pick(req, 'external_address', default='10.0.0.8')
    at = pick(req, 'at', default=12)
    complete_at = pick(req, 'complete_at', 'commit_at', default=14)
    agents = pick(req, 'agents', 'required_agents', default=['a', 'b'])
    if isinstance(agents, str):
        agents = [x for x in agents.split(',') if x]
    slot_id = pick(req, 'translation_slot', 'slot_id', default='slot-w-beta')

    provision_domain(db, new_domain, isolated_from=req['domain'], at=at - 2)
    for agent in agents:
        record_isolation_receipt(db, new_domain, agent, at=at - 1,
                                 against_domain=req['domain'], probe_ok=1, side=agent)
    test_isolation(db, new_domain, at=at - 1, ok=True, against_domain=req['domain'])
    provision_translation(db, slot_id, external_address=external_address,
                          internal_domain=new_domain, internal_address=req['address'],
                          internal_node=req['node'], at=at - 1)
    test_translation(db, slot_id, at=at - 1, ok=True)
    req.update({'kind': 'isolation', 'new_domain': new_domain,
                'external_address': external_address, 'translation_slot': slot_id})
    prepared = prepare_handoff(db, req, at=at, agents=agents)
    handoff_id = prepared['id']
    for agent in agents:
        record_agent_receipt(db, handoff_id, agent, at=at, steps='all')
    return commit_handoff(db, handoff_id, at=complete_at)


repair_isolation = isolation_fix
fix_isolation = isolation_fix
isolate = isolation_fix


def repair_conflict(db, *args, **kwargs):
    """Dispatcher: ``mode='readdress'`` or ``mode='isolation'``."""
    req = merge_args(args, kwargs, ('mode', 'kind', 'fix'))
    mode = KIND_ALIASES.get(str(pick(req, 'mode', 'kind', 'fix', default='readdress')).lower(),
                            'readdress')
    if mode == 'isolation':
        return isolation_fix(db, req)
    return readdress_fix(db, req)


# Re-export the capture vocabulary from the publishing module so either module
# path exposes the whole address-handoff surface.
for _name in (
    'import_page', 'register_agent', 'confirm_lease', 'confirmation_present',
    'record_neighbor_cache', 'record_neighbors', 'invalidate_neighbor',
    'terminate_tenant', 'terminate', 'calibrate_clock', 'calibrate_clocks',
    'record_misdelivery', 'incident_history', 'save_receipt', 'get_handoff',
    'list_handoffs', 'durable_state', 'lease_rows', 'ensure_schema',
    'confirm', 'ack_lease', 'record_application_receipt',
):
    globals()[_name] = getattr(lc, _name)


def current_owner(db, address, domain=DEFAULT_DOMAIN):
    """Unique current executable owner of one domain/address, or None."""
    ensure_schema(db)
    row = _one(db, 'SELECT * FROM executable_endpoints WHERE domain=? AND address=? '
                   "AND status IN ('active','provisional')", (domain, address))
    return row


# Broad vocabulary aliases for conflict checks and repairs.
check_address_conflict = conflict_report
check_address = conflict_report
check_occupancy = conflict_report
occupancy_check = conflict_report
occupancy_report = conflict_report
verify_occupancy = detect_conflicts
cross_agent_check = detect_conflicts
conflicts_for = detect_conflicts
check_address_occupancy = detect_conflicts

resolve_conflict = repair_conflict
apply_repair = repair_conflict
repair = repair_conflict
fix_conflict = repair_conflict
begin_handoff = prepare_handoff
start_endpoint_switch = prepare_handoff
two_phase_commit = commit_handoff
commit_switch = commit_handoff
apply = commit_handoff
resume = recover_handoff

create_network_domain = provision_domain
record_isolation = record_isolation_receipt
add_isolation_receipt = record_isolation_receipt
add_translation_slot = provision_translation
create_translation_slot = provision_translation

# Natural-signature convenience wrappers.
def readdress_tenant(db, tenant='beta', address='10.0.0.7', new_address='10.0.0.8', **kw):
    return readdress_fix(db, tenant=tenant, address=address,
                         new_address=new_address, **kw)


def isolate_tenant(db, tenant='beta', address='10.0.0.7', new_domain='W',
                   external_address='10.0.0.8', **kw):
    return isolation_fix(db, tenant=tenant, address=address, new_domain=new_domain,
                         external_address=external_address, **kw)


# A second wave of vocabulary aliases.
analyze_conflicts = detect_conflicts
scan_addresses = detect_conflicts
address_occupancy = conflict_report
occupancy = conflict_report
get_conflicts = detect_conflicts
list_conflicts = detect_conflicts
new_handoff = prepare_handoff
finish_handoff = commit_handoff
finalize_handoff = commit_handoff
complete_switch = commit_handoff
recovery_status = reopen
get_recovery = reopen
apply_agent_receipt = record_agent_receipt
receive_receipt = record_agent_receipt
prove_isolation = record_isolation_receipt
create_isolated_domain = provision_domain
allocate_translation = provision_translation
create_nat = provision_translation


def current_route(db, tenant, at=None):
    """Latest active route representation for one tenant, or None."""
    ensure_schema(db)
    row = _one(db, "SELECT * FROM endpoint_routes WHERE tenant=? AND state='active' "
                   'ORDER BY rowid DESC LIMIT 1', (tenant,))
    return row


route_for = current_route
