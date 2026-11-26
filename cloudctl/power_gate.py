"""Power gating: naive provisional permits plus safe traceable transfers.

``energize`` is the original per-node primitive and is kept byte-for-byte in
behaviour (the seed test pins it).  It intentionally only looks at the latest
reading of one source for one node and therefore can leave two independent
6/10 permits on the same bus.

The safe path is :func:`sign_transfer`.  A transfer ticket can only be signed
when *real* evidence agrees:

1. physical contact readbacks prove every other external source is open
   (an open command or a dispatch "success" receipt is not proof);
2. the target source contact is physically closed and an on-load measurement
   confirms the actual transfer;
3. source available power and the total load of running nodes are evaluated
   for the *same minute* using evidence that had actually arrived by then;
4. optional battery bridges are debited from measured charge using the actual
   per-minute draws, with no guesswork across missing/late minutes.

Every submission is immutable by id: same id + same request replays the
original decision, different content conflicts.  A held ticket can never
mutate into a signed one under the same id -- a new ticket id is required
after new physical evidence arrives.
"""
import json

from . import feed_capture as fc


def energize(db, node, bus, source, draw_kw, at):
    db.execute('CREATE TABLE IF NOT EXISTS power_permits (node TEXT,bus TEXT,source TEXT,draw_kw INTEGER,at INTEGER,decision TEXT)')
    try:
        row = db.execute('SELECT voltage,available_kw FROM feed_rows WHERE bus=? AND source=? ORDER BY tick DESC LIMIT 1', (bus, source)).fetchone()
    except __import__('sqlite3').OperationalError:
        row = None
    decision = 'permit' if row and row[0] >= 220 and row[1] >= draw_kw else 'hold'
    with db:
        db.execute('INSERT INTO power_permits VALUES (?,?,?,?,?,?)', (node, bus, source, draw_kw, at, decision))
    return {'node': node, 'bus': bus, 'source': source, 'decision': decision}


GATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS transfer_tickets (
    ticket_id TEXT PRIMARY KEY,
    bus TEXT, source TEXT, at INTEGER,
    total_kw REAL, available_kw REAL,
    decision TEXT, reasons TEXT, request TEXT, digest TEXT
);
CREATE TABLE IF NOT EXISTS transfer_ticket_nodes (
    ticket_id TEXT, node TEXT, draw_kw REAL,
    PRIMARY KEY (ticket_id, node)
);
CREATE TABLE IF NOT EXISTS service_certificates (
    cert_id TEXT PRIMARY KEY,
    node TEXT, bus TEXT, start_tick INTEGER, end_tick INTEGER, at INTEGER,
    battery TEXT, decision TEXT, reasons TEXT, detail TEXT, digest TEXT
);
"""

VOLTAGE_MIN = 220.0
_EPS = 1e-9
# Marker used on load rows that are served by a node-local battery branch
# rather than by any external bus source; never an interlock participant.
BRANCH_MARKERS = {'battery'}


def ensure_schema(db):
    fc.ensure_schema(db)
    db.executescript(GATE_SCHEMA)
    return db


def _digest(obj):
    return fc._digest(obj)


def _dicts(db, sql, args=()):
    cur = db.execute(sql, args)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def normalize_nodes(nodes):
    out = {}
    order = []
    if not isinstance(nodes, (list, tuple)):
        raise ValueError('invalid_nodes')
    for item in nodes:
        if isinstance(item, dict):
            node = item.get('node')
            kw = item.get('draw_kw', item.get('kw'))
        else:
            node, kw = item[0], item[1]
        if not node or not isinstance(node, str):
            raise ValueError('invalid_node_id')
        if not fc._num(kw) or kw < 0:
            raise ValueError('invalid_draw_kw')
        if node in out and abs(out[node] - float(kw)) > _EPS:
            raise ValueError('duplicate_node_draw_conflict')
        if node not in out:
            order.append(node)
        out[node] = float(kw)
    return [{'node': n, 'draw_kw': out[n]} for n in order]


# ---------------------------------------------------------------------------
# Physical contact / source / load read helpers
# ---------------------------------------------------------------------------

def latest_contact(db, bus, source, at):
    """Latest physical readback arrived by ``at`` (highest tick, then seq).

    Contradictory readbacks at the same maximum tick are returned with
    ``ambiguous=True`` so the gate fails closed instead of silently picking
    the last insertion.
    """
    rows = _dicts(
        db,
        'SELECT doc_id,state,welded,tick,received_at,seq FROM contact_readbacks '
        'WHERE bus=? AND source=? AND received_at<=? '
        'ORDER BY tick DESC, seq DESC',
        (bus, source, at),
    )
    if not rows:
        return None
    latest = rows[0]
    latest['welded'] = bool(latest['welded'])
    top = [r for r in rows if r['tick'] == latest['tick']]
    variants = {(r['state'], bool(r['welded'])) for r in top}
    if len(variants) > 1:
        latest = dict(latest)
        latest['ambiguous'] = True
    return latest


contact_readback = latest_contact


def known_sources(db, bus):
    sources = set()
    if fc._table_exists(db, 'feed_rows'):
        sources.update(r[0] for r in db.execute(
            'SELECT DISTINCT source FROM feed_rows WHERE bus=?', (bus,)).fetchall())
    if fc._table_exists(db, 'contact_readbacks'):
        sources.update(r[0] for r in db.execute(
            'SELECT DISTINCT source FROM contact_readbacks WHERE bus=?', (bus,)).fetchall())
    if fc._table_exists(db, 'load_measurements'):
        sources.update(r[0] for r in db.execute(
            'SELECT DISTINCT source FROM load_measurements WHERE bus=?', (bus,)).fetchall())
    if fc._table_exists(db, 'transfer_tickets'):
        sources.update(r[0] for r in db.execute(
            'SELECT DISTINCT source FROM transfer_tickets WHERE bus=?', (bus,)).fetchall())
    sources.discard(None)
    for marker in BRANCH_MARKERS:
        sources.discard(marker)
    return sources


def supply_for_minute(db, bus, source, tick, at=None):
    """Same-minute supply reading that had actually arrived by ``at``.

    Returns ``None`` when there is no exact ``tick`` reading (so a late
    minute-12 "230V normal" report cannot be reused at minute 13), or
    ``{'conflict': True, ...}`` when arrived same-minute readings disagree.
    """
    if at is None:
        at = tick
    readings = _dicts(
        db,
        'SELECT r.voltage AS voltage, r.available_kw AS available_kw, p.received_at AS received_at '
        'FROM feed_rows r JOIN feed_pages p ON p.id = r.page_id '
        'WHERE r.bus=? AND r.source=? AND r.tick=? AND p.received_at<=?',
        (bus, source, tick, at),
    )
    pairs = {(r['voltage'], r['available_kw']) for r in readings}
    if len(pairs) > 1:
        return {'conflict': True, 'readings': readings}
    if len(pairs) == 1:
        v, a = next(iter(pairs))
        return {'voltage': float(v), 'available_kw': float(a), 'readings': readings}

    loads = _dicts(
        db,
        'SELECT voltage, available_kw, received_at FROM load_measurements '
        'WHERE bus=? AND source=? AND tick=? AND received_at<=? AND available_kw IS NOT NULL',
        (bus, source, tick, at),
    )
    pairs = {(r['voltage'], r['available_kw']) for r in loads}
    if len(pairs) > 1:
        return {'conflict': True, 'readings': loads}
    if len(pairs) == 1:
        v, a = next(iter(pairs))
        return {'voltage': None if v is None else float(v),
                'available_kw': float(a), 'readings': loads}
    return None


def node_loads_for_minute(db, bus, tick, at=None):
    if at is None:
        at = tick
    return _dicts(
        db,
        'SELECT node,source,load_kw,voltage,received_at FROM load_measurements '
        'WHERE bus=? AND tick=? AND node IS NOT NULL AND received_at<=?',
        (bus, tick, at),
    )


def source_onload_measurement(db, bus, source, tick, at=None):
    """Source/bus-level on-load measurement (node IS NULL)."""
    if at is None:
        at = tick
    rows = _dicts(
        db,
        'SELECT load_kw,voltage,available_kw,received_at,doc_id FROM load_measurements '
        'WHERE bus=? AND source=? AND tick=? AND node IS NULL AND received_at<=? '
        'ORDER BY seq DESC LIMIT 1',
        (bus, source, tick, at),
    )
    return rows[0] if rows else None


def other_source_loaded(db, bus, source, tick, at=None):
    """Source-level on-load rows for any other external source at this minute."""
    if at is None:
        at = tick
    return _dicts(
        db,
        'SELECT source,load_kw,tick FROM load_measurements '
        'WHERE bus=? AND tick=? AND node IS NULL AND received_at<=? '
        'AND source<>? AND load_kw>0',
        (bus, tick, at, source),
    )


def bus_load_kw(db, bus, tick, at=None, include_battery=False):
    """Same-minute metered load of running nodes on the bus.

    Battery-branch nodes are on their own verified branches and are excluded
    from external-source loading unless explicitly requested.
    """
    rows = node_loads_for_minute(db, bus, tick, at)
    total = 0.0
    for r in rows:
        if not include_battery and r['source'] == 'battery':
            continue
        total += float(r['load_kw'])
    return total


def active_source(db, bus):
    """Source of the most recently signed transfer ticket for the bus."""
    rows = db.execute(
        "SELECT source FROM transfer_tickets WHERE bus=? AND decision='signed' "
        'ORDER BY rowid DESC LIMIT 1', (bus,)).fetchall() if fc._table_exists(db, 'transfer_tickets') else []
    return rows[0][0] if rows else None


# ---------------------------------------------------------------------------
# Battery bridge accounting (电池耗量)
# ---------------------------------------------------------------------------

def battery_feasibility(charge_kwmin, max_discharge_kw, draw_kw, minutes):
    """Static pre-check of a planned bridge (measured charge vs demand)."""
    reasons = []
    required_energy = float(draw_kw) * int(minutes)
    if not fc._num(charge_kwmin) or charge_kwmin < 0:
        raise ValueError('invalid_battery_charge')
    if float(max_discharge_kw) + _EPS < float(draw_kw):
        reasons.append('battery_discharge_limit')
    if float(charge_kwmin) + _EPS < required_energy:
        reasons.append('battery_energy_shortfall')
    return {'ok': not reasons, 'reasons': reasons,
            'charge_kwmin': float(charge_kwmin),
            'max_discharge_kw': float(max_discharge_kw),
            'draw_kw': float(draw_kw), 'minutes': int(minutes),
            'required_kwmin': required_energy}


check_battery = battery_feasibility


def verify_bridge(db, battery, start_tick, end_tick, at=None, node=None, planned_draw_kw=None):
    """Verify an actual battery bridge using measured charge and draw ledger.

    Every minute in ``[start_tick, end_tick]`` must have an actual draw entry
    that had arrived by ``at``.  The balance is the measured baseline charge
    minus the ledger debits; a later optimistic telemetry report is never
    credited back, and a missing/late minute makes the bridge unverifiable
    instead of being guessed.
    """
    ensure_schema(db)
    if at is None:
        at = end_tick
    start_tick, end_tick = int(start_tick), int(end_tick)
    required_ticks = list(range(start_tick, end_tick + 1))
    result = {'ok': False, 'battery': battery, 'node': node,
              'start_tick': start_tick, 'end_tick': end_tick, 'at': at,
              'required_ticks': required_ticks, 'missing_ticks': list(required_ticks),
              'entries': [], 'consumed_kwmin': 0.0, 'charge_kwmin': None,
              'balance_kwmin': None, 'max_discharge_kw': None,
              'reasons': []}

    base = _dicts(
        db,
        'SELECT charge_kwmin,max_discharge_kw,tick,received_at FROM battery_reports '
        'WHERE battery=? AND tick<=? AND received_at<=? '
        'ORDER BY tick DESC, seq DESC LIMIT 1',
        (battery, start_tick, start_tick),
    )
    if not base:
        result['reasons'].append('battery_baseline_missing')
        return result
    base = base[0]
    charge = float(base['charge_kwmin'])
    max_kw = float(base['max_discharge_kw'])
    result['charge_kwmin'] = charge
    result['max_discharge_kw'] = max_kw

    if planned_draw_kw is not None and max_kw + _EPS < float(planned_draw_kw):
        result['reasons'].append('battery_discharge_limit')

    draws = _dicts(
        db,
        'SELECT entry_id,tick,draw_kw,energy_kwmin,received_at FROM battery_draws '
        'WHERE battery=? AND tick BETWEEN ? AND ? AND received_at<=? ORDER BY tick',
        (battery, start_tick, end_tick, at),
    )
    by_tick = {int(d['tick']): d for d in draws}
    result['entries'] = draws
    missing = [t for t in required_ticks if t not in by_tick]
    result['missing_ticks'] = missing
    if missing:
        result['reasons'].append('battery_draw_incomplete')

    consumed = 0.0
    balance = charge
    depleted_at = None
    for t in required_ticks:
        d = by_tick.get(t)
        if not d:
            continue
        kw = float(d['draw_kw'])
        energy = float(d['energy_kwmin'])
        if max_kw + _EPS < kw:
            result['reasons'].append('battery_discharge_limit:tick%d' % t)
        consumed += energy
        balance -= energy
        if balance < -_EPS and depleted_at is None:
            depleted_at = t
    result['consumed_kwmin'] = consumed
    result['balance_kwmin'] = balance
    if depleted_at is not None:
        result['depleted_at'] = depleted_at
        result['reasons'].append('battery_energy_shortfall')
    if not missing and balance + _EPS >= 0 and not any(
            r.startswith('battery_discharge_limit') for r in result['reasons']) \
            and 'battery_energy_shortfall' not in result['reasons']:
        result['ok'] = True
    return result


verify_battery_bridge = verify_bridge


# ---------------------------------------------------------------------------
# Transfer evaluation / signing
# ---------------------------------------------------------------------------

def _normalize_bridges(bridges):
    out = []
    for b in bridges or []:
        if isinstance(b, str):
            out.append({'battery': b})
        else:
            out.append(dict(b))
    return out


def evaluate_transfer(db, bus, source, nodes, at, bridges=None):
    """Pure assessment (does not persist anything)."""
    ensure_schema(db)
    node_list = normalize_nodes(nodes)
    bridges = _normalize_bridges(bridges)
    reasons = []
    detail = {'bus': bus, 'source': source, 'at': at, 'nodes': node_list}

    if not node_list:
        reasons.append('no_load_nodes')

    # 1) Interlock: every other known external source contact must be open
    #    according to a *physical readback* that has arrived by ``at``.
    interlock = {}
    for other in sorted(known_sources(db, bus) - {source}):
        rb = latest_contact(db, bus, other, at)
        if rb is None:
            interlock[other] = 'unverified'
            reasons.append('contact_open_unverified:%s' % other)
        elif rb.get('ambiguous'):
            interlock[other] = 'ambiguous'
            reasons.append('contact_readback_conflict:%s' % other)
            reasons.append('contact_open_unverified:%s' % other)
        elif rb['welded']:
            interlock[other] = 'welded'
            reasons.append('contact_welded:%s' % other)
            reasons.append('backfeed_risk')
        elif rb['state'] != 'open':
            interlock[other] = rb['state']
            reasons.append('contact_closed:%s' % other)
            reasons.append('backfeed_risk')
        else:
            interlock[other] = 'open'
    detail['interlock'] = interlock

    target = latest_contact(db, bus, source, at)
    detail['target_contact'] = target
    if not target or target.get('ambiguous') or target['state'] != 'closed' or target['welded']:
        reasons.append('target_close_unverified')

    # 2) Same-minute supply that had actually arrived.
    supply = supply_for_minute(db, bus, source, int(at), int(at))
    available = None
    detail['supply'] = supply
    if supply is None:
        reasons.append('same_minute_supply_missing')
    elif supply.get('conflict'):
        reasons.append('same_minute_telemetry_conflict')
    else:
        available = supply['available_kw']
        if supply.get('voltage') is not None and supply['voltage'] < VOLTAGE_MIN:
            reasons.append('source_undervoltage')
    detail['available_kw'] = available

    # 3) Same-minute metered running load, merged with the ticket request.
    merged = {n['node']: n['draw_kw'] for n in node_list}
    unlisted = []
    parallel = []
    for m in node_loads_for_minute(db, bus, int(at), int(at)):
        n = m['node']
        if m['source'] and m['source'] not in (source, 'battery') and float(m['load_kw']) > 0:
            parallel.append(n)
            reasons.append('parallel_feed_detected:%s@%s' % (n, m['source']))
        if m['source'] == 'battery':
            # On its own battery branch: not load on the external source.
            if n not in merged:
                continue
        if n in merged:
            if abs(float(m['load_kw']) - merged[n]) > _EPS:
                reasons.append('load_mismatch:%s' % n)
        else:
            merged[n] = float(m['load_kw'])
            unlisted.append(n)
    detail['unlisted_running_nodes'] = unlisted

    for ol in other_source_loaded(db, bus, source, int(at), int(at)):
        reasons.append('parallel_feed_detected:source:%s' % ol['source'])

    total_kw = round(sum(merged.values()), 6)
    detail['total_kw'] = total_kw
    detail['load_accounts'] = merged

    # 4) Capacity: one source, same-minute total running load.
    if available is not None and total_kw - available > _EPS:
        reasons.append('capacity_exceeded')
    detail['headroom_kw'] = None if available is None else round(available - total_kw, 6)

    # 5) On-load measurement confirming the real transfer at this minute.
    olm = source_onload_measurement(db, bus, source, int(at), int(at))
    detail['on_load'] = olm
    if olm is None:
        reasons.append('on_load_measurement_missing')
    else:
        if abs(float(olm['load_kw']) - total_kw) > _EPS:
            reasons.append('on_load_mismatch')
        if olm['voltage'] is not None and float(olm['voltage']) < VOLTAGE_MIN:
            reasons.append('on_load_undervoltage')

    # 6) Battery bridges for nodes whose continued service is claimed.
    bridge_results = []
    for b in bridges:
        br = verify_bridge(db, at=at, **b)
        bridge_results.append({k: v for k, v in br.items() if k != 'entries'})
        if not br['ok']:
            reasons.append('battery_bridge_unverified:%s' % br['battery'])
    detail['bridges'] = bridge_results

    ok = not reasons
    return {'ok': ok, 'decision': 'signable' if ok else 'blocked',
            'reasons': reasons, **detail}


assess_transfer = evaluate_transfer
review_transfer = evaluate_transfer


def _ticket_request(bus, source, node_list, at, bridges):
    return {'bus': bus, 'source': source, 'at': int(at),
            'nodes': sorted(node_list, key=lambda n: n['node']),
            'bridges': sorted(bridges, key=lambda b: json.dumps(b, sort_keys=True))}


def sign_transfer(db, ticket_id, bus, source, nodes, at, bridges=None):
    """Sign an immutable, traceable actual-transfer ticket.

    Returns the stored decision.  First submission evaluates current evidence
    and is ``signed`` only when every gate passes, otherwise ``held``.
    Replaying the same ``ticket_id`` + identical request returns the original
    decision; changing the request conflicts.
    """
    ensure_schema(db)
    node_list = normalize_nodes(nodes)
    bridges = _normalize_bridges(bridges)
    request = _ticket_request(bus, source, node_list, at, bridges)
    digest = _digest(request)

    old = _dicts(db, 'SELECT * FROM transfer_tickets WHERE ticket_id=?', (ticket_id,))
    if old:
        row = old[0]
        if row['digest'] != digest:
            fc.reject_conflict(db, ticket_id, 'transfer_ticket', request, int(at),
                               old_digest=row['digest'],
                               code='transfer_ticket_conflict')
        stored_nodes = _dicts(db, 'SELECT node,draw_kw FROM transfer_ticket_nodes WHERE ticket_id=?',
                              (ticket_id,))
        return {'status': 'replayed', 'ticket_id': ticket_id,
                'decision': row['decision'], 'ok': row['decision'] == 'signed',
                'reasons': json.loads(row['reasons']),
                'bus': row['bus'], 'source': row['source'], 'at': row['at'],
                'total_kw': row['total_kw'], 'available_kw': row['available_kw'],
                'nodes': stored_nodes}

    ev = evaluate_transfer(db, bus, source, node_list, at, bridges)
    decision = 'signed' if ev['ok'] else 'held'
    ticket_payload = dict(request)
    ticket_payload.update({'decision': decision, 'reasons': ev['reasons']})
    with db:
        db.execute(
            'INSERT INTO transfer_tickets VALUES (?,?,?,?,?,?,?,?,?,?)',
            (ticket_id, bus, source, int(at), ev['total_kw'], ev.get('available_kw'),
             decision, json.dumps(ev['reasons'], ensure_ascii=False),
             json.dumps(request, sort_keys=True, ensure_ascii=False), digest),
        )
        for n in node_list:
            db.execute('INSERT INTO transfer_ticket_nodes VALUES (?,?,?)',
                       (ticket_id, n['node'], n['draw_kw']))
        # Preserve the ticket original in the unified arrival ledger too.
        fc._store_evidence(db, 'ticket:' + ticket_id, 'transfer_ticket',
                           ticket_payload, int(at), int(at))
    result = dict(ev)
    result.update({'status': 'created', 'ticket_id': ticket_id,
                   'decision': decision, 'ok': ev['ok']})
    return result


issue_transfer_ticket = sign_transfer
create_transfer_ticket = sign_transfer
approve_transfer = sign_transfer
request_transfer = sign_transfer


# ---------------------------------------------------------------------------
# Continuous-service certificates (连续服务证明, battery-backed)
# ---------------------------------------------------------------------------

def certify_service(db, cert_id, node, bus, start_tick, end_tick, at, battery):
    """Certify continuous service over an interval.

    A missing/late battery minute or an energy shortfall yields a persisted
    ``refused`` certificate -- never a guessed claim of continuity.
    """
    ensure_schema(db)
    request = {'cert_id': cert_id, 'node': node, 'bus': bus,
               'start_tick': int(start_tick), 'end_tick': int(end_tick),
               'at': int(at), 'battery': battery}
    digest = _digest(request)
    old = _dicts(db, 'SELECT * FROM service_certificates WHERE cert_id=?', (cert_id,))
    if old:
        row = old[0]
        if row['digest'] != digest:
            fc.reject_conflict(db, cert_id, 'service_certificate', request, int(at),
                               old_digest=row['digest'],
                               code='service_certificate_conflict')
        return {'status': 'replayed', 'cert_id': cert_id,
                'decision': row['decision'], 'ok': row['decision'] == 'certified',
                'reasons': json.loads(row['reasons']),
                'bridge': json.loads(row['detail'])}

    bridge = verify_bridge(db, battery, start_tick, end_tick, at=at, node=node)
    decision = 'certified' if bridge['ok'] else 'refused'
    detail = {k: v for k, v in bridge.items() if k != 'entries'}
    with db:
        db.execute('INSERT INTO service_certificates VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                   (cert_id, node, bus, int(start_tick), int(end_tick), int(at), battery,
                    decision, json.dumps(bridge['reasons'], ensure_ascii=False),
                    json.dumps(detail, ensure_ascii=False, sort_keys=True),
                    digest))
        fc._store_evidence(db, 'cert:' + cert_id, 'service_certificate',
                           dict(request, decision=decision,
                                reasons=bridge['reasons']), int(at), int(at))
    return {'status': 'created', 'cert_id': cert_id,
            'decision': decision, 'ok': bridge['ok'],
            'reasons': bridge['reasons'], 'bridge': bridge}


# ---------------------------------------------------------------------------
# Whole-incident replay (事故原件按到达次序重放)
# ---------------------------------------------------------------------------

def replay_messages(db, messages):
    """Replay an ordered list of preserved incident originals.

    Each message uses a ``kind`` discriminator matching the ``feed_capture``
    / gate capture helpers.  Because every intake is idempotent, replaying the
    same fixture twice returns the same stored decisions without duplication.
    """
    ensure_schema(db)
    out = []
    for m in messages:
        kind = m.get('kind')
        if kind == 'page':
            res = fc.import_page(db, m['page_id'], m['rows'], m['received_at'])
        elif kind == 'evidence':
            res = fc.put_evidence(db, m['id'], m['evidence_kind'], m['payload'],
                                  m['received_at'], m.get('occurred_at'))
        elif kind == 'contact':
            res = fc.capture_contact(
                db, m['id'], m['bus'], m['source'], m['state'], m['tick'],
                m['received_at'], welded=m.get('welded', False))
        elif kind == 'command':
            res = fc.capture_command(
                db, m['id'], m['bus'], m['source'], m['action'], m['issued_at'],
                m.get('received_at'))
        elif kind == 'receipt':
            res = fc.capture_receipt(
                db, m['id'], m['command_id'], m['received_at'],
                m.get('dispatch_success', True))
        elif kind == 'outage_start':
            res = fc.capture_outage_start(
                db, m['outage_id'], m['bus'], m['tick'], m.get('received_at'))
        elif kind == 'outage_end':
            res = fc.capture_outage_end(
                db, m['outage_id'], m['bus'], m['tick'], m.get('received_at'))
        elif kind == 'battery':
            res = fc.capture_battery(
                db, m['id'], m['battery'], m['tick'], m['received_at'],
                charge_kwmin=m.get('charge_kwmin'),
                max_discharge_kw=m.get('max_discharge_kw'), node=m.get('node'),
                charge_kwh=m.get('charge_kwh'), draw_kw=m.get('draw_kw'),
                energy_kwmin=m.get('energy_kwmin'))
        elif kind == 'battery_draw':
            res = fc.capture_battery_draw(
                db, m['id'], m['battery'], m['tick'], m['draw_kw'],
                m['received_at'], minutes=m.get('minutes', 1),
                energy_kwmin=m.get('energy_kwmin'), node=m.get('node'))
        elif kind == 'load':
            res = fc.capture_load(
                db, m['id'], m['bus'], m['source'], m['tick'], m['load_kw'],
                m['received_at'], voltage=m.get('voltage'),
                available_kw=m.get('available_kw'), node=m.get('node'))
        elif kind == 'service':
            res = fc.record_service(
                db, m['id'], m['node'], m['bus'], m['tick'], m['state'],
                m['received_at'], source=m.get('source'), draw_kw=m.get('draw_kw'),
                reason=m.get('reason'))
        elif kind == 'ticket':
            res = sign_transfer(
                db, m['ticket_id'], m['bus'], m['source'], m['nodes'], m['at'],
                m.get('bridges'))
        elif kind == 'certificate':
            res = certify_service(
                db, m['cert_id'], m['node'], m['bus'], m['start_tick'],
                m['end_tick'], m['at'], m['battery'])
        else:
            raise ValueError('unknown_message_kind:%r' % kind)
        out.append(res)
    return out


# Incident archiving convenience re-exports.
build_incident_archive = fc.build_archive
archive_incident = fc.seal_archive
seal_incident_archive = fc.seal_archive

# Small vocabulary alias surface for integrators / alternative naming.
evaluate = evaluate_transfer
check_transfer = evaluate_transfer
gate_transfer = evaluate_transfer
review = evaluate_transfer
transfer = sign_transfer
transfer_power = sign_transfer
execute_transfer = sign_transfer
request_power = sign_transfer
create_transfer = sign_transfer
issue_ticket = sign_transfer
sign_ticket = sign_transfer
permit_transfer = sign_transfer
create_permit = sign_transfer
issue_permit = sign_transfer
safe_energize = sign_transfer
bus_total_load = bus_load_kw
account_battery_bridge = verify_bridge
certify_continuous_service = certify_service
continuous_service_certificate = certify_service
