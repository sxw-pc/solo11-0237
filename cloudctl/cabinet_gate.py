"""Cabinet cooling operation decisions.

A cabinet permit is an operating decision about the *physical branch* that
actually feeds the cabinet, not a copy of the shared header ticket.  Every
load-bearing cabinet needs, for the whole permitted minute:

* branch supply of at least ``BRANCH_MIN_FLOW`` L/min and return water no
  hotter than ``MAX_RETURN_TEMP``;
* a fresh sample for that minute -- two minutes without a sample is a hold,
  the previous good reading is never inherited;
* a physically consistent supply split across header and branches, using
  supply meters only (return/bypass meters never count as supply);
* one common batch calibration applied identically to header and branches.

Remote valve/pump actions are only *requests*.  A field application receipt,
followed by fresh branch measurements, is required before a ticket changes.
Every page, calibration, correction, command, receipt, ticket, incident and
shutdown minute is persisted so the whole chain is traceable after a restart;
the (cabinet, minute) ticket is unique and conflicting re-submissions can
never overwrite a signed ticket.
"""
import hashlib
import json
import sqlite3

from .cooling_capture import evaluate_meter, supply_balance
from .thermal_gate import header_ticket

BRANCH_MIN_FLOW = 45
MAX_RETURN_TEMP = 30
PUMP_MIN_FLOW = 60
PUMP_MAX_TEMP = 27
RECOVERY_MINUTES = 2


def _digest(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()


def ensure_schema(db):
    db.execute('CREATE TABLE IF NOT EXISTS cooling_sites ('
               'site_id TEXT PRIMARY KEY,main_meter TEXT,branch_meters TEXT,'
               'return_meters TEXT,bypass_meters TEXT,digest TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS cooling_topology ('
               'meter TEXT PRIMARY KEY,loop TEXT,role TEXT,site_id TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS cabinet_branches ('
               'cabinet TEXT PRIMARY KEY,branch_meter TEXT,branch_loop TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS cabinet_permits ('
               'cabinet TEXT,at INTEGER,decision TEXT,reason TEXT,'
               'evidence TEXT,ticket_id TEXT,kind TEXT DEFAULT \'normal\','
               'PRIMARY KEY(cabinet,at))')
    db.execute('CREATE TABLE IF NOT EXISTS cooling_commands ('
               'command_id TEXT PRIMARY KEY,kind TEXT,target TEXT,at INTEGER,'
               'digest TEXT,received_at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS cooling_receipts ('
               'receipt_id TEXT PRIMARY KEY,command_id TEXT UNIQUE,'
               'target TEXT,applied_at INTEGER,digest TEXT,received_at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS shutdown_minutes ('
               'cabinet TEXT,tick INTEGER,reason TEXT,PRIMARY KEY(cabinet,tick))')
    db.execute('CREATE TABLE IF NOT EXISTS pump_ledger ('
               'cabinet TEXT,at INTEGER,receipt_id TEXT,PRIMARY KEY(cabinet,at))')
    db.execute('CREATE TABLE IF NOT EXISTS cooling_incidents ('
               'incident_id TEXT PRIMARY KEY,kind TEXT,cabinet TEXT,at INTEGER,'
               'detail TEXT,recorded_at INTEGER,digest TEXT,'
               'UNIQUE(kind,cabinet,at))')


# ---------------------------------------------------------------- topology

def register_topology(db, site_id, main_meter, branches,
                      return_meters=None, bypass_meters=None, received_at=0):
    """Register the physical plumbing.

    ``branches`` is a list of ``{'meter','loop'}`` supply branches. Return and
    bypass meters are recorded with their real role so they can never be
    counted as supply.
    """
    ensure_schema(db)
    return_meters = return_meters or []
    bypass_meters = bypass_meters or []
    branch_meters = [b['meter'] for b in branches]
    payload = {'main_meter': main_meter, 'branches': branches,
               'return_meters': return_meters, 'bypass_meters': bypass_meters}
    digest = _digest(payload)
    old = db.execute('SELECT digest FROM cooling_sites WHERE site_id=?', (site_id,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('topology_conflict')
        return {'status': 'replayed', 'site_id': site_id}
    with db:
        db.execute('INSERT INTO cooling_sites VALUES (?,?,?,?,?,?)',
                   (site_id, main_meter, json.dumps(branch_meters),
                    json.dumps(return_meters), json.dumps(bypass_meters), digest))
        db.execute('INSERT INTO cooling_topology VALUES (?,?,?,?)',
                   (main_meter, main_meter, 'main', site_id))
        for b in branches:
            db.execute('INSERT INTO cooling_topology VALUES (?,?,?,?)',
                       (b['meter'], b['loop'], 'branch', site_id))
        for m in return_meters:
            db.execute('INSERT INTO cooling_topology VALUES (?,?,?,?)',
                       (m, m, 'return', site_id))
        for m in bypass_meters:
            db.execute('INSERT INTO cooling_topology VALUES (?,?,?,?)',
                       (m, m, 'bypass', site_id))
    return {'status': 'registered', 'site_id': site_id,
            'branches': branch_meters, 'digest': digest}


def link_cabinet(db, cabinet, branch_meter):
    ensure_schema(db)
    row = db.execute('SELECT loop FROM cooling_topology WHERE meter=? AND role=?',
                     (branch_meter, 'branch')).fetchone()
    if not row:
        raise ValueError('branch_not_registered')
    old = db.execute('SELECT branch_meter FROM cabinet_branches WHERE cabinet=?',
                     (cabinet,)).fetchone()
    if old:
        if old[0] != branch_meter:
            raise ValueError('cabinet_relocation_conflict')
        return {'status': 'replayed', 'cabinet': cabinet}
    with db:
        db.execute('INSERT INTO cabinet_branches VALUES (?,?,?)',
                   (cabinet, branch_meter, row[0]))
    return {'status': 'linked', 'cabinet': cabinet, 'branch_meter': branch_meter}


def _site_for(db, branch_meter):
    for site_id, main_meter, branches_json, _, _ in db.execute(
            'SELECT site_id,main_meter,branch_meters,return_meters,bypass_meters FROM cooling_sites'):
        if branch_meter in json.loads(branches_json):
            return site_id, main_meter, json.loads(branches_json)
    return None, None, None


# ------------------------------------------------------- commands/receipts

def request_command(db, command_id, kind, target, at, content, received_at=None):
    """A remote command is only a request until a field receipt comes back."""
    ensure_schema(db)
    if kind not in ('valve_close', 'pump_start'):
        raise ValueError('unknown_command_kind')
    received_at = received_at if received_at is not None else at
    digest = _digest({'kind': kind, 'target': target, 'at': at, 'content': content})
    old = db.execute('SELECT digest FROM cooling_commands WHERE command_id=?',
                     (command_id,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('command_conflict')
        return {'status': 'replayed', 'command_id': command_id}
    with db:
        db.execute('INSERT INTO cooling_commands VALUES (?,?,?,?,?,?)',
                   (command_id, kind, target, at, digest, received_at))
    return {'status': 'requested', 'command_id': command_id, 'kind': kind}


def apply_receipt(db, receipt_id, command_id, applied_at, content, received_at=None):
    """Field acknowledgement that the command was physically applied."""
    ensure_schema(db)
    command = db.execute('SELECT kind,target FROM cooling_commands WHERE command_id=?',
                         (command_id,)).fetchone()
    if not command:
        raise ValueError('receipt_without_command')
    received_at = received_at if received_at is not None else applied_at
    digest = _digest({'command_id': command_id, 'applied_at': applied_at,
                      'content': content})
    old = db.execute('SELECT receipt_id,digest FROM cooling_receipts WHERE command_id=?',
                     (command_id,)).fetchone()
    if old:
        if old[1] != digest:
            raise ValueError('receipt_conflict')
        return {'status': 'replayed', 'receipt_id': old[0], 'command_id': command_id}
    try:
        with db:
            db.execute('INSERT INTO cooling_receipts VALUES (?,?,?,?,?,?)',
                       (receipt_id, command_id, command[1], applied_at,
                        digest, received_at))
    except sqlite3.IntegrityError:
        raise ValueError('receipt_id_conflict')
    return {'status': 'applied', 'receipt_id': receipt_id,
            'command_id': command_id, 'kind': command[0], 'applied_at': applied_at}


def _receipt(db, kind, target, at):
    row = db.execute('SELECT r.receipt_id,r.applied_at FROM cooling_receipts r '
                     'JOIN cooling_commands c ON c.command_id=r.command_id '
                     'WHERE c.kind=? AND c.target=? AND r.applied_at<=? '
                     'ORDER BY r.applied_at DESC LIMIT 1', (kind, target, at)).fetchone()
    return {'receipt_id': row[0], 'applied_at': row[1]} if row else None


# ------------------------------------------------------------- downtime

def record_shutdown(db, cabinet, tick, reason):
    ensure_schema(db)
    with db:
        db.execute('INSERT OR IGNORE INTO shutdown_minutes VALUES (?,?,?)',
                   (cabinet, tick, reason))
    return {'cabinet': cabinet, 'tick': tick, 'reason': reason}


def _book_hold(db, cabinet, at, reason):
    with db:
        db.execute('INSERT OR IGNORE INTO shutdown_minutes VALUES (?,?,?)',
                   (cabinet, at, reason))


def shutdown_ledger(db, cabinet):
    ensure_schema(db)
    return [{'tick': t, 'reason': r} for t, r in db.execute(
        'SELECT tick,reason FROM shutdown_minutes WHERE cabinet=? ORDER BY tick', (cabinet,))]


def pump_ledger(db, cabinet=None):
    ensure_schema(db)
    if cabinet:
        return [{'at': a, 'receipt_id': r} for a, r in db.execute(
            'SELECT at,receipt_id FROM pump_ledger WHERE cabinet=? ORDER BY at', (cabinet,))]
    return [{'cabinet': c, 'at': a, 'receipt_id': r} for c, a, r in db.execute(
        'SELECT cabinet,at,receipt_id FROM pump_ledger ORDER BY at,cabinet')]


# ------------------------------------------------------------- incidents

def record_legacy_permit(db, cabinet, at, supply_loop, recorded_at=0):
    """Migrate a ticket the old header-copying rule had already signed."""
    ensure_schema(db)
    ticket_id = f'legacy:{cabinet}:{at}'
    evidence = {'source': 'header_ticket_copied', 'loop': supply_loop}
    with db:
        db.execute('INSERT OR IGNORE INTO cabinet_permits VALUES (?,?,?,?,?,?,?)',
                   (cabinet, at, 'permit', 'header_ticket_copied',
                    json.dumps(evidence, sort_keys=True), ticket_id, 'legacy'))
    return {'cabinet': cabinet, 'at': at, 'decision': 'permit',
            'kind': 'legacy', 'ticket_id': ticket_id}


def absorb_calibration(db, cal_id, recorded_at=0):
    """Re-judge permits signed before a late calibration took effect.

    Old tickets are never rewritten: a wrong permit stays on record and gets
    an incident; new minutes are held because the active calibration is now
    applied to every fresh reading.
    """
    ensure_schema(db)
    cal = db.execute('SELECT bias_lpm,effective_at FROM cooling_calibrations WHERE cal_id=?',
                     (cal_id,)).fetchone()
    if not cal:
        raise ValueError('unknown_calibration')
    bias, effective_at = cal
    opened = []
    tickets = db.execute('SELECT cabinet,at,reason FROM cabinet_permits '
                         'WHERE decision=? AND at<?', ('permit', effective_at)).fetchall()
    for cabinet, at, old_reason in tickets:
        link = db.execute('SELECT branch_meter FROM cabinet_branches WHERE cabinet=?',
                          (cabinet,)).fetchone()
        if not link:
            continue
        reading = evaluate_meter(db, link[0], at)
        wrong = (not reading['available'] or not reading['fresh']
                 or reading['corrected_flow'] < BRANCH_MIN_FLOW
                 or reading['temp_c'] > MAX_RETURN_TEMP)
        if not wrong:
            continue
        incident_id = f'miscount:{cabinet}:{at}'
        detail = {'cal_id': cal_id, 'bias_lpm': bias,
                  'old_reason': old_reason, 'reading': reading}
        digest = _digest(detail)
        with db:
            db.execute('INSERT OR IGNORE INTO cooling_incidents VALUES (?,?,?,?,?,?,?)',
                       (incident_id, 'miscount_permit', cabinet, at,
                        json.dumps(detail, sort_keys=True), recorded_at, digest))
        opened.append({'incident_id': incident_id, 'cabinet': cabinet, 'at': at,
                       'corrected_flow': reading['corrected_flow'],
                       'raw_flow': reading['raw_flow']})
    return {'cal_id': cal_id, 'incidents': opened}


def incidents(db):
    ensure_schema(db)
    return [{'incident_id': i, 'kind': k, 'cabinet': c, 'at': a, 'detail': json.loads(d)}
            for i, k, c, a, d in db.execute(
                'SELECT incident_id,kind,cabinet,at,detail FROM cooling_incidents ORDER BY at')]


# --------------------------------------------------------------- decision

def _reading_at(db, meter, tick):
    reading = evaluate_meter(db, meter, tick)
    if not reading['available'] or reading['tick'] != tick:
        return None
    return reading


def _consecutive_ok(db, meters, at, min_flow, max_temp, same_calibration):
    """Two consecutive fresh minutes (at-1 and at) for every meter."""
    grid = {}
    cal_ids = set()
    for meter in meters:
        pair = []
        for tick in (at - 1, at):
            reading = _reading_at(db, meter, tick)
            if reading is None:
                return False, 'sample_missing_or_stale', {meter: tick}, grid
            pair.append(reading)
            cal_ids.add(reading['cal_id'])
        grid[meter] = pair
        if any(r['corrected_flow'] < min_flow or r['temp_c'] > max_temp for r in pair):
            return False, 'branch_flow_or_temp_unverified', {'meter': meter}, grid
    if same_calibration and len(cal_ids) != 1:
        return False, 'calibration_condition_mismatch', {'cal_ids': sorted(str(c) for c in cal_ids)}, grid
    return True, 'recovery_verified', {}, grid


def _store_ticket(db, cabinet, at, decision, reason, evidence, kind='normal'):
    ticket_id = f'{kind}:{cabinet}:{at}:{_digest(evidence)[:12]}'
    evidence_text = json.dumps(evidence, sort_keys=True)
    try:
        with db:
            db.execute('INSERT INTO cabinet_permits VALUES (?,?,?,?,?,?,?)',
                       (cabinet, at, decision, reason, evidence_text, ticket_id, kind))
        return {'cabinet': cabinet, 'at': at, 'decision': decision,
                'reason': reason, 'evidence': evidence, 'ticket_id': ticket_id,
                'status': 'decided'}
    except sqlite3.IntegrityError:
        # Unique (cabinet, minute): never overwrite a signed ticket.
        row = db.execute('SELECT decision,reason,evidence,ticket_id FROM cabinet_permits '
                         'WHERE cabinet=? AND at=?', (cabinet, at)).fetchone()
        stored = {'cabinet': cabinet, 'at': at, 'decision': row[0],
                  'reason': row[1], 'evidence': json.loads(row[2]),
                  'ticket_id': row[3]}
        if row[0] == decision and row[1] == reason:
            return {**stored, 'status': 'replayed'}
        return {**stored, 'status': 'ticket_conflict',
                'conflicting_request': {'decision': decision, 'reason': reason}}


def _site_valves(db, at):
    """Applied valve-close receipts for every cabinet on this site."""
    out = []
    for (target,) in db.execute('SELECT DISTINCT target FROM cooling_commands WHERE kind=?',
                                ('valve_close',)).fetchall():
        receipt = _receipt(db, 'valve_close', target, at)
        if receipt:
            out.append({'cabinet': target, **receipt})
    return sorted(out, key=lambda r: r['applied_at'])


def permit(db, cabinet, at, plan=None):
    """Final, unique operating decision for one cabinet at one minute."""
    ensure_schema(db)
    link = db.execute('SELECT branch_meter,branch_loop FROM cabinet_branches WHERE cabinet=?',
                      (cabinet,)).fetchone()
    if not link:
        return _store_ticket(db, cabinet, at, 'hold', 'branch_not_registered',
                             {'cabinet': cabinet, 'plan': plan})
    branch_meter, branch_loop = link
    site_id, main_meter, all_branches = _site_for(db, branch_meter)
    if not site_id:
        return _store_ticket(db, cabinet, at, 'hold', 'topology_not_registered',
                             {'branch_meter': branch_meter, 'plan': plan})

    pump = _receipt(db, 'pump_start', site_id, at)
    evidence = {'plan': plan, 'site_id': site_id, 'branch_meter': branch_meter,
                'pump_receipt': pump}

    # ---------------- disposition 1: isolate one cabinet -----------------
    if plan == 'isolate':
        valves = _site_valves(db, at)
        evidence['valve_receipts'] = valves
        own_valve = next((v for v in valves if v['cabinet'] == cabinet), None)
        if own_valve:
            # The valve on this cabinet's branch is physically shut: it stays
            # down until a separately evidenced reopening/recovery playbook.
            decision = _store_ticket(db, cabinet, at, 'hold',
                                     'cabinet_isolated', evidence)
            _book_hold(db, cabinet, at, 'cabinet_isolated')
            return decision
        if not valves:
            # pending holds are not actual downtime: nothing is isolated yet
            return _store_ticket(db, cabinet, at, 'hold',
                                 'isolation_receipt_pending', evidence)
        valve = valves[-1]
        ok, why, bad, grid = _consecutive_ok(
            db, [branch_meter], at, BRANCH_MIN_FLOW, MAX_RETURN_TEMP,
            same_calibration=False)
        post_receipt = ok and all(r['tick'] >= valve['applied_at']
                                  for pair in grid.values() for r in pair)
        evidence['recovery_grid'] = {m: [r for r in pair] for m, pair in grid.items()}
        evidence['failed_at'] = bad
        evidence['valve_receipt'] = valve
        if ok and post_receipt:
            return _store_ticket(db, cabinet, at, 'permit',
                                 'isolation_recovery_verified', evidence)
        if ok:
            why = 'recovery_readings_predate_receipt'
        # unverified recovery is a provisional hold, not booked downtime
        return _store_ticket(db, cabinet, at, 'hold', why, evidence)

    # ---------------- disposition 2: standby pump, whole site ------------
    if plan == 'pump':
        if not pump:
            decision = _store_ticket(db, cabinet, at, 'hold',
                                     'pump_receipt_pending', evidence)
            _book_hold(db, cabinet, at, decision['reason'])
            return decision
        ok, why, bad, grid = _consecutive_ok(
            db, all_branches, at, PUMP_MIN_FLOW, PUMP_MAX_TEMP,
            same_calibration=True)
        evidence['recovery_grid'] = {m: [r for r in pair] for m, pair in grid.items()}
        evidence['failed_at'] = bad
        # The header is deliberately absent from the threshold check: main
        # flow can never supplement a short branch.
        if ok:
            decision = _store_ticket(db, cabinet, at, 'permit',
                                     'pump_recovery_verified', evidence)
            with db:
                db.execute('INSERT OR IGNORE INTO pump_ledger VALUES (?,?,?)',
                           (cabinet, at, pump['receipt_id']))
        else:
            decision = _store_ticket(db, cabinet, at, 'hold', why, evidence)
            _book_hold(db, cabinet, at, decision['reason'])
        return decision

    # ---------------- normal operation: branch-responsible ticket --------
    header = header_ticket(db, main_meter, at)
    evidence['header_ticket'] = {'decision': header['decision'],
                                 'reason': header['reason'],
                                 'reading': header['reading']}
    branch_reading = evaluate_meter(db, branch_meter, at)
    evidence['branch_reading'] = branch_reading
    balance = supply_balance(db, main_meter, all_branches, at)
    evidence['mass_balance'] = {k: v for k, v in balance.items()
                                if k not in ('main', 'branches')}

    if not branch_reading['available'] or not branch_reading['fresh']:
        reason = 'sample_missing_or_stale'
    elif branch_reading['corrected_flow'] < BRANCH_MIN_FLOW:
        reason = 'branch_flow_low'
    elif branch_reading['temp_c'] > MAX_RETURN_TEMP:
        reason = 'return_temp_high'
    elif not balance['ok']:
        reason = balance['reason']
    else:
        reason = 'branch_verified'
    decision = _store_ticket(db, cabinet, at,
                             'permit' if reason == 'branch_verified' else 'hold',
                             reason, evidence)
    if decision['decision'] == 'hold':
        _book_hold(db, cabinet, at, reason)
    return decision


def final_decision(db, cabinet, at):
    """The unique, explainable ticket for a cabinet-minute."""
    ensure_schema(db)
    row = db.execute('SELECT decision,reason,evidence,ticket_id,kind FROM cabinet_permits '
                     'WHERE cabinet=? AND at=?', (cabinet, at)).fetchone()
    if not row:
        return None
    return {'cabinet': cabinet, 'at': at, 'decision': row[0], 'reason': row[1],
            'evidence': json.loads(row[2]), 'ticket_id': row[3], 'kind': row[4]}
