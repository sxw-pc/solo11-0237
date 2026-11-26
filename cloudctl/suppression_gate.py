"""Field suppression response gate.

The detector-only :func:`release` provisional gate is kept byte-for-byte in
behaviour for existing callers/tests.  A provisional detector "release" is
*evidence of what the old automatic system did*: it is adjudicated against the
full field record and, when people / isolation / dose proof are missing,
preserved as an immutable early-discharge accident that later clearances
cannot backfill.

The responsible response path is plan based:

``register_plan`` -> ``evaluate_plan`` -> ``issue_release``
-> ``readback_cylinder`` (independent physical application readback)
-> ``finalize_release`` (proven released amount).

Every safety check is evaluated against an information horizon ``at``: only
facts whose physical time *and* arrival time are ``<= at`` count, so a
readback/page that arrives late cannot authorize an earlier spray.
"""
import json
import sqlite3

from .alarm_capture import (
    accept_record,
    ensure_ledger,
    ledger_append,
    ledger_entries,
)

SMOKE_THRESHOLD = 80
HEAT_THRESHOLD = 50

RESPONSE_SCHEMA = """
CREATE TABLE IF NOT EXISTS resp_spaces (
    space TEXT PRIMARY KEY,
    required_dose REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS resp_cylinders (
    cylinder_id TEXT PRIMARY KEY,
    space TEXT NOT NULL,
    capacity REAL NOT NULL,
    spent INTEGER NOT NULL DEFAULT 0,
    spent_release TEXT
);
CREATE TABLE IF NOT EXISTS resp_equipment (
    equip_id TEXT PRIMARY KEY,
    space TEXT,
    label TEXT
);
CREATE TABLE IF NOT EXISTS resp_people (
    person_id TEXT PRIMARY KEY,
    space TEXT,
    name TEXT,
    registered_at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_person_obs (
    ref TEXT PRIMARY KEY,
    person_id TEXT,
    space TEXT,
    state TEXT,
    method TEXT,
    detail TEXT,
    at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_headcounts (
    ref TEXT PRIMARY KEY,
    floor TEXT,
    total INTEGER,
    at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_dampers (
    damper TEXT PRIMARY KEY,
    note TEXT
);
CREATE TABLE IF NOT EXISTS resp_detectors (
    detector TEXT PRIMARY KEY,
    zone TEXT,
    position TEXT,
    duct TEXT
);
CREATE TABLE IF NOT EXISTS resp_airflow (
    link_id TEXT PRIMARY KEY,
    source_space TEXT,
    target_space TEXT,
    duct TEXT,
    damper TEXT,
    at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_sources (
    ref TEXT PRIMARY KEY,
    space TEXT,
    basis TEXT,
    at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_damper_commands (
    ref TEXT PRIMARY KEY,
    damper TEXT,
    action TEXT,
    at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_damper_readbacks (
    ref TEXT PRIMARY KEY,
    damper TEXT,
    state TEXT,
    at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_shutdowns (
    ref TEXT PRIMARY KEY,
    equip_id TEXT,
    state TEXT,
    at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_recovery (
    ref TEXT PRIMARY KEY,
    kind TEXT,
    scope TEXT,
    action TEXT,
    service_status TEXT,
    recovery_minutes INTEGER,
    note TEXT,
    at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_plans (
    name TEXT PRIMARY KEY,
    spec_json TEXT,
    registered_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_dose_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ref TEXT,
    at INTEGER,
    targets_json TEXT,
    cylinders_json TEXT,
    required REAL,
    available REAL,
    sufficient INTEGER,
    detail_json TEXT
);
CREATE TABLE IF NOT EXISTS resp_releases (
    release_id TEXT PRIMARY KEY,
    plan_name TEXT,
    spec_json TEXT,
    targets_json TEXT,
    cylinders_json TEXT,
    status TEXT,
    required_dose REAL,
    released_amount REAL,
    issued_at INTEGER,
    finalized_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_cylinder_commands (
    ref TEXT PRIMARY KEY,
    release_id TEXT,
    cylinder_id TEXT,
    action TEXT,
    at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_cylinder_readbacks (
    ref TEXT PRIMARY KEY,
    release_id TEXT,
    cylinder_id TEXT,
    state TEXT,
    released REAL,
    at INTEGER,
    received_at INTEGER
);
CREATE TABLE IF NOT EXISTS resp_accidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_rowid INTEGER UNIQUE,
    zone TEXT,
    at INTEGER,
    detector TEXT,
    safe INTEGER,
    blockers_json TEXT,
    finding_json TEXT,
    recorded_at INTEGER
);
"""


def ensure_response_schema(db):
    ensure_ledger(db)
    db.executescript(RESPONSE_SCHEMA)


# ---------------------------------------------------------------------------
# small query helpers (work with plain sqlite3 connections or sqlite3.Row)
# ---------------------------------------------------------------------------

def _dicts(db, sql, args=()):
    cur = db.execute(sql, args)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _one(db, sql, args=()):
    rows = _dicts(db, sql, args)
    return rows[0] if rows else None


def _latest_visible(db, table, key_column, key, at, extra_where='', args=()):
    return _one(
        db,
        'SELECT * FROM %s WHERE %s=? AND at<=? AND received_at<=? %s'
        ' ORDER BY at DESC, rowid DESC LIMIT 1' % (table, key_column, extra_where),
        (key, at, at) + tuple(args),
    )


# ---------------------------------------------------------------------------
# static scene configuration
# ---------------------------------------------------------------------------

def register_space(db, space, required_dose):
    ensure_response_schema(db)
    with db:
        db.execute(
            'INSERT INTO resp_spaces(space,required_dose) VALUES(?,?)'
            ' ON CONFLICT(space) DO UPDATE SET required_dose=excluded.required_dose',
            (space, float(required_dose)),
        )
    return {'status': 'registered', 'space': space, 'required_dose': float(required_dose)}


def register_cylinder(db, cylinder_id, space, capacity):
    """Register an agent cylinder/bank.  ``space='*'`` is a common/full-zone bank."""
    ensure_response_schema(db)
    with db:
        db.execute(
            'INSERT INTO resp_cylinders(cylinder_id,space,capacity) VALUES(?,?,?)'
            ' ON CONFLICT(cylinder_id) DO UPDATE SET'
            ' space=excluded.space, capacity=excluded.capacity',
            (cylinder_id, space, float(capacity)),
        )
    return {'status': 'registered', 'cylinder_id': cylinder_id, 'space': space,
            'capacity': float(capacity)}


def register_equipment(db, equip_id, space=None, label=None):
    ensure_response_schema(db)
    with db:
        db.execute(
            'INSERT INTO resp_equipment(equip_id,space,label) VALUES(?,?,?)'
            ' ON CONFLICT(equip_id) DO UPDATE SET space=excluded.space, label=excluded.label',
            (equip_id, space, label),
        )
    return {'status': 'registered', 'equip_id': equip_id}


def register_damper(db, damper, note=None):
    ensure_response_schema(db)
    with db:
        db.execute(
            'INSERT INTO resp_dampers(damper,note) VALUES(?,?)'
            ' ON CONFLICT(damper) DO UPDATE SET note=excluded.note',
            (damper, note),
        )
    return {'status': 'registered', 'damper': damper}


def register_detector(db, detector, zone, position='area', duct=None):
    """position='inlet' + duct correlates detectors sharing one duct inlet."""
    ensure_response_schema(db)
    with db:
        db.execute(
            'INSERT INTO resp_detectors(detector,zone,position,duct) VALUES(?,?,?,?)'
            ' ON CONFLICT(detector) DO UPDATE SET zone=excluded.zone,'
            ' position=excluded.position, duct=excluded.duct',
            (detector, zone, position, duct),
        )
    return {'status': 'registered', 'detector': detector}


def register_airflow(db, link_id, source_space, target_space,
                     duct=None, damper=None, at=0, received_at=None):
    """Preserve a source -> receiving-space airflow / shared-duct relation."""
    ensure_response_schema(db)
    payload = {'link_id': link_id, 'source_space': source_space,
               'target_space': target_space, 'duct': duct, 'damper': damper, 'at': at}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_airflow(link_id,source_space,target_space,duct,damper,at,received_at)'
            ' VALUES(?,?,?,?,?,?,?)',
            (link_id, source_space, target_space, duct, damper, at,
             at if received_at is None else received_at),
        )
        return {'link_id': link_id}

    return accept_record(
        db, link_id, 'airflow_link', payload, at, received_at,
        subject=link_id, write=write,
    )


def report_fire_source(db, source_id, space, basis, at, received_at=None):
    """Report/confirm the actual fire-origin space (e.g. cabinet inspection)."""
    ensure_response_schema(db)
    payload = {'source_id': source_id, 'space': space, 'basis': basis, 'at': at}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_sources(ref,space,basis,at,received_at) VALUES(?,?,?,?,?)',
            (source_id, space, basis, at, at if received_at is None else received_at),
        )
        return {'source_id': source_id, 'space': space}

    return accept_record(
        db, source_id, 'fire_source', payload, at, received_at,
        subject=space, write=write,
    )


# ---------------------------------------------------------------------------
# personnel: per-person, per-space clearance
# ---------------------------------------------------------------------------

def register_person(db, person_id, space, at, name=None, received_at=None, ref=None):
    ensure_response_schema(db)
    received_at = at if received_at is None else received_at
    ref = ref or 'person-register:%s:%s:%s' % (person_id, space, at)
    payload = {'person_id': person_id, 'space': space, 'at': at,
               'name': name, 'state': 'inside'}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_people(person_id,space,name,registered_at,received_at)'
            ' VALUES(?,?,?,?,?) ON CONFLICT(person_id) DO UPDATE SET'
            ' space=excluded.space, name=excluded.name,'
            ' registered_at=excluded.registered_at, received_at=excluded.received_at',
            (person_id, space, name, at, received_at),
        )
        conn.execute(
            'INSERT INTO resp_person_obs(ref,person_id,space,state,method,detail,at,received_at)'
            ' VALUES(?,?,?,?,?,?,?,?)',
            (ref, person_id, space, 'inside', 'register', None, at, received_at),
        )
        return {'person_id': person_id, 'space': space}

    return accept_record(db, ref, 'person_registration', payload, at, received_at,
                         subject=person_id, write=write)


def confirm_exit(db, person_id, space, at, method='badge', by=None,
                 received_at=None, ref=None):
    """Qualifying per-person leave confirmation for *space*.

    method must be 'badge' (access-control exit read) or 'onsite'
    (face-to-face field confirmation).
    """
    ensure_response_schema(db)
    if method not in ('badge', 'onsite'):
        raise ValueError('invalid_confirmation_method')
    received_at = at if received_at is None else received_at
    ref = ref or 'person-exit:%s:%s:%s:%s' % (person_id, space, at, method)
    payload = {'person_id': person_id, 'space': space, 'at': at,
               'method': method, 'by': by}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_person_obs(ref,person_id,space,state,method,detail,at,received_at)'
            ' VALUES(?,?,?,?,?,?,?,?)',
            (ref, person_id, space, 'left', method, by, at, received_at),
        )
        return {'person_id': person_id, 'space': space, 'left_at': at, 'method': method}

    return accept_record(db, ref, 'person_exit', payload, at, received_at,
                         subject=person_id, write=write)


def report_location(db, person_id, space, state, at, method='report',
                    received_at=None, ref=None, detail=None):
    """Append a location observation.  state='unknown' is treated as inside."""
    ensure_response_schema(db)
    if state not in ('inside', 'left', 'outside', 'unknown'):
        raise ValueError('invalid_person_state')
    received_at = at if received_at is None else received_at
    ref = ref or 'person-location:%s:%s:%s:%s' % (person_id, space, state, at)
    payload = {'person_id': person_id, 'space': space, 'state': state, 'at': at}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_person_obs(ref,person_id,space,state,method,detail,at,received_at)'
            ' VALUES(?,?,?,?,?,?,?,?)',
            (ref, person_id, space, state, method, detail, at, received_at),
        )
        return {'person_id': person_id, 'state': state}

    return accept_record(db, ref, 'person_location', payload, at, received_at,
                         subject=person_id, write=write)


def record_headcount(db, floor, total, at, received_at=None, ref=None):
    """Record a floor total headcount.  This can NEVER clear a room by itself."""
    ensure_response_schema(db)
    received_at = at if received_at is None else received_at
    ref = ref or 'headcount:%s:%s' % (floor, at)
    payload = {'floor': floor, 'total': total, 'at': at}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_headcounts(ref,floor,total,at,received_at) VALUES(?,?,?,?,?)',
            (ref, floor, int(total), at, received_at),
        )
        return {'floor': floor, 'total': int(total)}

    return accept_record(db, ref, 'floor_headcount', payload, at, received_at,
                         subject=floor, write=write)


def clearance(db, people_spaces, at):
    """Per-person clearance as known at information horizon *at*."""
    ensure_response_schema(db)
    spaces = list(people_spaces or [])
    cleared, pending, unknown_locations, roster_unknown = [], [], [], []
    for space in spaces:
        tied = set()
        for row in db.execute('SELECT person_id FROM resp_people WHERE space=?', (space,)):
            tied.add(row[0])
        for row in db.execute('SELECT DISTINCT person_id FROM resp_person_obs WHERE space=?', (space,)):
            tied.add(row[0])
        if not tied:
            # No roll call / registration for the space: nobody can prove it is
            # empty, and unknown personnel location is handled as occupied.
            roster_unknown.append(space)
            continue
        for person_id in sorted(tied):
            obs = _one(
                db,
                'SELECT state,method,at FROM resp_person_obs'
                ' WHERE person_id=? AND space=? AND at<=? AND received_at<=?'
                ' ORDER BY at DESC, rowid DESC LIMIT 1',
                (person_id, space, at, at),
            )
            if obs and obs['state'] == 'left' and obs['method'] in ('badge', 'onsite'):
                cleared.append({'person': person_id, 'space': space,
                                'at': obs['at'], 'method': obs['method']})
            else:
                pending.append(person_id)
                if obs and obs['state'] == 'unknown':
                    unknown_locations.append(person_id)
    headcounts = _dicts(
        db,
        'SELECT floor,total,at,received_at FROM resp_headcounts'
        ' WHERE at<=? AND received_at<=? ORDER BY at',
        (at, at),
    )
    pending = sorted(set(pending))
    return {
        'clear': not pending and not roster_unknown,
        'pending': pending,
        'unknown_locations': sorted(set(unknown_locations)),
        'roster_unknown': roster_unknown,
        'cleared': cleared,
        'floor_headcounts': headcounts,
        'floor_counts_are_not_clearance': True,
    }


# ---------------------------------------------------------------------------
# dampers / physical readback
# ---------------------------------------------------------------------------

def command_damper(db, damper, at, action='close', received_at=None, ref=None):
    ensure_response_schema(db)
    received_at = at if received_at is None else received_at
    ref = ref or 'damper-command:%s:%s:%s' % (damper, action, at)
    payload = {'damper': damper, 'action': action, 'at': at}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_damper_commands(ref,damper,action,at,received_at)'
            ' VALUES(?,?,?,?,?)',
            (ref, damper, action, at, received_at),
        )
        return {'damper': damper, 'action': action}

    return accept_record(db, ref, 'damper_command', payload, at, received_at,
                         subject=damper, write=write)


def readback_damper(db, damper, state, at, received_at=None, ref=None):
    """Independent physical damper application readback ('open'/'closed')."""
    ensure_response_schema(db)
    if state not in ('open', 'closed'):
        raise ValueError('invalid_damper_state')
    received_at = at if received_at is None else received_at
    ref = ref or 'damper-readback:%s:%s:%s' % (damper, state, at)
    payload = {'damper': damper, 'state': state, 'at': at}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_damper_readbacks(ref,damper,state,at,received_at)'
            ' VALUES(?,?,?,?,?)',
            (ref, damper, state, at, received_at),
        )
        return {'damper': damper, 'state': state}

    return accept_record(db, ref, 'damper_readback', payload, at, received_at,
                         subject=damper, write=write)


def isolation_status(db, damper_ids, at):
    """Physical isolation proven by arrived 'closed' readbacks only."""
    ensure_response_schema(db)
    damper_ids = list(damper_ids or [])
    missing_readback, open_dampers, closed, details = [], [], [], []
    for damper in damper_ids:
        cmd = _latest_visible(db, 'resp_damper_commands', 'damper', damper, at,
                              extra_where="AND action='close'")
        rb = _latest_visible(db, 'resp_damper_readbacks', 'damper', damper, at)
        detail = {'damper': damper,
                  'command_at': cmd['at'] if cmd else None,
                  'readback_state': rb['state'] if rb else None,
                  'readback_at': rb['at'] if rb else None}
        details.append(detail)
        if rb is None:
            missing_readback.append(damper)
        elif rb['state'] != 'closed':
            open_dampers.append(damper)
        else:
            closed.append(damper)
    blockers = ['damper_readback_missing:%s' % d for d in missing_readback]
    blockers += ['damper_not_closed:%s' % d for d in open_dampers]
    return {'isolated': not blockers, 'closed': closed,
            'missing_readback': missing_readback, 'open': open_dampers,
            'details': details, 'blockers': blockers}


def airflow_path_status(db, link_id, at):
    """Whether a registered smoke/gas path is physically severed by readback."""
    ensure_response_schema(db)
    link = _one(db, 'SELECT * FROM resp_airflow WHERE link_id=?', (link_id,))
    if link is None:
        raise KeyError('unknown_airflow_link:%s' % link_id)
    if not link['damper']:
        return {'link_id': link_id, 'severed': False,
                'reason': 'no_isolation_damper', 'damper': None}
    isolation = isolation_status(db, [link['damper']], at)
    return {'link_id': link_id, 'damper': link['damper'],
            'severed': isolation['isolated'], 'isolation': isolation,
            'blockers': isolation['blockers']}


# ---------------------------------------------------------------------------
# equipment shutdown (actual stopped confirmation)
# ---------------------------------------------------------------------------

def record_shutdown(db, equip_id, at, state='stopped', received_at=None, ref=None):
    ensure_response_schema(db)
    received_at = at if received_at is None else received_at
    ref = ref or 'shutdown:%s:%s' % (equip_id, at)
    payload = {'equip_id': equip_id, 'state': state, 'at': at}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_shutdowns(ref,equip_id,state,at,received_at)'
            ' VALUES(?,?,?,?,?)',
            (ref, equip_id, state, at, received_at),
        )
        return {'equip_id': equip_id, 'state': state}

    return accept_record(db, ref, 'equipment_shutdown', payload, at, received_at,
                         subject=equip_id, write=write)


def shutdown_status(db, equipment_ids, at):
    ensure_response_schema(db)
    pending, stopped = [], []
    for equip_id in equipment_ids or []:
        row = _latest_visible(db, 'resp_shutdowns', 'equip_id', equip_id, at,
                              extra_where="AND state='stopped'")
        if row is None:
            pending.append(equip_id)
        else:
            stopped.append(equip_id)
    return {'stopped': not pending, 'stopped_equipment': stopped,
            'pending': pending,
            'blockers': ['equipment_not_stopped:%s' % e for e in pending]}


# ---------------------------------------------------------------------------
# dose proof -- no pooling neighbour stock for a single-side claim
# ---------------------------------------------------------------------------

def verify_dose(db, targets, cylinder_ids, at=None, persist=False, ref=None):
    """Prove *targets* can reach design dose using exactly *cylinder_ids*.

    A cylinder registered to another (non-target) space is rejected as
    ``foreign_inventory``: A and B stock may not be summed to certify B alone.
    For a legitimate combined-zone spray, pass the combined target list once
    and verify the sum of requirements against the joint bank.
    """
    ensure_response_schema(db)
    targets = list(targets or [])
    cylinder_ids = list(cylinder_ids or [])
    errors, required = [], 0.0
    for space in targets:
        row = _one(db, 'SELECT required_dose FROM resp_spaces WHERE space=?', (space,))
        if row is None:
            errors.append('space_unknown:%s' % space)
        else:
            required += float(row['required_dose'])
    available = 0.0
    cylinder_detail = []
    for cid in cylinder_ids:
        row = _one(db, 'SELECT space,capacity,spent FROM resp_cylinders WHERE cylinder_id=?', (cid,))
        if row is None:
            errors.append('cylinder_unknown:%s' % cid)
            cylinder_detail.append({'cylinder': cid, 'eligible': False})
            continue
        foreign = row['space'] != '*' and row['space'] not in targets
        spent = bool(row['spent'])
        item = {'cylinder': cid, 'space': row['space'],
                'capacity': float(row['capacity']), 'spent': spent,
                'foreign': foreign, 'eligible': not foreign and not spent}
        cylinder_detail.append(item)
        if foreign:
            errors.append('foreign_inventory:%s' % cid)
        elif spent:
            errors.append('cylinder_spent:%s' % cid)
        else:
            available += float(row['capacity'])
    sufficient = not errors and required > 0 and available + 1e-9 >= required
    if not errors and not sufficient:
        errors.append('dose_insufficient:need%.2f:have%.2f' % (required, available))
    result = {'sufficient': sufficient, 'targets': targets,
              'cylinder_ids': cylinder_ids, 'required_dose': required,
              'available_dose': available, 'errors': errors,
              'blockers': list(errors), 'cylinders': cylinder_detail}
    if persist:
        with db:
            db.execute(
                'INSERT INTO resp_dose_checks(ref,at,targets_json,cylinders_json,'
                'required,available,sufficient,detail_json) VALUES(?,?,?,?,?,?,?,?)',
                (ref, at, json.dumps(targets, sort_keys=True),
                 json.dumps(cylinder_ids, sort_keys=True), required, available,
                 1 if sufficient else 0,
                 json.dumps(result, sort_keys=True, default=str)),
            )
    return result


def prove_partitions(db, partitions, at=None):
    """Prove dose for several partition plans without double-counting stock.

    Each partition is {'name', 'targets', 'cylinder_ids'}.  A cylinder used by
    two partitions makes the whole proof ``inventory_double_counted``: one
    pooled pile cannot certify both sides.
    """
    ensure_response_schema(db)
    seen, overlap = {}, set()
    for part in partitions:
        for cid in part.get('cylinder_ids', []):
            if cid in seen:
                overlap.add(cid)
            seen[cid] = part.get('name')
    if overlap:
        return {'proven': False, 'code': 'inventory_double_counted',
                'overlap': sorted(overlap), 'partitions': []}
    checks = []
    for part in partitions:
        check = verify_dose(db, part.get('targets', []), part.get('cylinder_ids', []), at=at)
        check['name'] = part.get('name')
        checks.append(check)
    return {'proven': all(c['sufficient'] for c in checks),
            'code': 'proven' if all(c['sufficient'] for c in checks) else 'dose_insufficient',
            'partitions': checks}


# ---------------------------------------------------------------------------
# recovery / remediation records
# ---------------------------------------------------------------------------

def _record_action(db, kind, ref, scope, action, at, received_at,
                   service_status=None, recovery_minutes=None, note=None):
    ensure_response_schema(db)
    received_at = at if received_at is None else received_at
    payload = {'kind': kind, 'scope': scope, 'action': action, 'at': at,
               'service_status': service_status, 'recovery_minutes': recovery_minutes}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_recovery(ref,kind,scope,action,service_status,'
            'recovery_minutes,note,at,received_at) VALUES(?,?,?,?,?,?,?,?,?)',
            (ref, kind, scope, action, service_status, recovery_minutes, note, at, received_at),
        )
        return {'ref': ref, 'kind': kind}

    return accept_record(db, ref, kind, payload, at, received_at,
                         subject=scope, write=write)


def record_recovery(db, ref, scope, action, at, service_status='restored',
                   recovery_minutes=None, note=None, received_at=None):
    return _record_action(db, 'recovery', ref, scope, action, at, received_at,
                          service_status=service_status,
                          recovery_minutes=recovery_minutes, note=note)


def record_remediation(db, ref, scope, action, at, note=None, received_at=None):
    return _record_action(db, 'remediation', ref, scope, action, at, received_at,
                          service_status=None, note=note)


# ---------------------------------------------------------------------------
# plans and evaluation
# ---------------------------------------------------------------------------

def register_plan(db, name, targets, damper_ids=(), equipment_ids=(),
                  cylinder_ids=(), people_spaces=None, at=0):
    ensure_response_schema(db)
    spec = {'name': name,
            'targets': list(targets),
            'people_spaces': list(people_spaces if people_spaces is not None else targets),
            'damper_ids': list(damper_ids),
            'equipment_ids': list(equipment_ids),
            'cylinder_ids': list(cylinder_ids)}
    with db:
        db.execute(
            'INSERT INTO resp_plans(name,spec_json,registered_at) VALUES(?,?,?)'
            ' ON CONFLICT(name) DO UPDATE SET spec_json=excluded.spec_json',
            (name, json.dumps(spec, sort_keys=True), at),
        )
    return {'status': 'registered', 'plan': name, 'spec': spec}


def load_plan(db, name):
    row = _one(db, 'SELECT spec_json FROM resp_plans WHERE name=?', (name,))
    if row is None:
        raise KeyError('unknown_plan:%s' % name)
    return json.loads(row['spec_json'])


def evaluate_plan(db, at, name=None, plan=None):
    """Evaluate a response plan using only evidence arrived by *at*."""
    ensure_response_schema(db)
    if plan is None:
        if name is None:
            raise ValueError('plan_or_name_required')
        plan = load_plan(db, name)
    plan = dict(plan)
    plan.setdefault('name', name)
    people = clearance(db, plan.get('people_spaces', plan.get('targets', [])), at)
    isolation = isolation_status(db, plan.get('damper_ids', []), at)
    shutdown = shutdown_status(db, plan.get('equipment_ids', []), at)
    dose = verify_dose(db, plan.get('targets', []), plan.get('cylinder_ids', []), at=at)
    blockers = []
    blockers += ['person_not_clear:%s' % p for p in people['pending']]
    blockers += ['roster_unknown:%s' % s for s in people['roster_unknown']]
    blockers += isolation['blockers']
    blockers += shutdown['blockers']
    blockers += dose['blockers']
    report = {'decision': 'release' if not blockers else 'hold',
              'authorized': not blockers,
              'plan': plan.get('name'),
              'at': at,
              'blockers': blockers,
              'people': people,
              'isolation': isolation,
              'shutdown': shutdown,
              'dose': dose}
    with db:
        ledger_append(db, 'plan_evaluation', payload={
            'plan': plan.get('name'), 'at': at, 'decision': report['decision'],
            'blockers': blockers,
        }, subject=plan.get('name'), occurred_at=at, received_at=at)
    return report


# ---------------------------------------------------------------------------
# authorized discharge lifecycle
# ---------------------------------------------------------------------------

def _release_row(db, release_id):
    row = _one(db, 'SELECT * FROM resp_releases WHERE release_id=?', (release_id,))
    if row is None:
        return None
    row['targets'] = json.loads(row['targets_json'])
    row['cylinder_ids'] = json.loads(row['cylinders_json'])
    row['spec'] = json.loads(row['spec_json']) if row['spec_json'] else {}
    return row


def get_release(db, release_id):
    ensure_response_schema(db)
    return _release_row(db, release_id)


def issue_release(db, release_id, at, name=None, plan=None, received_at=None):
    """Gate and issue a safe release (writes cylinder open commands).

    When preconditions fail, only an immutable held-attempt ledger entry is
    written; no release row exists, so the same id may be retried later once
    missing evidence has arrived.
    """
    ensure_response_schema(db)
    received_at = at if received_at is None else received_at
    if plan is None:
        plan = load_plan(db, name)
    plan = dict(plan)
    plan.setdefault('name', name)
    spec_json = json.dumps(plan, sort_keys=True)

    existing = _release_row(db, release_id)
    if existing is not None:
        if existing['spec_json'] != spec_json:
            raise ValueError('release_conflict')
        return {'status': 'idempotent', 'decision': 'release',
                'release_id': release_id, 'release_status': existing['status']}

    verdict = evaluate_plan(db, at, plan=plan)
    if verdict['decision'] != 'release':
        with db:
            ledger_append(db, 'release_held', payload={
                'release_id': release_id, 'at': at,
                'blockers': verdict['blockers'],
            }, ref=release_id, subject=release_id, occurred_at=at,
                received_at=received_at)
        return {'status': 'held', 'decision': 'hold', 'release_id': release_id,
                'blockers': verdict['blockers']}

    targets = plan.get('targets', [])
    cylinder_ids = plan.get('cylinder_ids', [])
    required_dose = verdict['dose']['required_dose']
    with db:
        db.execute(
            'INSERT INTO resp_releases(release_id,plan_name,spec_json,targets_json,'
            'cylinders_json,status,required_dose,released_amount,issued_at,finalized_at)'
            ' VALUES(?,?,?,?,?,?,?,NULL,?,NULL)',
            (release_id, plan.get('name'), spec_json,
             json.dumps(targets, sort_keys=True),
             json.dumps(cylinder_ids, sort_keys=True), 'issued',
             required_dose, at),
        )
        for cid in cylinder_ids:
            db.execute(
                'INSERT INTO resp_cylinder_commands(ref,release_id,cylinder_id,action,at,received_at)'
                ' VALUES(?,?,?,?,?,?)',
                ('%s:cmd:%s' % (release_id, cid), release_id, cid, 'open', at, received_at),
            )
        db.execute(
            'INSERT INTO resp_dose_checks(ref,at,targets_json,cylinders_json,required,'
            'available,sufficient,detail_json) VALUES(?,?,?,?,?,?,?,?)',
            ('dose:%s' % release_id, at, json.dumps(targets, sort_keys=True),
             json.dumps(cylinder_ids, sort_keys=True), required_dose,
             verdict['dose']['available_dose'], 1,
             json.dumps(verdict['dose'], sort_keys=True, default=str)),
        )
        ledger_append(db, 'release_issued', payload={
            'release_id': release_id, 'targets': targets,
            'cylinder_ids': cylinder_ids, 'required_dose': required_dose,
        }, ref=release_id, subject=release_id, occurred_at=at, received_at=received_at)
    return {'status': 'issued', 'decision': 'release', 'release_id': release_id,
            'commanded_cylinders': cylinder_ids, 'required_dose': required_dose}


def readback_cylinder(db, release_id, cylinder_id, state, at, released=None,
                      received_at=None, ref=None):
    """Independent physical cylinder application readback.

    state='opened' with measured *released* amount is required to finalize.
    """
    ensure_response_schema(db)
    if state not in ('opened', 'closed', 'fault'):
        raise ValueError('invalid_cylinder_state')
    received_at = at if received_at is None else received_at
    ref = ref or 'cylinder-readback:%s:%s:%s:%s:%s' % (
        release_id, cylinder_id, at, state, released)
    payload = {'release_id': release_id, 'cylinder_id': cylinder_id,
               'state': state, 'released': released, 'at': at}

    def write(conn):
        conn.execute(
            'INSERT INTO resp_cylinder_readbacks(ref,release_id,cylinder_id,state,'
            'released,at,received_at) VALUES(?,?,?,?,?,?,?)',
            (ref, release_id, cylinder_id, state, released, at, received_at),
        )
        return {'release_id': release_id, 'cylinder_id': cylinder_id, 'state': state}

    return accept_record(db, ref, 'cylinder_readback', payload, at, received_at,
                         subject=release_id, write=write)


def finalize_release(db, release_id, at, received_at=None):
    """Confirm physical agent application and record the actual release amount."""
    ensure_response_schema(db)
    rel = _release_row(db, release_id)
    if rel is None:
        raise KeyError('unknown_release:%s' % release_id)
    if rel['status'] == 'released':
        return {'status': 'idempotent', 'decision': 'release',
                'release_id': release_id, 'released_amount': rel['released_amount']}
    blockers, total, readbacks = [], 0.0, []
    for cid in rel['cylinder_ids']:
        rb = _one(
            db,
            'SELECT state,released,at FROM resp_cylinder_readbacks'
            ' WHERE release_id=? AND cylinder_id=? AND at<=? AND received_at<=?'
            ' ORDER BY at DESC, rowid DESC LIMIT 1',
            (release_id, cid, at, at if received_at is None else received_at),
        )
        if rb is None:
            blockers.append('cylinder_readback_missing:%s' % cid)
        elif rb['state'] != 'opened':
            blockers.append('cylinder_not_opened:%s:%s' % (cid, rb['state']))
        elif rb['released'] is None:
            blockers.append('cylinder_amount_missing:%s' % cid)
        else:
            total += float(rb['released'])
            readbacks.append({'cylinder': cid, 'released': float(rb['released']),
                              'at': rb['at']})
    required = float(rel['required_dose'] or 0.0)
    if not blockers and total + 1e-9 < required:
        blockers.append('release_amount_short:need%.2f:got%.2f' % (required, total))
    if blockers:
        with db:
            ledger_append(db, 'release_finalize_held', payload={
                'release_id': release_id, 'blockers': blockers,
                'measured_amount': total,
            }, ref='finalize-held:%s:%s' % (release_id, at),
                subject=release_id, occurred_at=at,
                received_at=at if received_at is None else received_at)
        return {'status': 'held', 'decision': 'hold', 'release_id': release_id,
                'blockers': blockers, 'released_amount': total}
    with db:
        db.execute(
            "UPDATE resp_releases SET status='released', released_amount=?,"
            ' finalized_at=? WHERE release_id=?',
            (total, at, release_id),
        )
        db.execute(
            'UPDATE resp_cylinders SET spent=1, spent_release=?'
            ' WHERE cylinder_id IN (%s)' % ','.join('?' for _ in rel['cylinder_ids']),
            [release_id] + rel['cylinder_ids'],
        )
        ledger_append(db, 'release_finalized', payload={
            'release_id': release_id, 'released_amount': total,
            'readbacks': readbacks,
        }, ref='finalized:%s' % release_id, subject=release_id,
            occurred_at=at, received_at=at if received_at is None else received_at)
    return {'status': 'released', 'decision': 'release', 'release_id': release_id,
            'released_amount': total, 'readbacks': readbacks}


def releases(db):
    ensure_response_schema(db)
    return _dicts(db, 'SELECT release_id,plan_name,status,required_dose,'
                      'released_amount,issued_at,finalized_at FROM resp_releases'
                      ' ORDER BY issued_at, release_id')


# ---------------------------------------------------------------------------
# source / airflow analysis
# ---------------------------------------------------------------------------

def analyze_sources(db, at=None):
    """Separate the alarm-receiving zone from the likely fire-origin space."""
    ensure_response_schema(db)
    try:
        if at is None:
            alarm_rows = _dicts(db, 'SELECT detector,zone,tick,smoke,heat FROM alarm_rows ORDER BY tick')
        else:
            alarm_rows = _dicts(
                db,
                'SELECT r.detector AS detector, r.zone AS zone, r.tick AS tick,'
                ' r.smoke AS smoke, r.heat AS heat FROM alarm_rows r'
                ' JOIN alarm_pages p ON p.id=r.page_id'
                ' WHERE p.received_at<=? AND r.tick<=? ORDER BY r.tick',
                (at, at),
            )
    except sqlite3.OperationalError:
        alarm_rows = []
    if at is None:
        links = _dicts(db, 'SELECT * FROM resp_airflow ORDER BY link_id')
        sources = _dicts(db, 'SELECT space,basis,at FROM resp_sources ORDER BY at')
    else:
        links = _dicts(db, 'SELECT * FROM resp_airflow WHERE at<=? AND received_at<=?', (at, at))
        sources = _dicts(db, 'SELECT space,basis,at FROM resp_sources WHERE at<=? AND received_at<=?', (at, at))
    detector_meta = {r['detector']: r for r in _dicts(db, 'SELECT * FROM resp_detectors')}

    hot, elevated = [], []
    for row in alarm_rows:
        if row['smoke'] >= 50:
            elevated.append(row)
        if row['smoke'] >= SMOKE_THRESHOLD and row['heat'] >= HEAT_THRESHOLD:
            item = dict(row)
            meta = detector_meta.get(row['detector'], {})
            item['position'] = meta.get('position', 'area')
            item['duct'] = meta.get('duct')
            hot.append(item)
    alarm_zones = sorted({r['zone'] for r in hot})

    inlet_groups = {}
    for det, meta in detector_meta.items():
        if meta.get('duct'):
            inlet_groups.setdefault(meta['duct'], []).append(det)
    for duct in inlet_groups:
        inlet_groups[duct] = sorted(inlet_groups[duct])
    hot_by_detector = {r['detector']: r for r in hot}
    hot_inlet_groups = {
        duct: [d for d in dets if d in hot_by_detector]
        for duct, dets in sorted(inlet_groups.items())
    }
    hot_inlet_groups = {k: v for k, v in hot_inlet_groups.items() if v}

    elevated_zones = {r['zone'] for r in elevated}
    source_spaces = {s['space'] for s in sources}
    paths = []
    origins = set(source_spaces)
    for link in links:
        feeds_alarm_zone = link['target_space'] in alarm_zones
        corroborated = (link['source_space'] in elevated_zones
                        or link['source_space'] in source_spaces)
        paths.append({'link_id': link['link_id'],
                      'source_space': link['source_space'],
                      'target_space': link['target_space'],
                      'duct': link['duct'], 'damper': link['damper'],
                      'feeds_alarm_zone': feeds_alarm_zone,
                      'corroborated': corroborated})
        if feeds_alarm_zone and corroborated:
            origins.add(link['source_space'])
    return {
        'hot_detectors': hot,
        'alarm_zones': alarm_zones,
        'elevated_zones': sorted(elevated_zones),
        'inlet_groups': hot_inlet_groups,
        'all_duct_detectors': inlet_groups,
        'airflow_paths': paths,
        'source_reports': sources,
        'origins': sorted(origins),
        'note': 'detectors sharing one duct inlet are one airflow path, not two zone votes',
    }


# ---------------------------------------------------------------------------
# immutable accident adjudication of the legacy provisional release
# ---------------------------------------------------------------------------

def accidents(db):
    ensure_response_schema(db)
    rows = _dicts(db, 'SELECT * FROM resp_accidents ORDER BY id')
    for row in rows:
        row['safe'] = bool(row['safe'])
        row['blockers'] = json.loads(row.pop('blockers_json') or '[]')
        row['finding'] = json.loads(row.pop('finding_json') or '{}')
    return rows


def _adjudicate_provisional(db, source_rowid, zone, at, detector):
    ensure_response_schema(db)
    if db.execute('SELECT 1 FROM resp_accidents WHERE source_rowid=?',
                  (source_rowid,)).fetchone() is not None:
        return
    blockers = []
    people = clearance(db, [zone], at)
    blockers += ['person_not_clear:%s' % p for p in people['pending']]
    blockers += ['roster_unknown:%s' % s for s in people['roster_unknown']]

    damper_ids = [r[0] for r in db.execute(
        'SELECT DISTINCT damper FROM resp_airflow'
        ' WHERE damper IS NOT NULL AND (target_space=? OR source_space=?)',
        (zone, zone))]
    isolation = isolation_status(db, damper_ids, at)
    blockers += isolation['blockers']
    # The detector-only gate never proved an extinguishing dose either.
    blockers.append('dose_unverified')

    safe = 1 if not blockers else 0
    finding = {'zone': zone, 'at': at, 'detector': detector, 'safe': bool(safe),
               'blockers': blockers, 'people': people,
               'isolation': isolation,
               'classification': 'safe_release' if safe else 'accidental_early_discharge'}
    with db:
        db.execute(
            'INSERT INTO resp_accidents(source_rowid,zone,at,detector,safe,'
            'blockers_json,finding_json,recorded_at) VALUES(?,?,?,?,?,?,?,?)',
            (source_rowid, zone, at, detector, safe,
             json.dumps(blockers, sort_keys=True),
             json.dumps(finding, sort_keys=True, default=str), at),
        )
        ledger_append(db, 'provisional_release_adjudicated', payload=finding,
                      ref='accident-row:%s' % source_rowid, subject=zone,
                      occurred_at=at, received_at=at)


# ---------------------------------------------------------------------------
# legacy provisional gate -- behaviour preserved for the original 14 tests
# ---------------------------------------------------------------------------

def release(db, zone, at):
    ensure_response_schema(db)
    db.execute('CREATE TABLE IF NOT EXISTS suppression_releases (zone TEXT,at INTEGER,decision TEXT,detector TEXT)')
    try:
        row = db.execute('SELECT detector,smoke,heat FROM alarm_rows WHERE zone=? ORDER BY tick DESC LIMIT 1', (zone,)).fetchone()
    except sqlite3.OperationalError:
        row = None
    decision = 'release' if row and row[1] >= 80 and row[2] >= 50 else 'hold'
    with db:
        cur = db.execute('INSERT INTO suppression_releases VALUES (?,?,?,?)', (zone, at, decision, row[0] if row else None))
        source_rowid = cur.lastrowid
    if decision == 'release':
        # Preserve the naive spray as an adjudicated accident when the field
        # record cannot prove it safe.  Never raises into legacy callers.
        _adjudicate_provisional(db, source_rowid, zone, at, row[0])
    return {'zone': zone, 'decision': decision}


# ---------------------------------------------------------------------------
# read views
# ---------------------------------------------------------------------------

def timeline(db, order='arrival'):
    return ledger_entries(db, order=order)


# Descriptive aliases for the response vocabulary.
evaluate_response = evaluate_plan
authorize = evaluate_plan
attempt_release = issue_release
authorize_release = issue_release
add_person = register_person
register_worker = register_person
record_person_exit = confirm_exit
confirm_person_left = confirm_exit
clear_person = confirm_exit
person_left = confirm_exit
record_person_location = report_location
add_damper = register_damper
register_valve = register_damper
add_valve = register_damper
close_valve = command_damper
command_valve = command_damper
record_damper_readback = readback_damper
damper_readback = readback_damper
record_valve_readback = readback_damper
valve_readback = readback_damper
valve_status = isolation_status
add_cylinder = register_cylinder
add_equipment = register_equipment
record_equipment_shutdown = record_shutdown
add_airflow_path = register_airflow
register_design_dose = register_space
dose_proof = verify_dose
discharge = finalize_release
