"""Capture power incident evidence with originals and arrival order.

The module keeps the original telemetry page intake (:func:`import_page`) and
adds an append-only evidence ledger used by the safe transfer gate:

* physical contact readbacks (触点回读) -- open command / dispatch success are
  deliberately stored separately and are never treated as contact proof;
* dispatch commands and receipts (调度回执);
* outage start/end records (停电起止);
* measured batteries and their per-minute actual draw ledger (电池耗量);
* node / source on-load measurements (母排负载 / 带载测量);
* actual service events (已发生服务的账);
* a sealed incident archive (事故留档).

Every artifact carries a caller supplied id.  Re-sending the same id with the
same content is idempotent; the same id with *different* content quarantines
the incoming original and raises a ``*_conflict`` ``ValueError``.  Originals
(canonical JSON) and a monotonic arrival sequence are stored in
``ev_evidence`` so restarting the process can never erase or re-order them.
"""
import hashlib
import json

FEED_TABLES = """
CREATE TABLE IF NOT EXISTS feed_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS feed_rows (page_id TEXT,line_no INTEGER,bus TEXT,source TEXT,tick INTEGER,voltage INTEGER,available_kw INTEGER,PRIMARY KEY(page_id,line_no));
"""

EVIDENCE_SCHEMA = FEED_TABLES + """
CREATE TABLE IF NOT EXISTS ev_evidence (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id TEXT UNIQUE NOT NULL,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    payload TEXT NOT NULL,
    occurred_at INTEGER,
    received_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_conflicts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id TEXT, kind TEXT, code TEXT,
    existing_digest TEXT, incoming_digest TEXT,
    incoming_payload TEXT, received_at INTEGER
);
CREATE TABLE IF NOT EXISTS contact_readbacks (
    doc_id TEXT PRIMARY KEY, bus TEXT, source TEXT, state TEXT, welded INTEGER,
    tick INTEGER, received_at INTEGER, seq INTEGER
);
CREATE TABLE IF NOT EXISTS dispatch_commands (
    command_id TEXT PRIMARY KEY, bus TEXT, source TEXT, action TEXT,
    issued_at INTEGER, received_at INTEGER, payload TEXT, seq INTEGER
);
CREATE TABLE IF NOT EXISTS dispatch_receipts (
    receipt_id TEXT PRIMARY KEY, command_id TEXT, dispatch_success INTEGER,
    received_at INTEGER, payload TEXT, seq INTEGER
);
CREATE TABLE IF NOT EXISTS outages (
    outage_id TEXT PRIMARY KEY, bus TEXT, started_at INTEGER, ended_at INTEGER,
    start_doc TEXT, end_doc TEXT, seq INTEGER
);
CREATE TABLE IF NOT EXISTS battery_reports (
    report_id TEXT PRIMARY KEY, battery TEXT, node TEXT, tick INTEGER,
    charge_kwmin REAL, max_discharge_kw REAL, received_at INTEGER, seq INTEGER
);
CREATE TABLE IF NOT EXISTS battery_draws (
    entry_id TEXT PRIMARY KEY, battery TEXT, node TEXT, tick INTEGER,
    draw_kw REAL, minutes REAL, energy_kwmin REAL, received_at INTEGER, seq INTEGER,
    UNIQUE(battery, tick)
);
CREATE TABLE IF NOT EXISTS load_measurements (
    doc_id TEXT PRIMARY KEY, bus TEXT, source TEXT, tick INTEGER, node TEXT,
    load_kw REAL, voltage REAL, available_kw REAL, received_at INTEGER, seq INTEGER
);
CREATE TABLE IF NOT EXISTS service_events (
    event_id TEXT PRIMARY KEY, node TEXT, bus TEXT, tick INTEGER, state TEXT,
    source TEXT, draw_kw REAL, reason TEXT, received_at INTEGER, seq INTEGER
);
CREATE TABLE IF NOT EXISTS incident_archives (
    incident_id TEXT PRIMARY KEY, bus TEXT, digest TEXT NOT NULL,
    payload TEXT NOT NULL, sealed_at INTEGER, seq INTEGER
);
"""


class EvidenceConflict(ValueError):
    """Same artifact id re-submitted with different content."""

    def __init__(self, code, doc_id):
        super().__init__(code)
        self.code = code
        self.doc_id = doc_id


def ensure_schema(db):
    db.executescript(EVIDENCE_SCHEMA)
    return db


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _digest(payload):
    body = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(body.encode('utf-8')).hexdigest()


def _replay(db, doc_id):
    return db.execute('SELECT seq,digest FROM ev_evidence WHERE doc_id=?', (doc_id,)).fetchone()


def _store_evidence(db, doc_id, kind, payload, received_at, occurred_at=None, digest=None):
    """Insert an original inside the caller's transaction (no own commit)."""
    digest = digest or _digest(payload)
    old = _replay(db, doc_id)
    if old:
        if old[1] != digest:
            raise EvidenceConflict('%s_conflict' % kind, doc_id)
        return 'replayed', old[0], digest
    cur = db.execute(
        'INSERT INTO ev_evidence(doc_id,kind,digest,payload,occurred_at,received_at) '
        'VALUES (?,?,?,?,?,?)',
        (doc_id, kind, digest,
         json.dumps(payload, sort_keys=True, ensure_ascii=False), occurred_at, received_at),
    )
    return 'captured', cur.lastrowid, digest


def reject_conflict(db, doc_id, kind, payload, received_at, old_digest=None,
                    code=None, existing_digest=None):
    """Preserve the contradictory incoming original, then raise."""
    code = code or ('%s_conflict' % kind)
    new_digest = _digest(payload)
    with db:
        db.execute(
            'INSERT INTO evidence_conflicts(doc_id,kind,code,existing_digest,'
            'incoming_digest,incoming_payload,received_at) VALUES (?,?,?,?,?,?,?)',
            (doc_id, kind, code, existing_digest if existing_digest is not None else old_digest,
             new_digest, json.dumps(payload, sort_keys=True, ensure_ascii=False), received_at),
        )
    raise EvidenceConflict(code, doc_id)


def capture_artifact(db, doc_id, kind, payload, received_at, project, occurred_at=None):
    """Idempotent append-only capture shared by every typed artifact.

    ``project(db, seq)`` inserts the queryable projection inside the same
    transaction as the original evidence row.
    """
    ensure_schema(db)
    digest = _digest(payload)
    old = _replay(db, doc_id)
    if old:
        if old[1] != digest:
            reject_conflict(db, doc_id, kind, payload, received_at, old_digest=old[1])
        return {'status': 'replayed', 'id': doc_id, 'seq': old[0], 'digest': digest}
    with db:
        cur = db.execute(
            'INSERT INTO ev_evidence(doc_id,kind,digest,payload,occurred_at,received_at) '
            'VALUES (?,?,?,?,?,?)',
            (doc_id, kind, digest,
             json.dumps(payload, sort_keys=True, ensure_ascii=False), occurred_at, received_at),
        )
        seq = cur.lastrowid
        project(db, seq)
    return {'status': 'captured', 'id': doc_id, 'seq': seq, 'digest': digest}


def put_evidence(db, doc_id, kind, payload, received_at, occurred_at=None):
    """Public generic append-only artifact intake."""
    ensure_schema(db)
    if not doc_id or not isinstance(kind, str) or not isinstance(received_at, int):
        raise ValueError('invalid_evidence')
    if not isinstance(payload, dict):
        raise ValueError('invalid_evidence_payload')

    def _noop(db, seq):
        return None

    return capture_artifact(db, doc_id, kind, payload, received_at, _noop, occurred_at)


# ---------------------------------------------------------------------------
# Telemetry pages (original entry point, behaviour preserved exactly)
# ---------------------------------------------------------------------------

def import_page(db, page_id, rows, received_at):
    db.execute('CREATE TABLE IF NOT EXISTS feed_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS feed_rows (page_id TEXT,line_no INTEGER,bus TEXT,source TEXT,tick INTEGER,voltage INTEGER,available_kw INTEGER,PRIMARY KEY(page_id,line_no))')
    keys = {'bus', 'source', 'tick', 'voltage', 'available_kw'}
    if not isinstance(rows, list) or any(not isinstance(r, dict) or set(r) != keys or not all(isinstance(r[k], int) for k in ('tick', 'voltage', 'available_kw')) or r['available_kw'] < 0 for r in rows):
        raise ValueError('invalid_feed_page')
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    old = db.execute('SELECT digest FROM feed_pages WHERE id=?', (page_id,)).fetchone()
    if old:
        if old[0] != digest:
            ensure_schema(db)
            reject_conflict(
                db, 'feed_page:' + page_id, 'feed_page',
                {'page_id': page_id, 'rows': rows}, received_at,
                old_digest=None, code='feed_page_conflict', existing_digest=old[0],
            )
        return {'status': 'replayed', 'rows': len(rows)}
    with db:
        db.execute('INSERT INTO feed_pages VALUES (?,?,?)', (page_id, digest, received_at))
        for i, r in enumerate(rows, 1):
            db.execute('INSERT INTO feed_rows VALUES (?,?,?,?,?,?,?)', (page_id, i, r['bus'], r['source'], r['tick'], r['voltage'], r['available_kw']))
        # Mirror the original page into the unified arrival ledger so the
        # incident timeline interleaves telemetry with contacts/receipts.
        ensure_schema(db)
        db.execute(
            'INSERT OR IGNORE INTO ev_evidence(doc_id,kind,digest,payload,occurred_at,received_at) '
            'VALUES (?,?,?,?,?,?)',
            ('feed_page:' + page_id, 'feed_page', digest,
             json.dumps({'page_id': page_id, 'rows': rows}, sort_keys=True, ensure_ascii=False),
             None, received_at),
        )
    return {'status': 'captured', 'rows': len(rows)}


# ---------------------------------------------------------------------------
# Physical contacts (触点回读)
# ---------------------------------------------------------------------------

def capture_contact(db, doc_id, bus, source, state, tick, received_at, welded=False, **extra):
    """Record a physical contact readback.

    ``state`` is ``'open'`` or ``'closed'``.  ``welded=True`` is an explicit
    weld/fault indication.  An open *command* or a dispatch success receipt is
    not accepted through here and can never satisfy the interlock gate.
    """
    if state not in ('open', 'closed'):
        raise ValueError('invalid_contact_state')
    if not isinstance(tick, int) or not isinstance(received_at, int):
        raise ValueError('invalid_contact_time')
    payload = {'doc_id': doc_id, 'bus': bus, 'source': source, 'state': state,
               'tick': tick, 'received_at': received_at, 'welded': bool(welded)}
    payload.update(extra)

    def project(db, seq):
        db.execute('INSERT INTO contact_readbacks VALUES (?,?,?,?,?,?,?,?)',
                   (doc_id, bus, source, state, 1 if welded else 0, tick, received_at, seq))

    res = capture_artifact(db, doc_id, 'contact_readback', payload, received_at, project, tick)
    res.update(state=state, welded=bool(welded))
    return res


record_contact_readback = capture_contact
capture_contact_readback = capture_contact
import_contact_readback = capture_contact
record_contact = capture_contact
add_contact_readback = capture_contact
contact_reading = capture_contact


# ---------------------------------------------------------------------------
# Dispatch commands / receipts (调度命令与回执)
# ---------------------------------------------------------------------------

def capture_command(db, command_id, bus, source, action, issued_at, received_at=None, **extra):
    """An outbound dispatch command (e.g. grid breaker open at minute 13)."""
    received_at = issued_at if received_at is None else received_at
    payload = {'command_id': command_id, 'bus': bus, 'source': source, 'action': action,
               'issued_at': issued_at, 'received_at': received_at}
    payload.update(extra)
    extra_json = json.dumps(extra, sort_keys=True, ensure_ascii=False)

    def project(db, seq):
        db.execute('INSERT INTO dispatch_commands VALUES (?,?,?,?,?,?,?,?)',
                   (command_id, bus, source, action, issued_at, received_at, extra_json, seq))

    res = capture_artifact(db, command_id, 'dispatch_command', payload, received_at,
                           project, issued_at)
    res['action'] = action
    return res


record_dispatch_command = capture_command


def capture_receipt(db, receipt_id, command_id, received_at, dispatch_success=True, **extra):
    """Dispatch-system receipt.  Success here does *not* prove contact state."""
    payload = {'receipt_id': receipt_id, 'command_id': command_id,
               'received_at': received_at, 'dispatch_success': bool(dispatch_success)}
    payload.update(extra)
    extra_json = json.dumps(extra, sort_keys=True, ensure_ascii=False)

    def project(db, seq):
        db.execute('INSERT INTO dispatch_receipts VALUES (?,?,?,?,?,?)',
                   (receipt_id, command_id, 1 if dispatch_success else 0, received_at,
                    extra_json, seq))

    res = capture_artifact(db, receipt_id, 'dispatch_receipt', payload, received_at, project)
    res['dispatch_success'] = bool(dispatch_success)
    return res


record_dispatch_receipt = capture_receipt
capture_dispatch_receipt = capture_receipt


# ---------------------------------------------------------------------------
# Outage start / end (停电起止)
# ---------------------------------------------------------------------------

def capture_outage_start(db, outage_id, bus, tick, received_at=None, **extra):
    received_at = tick if received_at is None else received_at
    doc_id = outage_id + ':start'
    payload = {'outage_id': outage_id, 'bus': bus, 'phase': 'start',
               'tick': tick, 'received_at': received_at}
    payload.update(extra)

    def project(db, seq):
        old = db.execute('SELECT outage_id FROM outages WHERE outage_id=?', (outage_id,)).fetchone()
        if old:
            db.execute('UPDATE outages SET started_at=?, start_doc=? WHERE outage_id=?',
                       (tick, doc_id, outage_id))
        else:
            db.execute('INSERT INTO outages(outage_id,bus,started_at,ended_at,start_doc,end_doc,seq) '
                       'VALUES (?,?,?,?,NULL,NULL,?)', (outage_id, bus, tick, doc_id, seq))

    res = capture_artifact(db, doc_id, 'outage_start', payload, received_at, project, tick)
    res['outage_id'] = outage_id
    res['started_at'] = tick
    return res


def capture_outage_end(db, outage_id, bus, tick, received_at=None, **extra):
    received_at = tick if received_at is None else received_at
    doc_id = outage_id + ':end'
    payload = {'outage_id': outage_id, 'bus': bus, 'phase': 'end',
               'tick': tick, 'received_at': received_at}
    payload.update(extra)

    def project(db, seq):
        old = db.execute('SELECT outage_id FROM outages WHERE outage_id=?', (outage_id,)).fetchone()
        if old:
            db.execute('UPDATE outages SET ended_at=?, end_doc=? WHERE outage_id=?',
                       (tick, doc_id, outage_id))
        else:
            db.execute('INSERT INTO outages(outage_id,bus,started_at,ended_at,start_doc,end_doc,seq) '
                       'VALUES (?,?,NULL,?,NULL,?,?)', (outage_id, bus, tick, doc_id, seq))

    res = capture_artifact(db, doc_id, 'outage_end', payload, received_at, project, tick)
    res['outage_id'] = outage_id
    res['ended_at'] = tick
    return res


record_outage = capture_outage_start


# ---------------------------------------------------------------------------
# Batteries: measured charge / max discharge + per-minute actual draw
# ---------------------------------------------------------------------------

def _check_minute_duplicate(db, entry_id, battery, tick, draw_kw, energy_kwmin,
                            received_at, payload):
    """Guard the single-debit-per-minute invariant.

    Same logical minute re-delivered under another id with identical figures
    is treated as a replay; different figures conflict so a later message can
    never silently rewrite the debit.
    """
    dup = db.execute('SELECT entry_id,draw_kw,energy_kwmin FROM battery_draws '
                     'WHERE battery=? AND tick=?', (battery, tick)).fetchone()
    if not dup or dup[0] == entry_id:
        return None
    same = abs(float(dup[1]) - float(draw_kw)) < 1e-9 and (
        energy_kwmin is None or abs(float(dup[2]) - float(energy_kwmin)) < 1e-9)
    if same:
        return {'status': 'replayed', 'id': dup[0], 'duplicate_delivery_id': entry_id}
    reject_conflict(db, entry_id, 'battery_draw', payload, received_at,
                    code='battery_minute_conflict')


def capture_battery(db, report_id, battery, tick, received_at,
                    charge_kwmin=None, max_discharge_kw=None, node=None,
                    charge_kwh=None, draw_kw=None, energy_kwmin=None, **extra):
    """Measured battery report (已测荷电量 / 最大放电功率).

    ``charge_kwmin`` is measured stored energy in kW-minutes; ``charge_kwh``
    is accepted and converted.  If the report also carries the actual draw for
    minute ``tick`` it is posted to the draw ledger.
    """
    if charge_kwmin is None and charge_kwh is not None:
        charge_kwmin = float(charge_kwh) * 60.0
    if charge_kwmin is None or not _num(charge_kwmin) or charge_kwmin < 0:
        raise ValueError('invalid_battery_charge')
    if max_discharge_kw is None or not _num(max_discharge_kw) or max_discharge_kw < 0:
        raise ValueError('invalid_battery_discharge_limit')
    if not isinstance(tick, int) or not isinstance(received_at, int):
        raise ValueError('invalid_battery_time')
    payload = {'report_id': report_id, 'battery': battery, 'node': node, 'tick': tick,
               'received_at': received_at, 'charge_kwmin': charge_kwmin,
               'max_discharge_kw': max_discharge_kw, 'draw_kw': draw_kw,
               'energy_kwmin': energy_kwmin}
    payload.update(extra)

    if draw_kw is not None:
        dup = _check_minute_duplicate(db, report_id, battery, tick, draw_kw,
                                      energy_kwmin, received_at, payload)
        if dup:
            return dup

    def project(db, seq):
        db.execute('INSERT INTO battery_reports VALUES (?,?,?,?,?,?,?,?)',
                   (report_id, battery, node, tick, float(charge_kwmin),
                    float(max_discharge_kw), received_at, seq))
        if draw_kw is not None:
            energy = energy_kwmin if energy_kwmin is not None else float(draw_kw)
            db.execute('INSERT INTO battery_draws VALUES (?,?,?,?,?,?,?,?,?)',
                       (report_id, battery, node, tick, float(draw_kw), 1.0,
                        float(energy), received_at, seq))

    res = capture_artifact(db, report_id, 'battery_report', payload, received_at, project, tick)
    res.update(charge_kwmin=float(charge_kwmin),
               max_discharge_kw=float(max_discharge_kw))
    return res


capture_battery_report = capture_battery
record_battery_report = capture_battery


def capture_battery_draw(db, entry_id, battery, tick, draw_kw, received_at,
                         minutes=1, energy_kwmin=None, node=None):
    """Post the *actual* consumption for one minute (每分钟实际耗量)."""
    if not _num(draw_kw) or draw_kw < 0:
        raise ValueError('invalid_battery_draw')
    if not isinstance(tick, int) or not isinstance(received_at, int):
        raise ValueError('invalid_draw_time')
    if energy_kwmin is None:
        energy_kwmin = float(draw_kw) * float(minutes)
    payload = {'entry_id': entry_id, 'battery': battery, 'node': node, 'tick': tick,
               'draw_kw': draw_kw, 'minutes': minutes, 'energy_kwmin': energy_kwmin,
               'received_at': received_at}
    dup = _check_minute_duplicate(db, entry_id, battery, tick, draw_kw,
                                  energy_kwmin, received_at, payload)
    if dup:
        return dup

    def project(db, seq):
        db.execute('INSERT INTO battery_draws VALUES (?,?,?,?,?,?,?,?,?)',
                   (entry_id, battery, node, tick, float(draw_kw), float(minutes),
                    float(energy_kwmin), received_at, seq))

    res = capture_artifact(db, entry_id, 'battery_draw', payload, received_at, project, tick)
    res['energy_kwmin'] = float(energy_kwmin)
    return res


record_battery_draw = capture_battery_draw
record_battery_minute = capture_battery_draw
record_battery_consumption = capture_battery_draw
battery_drain = capture_battery_draw
consume_battery_minute = capture_battery_draw


# ---------------------------------------------------------------------------
# Load / on-load measurements (母排负载 / 带载测量)
# ---------------------------------------------------------------------------

def capture_load(db, doc_id, bus, source, tick, load_kw, received_at,
                 voltage=None, available_kw=None, node=None, **extra):
    """Metered load.

    With ``node`` this is a node-level same-minute draw; without ``node`` it
    is the source/bus on-load measurement (带载测量) used to confirm the
    actual transfer and to cross-check the ticket total.
    """
    if not _num(load_kw) or load_kw < 0:
        raise ValueError('invalid_load')
    if not isinstance(tick, int) or not isinstance(received_at, int):
        raise ValueError('invalid_load_time')
    payload = {'doc_id': doc_id, 'bus': bus, 'source': source, 'tick': tick,
               'node': node, 'load_kw': load_kw, 'voltage': voltage,
               'available_kw': available_kw, 'received_at': received_at}
    payload.update(extra)

    def project(db, seq):
        db.execute('INSERT INTO load_measurements VALUES (?,?,?,?,?,?,?,?,?,?)',
                   (doc_id, bus, source, tick, node, float(load_kw),
                    None if voltage is None else float(voltage),
                    None if available_kw is None else float(available_kw),
                    received_at, seq))

    res = capture_artifact(db, doc_id, 'load_measurement', payload, received_at, project, tick)
    res['load_kw'] = float(load_kw)
    return res


record_load = capture_load
capture_on_load = capture_load
record_on_load_measurement = capture_load
meter_load = capture_load


# ---------------------------------------------------------------------------
# Actual service events (已发生服务的账)
# ---------------------------------------------------------------------------

SERVICE_STATES = ('serving', 'stopped', 'battery', 'restored', 'interrupted')


def record_service(db, event_id, node, bus, tick, state, received_at,
                   source=None, draw_kw=None, reason=None, **extra):
    if state not in SERVICE_STATES:
        raise ValueError('invalid_service_state')
    if not isinstance(tick, int) or not isinstance(received_at, int):
        raise ValueError('invalid_service_time')
    payload = {'event_id': event_id, 'node': node, 'bus': bus, 'tick': tick,
               'state': state, 'source': source, 'draw_kw': draw_kw,
               'reason': reason, 'received_at': received_at}
    payload.update(extra)

    def project(db, seq):
        db.execute('INSERT INTO service_events VALUES (?,?,?,?,?,?,?,?,?,?)',
                   (event_id, node, bus, tick, state, source,
                    None if draw_kw is None else float(draw_kw), reason, received_at, seq))

    return capture_artifact(db, event_id, 'service_event', payload, received_at, project, tick)


record_service_event = record_service


def stop_node(db, event_id, node, bus, at, received_at=None, reason='operator_shutdown', draw_kw=None):
    """Record an intentional shutdown and the start of an interruption."""
    return record_service(db, event_id, node, bus, at, 'stopped',
                          at if received_at is None else received_at,
                          reason=reason, draw_kw=draw_kw)


def put_on_battery(db, event_id, node, bus, at, received_at=None, battery=None, draw_kw=None):
    """Record transfer of a node onto its verified battery branch."""
    return record_service(db, event_id, node, bus, at, 'battery',
                          at if received_at is None else received_at,
                          draw_kw=draw_kw, reason='battery_bridge', battery=battery)


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def _table_exists(db, name):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def evidence_timeline(db):
    """All preserved originals in true arrival order."""
    ensure_schema(db)
    rows = db.execute('SELECT seq,doc_id,kind,digest,payload,occurred_at,received_at '
                      'FROM ev_evidence ORDER BY seq').fetchall()
    out = []
    for seq, doc_id, kind, digest, payload, occurred_at, received_at in rows:
        item = json.loads(payload)
        out.append({'seq': seq, 'id': doc_id, 'kind': kind, 'digest': digest,
                    'occurred_at': occurred_at, 'received_at': received_at, 'original': item})
    return out


# ---------------------------------------------------------------------------
# Incident archive (事故留档)
# ---------------------------------------------------------------------------

def _all_dicts(db, sql, args=()):
    cur = db.execute(sql, args)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def build_archive(db, incident_id='P1-incident', bus='P1'):
    """Assemble every original artifact for the incident.

    The archive is a read-only projection; ``arrival_order`` is the unified
    monotonic evidence sequence and therefore survives restarts.
    """
    ensure_schema(db)
    archive = {'incident_id': incident_id, 'bus': bus}

    pages = []
    if _table_exists(db, 'feed_pages'):
        for p in _all_dicts(db, 'SELECT id,digest,received_at,rowid AS arrival FROM feed_pages ORDER BY rowid'):
            p['rows'] = _all_dicts(db, 'SELECT line_no,bus,source,tick,voltage,available_kw '
                                       'FROM feed_rows WHERE page_id=? ORDER BY line_no', (p['id'],))
            pages.append(p)
    archive['telemetry_pages'] = pages

    archive['arrival_order'] = evidence_timeline(db)
    archive['conflicting_deliveries'] = _all_dicts(
        db, 'SELECT seq,doc_id,kind,code,incoming_payload,received_at '
            'FROM evidence_conflicts ORDER BY seq') if _table_exists(db, 'evidence_conflicts') else []
    archive['contacts'] = _all_dicts(db, 'SELECT * FROM contact_readbacks WHERE bus=? ORDER BY seq', (bus,))
    archive['commands'] = _all_dicts(db, 'SELECT * FROM dispatch_commands WHERE bus=? ORDER BY seq', (bus,))
    archive['receipts'] = _all_dicts(
        db,
        'SELECT r.* FROM dispatch_receipts r JOIN dispatch_commands c ON c.command_id=r.command_id '
        'WHERE c.bus=? ORDER BY r.seq', (bus,))
    archive['outages'] = _all_dicts(db, 'SELECT * FROM outages WHERE bus=? ORDER BY seq', (bus,))
    archive['battery_reports'] = _all_dicts(db, 'SELECT * FROM battery_reports ORDER BY seq')
    archive['battery_draws'] = _all_dicts(db, 'SELECT * FROM battery_draws ORDER BY seq')
    archive['loads'] = _all_dicts(db, 'SELECT * FROM load_measurements WHERE bus=? ORDER BY seq', (bus,))
    archive['service_events'] = _all_dicts(db, 'SELECT * FROM service_events WHERE bus=? ORDER BY seq', (bus,))

    # Legacy provisional permits: kept verbatim.  These include the dangerous
    # double 6/10 permits and must survive restart / never be silently removed.
    permits = []
    if _table_exists(db, 'power_permits'):
        permits = _all_dicts(db, 'SELECT rowid AS arrival,node,bus,source,draw_kw,at,decision '
                                 'FROM power_permits ORDER BY rowid')
    archive['legacy_permits'] = permits

    tickets = []
    if _table_exists(db, 'transfer_tickets'):
        tickets = _all_dicts(db, 'SELECT rowid AS arrival,* FROM transfer_tickets ORDER BY rowid')
        for t in tickets:
            t['reasons'] = json.loads(t.get('reasons') or '[]')
            t['request'] = json.loads(t.get('request') or '{}')
            t['nodes'] = _all_dicts(db, 'SELECT node,draw_kw FROM transfer_ticket_nodes '
                                        'WHERE ticket_id=? ORDER BY rowid', (t['ticket_id'],))
    archive['transfer_tickets'] = tickets

    certs = []
    if _table_exists(db, 'service_certificates'):
        certs = _all_dicts(db, 'SELECT rowid AS arrival,* FROM service_certificates ORDER BY rowid')
        for c in certs:
            c['reasons'] = json.loads(c.get('reasons') or '[]')
            c['detail'] = json.loads(c.get('detail') or '{}')
    archive['service_certificates'] = certs

    # Explicit safety finding so the historical dangerous release is legible.
    findings = []
    by_bus = {}
    for p in permits:
        if p.get('decision') == 'permit':
            by_bus.setdefault(p['bus'], set()).add(p['source'])
    for b, sources in by_bus.items():
        if len(sources) > 1:
            findings.append({'code': 'dual_source_permits_without_interlock',
                             'bus': b, 'sources': sorted(sources)})
    held = [t['ticket_id'] for t in tickets if t.get('decision') == 'held']
    if held:
        findings.append({'code': 'transfer_requests_held', 'ticket_ids': held})
    refused = [c['cert_id'] for c in certs if c.get('decision') == 'refused']
    if refused:
        findings.append({'code': 'continuity_claims_refused', 'cert_ids': refused})
    archive['findings'] = findings
    return archive


def seal_archive(db, incident_id, bus='P1', sealed_at=None):
    """Seal a canonical archive with a digest.

    Re-sealing the same ``incident_id`` with identical evidence is idempotent;
    a changed dossier conflicts instead of silently rewriting history.
    """
    ensure_schema(db)
    archive = build_archive(db, incident_id=incident_id, bus=bus)
    digest = _digest(archive)
    body = json.dumps(archive, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    old = db.execute('SELECT digest,payload FROM incident_archives WHERE incident_id=?',
                     (incident_id,)).fetchone()
    if old:
        if old[0] != digest:
            reject_conflict(db, incident_id, 'incident_archive', archive, sealed_at,
                            old_digest=old[0], code='incident_archive_conflict')
        return {'status': 'replayed', 'incident_id': incident_id, 'digest': digest,
                'archive': json.loads(old[1])}
    seq = db.execute('SELECT COALESCE(MAX(seq),0)+1 FROM ev_evidence').fetchone()[0]
    with db:
        db.execute('INSERT INTO incident_archives VALUES (?,?,?,?,?,?)',
                   (incident_id, bus, digest, body, sealed_at, seq))
    return {'status': 'sealed', 'incident_id': incident_id, 'digest': digest, 'archive': archive}


def export_archive_file(db, incident_id, path, bus='P1'):
    """Write the sealed incident dossier as UTF-8 JSON to ``path``."""
    import os
    sealed = seal_archive(db, incident_id=incident_id, bus=bus)
    path = os.fspath(path)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(sealed['archive'], fh, ensure_ascii=False, indent=2, sort_keys=True)
    return {'path': path, 'digest': sealed['digest']}


archive_incident = seal_archive
build_incident_archive = build_archive
preserve_incident = seal_archive
export_incident = export_archive_file
