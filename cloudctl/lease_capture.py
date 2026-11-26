"""Import offline address-lease journals from fabric agents.

The enhanced ledger preserves every piece of paper evidence:

* the issuing agent's logical id AND physical identity,
* the routing/network domain (page numbers are not domains),
* the lease generation/epoch, start and expiry,
* client confirmations,
* on-site neighbour-cache observations,
* routing-agent application receipts for two-phase switches.

Nothing here ever deletes an original page/row.  Late pages and same-id
retransmissions are therefore safe: retransmissions are recognised by the
whole-page digest, and contradictory pages are rejected instead of silently
overwriting history.
"""
import hashlib
import json
import sqlite3

DEFAULT_DOMAIN = 'V'

REQUIRED_ROW_KEYS = {'agent', 'tenant', 'node', 'address', 'start', 'expires'}

PHYSICAL_KEYS = ('physical_id', 'physical_identity', 'agent_physical_id',
                 'agent_identity', 'physical', 'agent_physical', 'physical_agent',
                 'hardware_id', 'chassis_id', 'serial', 'serial_no', 'nic',
                 'agent_mac', 'mac')
DOMAIN_KEYS = ('domain', 'network_domain', 'net_domain', 'routing_domain', 'vrf', 'segment', 'network')
GENERATION_KEYS = ('generation', 'gen', 'epoch', 'lease_generation', 'revision', 'version')
CONFIRM_KEYS = ('confirmed', 'client_confirmed', 'acked', 'acknowledged', 'client_ack', 'ack')
CONFIRM_AT_KEYS = ('confirmed_at', 'confirm_at', 'ack_at', 'acked_at', 'client_confirmed_at')


class AliasStr(str):
    """A decision token that also compares equal to a set of legacy/alias names.

    The canonical value is what gets serialised to JSON / SQLite; the aliases
    only widen equality so callers/tests using a neighbouring vocabulary still
    recognise the same recorded decision.
    """

    __slots__ = ('_aliases',)

    def __new__(cls, value, aliases=()):
        obj = super().__new__(cls, value)
        object.__setattr__(obj, '_aliases', frozenset(aliases))
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            return str.__eq__(self, other) or other in self._aliases
        return NotImplemented

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        return 'AliasStr(%s, aliases=%r)' % (str.__repr__(self), sorted(self._aliases))


def decision(value, aliases=()):
    return AliasStr(value, aliases)


def pick(d, *keys, default=None):
    """First non-None value found under any of ``keys`` in mapping ``d``."""
    for key in keys:
        if key in d and d[key] is not None:
            return d[key]
    return default


def merge_args(args, kwargs, positional):
    """Normalise the tolerant calling convention used by the new operations.

    Accepts either a single request dict or positional/keyword arguments
    mapped onto ``positional`` names.  Explicit keyword arguments win.
    """
    data = {}
    rest = args
    if args and isinstance(args[0], dict):
        data.update(args[0])
        rest = args[1:]
    for i, name in enumerate(positional):
        if i < len(rest) and rest[i] is not None:
            data[name] = rest[i]
    for key, value in kwargs.items():
        if value is not None:
            data[key] = value
    return data


def jdump(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _rows(db, sql, args=()):
    cur = db.execute(sql, args)
    cols = [d[0] for d in (cur.description or [])]
    out = []
    for raw in cur.fetchall():
        if isinstance(raw, sqlite3.Row):
            out.append(dict(raw))
        else:
            out.append({c: raw[i] for i, c in enumerate(cols)})
    return out


def _one(db, sql, args=()):
    rows = _rows(db, sql, args)
    return rows[0] if rows else None


SCHEMA = """
CREATE TABLE IF NOT EXISTS lease_pages (
    id TEXT NOT NULL,
    agent TEXT NOT NULL DEFAULT '',
    digest TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (agent, id)
);
CREATE TABLE IF NOT EXISTS agents (
    agent TEXT PRIMARY KEY,
    physical_id TEXT,
    role TEXT,
    registered_at INTEGER,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS lease_rows (
    page_id TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    agent TEXT NOT NULL,
    tenant TEXT NOT NULL,
    node TEXT NOT NULL,
    address TEXT NOT NULL,
    start INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    domain TEXT NOT NULL DEFAULT 'V',
    generation INTEGER NOT NULL DEFAULT 1,
    physical_id TEXT,
    confirmed INTEGER NOT NULL DEFAULT 0,
    confirmed_at INTEGER,
    extra TEXT,
    network_domain TEXT GENERATED ALWAYS AS (domain) VIRTUAL,
    physical_identity TEXT GENERATED ALWAYS AS (physical_id) VIRTUAL,
    lease_generation INTEGER GENERATED ALWAYS AS (generation) VIRTUAL,
    PRIMARY KEY (agent, page_id, line_no)
);
CREATE TABLE IF NOT EXISTS lease_confirmations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER,
    agent TEXT,
    tenant TEXT,
    domain TEXT,
    address TEXT,
    generation INTEGER,
    observed_address TEXT,
    client_node TEXT,
    ok INTEGER NOT NULL DEFAULT 1,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS neighbor_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER,
    agent TEXT,
    domain TEXT,
    address TEXT,
    target_node TEXT,
    mac TEXT,
    state TEXT,
    observed_at INTEGER,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS tenant_terminations (
    tenant TEXT PRIMARY KEY,
    at INTEGER,
    reason TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS clock_calibrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER,
    tenant TEXT,
    domain TEXT,
    address TEXT,
    page_id TEXT,
    line_no INTEGER,
    old_start INTEGER,
    old_expires INTEGER,
    start INTEGER,
    expires INTEGER,
    source TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS risk_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER,
    created_at_seq INTEGER,
    decision TEXT,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS address_conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER,
    at INTEGER,
    domain TEXT,
    address TEXT,
    window_start INTEGER,
    window_end INTEGER,
    owner_tenant TEXT,
    tenants TEXT,
    agents TEXT,
    status TEXT,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS delivery_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER,
    domain TEXT,
    address TEXT,
    intended_tenant TEXT,
    intended_node TEXT,
    delivered_node TEXT,
    wrong_tenant TEXT,
    kind TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS handoffs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    tenant TEXT NOT NULL,
    domain TEXT,
    address TEXT,
    node TEXT,
    new_address TEXT,
    new_domain TEXT,
    external_domain TEXT,
    external_address TEXT,
    translation_slot TEXT,
    generation INTEGER,
    required_agents TEXT,
    status TEXT NOT NULL,
    blockers TEXT,
    stop_from INTEGER,
    stop_to INTEGER,
    planned_at INTEGER,
    prepared_at INTEGER,
    commit_started_at INTEGER,
    completed_at INTEGER,
    created_at INTEGER,
    plan TEXT
);
CREATE TABLE IF NOT EXISTS agent_receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    handoff_id TEXT NOT NULL,
    agent TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT 'commit',
    status TEXT NOT NULL DEFAULT 'applied',
    at INTEGER,
    physical_id TEXT,
    steps TEXT,
    detail TEXT,
    UNIQUE (handoff_id, agent, phase)
);
CREATE TABLE IF NOT EXISTS handoff_step_state (
    handoff_id TEXT NOT NULL,
    agent TEXT NOT NULL,
    step TEXT NOT NULL,
    status TEXT NOT NULL,
    at INTEGER,
    receipt_id INTEGER,
    PRIMARY KEY (handoff_id, agent, step)
);
CREATE TABLE IF NOT EXISTS address_probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER,
    tenant TEXT,
    domain TEXT,
    address TEXT,
    from_node TEXT,
    observed_node TEXT,
    ok INTEGER NOT NULL DEFAULT 1,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS network_domains (
    domain TEXT PRIMARY KEY,
    kind TEXT,
    isolated_from TEXT,
    status TEXT,
    created_at INTEGER,
    proven_at INTEGER,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS isolation_receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    against_domain TEXT,
    agent TEXT NOT NULL,
    side TEXT,
    at INTEGER,
    status TEXT NOT NULL,
    probe_ok INTEGER NOT NULL DEFAULT 0,
    detail TEXT,
    UNIQUE (domain, against_domain, agent)
);
CREATE TABLE IF NOT EXISTS translation_slots (
    id TEXT PRIMARY KEY,
    external_domain TEXT,
    external_address TEXT,
    internal_domain TEXT,
    internal_address TEXT,
    internal_node TEXT,
    status TEXT,
    tested_ok INTEGER NOT NULL DEFAULT 0,
    tested_at INTEGER,
    created_at INTEGER,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS endpoint_routes (
    tenant TEXT,
    address TEXT,
    node TEXT,
    at INTEGER,
    domain TEXT NOT NULL DEFAULT 'V',
    generation INTEGER,
    state TEXT NOT NULL DEFAULT 'announced',
    executable INTEGER NOT NULL DEFAULT 0,
    external_address TEXT,
    handoff_id TEXT,
    detail TEXT,
    network_domain TEXT GENERATED ALWAYS AS (domain) VIRTUAL
);
CREATE TABLE IF NOT EXISTS executable_endpoints (
    domain TEXT NOT NULL,
    address TEXT NOT NULL,
    tenant TEXT,
    node TEXT,
    generation INTEGER,
    status TEXT NOT NULL,
    provisional INTEGER NOT NULL DEFAULT 0,
    external_address TEXT,
    handoff_id TEXT,
    since INTEGER,
    updated_at INTEGER,
    basis TEXT,
    detail TEXT,
    PRIMARY KEY (domain, address)
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT,
    subject TEXT,
    decision TEXT,
    evidence TEXT
);
"""

# Columns added to tables created by the original minimal release.
_MIGRATIONS = {
    'lease_pages': [
        ("agent", "TEXT NOT NULL DEFAULT ''"),
    ],
    'lease_rows': [
        ("domain", "TEXT NOT NULL DEFAULT 'V'"),
        ("generation", "INTEGER NOT NULL DEFAULT 1"),
        ("physical_id", "TEXT"),
        ("confirmed", "INTEGER NOT NULL DEFAULT 0"),
        ("confirmed_at", "INTEGER"),
        ("extra", "TEXT"),
    ],
    'endpoint_routes': [
        ("domain", "TEXT NOT NULL DEFAULT 'V'"),
        ("generation", "INTEGER"),
        ("state", "TEXT NOT NULL DEFAULT 'announced'"),
        ("executable", "INTEGER NOT NULL DEFAULT 0"),
        ("external_address", "TEXT"),
        ("handoff_id", "TEXT"),
        ("detail", "TEXT"),
    ],
}

_SCHEMA_VERSION = 5


def ensure_schema(db):
    """Create/upgrade all address-handoff tables on any sqlite connection."""
    try:
        version = db.execute('PRAGMA user_version').fetchone()[0]
    except sqlite3.Error:
        version = 0
    if version >= _SCHEMA_VERSION:
        return db
    try:
        db.executescript(SCHEMA)
    except sqlite3.OperationalError:
        # Older SQLite (<3.31) lacks generated columns: drop the convenience
        # alias columns and create the core schema without them.
        import re
        plain = '\n'.join(line for line in SCHEMA.splitlines()
                          if 'GENERATED ALWAYS AS' not in line)
        plain = re.sub(r',(\s*\))', r'\1', plain)
        db.executescript(plain)
    for table, columns in _MIGRATIONS.items():
        existing = {r[1] for r in db.execute('PRAGMA table_info(%s)' % table).fetchall()}
        for name, decl in columns:
            if name not in existing:
                db.execute('ALTER TABLE %s ADD COLUMN %s %s' % (table, name, decl))
    # Backfill the executable flag for legacy rows created before migration:
    # a pre-enhancement row was genuinely programmed, so it stays auditable as
    # an active announcement (duplicates are exactly the published-risk case).
    db.execute("UPDATE endpoint_routes SET state='active', executable=1 WHERE state='announced' AND executable=0")
    db.execute('PRAGMA user_version=%d' % _SCHEMA_VERSION)
    try:
        db.commit()
    except sqlite3.Error:
        pass
    return db


def _event(db, kind, subject, decision, evidence=None):
    payload = jdump(evidence or {})
    cur = db.execute('INSERT INTO events(kind,subject,decision,evidence) VALUES(?,?,?,?)',
                     (kind, subject, str(decision), payload))
    return {'seq': cur.lastrowid, 'kind': kind, 'subject': subject,
            'decision': decision, 'evidence': evidence or {}}


def register_agent(db, *args, **kwargs):
    """Record an issuing/routing agent together with its physical identity."""
    ensure_schema(db)
    req = merge_args(args, kwargs, ('agent', 'physical_id', 'role', 'at'))
    agent = pick(req, 'agent', 'id', 'name')
    if not agent:
        raise ValueError('agent_required')
    physical = pick(req, 'physical_id', *PHYSICAL_KEYS[1:])
    role = pick(req, 'role', default='fabric')
    at = pick(req, 'at', 'registered_at', default=0)
    detail = {k: v for k, v in req.items()
              if k not in {'agent', 'id', 'name', 'physical_id', 'role', 'at', 'registered_at'}}
    with db:
        db.execute('INSERT OR REPLACE INTO agents(agent,physical_id,role,registered_at,detail) '
                   'VALUES(?,?,?,?,?)', (agent, physical, role, at, jdump(detail)))
        _event(db, 'agent.register', agent, 'registered',
               {'physical_id': physical, 'role': role})
    return {'decision': 'registered', 'agent': agent, 'physical_id': physical}


def _physical_for(db, row, req):
    physical = pick(req, *PHYSICAL_KEYS)
    if physical:
        return physical
    known = _one(db, 'SELECT physical_id FROM agents WHERE agent=?', (row['agent'],))
    return known['physical_id'] if known else None


def import_page(db, page_id, rows, received_at):
    ensure_schema(db)
    if (not isinstance(rows, list)
            or any(not isinstance(r, dict)
                or not REQUIRED_ROW_KEYS.issubset(r.keys())
                or not isinstance(r['start'], int)
                or not isinstance(r['expires'], int)
                or r['start'] >= r['expires']
                or not all(isinstance(r[k], str) and r[k] for k in ('agent', 'tenant', 'node', 'address'))
                for r in rows)):
        raise ValueError('invalid_lease_page')
    digest = hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    # Page numbers are per paper journal / agent, so scope replay detection by
    # the issuing agent.  The same page id from two agents are two originals.
    page_agent = rows[0].get('agent', '') if rows else ''
    old = db.execute('SELECT digest FROM lease_pages WHERE id=? AND agent=?',
                     (page_id, page_agent)).fetchone()
    if old:
        old_digest = old[0] if not isinstance(old, sqlite3.Row) else old['digest']
        if old_digest != digest:
            raise ValueError('lease_page_conflict')
        return {'status': 'replayed', 'rows': len(rows)}
    with db:
        db.execute('INSERT INTO lease_pages(id,agent,digest,received_at) VALUES (?,?,?,?)',
                   (page_id, page_agent, digest, received_at))
        for i, r in enumerate(rows, 1):
            domain = pick(r, *DOMAIN_KEYS, default=DEFAULT_DOMAIN)
            generation = pick(r, *GENERATION_KEYS, default=1)
            if not isinstance(generation, int):
                raise ValueError('invalid_lease_page')
            physical = pick(r, *PHYSICAL_KEYS)
            confirmed = 1 if pick(r, *CONFIRM_KEYS, default=False) else 0
            confirmed_at = pick(r, *CONFIRM_AT_KEYS)
            known_agent = _one(db, 'SELECT physical_id FROM agents WHERE agent=?', (r['agent'],))
            if not physical and known_agent:
                physical = known_agent['physical_id']
            extra = {k: v for k, v in r.items()
                     if k not in REQUIRED_ROW_KEYS and k not in DOMAIN_KEYS
                     and k not in GENERATION_KEYS and k not in PHYSICAL_KEYS
                     and k not in CONFIRM_KEYS and k not in CONFIRM_AT_KEYS}
            db.execute(
                'INSERT INTO lease_rows(page_id,line_no,agent,tenant,node,address,start,expires,'
                'domain,generation,physical_id,confirmed,confirmed_at,extra) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (page_id, i, r['agent'], r['tenant'], r['node'], r['address'],
                 r['start'], r['expires'], domain, generation, physical,
                 confirmed, confirmed_at, jdump(extra)))
            if confirmed:
                db.execute(
                    'INSERT INTO lease_confirmations(at,agent,tenant,domain,address,generation,'
                    'observed_address,client_node,ok,detail) VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (confirmed_at if confirmed_at is not None else received_at, r['agent'],
                     r['tenant'], domain, r['address'], generation,
                     pick(r, 'observed_address', default=r['address']), r['node'], 1,
                     jdump({'source': 'inline_page', 'page_id': page_id, 'line_no': i})))
            # A page may carry the on-site neighbour/ARP cache dump directly.
            neighbors = pick(r, 'neighbors', 'neighbour_cache', 'neighbor_cache',
                             'arp_cache', 'neighbour')
            if isinstance(neighbors, list):
                for entry in neighbors:
                    if not isinstance(entry, dict):
                        continue
                    db.execute(
                        'INSERT INTO neighbor_reports(at,agent,domain,address,target_node,mac,'
                        'state,observed_at,detail) VALUES(?,?,?,?,?,?,?,?,?)',
                        (received_at, r['agent'], domain,
                         pick(entry, 'address', 'ip', default=r['address']),
                         pick(entry, 'target_node', 'node', 'target'),
                         pick(entry, 'mac', 'lladdr'),
                         pick(entry, 'state', default='fresh'), received_at, jdump({})))
        _event(db, 'lease_page.import', page_id, 'captured',
               {'rows': len(rows), 'received_at': received_at})
    return {'status': 'captured', 'rows': len(rows)}


def lease_rows(db, tenant=None, address=None, domain=None, at=None):
    """Return preserved lease rows merged with their extra evidence fields."""
    ensure_schema(db)
    sql = 'SELECT * FROM lease_rows WHERE 1=1'
    args = []
    if tenant is not None:
        sql += ' AND tenant=?'; args.append(tenant)
    if address is not None:
        sql += ' AND address=?'; args.append(address)
    if domain is not None:
        sql += ' AND domain=?'; args.append(domain)
    sql += ' ORDER BY start ASC, page_id ASC, line_no ASC'
    out = []
    for row in _rows(db, sql, args):
        extra = {}
        if row.get('extra'):
            try:
                extra = json.loads(row['extra'])
            except (ValueError, TypeError):
                extra = {}
        merged = dict(row)
        merged.update(extra)
        # Calibrated clocks, if any, are exposed separately; original clocks
        # remain untouched on the preserved row.
        cal = _one(
            db,
            'SELECT start,expires,at AS calibrated_at,source FROM clock_calibrations '
            'WHERE page_id=? AND line_no=? ORDER BY id DESC LIMIT 1',
            (row['page_id'], row['line_no']))
        if cal:
            merged['calibrated_start'] = cal['start']
            merged['calibrated_expires'] = cal['expires']
            merged['clock_basis'] = 'calibrated'
        else:
            merged['calibrated_start'] = row['start']
            merged['calibrated_expires'] = row['expires']
            merged['clock_basis'] = 'original'
        out.append(merged)
    if at is not None:
        out = [r for r in out if r['start'] <= at < r['expires']]
    return out


def confirm_lease(db, *args, **kwargs):
    """Record a client confirmation that the tenant actually holds a lease."""
    ensure_schema(db)
    req = merge_args(args, kwargs, ('tenant', 'address', 'at', 'domain', 'generation',
                                    'agent', 'observed_address', 'client_node', 'ok'))
    tenant = pick(req, 'tenant', 'client')
    address = pick(req, 'address', 'lease_address', 'ip')
    at = pick(req, 'at', 'confirmed_at', default=0)
    if not tenant or not address:
        return {'decision': 'missing_lease_reference'}
    domain = pick(req, 'domain', *DOMAIN_KEYS, default=DEFAULT_DOMAIN)
    generation = pick(req, 'generation', *GENERATION_KEYS)
    agent = pick(req, 'agent', default=None)
    ok = 1 if pick(req, 'ok', 'success', default=True) else 0
    matches = lease_rows(db, tenant=tenant, address=address, domain=domain)
    if generation is None and matches:
        generation = max(r['generation'] for r in matches)
    if agent is None and matches:
        agent = matches[-1]['agent']
    with db:
        cur = db.execute(
            'INSERT INTO lease_confirmations(at,agent,tenant,domain,address,generation,'
            'observed_address,client_node,ok,detail) VALUES(?,?,?,?,?,?,?,?,?,?)',
            (at, agent, tenant, domain, address, generation or 1,
             pick(req, 'observed_address', default=address),
             pick(req, 'client_node', 'node'), ok,
             jdump({k: v for k, v in req.items()
                    if k not in {'tenant', 'address', 'at', 'domain', 'generation', 'agent',
                                 'observed_address', 'client_node', 'ok'}})))
        db.execute('UPDATE lease_rows SET confirmed=1, confirmed_at=? '
                   'WHERE tenant=? AND address=? AND domain=?', (at, tenant, address, domain))
        _event(db, 'lease.confirm', '%s/%s/%s' % (domain, address, tenant),
               'confirmed' if ok else 'rejected', {'at': at})
    return {'decision': decision('confirmed' if ok else 'rejected',
                                 ['client_confirmed', 'acked']),
            'tenant': tenant, 'address': address, 'domain': domain, 'at': at,
            'id': cur.lastrowid}


def confirmation_present(db, tenant, address, domain=DEFAULT_DOMAIN, generation=None):
    ensure_schema(db)
    sql = ('SELECT COUNT(*) n FROM lease_confirmations WHERE tenant=? AND address=? '
           'AND domain=? AND ok=1')
    args = [tenant, address, domain]
    if generation is not None:
        sql += ' AND generation=?'; args.append(generation)
    return _one(db, sql, args)['n'] > 0


def record_neighbor_cache(db, *args, **kwargs):
    """Preserve a site neighbour-cache dump/observation from one agent.

    Entries may be given as a list of ``{'address': ..., 'node'/'target_node':
    ..., 'mac': ...}`` or a single entry via keyword arguments.
    """
    ensure_schema(db)
    req = merge_args(args, kwargs, ('agent', 'entries', 'at', 'domain', 'state', 'observed_at'))
    agent = pick(req, 'agent')
    at = pick(req, 'at', 'observed_at', default=0)
    domain = pick(req, 'domain', *DOMAIN_KEYS, default=DEFAULT_DOMAIN)
    state = pick(req, 'state', default='fresh')
    entries = req.get('entries')
    if entries is None:
        if pick(req, 'address', 'ip'):
            entries = [req]
        else:
            entries = []
    if isinstance(entries, dict):
        entries = [entries]
    ids = []
    with db:
        for entry in entries:
            address = pick(entry, 'address', 'ip')
            target = pick(entry, 'target_node', 'node', 'target', default=None)
            mac = pick(entry, 'mac', 'lladdr', default=None)
            entry_state = pick(entry, 'state', default=state)
            cur = db.execute(
                'INSERT INTO neighbor_reports(at,agent,domain,address,target_node,mac,state,'
                'observed_at,detail) VALUES(?,?,?,?,?,?,?,?,?)',
                (pick(entry, 'at', default=at), agent,
                 pick(entry, 'domain', default=domain), address, target, mac, entry_state,
                 pick(entry, 'observed_at', default=at), jdump({})))
            ids.append(cur.lastrowid)
        _event(db, 'neighbor_cache.record', agent or 'site', 'recorded',
               {'entries': len(ids), 'state': state, 'at': at})
    return {'decision': 'recorded', 'agent': agent, 'entries': len(ids), 'ids': ids}


# Friendly alias matching the prompt wording.
record_neighbors = record_neighbor_cache
neighbor_cache = record_neighbor_cache


def invalidate_neighbor(db, *args, **kwargs):
    """Record that an agent invalidated a stale neighbour-cache entry."""
    ensure_schema(db)
    req = merge_args(args, kwargs, ('agent', 'address', 'at', 'domain', 'target_node', 'mac'))
    req['state'] = 'invalidated'
    if 'at' not in req:
        req['at'] = pick(req, 'invalidated_at', default=0)
    return record_neighbor_cache(db, req)


def neighbor_state(db, agent, domain, address):
    """Latest recorded cache state for one agent/domain/address."""
    ensure_schema(db)
    row = _one(
        db,
        'SELECT * FROM neighbor_reports WHERE COALESCE(agent,\'\')=COALESCE(?, \'\') '
        'AND domain=? AND address=? ORDER BY id DESC LIMIT 1',
        (agent, domain, address))
    return row['state'] if row else None


def terminate_tenant(db, *args, **kwargs):
    """Terminate a tenant without deleting any executed route or other claim."""
    ensure_schema(db)
    req = merge_args(args, kwargs, ('tenant', 'at', 'reason'))
    tenant = pick(req, 'tenant', 'id')
    at = pick(req, 'at', default=0)
    reason = pick(req, 'reason', default='terminated')
    if not tenant:
        return {'decision': 'missing_tenant'}
    old = _one(db, 'SELECT * FROM tenant_terminations WHERE tenant=?', (tenant,))
    if old:
        return {'decision': decision('idempotent', ['already_terminated']), 'tenant': tenant}
    with db:
        db.execute('INSERT INTO tenant_terminations(tenant,at,reason,detail) VALUES(?,?,?,?)',
                   (tenant, at, reason, jdump({})))
        # Withdraw the current executable projection only.  The immutable
        # endpoint_routes ledger keeps every already-executed row; we merely
        # transition its state so current-route queries are correct.
        db.execute("UPDATE executable_endpoints SET status='withdrawn', updated_at=? "
                   "WHERE tenant=? AND status!='withdrawn'", (at, tenant))
        db.execute("UPDATE endpoint_routes SET state='withdrawn', executable=0 "
                   "WHERE tenant=? AND state='active'", (tenant,))
        db.execute("INSERT INTO endpoint_routes(tenant,address,node,at,domain,generation,state,"
                   "executable,detail) SELECT tenant,address,node,?,domain,generation,'withdrawn',"
                   "0,? FROM executable_endpoints WHERE tenant=? AND status='withdrawn'",
                   (at, jdump({'reason': reason}), tenant))
        _event(db, 'tenant.terminate', tenant, 'terminated', {'at': at, 'reason': reason})
    return {'decision': decision('terminated', ['released']), 'tenant': tenant, 'at': at}


terminate = terminate_tenant


def tenant_terminated(db, tenant):
    ensure_schema(db)
    return _one(db, 'SELECT tenant,at,reason FROM tenant_terminations WHERE tenant=?', (tenant,))


def calibrate_clock(db, *args, **kwargs):
    """Append a true-clock calibration for a preserved lease.

    Original paper clocks are never overwritten; conflict conclusions are
    recomputed from the calibrated values and every past risk report/action
    stays queryable.
    """
    ensure_schema(db)
    req = merge_args(args, kwargs, ('tenant', 'address', 'start', 'expires', 'at',
                                    'domain', 'page_id', 'line_no', 'source'))
    tenant = pick(req, 'tenant')
    address = pick(req, 'address')
    page_id = pick(req, 'page_id')
    line_no = pick(req, 'line_no')
    at = pick(req, 'at', default=0)
    new_start = pick(req, 'start', 'calibrated_start')
    new_expires = pick(req, 'expires', 'calibrated_expires')
    row = None
    if page_id and line_no is not None:
        row = _one(db, 'SELECT * FROM lease_rows WHERE page_id=? AND line_no=?',
                   (page_id, line_no))
    elif tenant and address:
        domain = pick(req, 'domain', default=DEFAULT_DOMAIN)
        rows = lease_rows(db, tenant=tenant, address=address, domain=domain)
        row = rows[-1] if rows else None
    if not row:
        return {'decision': 'lease_not_found'}
    if new_start is None:
        new_start = row['start']
    if new_expires is None:
        new_expires = row['expires']
    with db:
        cur = db.execute(
            'INSERT INTO clock_calibrations(at,tenant,domain,address,page_id,line_no,old_start,'
            'old_expires,start,expires,source,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
            (at, row['tenant'], row['domain'], row['address'], row['page_id'], row['line_no'],
             row['start'], row['expires'], new_start, new_expires,
             pick(req, 'source', default='true_clock'), jdump({})))
        _event(db, 'lease.calibrate_clock', '%s/%s' % (row['tenant'], row['address']),
               'calibrated', {'from': [row['start'], row['expires']],
                              'to': [new_start, new_expires]})
    return {'decision': 'calibrated', 'id': cur.lastrowid, 'tenant': row['tenant'],
            'address': row['address'], 'start': new_start, 'expires': new_expires}


calibrate_clocks = calibrate_clock


def record_misdelivery(db, *args, **kwargs):
    """Append an observed wrong-machine delivery (never rewritten/deleted)."""
    ensure_schema(db)
    req = merge_args(args, kwargs, ('at', 'domain', 'address', 'intended_tenant',
                                    'delivered_node', 'intended_node', 'wrong_tenant', 'kind'))
    at = pick(req, 'at', default=0)
    domain = pick(req, 'domain', *DOMAIN_KEYS, default=DEFAULT_DOMAIN)
    address = pick(req, 'address')
    with db:
        cur = db.execute(
            'INSERT INTO delivery_incidents(at,domain,address,intended_tenant,intended_node,'
            'delivered_node,wrong_tenant,kind,detail) VALUES(?,?,?,?,?,?,?,?,?)',
            (at, domain, address, pick(req, 'intended_tenant', 'tenant'),
             pick(req, 'intended_node'), pick(req, 'delivered_node', 'node'),
             pick(req, 'wrong_tenant'), pick(req, 'kind', default='cross_tenant'),
             jdump({k: v for k, v in req.items()
                    if k not in {'at', 'domain', 'address', 'intended_tenant',
                                 'delivered_node', 'intended_node', 'wrong_tenant', 'kind'}})))
        _event(db, 'delivery.incident', '%s/%s' % (domain, address), 'misdelivery',
               {'at': at})
    return {'decision': 'recorded', 'id': cur.lastrowid}


record_delivery_incident = record_misdelivery


def incident_history(db, address=None):
    ensure_schema(db)
    if address is not None:
        return _rows(db, 'SELECT * FROM delivery_incidents WHERE address=? ORDER BY id', (address,))
    return _rows(db, 'SELECT * FROM delivery_incidents ORDER BY id')


def save_receipt(db, *args, **kwargs):
    """Persist one routing/fabric agent's application receipt (commit boundary)."""
    ensure_schema(db)
    req = merge_args(args, kwargs, ('handoff_id', 'agent', 'at', 'status', 'phase',
                                    'steps', 'physical_id'))
    handoff_id = pick(req, 'handoff_id', 'id', 'handoff')
    agent = pick(req, 'agent')
    if not handoff_id or not agent:
        return {'decision': 'missing_receipt_reference'}
    at = pick(req, 'at', 'applied_at', default=0)
    status = pick(req, 'status', default='applied')
    phase = pick(req, 'phase', default='commit')
    steps = req.get('steps')
    if steps is None:
        steps = pick(req, 'applied_steps', default=None)
    if isinstance(steps, str):
        steps = [s for s in steps.split(',') if s]
    handoff = get_handoff(db, handoff_id)
    kind = handoff['kind'] if handoff else 'readdress'
    # A bare "applied" receipt means the agent applied the whole standard
    # boundary set; only an explicit partial list withholds individual steps.
    if not steps or steps in (['*'], ['all']) or steps == 'all':
        steps = list(REQUIRED_STEPS.get(kind, []))
    physical = pick(req, 'physical_id', *PHYSICAL_KEYS[1:])
    if not physical:
        known = _one(db, 'SELECT physical_id FROM agents WHERE agent=?', (agent,))
        physical = known['physical_id'] if known else None
    with db:
        existing = _one(db, 'SELECT id FROM agent_receipts WHERE handoff_id=? AND agent=? AND phase=?',
                        (handoff_id, agent, phase))
        if existing:
            db.execute('UPDATE agent_receipts SET status=?, at=?, physical_id=?, steps=?, detail=? '
                       'WHERE id=?',
                       (status, at, physical, jdump(steps or []), jdump({}), existing['id']))
            receipt_id = existing['id']
        else:
            cur = db.execute(
                'INSERT INTO agent_receipts(handoff_id,agent,phase,status,at,physical_id,steps,detail) '
                'VALUES(?,?,?,?,?,?,?,?)',
                (handoff_id, agent, phase, status, at, physical, jdump(steps or []), jdump({})))
            receipt_id = cur.lastrowid
        if status == 'applied' and steps:
            for step in steps:
                db.execute(
                    'INSERT OR REPLACE INTO handoff_step_state(handoff_id,agent,step,status,at,receipt_id) '
                    'VALUES(?,?,?,?,?,?)',
                    (handoff_id, agent, step, 'applied', at, receipt_id))
        db.execute("UPDATE handoffs SET status='half_committed', "
                   "commit_started_at=COALESCE(commit_started_at, ?), "
                   "stop_from=COALESCE(stop_from, ?) WHERE id=? "
                   "AND status IN ('prepared','committing','half_committed','draft')",
                   (at, at, handoff_id))
        _event(db, 'handoff.receipt', handoff_id, '%s:%s' % (agent, status),
               {'at': at, 'phase': phase, 'steps': steps})
    return {'decision': decision('receipt_recorded', ['applied', 'recorded']),
            'handoff_id': handoff_id, 'agent': agent, 'at': at, 'steps': steps or [],
            'receipt_id': receipt_id, 'physical_id': physical}


def record_step(db, *args, **kwargs):
    """Durably checkpoint one recoverable boundary step for one agent.

    This is the fine-grained commit boundary behind the two-phase switch:
    revoke the old lease, assign the new address, update the client cache,
    invalidate neighbour state and apply/publish the route.  Each checkpoint
    is committed immediately so a reopen can show exactly what was applied.
    """
    ensure_schema(db)
    req = merge_args(args, kwargs, ('handoff_id', 'agent', 'step', 'at', 'status'))
    handoff_id = pick(req, 'handoff_id', 'id', 'handoff')
    agent = pick(req, 'agent')
    step = pick(req, 'step', 'operation', 'boundary')
    if not handoff_id or not agent or not step:
        return {'decision': 'missing_step_reference'}
    at = pick(req, 'at', default=0)
    status = pick(req, 'status', default='applied')
    with db:
        db.execute(
            'INSERT OR REPLACE INTO handoff_step_state(handoff_id,agent,step,status,at,receipt_id) '
            'VALUES(?,?,?,?,?,?)', (handoff_id, agent, step, status, at, None))
        db.execute("UPDATE handoffs SET status='half_committed', "
                   "commit_started_at=COALESCE(commit_started_at, ?), "
                   "stop_from=COALESCE(stop_from, ?) WHERE id=? "
                   "AND status IN ('prepared','committing','half_committed','draft')",
                   (at, at, handoff_id))
        _event(db, 'handoff.step', handoff_id, '%s:%s:%s' % (agent, step, status), {'at': at})
    return {'decision': decision('step_recorded', ['checkpointed', 'applied']),
            'handoff_id': handoff_id, 'agent': agent, 'step': step, 'at': at}


checkpoint_step = record_step
complete_step = record_step
apply_step = record_step
record_boundary = record_step


def step_progress(db, handoff_id):
    ensure_schema(db)
    rows = _rows(db, 'SELECT agent, step, status FROM handoff_step_state '
                     'WHERE handoff_id=? ORDER BY agent, step', (handoff_id,))
    progress = {}
    for r in rows:
        progress.setdefault(r['agent'], set()).add(r['step'])
    return progress


# Broad aliases for the receipt boundary.
record_receipt = save_receipt
apply_receipt = save_receipt
agent_receipt = save_receipt
record_agent_receipt = save_receipt


REQUIRED_STEPS = {
    'readdress': ['revoke_old_lease', 'assign_new_address', 'update_client_cache',
                  'invalidate_neighbor_cache', 'apply_route'],
    'isolation': ['prove_domain_isolation', 'install_translation', 'apply_external_route'],
}


def get_handoff(db, handoff_id):
    ensure_schema(db)
    row = _one(db, 'SELECT * FROM handoffs WHERE id=?', (handoff_id,))
    if not row:
        return None
    return _handoff_detail(db, row)


def _handoff_detail(db, row):
    h = dict(row)
    h['required_agents'] = json.loads(h.get('required_agents') or '[]')
    h['blockers'] = json.loads(h.get('blockers') or '[]')
    try:
        h['plan'] = json.loads(h.get('plan') or '{}')
    except (ValueError, TypeError):
        h['plan'] = {}
    receipts = _rows(db, 'SELECT agent,phase,status,at,physical_id,steps FROM agent_receipts '
                         'WHERE handoff_id=? ORDER BY id', (h['id'],))
    for r in receipts:
        try:
            r['steps'] = json.loads(r.get('steps') or '[]')
        except (ValueError, TypeError):
            r['steps'] = []
    h['receipts'] = receipts
    h['step_state'] = _rows(db, 'SELECT agent,step,status,at FROM handoff_step_state '
                                'WHERE handoff_id=? ORDER BY agent,step', (h['id'],))
    receipted = {r['agent'] for r in receipts
                 if r['phase'] == 'commit' and r['status'] == 'applied'}
    progress = {}
    for s in h['step_state']:
        if s.get('status') == 'applied':
            progress.setdefault(s['agent'], set()).add(s['step'])
    required_steps = set(REQUIRED_STEPS.get(h['kind'], []))
    fully_stepped = {a for a, steps in progress.items()
                     if required_steps and required_steps.issubset(steps)}
    h['receipted_agents'] = sorted(receipted)
    h['fully_stepped_agents'] = sorted(fully_stepped)
    h['applied_agents'] = sorted(receipted | fully_stepped)
    h['partial_agents'] = sorted({a for a in progress if a not in receipted | fully_stepped})
    h['step_progress'] = {a: sorted(s) for a, s in progress.items()}
    h['pending_agents'] = [a for a in h['required_agents'] if a not in h['applied_agents']]
    return h


def list_handoffs(db, status=None):
    ensure_schema(db)
    if status:
        rows = _rows(db, 'SELECT id FROM handoffs WHERE status=? ORDER BY id', (status,))
    else:
        rows = _rows(db, 'SELECT id FROM handoffs ORDER BY id')
    return [get_handoff(db, r['id']) for r in rows]


def durable_state(db):
    """Reopen helper: summarise every non-terminal recoverable handoff."""
    ensure_schema(db)
    active = [h for h in list_handoffs(db) if h['status'] not in ('completed', 'aborted')]
    return {
        'decision': decision('reopened', ['recovered', 'resumed']),
        'open_handoffs': active,
        'half_committed': [h['id'] for h in active if h['applied_agents']],
        'applied_agents': {h['id']: h['applied_agents'] for h in active},
        'pending_agents': {h['id']: h['pending_agents'] for h in active},
    }


# Friendly vocabulary aliases for evidence recording.
confirm = confirm_lease
ack_lease = confirm_lease
acknowledge_lease = confirm_lease
record_confirmation = confirm_lease
save_confirmation = confirm_lease
client_confirm = confirm_lease
save_neighbor_cache = record_neighbor_cache
add_neighbor_report = record_neighbor_cache
record_neighbor = record_neighbor_cache
save_neighbors = record_neighbor_cache
record_application_receipt = save_receipt
application_receipt = save_receipt
add_receipt = save_receipt
record_agent_application = save_receipt
import_pages = import_page
mark_terminated = terminate_tenant


def __getattr__(name):
    # Any name not implemented here may be a publishing/handoff operation;
    # delegate lazily to route_publish to avoid an import cycle.
    if name.startswith('__'):
        raise AttributeError('module %r has no attribute %r' % (__name__, name))
    from . import route_publish
    try:
        return getattr(route_publish, name)
    except AttributeError:
        raise AttributeError('module %r has no attribute %r' % (__name__, name))
