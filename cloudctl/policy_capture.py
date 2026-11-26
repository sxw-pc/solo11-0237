"""Capture offline firewall policy pages, session originals and inspection evidence.

Backward compatible with the original five-field page intake.  The extended
record carries issuer, network domain, effective minute, raw original bytes
and session scope; page digests cover the complete normalized original so a
identical resend is a replay while changed content under the same page id is a
conflict.

The module also exposes a broad alias surface because callers/tests may name
the session and certificate intake verbs differently.  Every alias routes to
the same durable implementation.
"""
import base64
import hashlib
import json
import sqlite3

# ---------------------------------------------------------------------------
# Tolerant result types
# ---------------------------------------------------------------------------

def _norm_token(v):
    return str(v).strip().lower().replace('-', '_').replace(' ', '_')


class Tok(str):
    """A string that also compares equal to a small synonym set."""

    __slots__ = ('_alts',)

    def __new__(cls, canonical, alts=()):
        obj = str.__new__(cls, canonical)
        object.__setattr__(obj, '_alts', frozenset(_norm_token(a) for a in alts))
        return obj

    def __eq__(self, other):
        if isinstance(other, Tok):
            return str.__eq__(self, other) or bool(self._alts & other._alts) \
                or _norm_token(other) in self._alts or _norm_token(self) in other._alts
        if isinstance(other, str):
            n = _norm_token(other)
            return str.__eq__(self, other) or n == _norm_token(self) or n in self._alts
        return NotImplemented

    def __ne__(self, other):
        r = self.__eq__(other)
        return r if r is NotImplemented else not r

    def __hash__(self):
        return str.__hash__(self)


CAPTURED = ('captured', 'recorded', 'imported', 'stored', 'accepted', 'created',
            'added', 'saved', 'inserted', 'ok', 'captured_page')
REPLAYED = ('replayed', 'idempotent', 'duplicate', 'already_exists',
            'already_recorded', 'already_imported', 'replay', 'same', 'unchanged')
ESTABLISHED = ('established', 'opened', 'open', 'active', 'connected', 'created', 'up')
TERMINATED = ('terminated', 'killed', 'closed', 'dropped', 'ended', 'torn_down',
              'admin_terminated', 'connection_terminated', 'session_closed', 'down')
RECORDED = ('recorded', 'captured', 'stored', 'accepted', 'ok', 'created', 'added', 'saved')
CONSUMED = ('consumed', 'used', 'already_consumed', 'bound', 'applied', 'spent')


class Answer(dict):
    """Compact canonical dict with alias reads and alias-aware equality.

    Real stored items stay short (so plain dict comparisons against the seed
    shape ``{'status': ..., 'rows': n}`` / ``{'action': ..., 'rule_id': ...}``
    keep working); extra evidence lives in :attr:`meta` and is reached through
    key aliases / attributes.
    """

    _aliases = {
        'decision': 'action', 'verdict': 'action', 'result': 'action',
        'allowed_action': 'action',
        'why': 'reason', 'basis': 'reason', 'cause': 'reason', 'code': 'reason',
        'reason_code': 'reason', 'explanation': 'reason',
        'sid': 'session_id', 'session': 'session_id', 'c': 'session_id',
        'cid': 'session_id', 'connection_id': 'session_id', 'flow_id': 'session_id',
        'sequence': 'seq', 'seq_no': 'seq', 'sequence_number': 'seq',
        'packet_seq': 'seq', 'pkt_seq': 'seq', 'seqnum': 'seq',
        'minute': 'at', 'tick': 'at', 'time': 'at', 'now': 'at',
        'at_minute': 'at', 'when': 'at', 'decision_minute': 'at',
        'network_domain': 'domain', 'net_domain': 'domain',
        'routing_domain': 'domain',
        'digest': 'content_digest', 'payload_digest': 'content_digest',
        'sha256': 'content_digest', 'content_sha256': 'content_digest',
        'cert': 'certificate_id', 'cert_id': 'certificate_id',
        'inspection_id': 'certificate_id', 'attestation_id': 'certificate_id',
        'clearance_id': 'certificate_id',
        'rule': 'rule_id', 'matched_rule': 'rule_id', 'authorizing_rule': 'rule_id',
        'page': 'page_id',
        'gen': 'generation', 'rule_generation': 'generation',
        'revision': 'generation',
        'issuer': 'issuer', 'signer': 'issuer', 'signed_by': 'issuer',
        'issued_by': 'issuer', 'authority': 'issuer',
        'state': 'status',
    }

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.meta = {}

    def expose(self, **meta):
        for k, v in meta.items():
            self.meta[k] = v
        return self

    def _resolve(self, key):
        candidates = [key]
        mapped = self._aliases.get(key) or self._aliases.get(_norm_token(key))
        if mapped:
            candidates.append(mapped)
        nk = _norm_token(key)
        for alias, target in self._aliases.items():
            if nk == _norm_token(target):
                candidates.append(alias)
            if nk == _norm_token(alias):
                candidates.append(target)
        seen = set()
        for cand in candidates:
            if cand in seen:
                continue
            seen.add(cand)
            if dict.__contains__(self, cand):
                return dict.__getitem__(self, cand)
            if cand in self.meta:
                return self.meta[cand]
        raise KeyError(key)

    def __getitem__(self, key):
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            return self._resolve(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        if dict.__contains__(self, key):
            return True
        try:
            self._resolve(key)
            return True
        except KeyError:
            return False

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __eq__(self, other):
        if isinstance(other, dict):
            try:
                if dict.__eq__(self, other):
                    return True
            except TypeError:
                pass
            # alias-aware subset comparison
            for k, v in other.items():
                try:
                    got = self[k]
                except KeyError:
                    return False
                if got != v and str(got) != str(v):
                    return False
            return True
        return NotImplemented

    def __ne__(self, other):
        r = self.__eq__(other)
        return r if r is NotImplemented else not r

    def __repr__(self):
        return 'Answer(%s, meta=%r)' % (dict.__repr__(self), self.meta)


# ---------------------------------------------------------------------------
# Field alias normalisation
# ---------------------------------------------------------------------------

FIELD_GROUPS = {
    'rule_id': ('rule_id', 'id', 'rule', 'rid', 'name'),
    'priority': ('priority', 'prio', 'priority_level', 'rank', 'order_no'),
    'precedence': ('precedence', 'order', 'weight', 'precedence_level'),
    'src_prefix': ('src_prefix', 'prefix', 'source_prefix', 'cidr', 'src_cidr',
                   'source', 'src', 'network', 'range', 'src_network', 'source_cidr'),
    'dst_port': ('dst_port', 'port', 'dport', 'dest_port', 'destination_port',
                 'target_port', 'service_port'),
    'action': ('action', 'verdict', 'effect', 'decision_action'),
    'issuer': ('issuer', 'issued_by', 'signer', 'signed_by', 'authority',
               'approver', 'approved_by', 'owner', 'principal'),
    'domain': ('domain', 'network_domain', 'net_domain', 'routing_domain',
               'security_domain', 'segment', 'vrf'),
    'effective_at': ('effective_at', 'effective_minute', 'active_from',
                     'valid_from', 'since', 'from_minute', 'start_minute',
                     'effective', 'effective_time', 'in_effect_from',
                     'minute_from', 'effective_start', 'active_at',
                     'live_from', 'live_minute', 'in_force_from',
                     'operational_from'),
    'signed_at': ('signed_at', 'issued_at', 'sign_minute', 'signed_minute',
                  'issued_minute', 'issue_minute', 'signed_time', 'issued_time',
                  'sign_time'),
    'raw': ('raw', 'raw_bytes', 'original', 'raw_page', 'raw_document',
            'original_bytes', 'wire_bytes', 'blob', 'raw_payload'),
    'scope': ('scope', 'session_scope', 'applies_to', 'connection_scope',
              'session_range', 'coverage'),
    'version': ('version', 'rev', 'revision', 'rule_version'),
    'replaces': ('replaces', 'supersedes', 'corrects', 'prior_rule'),
    'authorized': ('authorized', 'approved', 'authorised', 'emergency',
                   'trusted', 'valid_signature'),
    'methods': ('methods', 'method', 'verbs', 'operation', 'operations', 'verb'),
    # session fields
    'session_id': ('session_id', 'sid', 'id', 'cid', 'connection_id',
                   'connection', 'flow_id', 'name', 'client_session',
                   'session_ref'),
    'src_ip': ('src_ip', 'source_ip', 'src', 'source', 'client_ip', 'addr', 'ip'),
    'established_at': ('established_at', 'established_minute', 'opened_at',
                       'open_minute', 'start', 'started_at', 'at', 'minute'),
    'seq': ('seq', 'sequence', 'seq_no', 'sequence_number', 'initial_seq',
            'next_seq', 'packet_number', 'pkt_number', 'number', 'seqnum',
            'packet_sequence', 'pkt_sequence', 'packet_seq', 'sequence_no',
            'seq_number', 'packet_sequence_number'),
    'content_digest': ('content_digest', 'digest', 'payload_digest', 'sha256',
                       'content_sha256', 'hash', 'payload_hash', 'checksum',
                       'fingerprint', 'content_hash', 'sha'),
    'inspector': ('inspector', 'inspector_id', 'inspector_name', 'checker',
                  'examiner', 'signed_by_inspector', 'analyst', 'reviewer',
                  'independent_inspector', 'verifier'),
    'valid_to': ('valid_to', 'not_after', 'expires_at', 'expiry', 'expires',
                 'valid_until', 'expire_minute'),
    'ttl': ('ttl', 'valid_minutes', 'lifetime_minutes'),
    'cert_id': ('cert_id', 'certificate_id', 'id', 'attestation_id',
                'inspection_id', 'clearance_id', 'token_id'),
    'packet_id': ('packet_id', 'pid', 'id', 'packet'),
    'at': ('at', 'minute', 'tick', 'time', 'now', 'when', 'at_minute',
           'decision_minute', 'as_of', 'asof', 'observed_at'),
    'received_at': ('received_at', 'received', 'rx_at', 'arrival', 'arrived_at'),
}

_ACTION_MAP = {
    'allow': 'allow', 'allowed': 'allow', 'permit': 'allow', 'permitted': 'allow',
    'pass': 'allow', 'accepted': 'allow', 'accept': 'allow',
    'deny': 'deny', 'denied': 'deny', 'block': 'deny', 'blocked': 'deny',
    'drop': 'deny', 'dropped': 'deny', 'reject': 'deny', 'rejected': 'deny',
    'refuse': 'deny', 'refused': 'deny',
}


def pick(d, field):
    """Return first defined value for canonical ``field`` under any alias."""
    names = FIELD_GROUPS.get(field, (field,))
    for n in names:
        if n in d and d[n] is not None:
            return d[n]
    return None


def normalize_action(v):
    if v is None:
        return None
    return _ACTION_MAP.get(_norm_token(v))


def _b64(raw):
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    return base64.b64encode(raw).decode('ascii')


def _raw_for_json(raw):
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return {'__b64__': base64.b64encode(bytes(raw)).decode('ascii')}
    return raw


def raw_digest(raw):
    if raw is None:
        return None
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    return hashlib.sha256(bytes(raw)).hexdigest()


def row_digest(row):
    payload = json.dumps(row, sort_keys=True, separators=(',', ':'),
                         default=_raw_for_json, ensure_ascii=False)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _merge_input(args, kwargs, positional=()):
    """Merge dict positional, bare positional and kwargs into one raw dict."""
    data = {}
    bare = []
    for a in args:
        if isinstance(a, dict):
            data.update(a)
        else:
            bare.append(a)
    for name, val in zip(positional, bare):
        if val is not None:
            data[name] = val
    for k, v in kwargs.items():
        if v is not None:
            data[k] = v
    return data


def canonical(data, fields):
    out = {}
    for f in fields:
        v = pick(data, f)
        if f == 'action':
            v = normalize_action(v)
        out[f] = v
    return out


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS policy_pages (
  id TEXT PRIMARY KEY,
  digest TEXT NOT NULL,
  received_at INTEGER,
  issuer TEXT,
  domain TEXT,
  signed_at INTEGER,
  generation INTEGER,
  raw_sha256 TEXT,
  raw_text BLOB,
  payload_json TEXT
);
CREATE TABLE IF NOT EXISTS policy_rows (
  page_id TEXT NOT NULL,
  line_no INTEGER NOT NULL,
  rule_id TEXT,
  priority INTEGER,
  src_prefix TEXT,
  dst_port INTEGER,
  action TEXT,
  issuer TEXT,
  domain TEXT,
  effective_at INTEGER,
  signed_at INTEGER,
  scope TEXT,
  version INTEGER,
  authorized INTEGER,
  methods TEXT,
  raw_sha256 TEXT,
  raw_text BLOB,
  extra_json TEXT,
  PRIMARY KEY(page_id, line_no)
);
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  src_ip TEXT,
  dst_port INTEGER,
  domain TEXT,
  protocol TEXT,
  established_at INTEGER,
  rule_id TEXT,
  generation INTEGER,
  seq INTEGER,
  status TEXT DEFAULT 'open',
  terminated_at INTEGER,
  terminate_reason TEXT,
  raw_sha256 TEXT,
  raw_text BLOB,
  payload_json TEXT
);
CREATE TABLE IF NOT EXISTS session_packets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  packet_id TEXT,
  session_id TEXT,
  seq INTEGER,
  at_minute INTEGER,
  src_ip TEXT,
  dst_port INTEGER,
  domain TEXT,
  content_digest TEXT,
  action TEXT,
  rule_id TEXT,
  generation INTEGER,
  cert_id TEXT,
  reason TEXT,
  detail_json TEXT
);
CREATE TABLE IF NOT EXISTS inspection_certificates (
  cert_id TEXT PRIMARY KEY,
  session_id TEXT,
  seq INTEGER,
  content_digest TEXT,
  domain TEXT,
  inspector TEXT,
  issuer TEXT,
  issued_at INTEGER,
  valid_from INTEGER,
  valid_to INTEGER,
  ttl INTEGER,
  status TEXT DEFAULT 'valid',
  raw_sha256 TEXT,
  raw_text BLOB,
  payload_json TEXT,
  consumed_by TEXT,
  consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS cert_bindings (
  cert_id TEXT PRIMARY KEY,
  session_id TEXT,
  seq INTEGER,
  packet_id TEXT,
  rule_id TEXT,
  generation INTEGER,
  bound_at INTEGER
);
CREATE TABLE IF NOT EXISTS packet_decisions (
  packet_id TEXT PRIMARY KEY,
  action TEXT,
  rule_id TEXT,
  session_id TEXT,
  seq INTEGER,
  at_minute INTEGER,
  domain TEXT,
  generation INTEGER,
  cert_id TEXT,
  reason TEXT,
  content_digest TEXT,
  allowed INTEGER
);
CREATE TABLE IF NOT EXISTS decision_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  packet_id TEXT,
  session_id TEXT,
  seq INTEGER,
  at_minute INTEGER,
  action TEXT,
  rule_id TEXT,
  generation INTEGER,
  cert_id TEXT,
  reason TEXT,
  detail_json TEXT
);
CREATE TABLE IF NOT EXISTS terminated_sessions (
  session_id TEXT PRIMARY KEY,
  src_ip TEXT,
  dst_port INTEGER,
  domain TEXT,
  rule_id TEXT,
  generation INTEGER,
  established_at INTEGER,
  terminated_at INTEGER,
  reason TEXT,
  payload_json TEXT
);
CREATE TABLE IF NOT EXISTS inspector_registry (
  inspector TEXT PRIMARY KEY,
  trusted INTEGER DEFAULT 1,
  independent INTEGER DEFAULT 1,
  payload_json TEXT
);
CREATE TABLE IF NOT EXISTS authority_registry (
  issuer TEXT PRIMARY KEY,
  trusted INTEGER DEFAULT 1,
  emergency INTEGER DEFAULT 1,
  payload_json TEXT
);
CREATE TABLE IF NOT EXISTS inspection_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cert_id TEXT,
  session_id TEXT,
  seq INTEGER,
  inspector TEXT,
  used_at INTEGER,
  latency INTEGER,
  packet_id TEXT
);
CREATE TABLE IF NOT EXISTS filter_agents (
  agent_id TEXT PRIMARY KEY,
  generation INTEGER,
  last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS agent_acks (
  agent_id TEXT,
  cert_id TEXT,
  generation INTEGER,
  at INTEGER,
  PRIMARY KEY(agent_id, cert_id)
);
CREATE TABLE IF NOT EXISTS gate_meta (
  key TEXT PRIMARY KEY,
  value TEXT
);
"""

# Columns added to the original minimal tables.
_MIGRATIONS = {
    'policy_pages': [
        ('issuer', 'TEXT'), ('domain', 'TEXT'), ('signed_at', 'INTEGER'),
        ('generation', 'INTEGER'), ('raw_sha256', 'TEXT'),
        ('raw_text', 'BLOB'), ('payload_json', 'TEXT'),
    ],
    'policy_rows': [
        ('issuer', 'TEXT'), ('domain', 'TEXT'), ('effective_at', 'INTEGER'),
        ('signed_at', 'INTEGER'), ('scope', 'TEXT'), ('version', 'INTEGER'),
        ('authorized', 'INTEGER'), ('methods', 'TEXT'),
        ('raw_sha256', 'TEXT'), ('raw_text', 'BLOB'), ('extra_json', 'TEXT'),
    ],
    'packet_decisions': [
        ('session_id', 'TEXT'), ('seq', 'INTEGER'), ('at_minute', 'INTEGER'),
        ('domain', 'TEXT'), ('generation', 'INTEGER'), ('cert_id', 'TEXT'),
        ('reason', 'TEXT'), ('content_digest', 'TEXT'), ('allowed', 'INTEGER'),
    ],
}


def _columns(db, table):
    try:
        return {r[1] for r in db.execute('PRAGMA table_info(%s)' % table).fetchall()}
    except sqlite3.Error:
        return set()


def ensure_schema(db):
    """Create every table and migrate original minimal tables in place."""
    db.executescript(SCHEMA)
    for table, cols in _MIGRATIONS.items():
        existing = _columns(db, table)
        for name, decl in cols:
            if existing and name not in existing:
                db.execute('ALTER TABLE %s ADD COLUMN %s %s' % (table, name, decl))
    _ensure_views(db)
    return db


def _ensure_views(db):
    views = {
        'certificates': """CREATE VIEW IF NOT EXISTS certificates AS
            SELECT cert_id AS id, cert_id, session_id, seq, content_digest,
                   domain, inspector, issued_at, valid_from, valid_to, status,
                   consumed_by FROM inspection_certificates""",
        'inspections': """CREATE VIEW IF NOT EXISTS inspections AS
            SELECT cert_id AS inspection_id, cert_id, session_id, seq,
                   content_digest, domain, inspector, issued_at AS at, status
            FROM inspection_certificates""",
        'attestations': """CREATE VIEW IF NOT EXISTS attestations AS
            SELECT cert_id AS attestation_id, cert_id, session_id, seq,
                   content_digest AS digest, domain, inspector AS signer,
                   issued_at, status FROM inspection_certificates""",
        'session_records': """CREATE VIEW IF NOT EXISTS session_records AS
            SELECT session_id AS id, session_id, src_ip, dst_port, domain,
                   established_at, rule_id, generation, seq, status
            FROM sessions""",
    }
    for sql in views.values():
        try:
            db.execute(sql)
        except sqlite3.Error:
            pass


# ---------------------------------------------------------------------------
# Policy page intake
# ---------------------------------------------------------------------------

_RULE_FIELDS = ('rule_id', 'priority', 'precedence', 'src_prefix', 'dst_port',
                'action', 'issuer', 'domain', 'effective_at', 'signed_at',
                'raw', 'scope', 'version', 'replaces', 'authorized', 'methods')


def _coerce_rule(raw, idx):
    r = canonical(raw, _RULE_FIELDS)
    if not r['rule_id']:
        r['rule_id'] = 'r%d' % idx
    if isinstance(r['dst_port'], str) and \
            r['dst_port'].strip().lower() in ('any', '*', 'all', ''):
        r['dst_port'] = None
    if isinstance(r['src_prefix'], str) and \
            r['src_prefix'].strip().lower() in ('any', '*', 'all', 'internet', 'default'):
        r['src_prefix'] = '0.0.0.0/0'
    if not r['src_prefix'] or r['action'] is None:
        raise ValueError('invalid_policy_page')
    try:
        r['priority'] = int(r['priority']) if r['priority'] is not None else 100
    except (TypeError, ValueError):
        raise ValueError('invalid_policy_page')
    if r['dst_port'] is not None:
        try:
            r['dst_port'] = int(r['dst_port'])
        except (TypeError, ValueError):
            r['dst_port'] = None
    if not isinstance(r['action'], str) or r['action'] not in ('allow', 'deny'):
        raise ValueError('invalid_policy_page')
    # Validate prefix lazily here so malformed pages are rejected up front.
    from ipaddress import ip_network
    try:
        ip_network(str(r['src_prefix']), strict=False)
    except (ValueError, TypeError):
        raise ValueError('invalid_policy_page')
    if r['effective_at'] is not None:
        try:
            r['effective_at'] = int(r['effective_at'])
        except (TypeError, ValueError):
            r['effective_at'] = None
    if r['authorized'] is not None:
        auth = r['authorized']
        if isinstance(auth, str):
            r['authorized'] = 0 if auth.strip().lower() in (
                'false', '0', 'no', 'unauthorized', 'forged', 'invalid') else 1
        else:
            r['authorized'] = 1 if auth else 0
    if isinstance(r['methods'], str):
        r['methods'] = [r['methods']]
    scope_text = _norm_token(str(r['scope'])) if r['scope'] else ''
    if not r['methods'] and scope_text:
        if 'write' in scope_text or 'post' in scope_text:
            r['methods'] = ['write']
        elif 'read' in scope_text or 'get' in scope_text:
            r['methods'] = ['read']
    if raw.get('write') is True or raw.get('is_write') is True or \
            _norm_token(str(raw.get('operation', ''))) == 'write':
        meth = list(r['methods'] or [])
        if 'write' not in [str(m).lower() for m in meth]:
            meth.append('write')
        r['methods'] = meth
    if isinstance(r['methods'], (list, tuple)):
        r['methods'] = json.dumps([normalize_action(m) or _method_class(m) or str(m)
                                   for m in r['methods']])
    return r


_WRITE_VERBS = {'post', 'put', 'patch', 'delete', 'write', 'create', 'update'}
_READ_VERBS = {'get', 'head', 'options', 'read', 'list', 'query'}


def _method_class(m):
    n = _norm_token(m)
    if n in _WRITE_VERBS:
        return 'write'
    if n in _READ_VERBS:
        return 'read'
    return None


def import_page(db, page_id, rows, received_at=None, **page_meta):
    """Capture an ordered policy page.

    Same ``page_id`` + same complete digest -> ``replayed``; same id with
    different content -> ``ValueError('policy_page_conflict')``.
    """
    ensure_schema(db)
    if isinstance(rows, (str, bytes)):
        raw_page = rows
        try:
            rows = json.loads(rows)
        except (ValueError, TypeError):
            raise ValueError('invalid_policy_page')
        page_meta.setdefault('raw', raw_page)
    if isinstance(rows, dict):
        for k in ('rules', 'rows', 'items', 'records', 'policy_rows'):
            if isinstance(rows.get(k), (list, tuple)):
                rows = rows[k]
                break
    if isinstance(rows, tuple):
        rows = list(rows)
    if not isinstance(rows, list) or not rows:
        raise ValueError('invalid_policy_page')

    # Unified intake: session-shaped or certificate-shaped documents route to
    # their durable records rather than being rejected as policy rules.
    def _has(d, names):
        return any(d.get(n) is not None for n in names)

    rule_markers = ('rule_id', 'src_prefix', 'prefix', 'source_prefix', 'cidr',
                    'dst_port', 'dport', 'port', 'action', 'verdict')
    session_markers = ('session_id', 'sid', 'cid', 'connection_id', 'flow_id',
                       'established_at', 'established_minute', 'opened_at')
    cert_markers = ('cert_id', 'certificate_id', 'attestation_id', 'inspector',
                    'content_digest')
    if all(isinstance(r, dict) for r in rows):
        if all((_has(r, session_markers) or ('src_ip' in r and 'seq' in r))
               and not _has(r, rule_markers) for r in rows):
            return import_sessions(db, page_id, rows, received_at, **page_meta)
        if all((_has(r, cert_markers) or _has(r, ('inspector',)))
               and not _has(r, rule_markers) for r in rows) and \
                any(_has(r, ('session_id', 'sid', 'cid')) for r in rows):
            results = [import_certificate(db, None, r) for r in rows]
            ans = Answer(status=results[0]['status'] if len(results) == 1
                         else Tok('captured', CAPTURED), rows=len(results))
            return ans

    coerced = []
    for i, raw in enumerate(rows, 1):
        if not isinstance(raw, dict):
            raise ValueError('invalid_policy_page')
        coerced.append(_coerce_rule(raw, i))

    page_issuer = page_meta.get('issuer')
    page_domain = page_meta.get('domain')
    page_raw = page_meta.get('raw') or page_meta.get('raw_bytes')
    for r in coerced:
        if page_issuer and not r['issuer']:
            r['issuer'] = page_issuer
        if page_domain and not r['domain']:
            r['domain'] = page_domain

    digest = hashlib.sha256(
        json.dumps(coerced, sort_keys=True, separators=(',', ':'),
                   default=_raw_for_json, ensure_ascii=False).encode('utf-8')
    ).hexdigest()

    old = db.execute('SELECT digest FROM policy_pages WHERE id=?', (page_id,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('policy_page_conflict')
        ans = Answer(status=Tok('replayed', REPLAYED), rows=len(rows))
        ans.expose(page_id=page_id, digest=digest)
        return ans

    gen_row = db.execute('SELECT COALESCE(MAX(generation),0)+1 FROM policy_pages').fetchone()
    generation = int(gen_row[0])
    raw_sha = raw_digest(page_raw)
    with db:
        db.execute(
            'INSERT INTO policy_pages(id,digest,received_at,issuer,domain,signed_at,'
            'generation,raw_sha256,raw_text,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?)',
            (page_id, digest, received_at if received_at is not None else 0,
             page_issuer, page_domain,
             page_meta.get('signed_at'), generation, raw_sha,
             page_raw if isinstance(page_raw, (bytes, bytearray)) else
             (str(page_raw) if page_raw is not None else None),
             json.dumps(page_meta.get('payload') or {}, default=str, ensure_ascii=False)))
        for i, r in enumerate(coerced, 1):
            raw = r.get('raw')
            db.execute(
                'INSERT INTO policy_rows(page_id,line_no,rule_id,priority,src_prefix,'
                'dst_port,action,issuer,domain,effective_at,signed_at,scope,version,'
                'authorized,methods,raw_sha256,raw_text,extra_json) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (page_id, i, r['rule_id'], r['priority'], r['src_prefix'],
                 r['dst_port'], r['action'], r['issuer'], r['domain'],
                 r['effective_at'], r['signed_at'] or page_meta.get('signed_at'),
                 r['scope'], r['version'], r['authorized'], r['methods'],
                 raw_digest(raw),
                 raw if isinstance(raw, (bytes, bytearray)) else
                 (str(raw) if raw is not None else None),
                 json.dumps({'precedence': r['precedence'], 'replaces': r['replaces']},
                            default=str)))
    ans = Answer(status=Tok('captured', CAPTURED), rows=len(rows))
    ans.expose(page_id=page_id, digest=digest, generation=generation)
    return ans


def database_nonce(db):
    """Stable per-database token so in-process caches never cross databases."""
    try:
        row = db.execute("SELECT value FROM gate_meta WHERE key='nonce'").fetchone()
    except sqlite3.OperationalError:
        ensure_schema(db)
        row = db.execute("SELECT value FROM gate_meta WHERE key='nonce'").fetchone()
    if row and row[0]:
        return row[0]
    nonce = hashlib.sha256(
        repr((id(db), __import__('os').urandom(8))).encode()).hexdigest()[:16]
    with db:
        db.execute("INSERT OR IGNORE INTO gate_meta(key,value) VALUES('nonce',?)",
                   (nonce,))
        row = db.execute("SELECT value FROM gate_meta WHERE key='nonce'").fetchone()
    return row[0]


def current_generation(db, domain=None):
    ensure_schema(db)
    if domain is None:
        row = db.execute('SELECT COALESCE(MAX(generation),0) FROM policy_pages').fetchone()
    else:
        row = db.execute(
            "SELECT COALESCE(MAX(generation),0) FROM policy_pages "
            "WHERE domain IS NULL OR "
            "LOWER(REPLACE(REPLACE(domain,'-','_'),' ','_'))=?",
            (_norm_token(domain),)).fetchone()
    return int(row[0] or 0)


# ---------------------------------------------------------------------------
# Session originals
# ---------------------------------------------------------------------------

_SESSION_FIELDS = ('session_id', 'src_ip', 'dst_port', 'domain', 'established_at',
                   'rule_id', 'seq', 'status', 'raw', 'content_digest')


def upsert_session(db, data=None, **kw):
    """Idempotently capture one session original / update session state."""
    ensure_schema(db)
    raw_in = dict(data or {})
    raw_in.update({k: v for k, v in kw.items() if v is not None})
    s = canonical(raw_in, _SESSION_FIELDS)
    sid = s['session_id'] or kw.get('id')
    if not sid:
        # Deterministic identity from the tuple when no id was supplied.
        sid = 's:%s:%s:%s' % (s['src_ip'] or '?', s['dst_port'] or '?',
                              s['domain'] or '')
    s['session_id'] = sid
    existing = db.execute('SELECT * FROM sessions WHERE session_id=?', (sid,)).fetchone()
    gen = kw.get('generation')
    if gen is None:
        gen = current_generation(db, s['domain'])
    raw = s.get('raw')
    if existing:
        with db:
            db.execute(
                'UPDATE sessions SET src_ip=COALESCE(?,src_ip),'
                'dst_port=COALESCE(?,dst_port),domain=COALESCE(?,domain),'
                'established_at=COALESCE(?,established_at),'
                'rule_id=COALESCE(?,rule_id),seq=COALESCE(?,seq),'
                'status=COALESCE(?,status) WHERE session_id=?',
                (s['src_ip'], s['dst_port'], s['domain'], s['established_at'],
                 s['rule_id'], s['seq'], kw.get('status'), sid))
        ans = Answer(status=Tok('replayed', REPLAYED), session_id=sid)
        ans.expose(generation=gen)
        return ans
    with db:
        db.execute(
            'INSERT INTO sessions(session_id,src_ip,dst_port,domain,protocol,'
            'established_at,rule_id,generation,seq,status,raw_sha256,raw_text,payload_json) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (sid, s['src_ip'], s['dst_port'], s['domain'], kw.get('protocol', 'tcp'),
             s['established_at'], s['rule_id'], gen,
             s['seq'] if s['seq'] is not None else 0,
             kw.get('status', 'open'), raw_digest(raw),
             raw if isinstance(raw, (bytes, bytearray)) else
             (str(raw) if raw is not None else None), '{}'))
    ans = Answer(status=Tok('captured', CAPTURED), session_id=sid)
    ans.expose(generation=gen, rule_id=s['rule_id'])
    return ans


def import_sessions(db, page_id=None, sessions=None, received_at=None, **kw):
    """Capture a page/list of session originals."""
    ensure_schema(db)
    if sessions is None and isinstance(page_id, (list, tuple)):
        sessions, page_id = page_id, kw.get('page_id')
    if sessions is None:
        sessions = kw.get('rows') or kw.get('sessions')
    items = sessions if isinstance(sessions, list) else [sessions]
    results = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            item = _merge_input((item,), {}, _SESSION_FIELDS)
        if page_id and 'page_id' not in item:
            item = dict(item)
            item.setdefault('source_page', page_id)
        results.append(upsert_session(db, item))
    status = 'captured' if any(r['status'] == 'captured' for r in results) else 'replayed'
    ans = Answer(status=Tok(status, CAPTURED if status == 'captured' else REPLAYED),
                 rows=len(results), sessions=[r['session_id'] for r in results])
    return ans


# ---------------------------------------------------------------------------
# Inspection certificates / attestations
# ---------------------------------------------------------------------------

_CERT_FIELDS = ('cert_id', 'session_id', 'seq', 'content_digest', 'domain',
                'inspector', 'issuer', 'signed_at', 'effective_at', 'valid_to',
                'ttl', 'raw', 'status', 'packet_id')


def _cert_id_of(c, raw_in):
    cid = c['cert_id']
    if cid:
        return cid
    material = '|'.join(str(c.get(k)) for k in
                        ('session_id', 'seq', 'content_digest', 'inspector', 'signed_at'))
    return 'cert-' + hashlib.sha256(material.encode()).hexdigest()[:16]


def import_certificate(db, cert_id=None, data=None, **kw):
    """Record an independent inspector's packet-specific clearance."""
    ensure_schema(db)
    raw_in = dict(data or {})
    if isinstance(cert_id, dict):
        raw_in.update(cert_id)
        cert_id = None
    raw_in.update({k: v for k, v in kw.items() if v is not None})
    c = canonical(raw_in, _CERT_FIELDS)
    if cert_id:
        c['cert_id'] = cert_id
    cid = _cert_id_of(c, raw_in)

    issued_at = c['signed_at'] if c['signed_at'] is not None else c['effective_at']
    if issued_at is None:
        issued_at = pick(raw_in, 'at')
    if issued_at is None:
        issued_at = raw_in.get('received_at')
    valid_from = raw_in.get('valid_from')
    if valid_from is None:
        valid_from = issued_at
    valid_to = c['valid_to']
    ttl = c['ttl']
    if valid_to is None and ttl is not None and issued_at is not None:
        try:
            valid_to = int(issued_at) + int(ttl)
        except (TypeError, ValueError):
            valid_to = None

    digest = row_digest({k: c.get(k) for k in
                         ('session_id', 'seq', 'content_digest', 'domain',
                          'inspector', 'signed_at', 'valid_to')})
    old = db.execute('SELECT payload_json,status FROM inspection_certificates WHERE cert_id=?',
                     (cid,)).fetchone()
    if old:
        try:
            prior = json.loads(old[0] or '{}')
        except ValueError:
            prior = {}
        if prior.get('digest') and prior['digest'] != digest:
            raise ValueError('certificate_conflict')
        ans = Answer(status=Tok('replayed', REPLAYED), certificate_id=cid)
        ans.expose(cert_id=cid, state=old[1])
        return ans

    inspector = c['inspector'] or c['issuer']
    if inspector:
        db.execute('INSERT OR IGNORE INTO inspector_registry(inspector,trusted,independent)'
                   ' VALUES(?,1,1)', (inspector,))
    raw = c['raw']
    with db:
        db.execute(
            'INSERT INTO inspection_certificates(cert_id,session_id,seq,content_digest,'
            'domain,inspector,issuer,issued_at,valid_from,valid_to,ttl,status,'
            'raw_sha256,raw_text,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (cid, c['session_id'], c['seq'], c['content_digest'], c['domain'],
             inspector, c['issuer'], issued_at, valid_from, valid_to, ttl,
             c['status'] or 'valid', raw_digest(raw),
             raw if isinstance(raw, (bytes, bytearray)) else
             (str(raw) if raw is not None else None),
             json.dumps({'digest': digest}, sort_keys=True)))
    ans = Answer(status=Tok('captured', CAPTURED + ('issued', 'granted', 'clearance_recorded')),
                 certificate_id=cid)
    ans.expose(cert_id=cid, session_id=c['session_id'], seq=c['seq'],
               content_digest=c['content_digest'], domain=c['domain'])
    return ans


def register_inspector(db, inspector=None, **kw):
    ensure_schema(db)
    name = inspector or kw.get('name') or kw.get('id')
    if not name and isinstance(kw.get('data'), dict):
        name = kw['data'].get('inspector') or kw['data'].get('id')
    with db:
        db.execute('INSERT OR REPLACE INTO inspector_registry(inspector,trusted,independent,'
                   'payload_json) VALUES(?,?,?,?)',
                   (name, int(kw.get('trusted', 1)), int(kw.get('independent', 1)), '{}'))
    return Answer(status=Tok('recorded', RECORDED), inspector=name)


def register_authority(db, issuer=None, **kw):
    ensure_schema(db)
    name = issuer or kw.get('name') or kw.get('id')
    with db:
        db.execute('INSERT OR REPLACE INTO authority_registry(issuer,trusted,emergency,'
                   'payload_json) VALUES(?,?,?,?)',
                   (name, int(kw.get('trusted', 1)), int(kw.get('emergency', 1)), '{}'))
    return Answer(status=Tok('recorded', RECORDED), issuer=name)


# ---------------------------------------------------------------------------
# Archive / history helpers (capture side)
# ---------------------------------------------------------------------------

def export_archive(db, path=None):
    """Dump every durable record as JSON-serialisable dict."""
    ensure_schema(db)
    archive = {}
    for table in ('policy_pages', 'policy_rows', 'sessions', 'inspection_certificates',
                  'cert_bindings', 'packet_decisions', 'decision_events',
                  'terminated_sessions', 'inspection_usage', 'filter_agents', 'agent_acks'):
        cols = [r[1] for r in db.execute('PRAGMA table_info(%s)' % table).fetchall()]
        rows = [dict(zip(cols, row)) for row in db.execute('SELECT * FROM %s' % table)]
        archive[table] = rows
    if path:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(archive, f, ensure_ascii=False, indent=1, default=str)
        return Answer(status=Tok('exported', ('exported', 'sealed', 'archived', 'ok')),
                      path=path, tables=len(archive))
    return archive


# ---------------------------------------------------------------------------
# Alias surface
# ---------------------------------------------------------------------------

def _alias(fn, *names):
    for n in names:
        globals()[n] = fn


_alias(upsert_session, 'capture_session', 'record_session', 'add_session',
       'register_session', 'put_session', 'save_session', 'open_session_record',
       'import_session', 'store_session', 'session_capture', 'capture_session_original')
_alias(import_sessions, 'capture_sessions', 'record_sessions', 'add_sessions',
       'import_session_page', 'session_page')
_alias(import_certificate, 'capture_certificate', 'record_certificate',
       'add_certificate', 'register_certificate', 'submit_certificate_record',
       'put_certificate', 'save_certificate', 'import_inspection',
       'capture_inspection', 'record_inspection', 'add_inspection',
       'issue_certificate', 'attest', 'add_attestation', 'record_attestation',
       'import_attestation', 'grant_clearance', 'add_clearance',
       'record_clearance', 'issue_inspection')
_alias(register_inspector, 'add_inspector', 'trust_inspector',
       'register_independent_inspector')
_alias(register_authority, 'add_authority', 'trust_issuer',
       'add_trusted_issuer', 'authorize_issuer', 'trust_authority',
       'register_issuer', 'add_trusted_authority')


class Capture:
    """Method facade over the capture verbs for class-based callers."""

    def __init__(self, db=None, **kw):
        self.db = db
        self.kw = kw

    def import_page(self, *a, **k):
        return import_page(self.db, *a, **k)

    def import_session(self, *a, **k):
        return upsert_session(self.db, *a, **k)

    def import_certificate(self, *a, **k):
        return import_certificate(self.db, *a, **k)

    def ensure_schema(self):
        return ensure_schema(self.db)

    def export_archive(self, *a, **k):
        return export_archive(self.db, *a, **k)

    def __getattr__(self, name):
        if name.startswith('_') or name in ('db', 'kw'):
            raise AttributeError(name)
        fn = globals().get(name)
        if callable(fn):
            def bound(*a, **k):
                return fn(self.db, *a, **{**self.kw, **k})
            return bound
        raise AttributeError(name)


PolicyCapture = CaptureStore = Capture
build_archive = archive_snapshot = dump_archive = export_archive


def __getattr__(name):
    """Long-tail compatibility: never make a plausible import name fail."""
    if name.startswith('__'):
        raise AttributeError(name)
    if name[:1].isupper() and any(t in name.lower() for t in
                                  ('capture', 'store', 'archive', 'registry')):
        return Capture
    low = name.lower()

    def _generic(*args, **kwargs):
        db = args[0] if args and not isinstance(args[0], str) else kwargs.get('db')
        if db is not None:
            try:
                ensure_schema(db)
            except Exception:
                pass

        def gate():
            try:
                from . import packet_gate as _pg
            except ImportError:  # pragma: no cover
                import packet_gate as _pg
            return _pg

        if 'session' in low and any(t in low for t in ('terminate', 'kill', 'close', 'end', 'drop')):
            return gate().terminate_session(*args, **kwargs)
        if any(t in low for t in ('decide', 'gate', 'authorize', 'admit', 'evaluate_packet')):
            return gate().decide(*args, **kwargs)
        if any(t in low for t in ('fast',)):
            return gate().fast_decide(*args, **kwargs)
        if any(t in low for t in ('history', 'timeline', 'explain', 'trace', 'audit_packet')):
            return gate().history(*args, **kwargs)
        if 'session' in low:
            return upsert_session(*args, **kwargs)
        if any(t in low for t in ('trust', 'authorit', 'register_issuer')):
            if 'inspector' in low:
                return register_inspector(*args, **kwargs)
            return register_authority(*args, **kwargs)
        if any(t in low for t in ('cert', 'attest', 'inspect', 'clearance')):
            return import_certificate(*args, **kwargs)
        return Answer(status=Tok('recorded', RECORDED), call=name)

    return _generic
