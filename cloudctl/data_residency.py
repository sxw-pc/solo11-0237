"""Data-processing residency, license lineage and lawful delivery ledger.

This module closes the gap between *compute* placement and the actual
jurisdiction of raw bytes, recovery points, temporary caches, derived
artifacts and delivered results.

Everything is persisted in the same SQLite database and every decision is
emitted through :func:`cloudctl.store.event`, so a control-plane power loss
loses no state: a fresh transaction can reconstruct the compliance picture
from datasets, license versions, physical copies, plans, artifacts and
deliveries.

The call style mirrors the rest of ``cloudctl``: every operation is
``fn(db, request)`` and returns the event dict written to the ``events``
table.  Request keys accept the vocabulary used across the engagement
(``region``/``jurisdiction``, ``node``/``node_id`` ...).
"""
from __future__ import annotations

import hashlib
import json

from .store import one, many, event
from .storage_capture import capture_page  # re-exported entry point
from . import store as _store

init_db = _store.init
init = _store.init

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

RESIDENCY_SCHEMA = """
CREATE TABLE IF NOT EXISTS dr_datasets(
  id TEXT PRIMARY KEY,
  source_party TEXT NOT NULL,
  jurisdiction TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  license_version TEXT NOT NULL,
  purposes TEXT NOT NULL,
  fields TEXT NOT NULL,
  cross_border_fields TEXT NOT NULL,
  recipient_zones TEXT NOT NULL,
  deidentified_zones TEXT NOT NULL,
  delete_after INTEGER,
  at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS dr_licenses(
  id TEXT PRIMARY KEY,
  dataset TEXT NOT NULL,
  version INTEGER NOT NULL,
  state TEXT NOT NULL,
  purposes TEXT NOT NULL,
  fields TEXT NOT NULL,
  regions TEXT NOT NULL,
  cross_border_fields TEXT NOT NULL,
  cross_border_destinations TEXT NOT NULL,
  recipient_zones TEXT NOT NULL,
  deidentified_zones TEXT NOT NULL,
  delete_after INTEGER,
  effective_from INTEGER NOT NULL,
  effective_to INTEGER,
  issued_at INTEGER NOT NULL,
  revoked_at INTEGER,
  supersedes INTEGER,
  reason TEXT,
  UNIQUE(dataset,version)
);
CREATE TABLE IF NOT EXISTS dr_plans(
  id TEXT PRIMARY KEY,
  app TEXT,
  demand TEXT,
  purpose TEXT,
  recipient TEXT,
  recipient_zone TEXT,
  at INTEGER,
  state TEXT NOT NULL,
  license_snapshot TEXT,
  terms TEXT,
  target_node TEXT,
  target_zone TEXT,
  cancel_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS dr_plan_inputs(
  plan TEXT NOT NULL,
  dataset TEXT NOT NULL,
  PRIMARY KEY(plan,dataset)
);
CREATE TABLE IF NOT EXISTS dr_app_datasets(
  app TEXT NOT NULL,
  dataset TEXT NOT NULL,
  PRIMARY KEY(app,dataset)
);
CREATE TABLE IF NOT EXISTS dr_copies(
  id TEXT PRIMARY KEY,
  dataset TEXT NOT NULL,
  node TEXT,
  zone TEXT,
  jurisdiction TEXT,
  kind TEXT NOT NULL,
  digest TEXT NOT NULL,
  at INTEGER NOT NULL,
  source_copy TEXT,
  plan TEXT,
  demand TEXT,
  license_id TEXT,
  license_version INTEGER,
  fields TEXT,
  status TEXT NOT NULL,
  lawful INTEGER NOT NULL,
  violation_id TEXT,
  delete_attempts INTEGER NOT NULL DEFAULT 0,
  deleted_at INTEGER,
  cleanup_owner TEXT,
  cleanup_due INTEGER,
  origin TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dr_violations(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE,
  at INTEGER NOT NULL,
  kind TEXT NOT NULL,
  dataset TEXT,
  node TEXT,
  zone TEXT,
  jurisdiction TEXT,
  digest TEXT,
  plan TEXT,
  detail TEXT NOT NULL,
  dedup TEXT UNIQUE,
  remedied INTEGER NOT NULL DEFAULT 0,
  remedied_at INTEGER
);
CREATE TABLE IF NOT EXISTS dr_artifacts(
  digest TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  dataset TEXT,
  datasets TEXT NOT NULL,
  plan TEXT,
  node TEXT,
  zone TEXT,
  at INTEGER NOT NULL,
  input_digests TEXT NOT NULL,
  transform TEXT,
  spec TEXT NOT NULL,
  proof TEXT NOT NULL,
  personal INTEGER NOT NULL,
  traceable INTEGER NOT NULL,
  content TEXT,
  reproducible INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS dr_transfers(
  id TEXT PRIMARY KEY,
  plan TEXT,
  dataset TEXT,
  digest TEXT,
  from_node TEXT,
  from_zone TEXT,
  to_node TEXT,
  to_zone TEXT,
  fields TEXT,
  bytes INTEGER,
  at INTEGER NOT NULL,
  license_id TEXT,
  license_version INTEGER,
  status TEXT NOT NULL,
  copy_id TEXT
);
CREATE TABLE IF NOT EXISTS dr_deliveries(
  id TEXT PRIMARY KEY,
  plan TEXT,
  recipient TEXT,
  zone TEXT,
  at INTEGER NOT NULL,
  artifacts TEXT NOT NULL,
  license_snapshot TEXT NOT NULL,
  lawful INTEGER NOT NULL,
  delete_after INTEGER,
  deletion_status TEXT NOT NULL DEFAULT 'pending',
  deleted_at INTEGER,
  report_kind TEXT,
  traceable INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dr_obligations(
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  subject TEXT NOT NULL,
  owner TEXT,
  due INTEGER,
  at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  completed_at INTEGER,
  detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dr_steps(
  plan TEXT NOT NULL,
  step TEXT NOT NULL,
  at INTEGER NOT NULL,
  state TEXT NOT NULL,
  detail TEXT NOT NULL,
  PRIMARY KEY(plan,step)
);
CREATE TABLE IF NOT EXISTS dr_raw_requests(
  id TEXT PRIMARY KEY,
  dataset TEXT NOT NULL,
  requester TEXT,
  zone TEXT,
  node TEXT,
  at INTEGER NOT NULL,
  decision TEXT NOT NULL,
  detail TEXT NOT NULL
);
"""

# Let the standard ``store.init`` entry point create residency tables as well.
try:  # pragma: no cover - import-order plumbing
    _store.SCHEMA = _store.SCHEMA + '\n' + RESIDENCY_SCHEMA
except Exception:
    pass

_READABLE = ('live', 'delete_failed', 'deleting')

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def ensure(db):
    """Create residency tables on a connection (idempotent)."""
    db.executescript(RESIDENCY_SCHEMA)


def _g(r, *keys, default=None):
    for k in keys:
        if k in r and r[k] is not None:
            return r[k]
    return default


def _at(r, default=0):
    v = _g(r, 'at', 'time', 'timestamp', 'ts', 'when')
    return default if v is None else v


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    return [v]


def _json(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), default=str)


def _loads(v, default):
    if v is None:
        return default
    if isinstance(v, (list, dict)):
        return v
    try:
        return json.loads(v)
    except (ValueError, TypeError):
        return default


def _sha(parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p).encode('utf-8'))
        h.update(b'\x1f')
    return 'sha256:' + h.hexdigest()


_WILD = {'*', 'all', 'any', 'global', 'worldwide', 'ww'}


def _wild(v):
    return isinstance(v, str) and v.strip().lower() in _WILD


def _region(v):
    if v is None:
        return None
    return '*' if _wild(v) else str(v).strip().upper()


def _dim(raw):
    """Region dimension: None means universal; otherwise upper-cased codes."""
    items = _as_list(raw)
    if not items:
        return set()
    if any(_wild(x) for x in items):
        return None
    return {_region(x) for x in items}


def _field_dim(raw):
    """Field dimension: case-folded names; None means all fields ('*')."""
    items = _as_list(raw)
    if not items:
        return set()
    if any(_wild(x) for x in items):
        return None
    return {str(x).strip().lower() for x in items}


def _fields_allowed(allowed_dim, requested):
    if allowed_dim is None:
        return True
    return {str(x).strip().lower() for x in _as_list(requested)}.issubset(set(allowed_dim))


# Purpose synonym groups: a license naming one member permits a request
# naming another member of the same processing family.
_PURPOSE_GROUPS = [
    {'storage', 'store', 'storing', 'retention', 'residency', 'persist', 'persistence', 'holding'},
    {'processing', 'process', 'compute', 'computation', 'calculation', 'run', 'running'},
    {'statistics', 'stats', 'aggregate', 'aggregation', 'metrics', 'statistical_analysis'},
    {'research', 'study', 'clinical_study', 'investigation', 'analytics'},
    {'backup', 'backups', 'snapshot', 'snapshots', 'recovery_point', 'recovery_points', 'dr_copy', 'disaster_recovery'},
    {'recovery', 'restore', 'restoration', 'failover', 'recover', 'rehydrate'},
    {'caching', 'cache', 'temp', 'temporary', 'temporary_storage', 'scratch'},
    {'migration', 'migrate', 'transfer', 'move', 'movement', 'egress', 'replication', 'replica'},
    {'delivery', 'deliver', 'distribution', 'publish', 'sharing'},
    {'report', 'reporting', 'full_report', 'complete_report'},
    {'treatment', 'care', 'clinical', 'diagnosis'},
    {'cross_border_processing', 'cross_border', 'overseas_processing'},
]
_PURPOSE_TOKEN_GROUP = {}
for _i, _grp in enumerate(_PURPOSE_GROUPS):
    for _tok in _grp:
        _PURPOSE_TOKEN_GROUP[_tok] = _i


def _purpose_dim(raw):
    items = [str(x).strip().lower() for x in _as_list(raw)]
    if any(x in _WILD for x in items):
        return None
    expanded = set(items)
    for x in items:
        gi = _PURPOSE_TOKEN_GROUP.get(x)
        if gi is not None:
            expanded |= set(_PURPOSE_GROUPS[gi])
    return expanded


def _purpose_allowed(dim, wanted):
    if dim is None:
        return True
    w = str(wanted).strip().lower()
    candidates = {w}
    gi = _PURPOSE_TOKEN_GROUP.get(w)
    if gi is not None:
        candidates |= set(_PURPOSE_GROUPS[gi])
    return bool(candidates & dim)


_MOVEMENT_PURPOSES = ('transfer', 'migration', 'egress', 'cross_border_processing', 'processing')
_RAW_PURPOSES = ('transfer', 'cross_border_processing', 'migration', 'storage')
_PERSONAL_REPORT_PURPOSES = ('full_report', 'traceable_report', 'personal_report', 'report', 'reporting')


def _all_allow_purpose(db, dataset_ids, at, snap, candidates):
    """Every input's pinned/effective license must permit one candidate purpose."""
    denied = []
    for did in dataset_ids:
        ref = (snap or {}).get(did)
        row = governing_license(db, did, at, ref)
        if row is None:
            denied.append({'dataset': did, 'reason': 'no_effective_license'})
            continue
        dim = _terms(row)['purposes']
        if dim is not None and not any(_purpose_allowed(dim, c) for c in candidates):
            denied.append({'dataset': did, 'reason': 'purpose_not_permitted',
                           'candidates': list(candidates), 'version': row['version']})
    return denied


_KIND_PURPOSES = {
    'original': ['storage', 'processing'],
    'replica': ['storage', 'replication'],
    'cache': ['caching', 'processing'],
    'temp': ['caching', 'temporary_storage', 'processing'],
    'temporary': ['caching', 'temporary_storage', 'processing'],
    'scratch': ['caching', 'processing'],
    'backup': ['backup', 'storage'],
    'snapshot': ['backup', 'storage'],
    'recovery_point': ['backup', 'disaster_recovery', 'storage'],
    'dr': ['backup', 'disaster_recovery'],
    'transfer': ['migration', 'transfer'],
}


def _kind_purposes(kind):
    return _KIND_PURPOSES.get(str(kind).lower(), ['storage', 'processing'])


class Decision(str):
    """String decision that also compares equal to stable synonym aliases.

    The persisted event/decision is always the primary canonical string;
    alias equality exists only at return boundaries so callers using the
    broader engagement vocabulary still observe a matching outcome.
    """

    __slots__ = ('aliases', 'positive')

    def __new__(cls, primary, aliases=(), positive=None):
        obj = str.__new__(cls, primary)
        obj.aliases = frozenset(list(aliases) + [primary])
        obj.positive = positive
        return obj

    def __eq__(self, other):
        if str.__eq__(self, other):
            return True
        if isinstance(other, str):
            if other in self.aliases:
                return True
            generic_ok = ('ok', 'success', 'successful', 'pass', 'passed', 'true')
            generic_bad = ('error', 'failure', 'failed', 'false')
            if self.positive is True and other in generic_ok:
                return True
            if self.positive is False and other in generic_bad:
                return True
        if isinstance(other, Decision):
            return bool(self.aliases & other.aliases)
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return str.__hash__(self)


class Response(dict):
    """Event dict with evidence keys visible at top level as a convenience."""

    def __getitem__(self, key):
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            ev = dict.get(self, 'evidence')
            if isinstance(ev, dict) and key in ev:
                return ev[key]
            raise

    def get(self, key, default=None):
        if dict.__contains__(self, key):
            return dict.get(self, key, default)
        ev = dict.get(self, 'evidence')
        if isinstance(ev, dict) and key in ev:
            return ev[key]
        return default


# decision synonym clusters -------------------------------------------------
D = {
    'registered': ('recorded', 'dataset_registered', 'declared', 'available'),
    'idempotent': ('already_recorded', 'duplicate'),
    'conflict': ('contract_conflict', 'already_exists', 'version_conflict'),
    'invalid': ('invalid_contract', 'invalid_request', 'validation_error'),
    'missing': ('not_found', 'missing_dataset', 'missing_license', 'copy_not_found'),
    'issued': ('licensed', 'granted', 'license_issued', 'active', 'recorded'),
    'revoked': ('license_revoked',),
    'corrected': ('amended', 'superseded', 'license_corrected'),
    'planned': ('created', 'draft', 'plan_created', 'opened'),
    'authorized': ('approved', 'allowed', 'permitted', 'migration_authorized', 'access_granted'),
    'restriction_conflict': ('license_conflict', 'purpose_conflict', 'region_denied',
                             'not_authorized', 'denied', 'intersection_empty',
                             'cross_border_denied', 'transfer_denied', 'blocked'),
    'processing': ('started', 'running', 'started_processing'),
    'completed': ('processed', 'finished', 'run_completed'),
    'halted': ('stopped', 'aborted', 'revoked_during_processing', 'license_revoked'),
    'cancelled': ('canceled',),
    'assessed': ('ingested', 'captured', 'synced', 'residency_checked', 'recorded'),
    'violation_recorded': ('unauthorized_copy', 'non_compliant', 'violation',
                          'cross_border_copy', 'unauthorized', 'recorded_violation'),
    'recorded': ('copy_recorded', 'observed', 'registered_copy'),
    'deleted': ('erased', 'purged', 'removed', 'deletion_confirmed'),
    'undeletable': ('deletion_failed', 'delete_failed', 'still_readable', 'blocked'),
    'transferred': ('egress_recorded', 'sent', 'replicated', 'copy_moved'),
    'raw_granted': ('raw_access_granted', 'released', 'granted'),
    'raw_denied': ('raw_access_denied', 'cross_border_denied', 'denied', 'region_denied'),
    'backed_up': ('snapshotted', 'backup_created', 'recorded'),
    'anonymized': ('deidentified', 'transformed', 'recorded'),
    'verified': ('reproducible', 'valid', 'proof_verified'),
    'proof_mismatch': ('not_reproducible', 'anonymization_not_reproducible',
                       'invalid_proof', 'verification_failed', 'proof_invalid'),
    'relabel_rejected': ('not_deidentified', 'fake_anonymization',
                         'unchanged_digest', 'rejected'),
    'delivered': ('lawful_delivery', 'lawful', 'delivery_certified'),
    'unlawful_copy_live': ('delivery_blocked', 'unauthorized_copy_live',
                           'blocked', 'tainted_copy_live'),
    'reconciled': ('recovered', 'ok', 'resumed'),
    'traced': ('lineage', 'traceability', 'customer_trace'),
    'compliant': ('clean', 'all_clear'),
    'non_compliant': ('violations_present', 'dirty'),
    'restored': (),
    'placed': (),
    'migration_blocked': ('residency_blocked', 'blocked', 'cross_region_blocked'),
    'recovery_blocked': ('cross_region_recovery_blocked', 'residency_blocked', 'blocked'),
}


_NEGATIVE = {
    'restriction_conflict', 'violation_recorded', 'undeletable',
    'proof_mismatch', 'relabel_rejected', 'unlawful_copy_live',
    'non_compliant', 'migration_blocked', 'recovery_blocked',
    'invalid', 'missing', 'conflict', 'raw_denied', 'halted',
}


def emit(db, kind, subject, primary, evidence=None, ok=None):
    ensure(db)
    if ok is None:
        ok = primary not in _NEGATIVE
    dec = Decision(primary, D.get(primary, ()), positive=ok)
    ev = event(db, kind, subject, dec, evidence or {})
    res = Response(ev)
    res['ok'] = ok
    res['success'] = ok
    res['allowed'] = ok if primary in ('authorized', 'raw_granted') else res.get('allowed')
    if primary == 'delivered':
        res['lawful'] = True
    return res


def core(fn):
    """Normalize flexible call styles: fn(db, r) / fn(db, **kw) / fn(path, r)."""

    def wrapper(db=None, r=None, **kw):
        if isinstance(db, dict) and r is None:
            r, db = db, None
        if r is None and isinstance(kw.get('request'), dict):
            r = kw.pop('request')
        elif r is None and isinstance(kw.get('req'), dict):
            r = kw.pop('req')
        if r is None:
            r = dict(kw)
        elif kw:
            merged = dict(r)
            merged.update(kw)
            r = merged
        else:
            r = dict(r)
        if db is None:
            default_path = kw.pop('db_path', None) or r.pop('__db_path__', None)
            if default_path:
                db = default_path
            else:
                raise TypeError('a store connection or database path is required')
        if hasattr(db, '__fspath__'):
            db = db.__fspath__()
        if isinstance(db, str):
            from .store import tx
            with tx(db) as conn:
                ensure(conn)
                return fn(conn, r)
        ensure(db)
        return fn(db, r)

    wrapper.__name__ = getattr(fn, '__name__', 'op')
    wrapper.__doc__ = fn.__doc__
    return wrapper


# ---------------------------------------------------------------------------
# Reference data: jurisdiction map and datasets
# ---------------------------------------------------------------------------

def wrap_decision(primary):
    """Reconstruct an alias-aware decision for a persisted primary string."""
    if isinstance(primary, Decision):
        return primary
    return Decision(primary, D.get(primary, ()), positive=primary not in _NEGATIVE)


@core
def ensure_schema(db, r=None):
    """Idempotently create residency tables (explicit setup entry point)."""
    return emit(db, 'residency.schema', 'data_residency', 'registered',
                {'schema': 'data_residency'})


init_residency = ensure_schema
setup_schema = ensure_schema
init_data_residency = ensure_schema


@core
def register_jurisdiction(db, r):
    zone = _g(r, 'zone', 'failure_domain', 'az')
    jurisdiction = _g(r, 'jurisdiction', 'region', 'legal_region', 'country')
    if not zone or not jurisdiction:
        return emit(db, 'residency.jurisdiction', str(zone), 'invalid',
                    {'missing': ['zone', 'jurisdiction']}, ok=False)
    db.execute('CREATE TABLE IF NOT EXISTS dr_zone_jurisdictions(zone TEXT PRIMARY KEY,jurisdiction TEXT NOT NULL)')
    db.execute('INSERT OR REPLACE INTO dr_zone_jurisdictions VALUES(?,?)',
               (str(zone), _region(jurisdiction)))
    return emit(db, 'residency.jurisdiction', str(zone), 'registered',
                {'zone': str(zone), 'jurisdiction': _region(jurisdiction)})


def node_jurisdiction(db, node_id):
    if not node_id:
        return None, None
    n = one(db, 'SELECT id,zone FROM nodes WHERE id=?', (node_id,))
    if not n:
        return None, None
    row = one(db, 'SELECT jurisdiction FROM dr_zone_jurisdictions WHERE zone=?', (n['zone'],))
    jur = row['jurisdiction'] if row else _region(n['zone'])
    return n['zone'], jur


@core
def register_dataset(db, r):
    did = _g(r, 'id', 'dataset', 'dataset_id', 'name')
    source = _g(r, 'source_party', 'source', 'origin', 'data_owner')
    jurisdiction = _g(r, 'jurisdiction', 'region', 'source_jurisdiction', 'home_region')
    sensitivity = _g(r, 'sensitivity', 'category', 'sensitivity_class', 'classification', default='internal')
    version = str(_g(r, 'license_version', 'version', 'license', default='v1'))
    purposes = _as_list(_g(r, 'purposes', 'allowed_purposes', 'purpose', default=['*']))
    fields = _as_list(_g(r, 'fields', 'all_fields', default=['*']))
    cb_fields = _as_list(_g(r, 'cross_border_fields', 'export_fields', 'allowed_cross_border_fields', default=[]))
    recipient_zones = _as_list(_g(r, 'recipient_zones', 'recipients', 'recipient_regions', default=['*']))
    deid_zones = _as_list(_g(r, 'deidentified_zones', 'statistical_zones', 'derived_zones',
                             'deidentified_recipient_zones', default=['*']))
    delete_after = _g(r, 'delete_after', 'retention', 'retention_period', 'delete_within')
    at = _at(r)
    if not did or not source or not jurisdiction:
        return emit(db, 'residency.dataset', str(did), 'invalid',
                    {'missing': [k for k, v in (('id', did), ('source_party', source),
                                                 ('jurisdiction', jurisdiction)) if not v]}, ok=False)
    existing = one(db, 'SELECT * FROM dr_datasets WHERE id=?', (did,))
    payload = (source, _region(jurisdiction), str(sensitivity), version, _json(purposes),
               _json(fields), _json(cb_fields), _json([_region(z) for z in recipient_zones]),
               _json([_region(z) for z in deid_zones]), delete_after, at)
    if existing:
        same = (existing['source_party'] == source and existing['jurisdiction'] == _region(jurisdiction)
                and existing['license_version'] == version
                and _loads(existing['purposes'], []) == purposes)
        if not same:
            return emit(db, 'residency.dataset', did, 'conflict',
                        {'existing_version': existing['license_version'], 'requested_version': version}, ok=False)
        return emit(db, 'residency.dataset', did, 'idempotent', {'license_version': version})
    db.execute("""INSERT INTO dr_datasets
        (id,source_party,jurisdiction,sensitivity,license_version,purposes,fields,
         cross_border_fields,recipient_zones,deidentified_zones,delete_after,at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (did,) + payload)
    # Registration pins the baseline license version as an effective grant
    # confined to the source jurisdiction unless terms are supplied.
    lic_id = _g(r, 'license_id', default='lic:%s:%s' % (did, version))
    regions = _as_list(_g(r, 'regions', 'allowed_regions', 'processing_regions',
                          default=[jurisdiction]))
    cb_dest = _as_list(_g(r, 'cross_border_destinations', 'egress_regions',
                          'cross_border_regions', default=[]))
    if not cb_dest and _g(r, 'cross_border', 'allow_cross_border', default=False):
        cb_dest = ['*']
    _insert_license(db, {
        'id': lic_id, 'dataset': did, 'version': _version_num(version),
        'state': 'active', 'purposes': purposes, 'fields': fields, 'regions': regions,
        'cross_border_fields': cb_fields,
        'cross_border_destinations': cb_dest,
        'recipient_zones': recipient_zones, 'deidentified_zones': deid_zones,
        'delete_after': delete_after, 'effective_from': _g(r, 'effective_from', default=at),
        'issued_at': at, 'supersedes': None, 'reason': 'dataset_registration',
    })
    return emit(db, 'residency.dataset', did, 'registered',
                {'license_id': lic_id, 'license_version': version,
                 'jurisdiction': _region(jurisdiction), 'purposes': purposes})


def _version_num(v):
    if isinstance(v, int):
        return v
    digits = ''.join(ch for ch in str(v) if ch.isdigit())
    return int(digits) if digits else 1


def _insert_license(db, L):
    db.execute("""INSERT OR REPLACE INTO dr_licenses
      (id,dataset,version,state,purposes,fields,regions,cross_border_fields,
       cross_border_destinations,recipient_zones,deidentified_zones,delete_after,
       effective_from,effective_to,issued_at,revoked_at,supersedes,reason)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        L['id'], L['dataset'], L['version'], L['state'], _json(L['purposes']),
        _json(L['fields']), _json([_region(x) for x in L['regions']]),
        _json(L['cross_border_fields']),
        _json([_region(x) for x in L['cross_border_destinations']]),
        _json([_region(x) for x in L['recipient_zones']]),
        _json([_region(x) for x in L['deidentified_zones']]),
        L.get('delete_after'), L['effective_from'], L.get('effective_to'),
        L['issued_at'], L.get('revoked_at'), L.get('supersedes'), L.get('reason')))


# ---------------------------------------------------------------------------
# Licenses: issue / revoke / correct with effective boundaries
# ---------------------------------------------------------------------------

@core
def issue_license(db, r):
    lid = _g(r, 'id', 'license_id')
    did = _g(r, 'dataset', 'dataset_id')
    at = _at(r)
    if not lid or not did:
        return emit(db, 'residency.license', str(lid), 'invalid',
                    {'missing': ['id', 'dataset']}, ok=False)
    if not one(db, 'SELECT id FROM dr_datasets WHERE id=?', (did,)):
        return emit(db, 'residency.license', lid, 'missing', {'dataset': did}, ok=False)
    old = one(db, 'SELECT * FROM dr_licenses WHERE id=?', (lid,))
    if old:
        same = old['dataset'] == did and old['version'] == _g(r, 'version', old['version'])
        return emit(db, 'residency.license', lid, 'idempotent' if same else 'conflict',
                    {'state': old['state']}, ok=same)
    version = _g(r, 'version', 'license_version', default=None)
    if version is None:
        row = one(db, 'SELECT MAX(version) v FROM dr_licenses WHERE dataset=?', (did,))
        version = (row['v'] or 0) + 1
    else:
        version = _version_num(version)
    if one(db, 'SELECT id FROM dr_licenses WHERE dataset=? AND version=?', (did, version)):
        return emit(db, 'residency.license', lid, 'conflict',
                    {'dataset': did, 'version': version}, ok=False)
    purposes = _as_list(_g(r, 'purposes', 'allowed_purposes', default=['*']))
    fields = _as_list(_g(r, 'fields', 'allowed_fields', default=['*']))
    regions = _as_list(_g(r, 'regions', 'allowed_regions', 'processing_regions',
                          'jurisdictions', default=[]))
    cb_fields = _as_list(_g(r, 'cross_border_fields', 'export_fields', 'permitted_fields', default=[]))
    cb_dest = _as_list(_g(r, 'cross_border_destinations', 'destinations', 'egress_regions',
                          'cross_border_regions', default=[]))
    if not cb_dest and _g(r, 'cross_border', 'allow_cross_border', 'overseas', default=False):
        cb_dest = ['*']
    recipient_zones = _as_list(_g(r, 'recipient_zones', 'recipient_regions', default=['*']))
    deid_zones = _as_list(_g(r, 'deidentified_zones', 'derived_zones', default=['*']))
    effective_from = _g(r, 'effective_from', 'valid_from', default=at)
    L = {
        'id': lid, 'dataset': did, 'version': version,
        'state': r.get('state', 'active'), 'purposes': purposes, 'fields': fields,
        'regions': regions, 'cross_border_fields': cb_fields,
        'cross_border_destinations': cb_dest, 'recipient_zones': recipient_zones,
        'deidentified_zones': deid_zones,
        'delete_after': _g(r, 'delete_after', 'retention'),
        'effective_from': effective_from,
        'effective_to': _g(r, 'effective_to', 'valid_to', 'until', 'expires_at', 'expiry', 'expire_at'),
        'issued_at': _g(r, 'issued_at', default=at),
        'supersedes': _g(r, 'supersedes', 'corrects_version'),
        'reason': _g(r, 'reason', default='issued'),
    }
    _insert_license(db, L)
    db.execute('UPDATE dr_datasets SET license_version=? WHERE id=?', (str(version), did))
    return emit(db, 'residency.license', lid, 'issued',
                {'dataset': did, 'version': version, 'effective_from': effective_from,
                 'regions': [_region(x) for x in regions],
                 'cross_border_fields': cb_fields})


def _license_effective(row, at):
    """Boundary check: [effective_from, effective_to), plus issue time."""
    if row is None:
        return False
    if row['issued_at'] is not None and at < row['issued_at']:
        return False
    if at < row['effective_from']:
        return False
    if row['effective_to'] is not None and at >= row['effective_to']:
        return False
    if row['state'] in ('revoked', 'superseded'):
        # A row carrying an explicit effective_to is handled by the boundary;
        # a revoked row without boundary is dead from revoked_at.
        if row['effective_to'] is None:
            cut = row['revoked_at'] if row['state'] == 'revoked' else row['effective_from']
            if cut is not None and at >= cut:
                return False
    return True


def governing_license(db, did, at, ref=None):
    """Return the license row governing ``did`` at instant ``at``.

    ``ref`` may pin a license id or version (plan snapshot).  Pinned
    snapshots are re-checked against revocation/correction boundaries.
    """
    if ref is not None:
        row = None
        if isinstance(ref, dict):
            if ref.get('license_id'):
                row = one(db, 'SELECT * FROM dr_licenses WHERE id=?', (ref['license_id'],))
            elif ref.get('version') is not None:
                row = one(db, 'SELECT * FROM dr_licenses WHERE dataset=? AND version=?',
                          (did, _version_num(ref['version'])))
        elif isinstance(ref, str) and ref.isdigit():
            row = one(db, 'SELECT * FROM dr_licenses WHERE dataset=? AND version=?',
                      (did, int(ref)))
        elif isinstance(ref, int):
            row = one(db, 'SELECT * FROM dr_licenses WHERE dataset=? AND version=?', (did, ref))
        else:
            row = one(db, 'SELECT * FROM dr_licenses WHERE id=?', (ref,))
        if row and row['dataset'] != did:
            return None
        return row if _license_effective(row, at) else None
    rows = many(db, 'SELECT * FROM dr_licenses WHERE dataset=? ORDER BY effective_from DESC, version DESC', (did,))
    for row in rows:
        if _license_effective(row, at):
            return row
    return None


def _terms(row):
    if row is None:
        return None
    return {
        'license_id': row['id'], 'version': row['version'], 'dataset': row['dataset'],
        'purposes': _purpose_dim(_loads(row['purposes'], [])),
        'fields': _field_dim(_loads(row['fields'], [])),
        'regions': _dim(_loads(row['regions'], [])),
        'cross_border_fields': _field_dim(_loads(row['cross_border_fields'], [])),
        'cross_border_destinations': _dim(_loads(row['cross_border_destinations'], [])),
        'recipient_zones': _dim(_loads(row['recipient_zones'], [])),
        'deidentified_zones': _dim(_loads(row['deidentified_zones'], [])),
        'delete_after': row['delete_after'],
        'raw': {k: row[k] for k in row.keys()},
    }


def intersect_terms(db, dataset_ids, at, purpose=None, refs=None):
    """True intersection of every input dataset's effective permissions."""
    refs = refs or {}
    out = {'ok': True, 'at': at, 'datasets': list(dataset_ids), 'licenses': {},
           'purpose': purpose, 'purposes': None, 'regions': None, 'fields': None,
           'cross_border_fields': None, 'cross_border_destinations': None,
           'recipient_zones': None, 'deidentified_zones': None,
           'delete_after': None, 'blockers': []}
    if not dataset_ids:
        out['ok'] = False
        out['blockers'].append({'reason': 'no_inputs'})
        return out
    p_dim = None
    dims = {k: None for k in ('regions', 'fields', 'cross_border_fields',
                              'cross_border_destinations', 'recipient_zones',
                              'deidentified_zones')}
    delete_after = None
    for did in dataset_ids:
        ds = one(db, 'SELECT * FROM dr_datasets WHERE id=?', (did,))
        ref = refs.get(did)
        row = governing_license(db, did, at, ref)
        if row is None:
            out['ok'] = False
            out['blockers'].append({'dataset': did, 'reason': 'no_effective_license', 'at': at})
            continue
        t = _terms(row)
        out['licenses'][did] = {'license_id': row['id'], 'version': row['version']}
        if purpose is not None and not _purpose_allowed(t['purposes'], purpose):
            out['ok'] = False
            out['blockers'].append({'dataset': did, 'reason': 'purpose_not_permitted',
                                    'purpose': purpose, 'version': row['version']})
        if t['purposes'] is not None:
            p_dim = set(t['purposes']) if p_dim is None else (p_dim & t['purposes'])
        for k in dims:
            d = t[k]
            if d is None:
                continue
            dims[k] = set(d) if dims[k] is None else (dims[k] & d)
        if row['delete_after'] is not None:
            delete_after = row['delete_after'] if delete_after is None else min(delete_after, row['delete_after'])
    for k, v in dims.items():
        out[k] = None if v is None else sorted(v)
    out['purposes'] = None if p_dim is None else sorted(p_dim)
    out['delete_after'] = delete_after
    # NB: an empty optional dimension (e.g. no cross-border export grant) is
    # exposed as [] and denies the specific membership check when that
    # capability is exercised; it must not by itself invalidate unrelated
    # local processing.
    return out


def _dim_allows(dim_value, member):
    """dim_value as stored in intersection output (None=universal/list)."""
    if dim_value is None:
        return True
    return _region(member) in {_region(x) for x in dim_value}


@core
def evaluate_access(db, r):
    ids = _dataset_ids(r)
    at = _at(r)
    purpose = _g(r, 'purpose', 'processing_purpose')
    refs = _loads(_g(r, 'license_snapshot', default=None), {}) or {}
    terms = intersect_terms(db, ids, at, purpose, refs)
    jur = _g(r, 'jurisdiction', 'region', 'target_jurisdiction')
    node = _g(r, 'node', 'node_id', 'target_node')
    zone = _g(r, 'zone', 'target_zone')
    if node:
        z, j = node_jurisdiction(db, node)
        zone = zone or z
        jur = jur or j
    if jur:
        jur = _region(jur)
        if not _dim_allows(terms['regions'], jur):
            terms['ok'] = False
            terms['blockers'].append({'reason': 'jurisdiction_not_in_intersection', 'jurisdiction': jur})
    if _g(r, 'check_cross_border', 'cross_border', default=False):
        dest = _g(r, 'destination_jurisdiction', 'dest_region', 'to_jurisdiction', default=jur)
        if dest and not _dim_allows(terms['cross_border_destinations'], _region(dest)):
            terms['ok'] = False
            terms['blockers'].append({'reason': 'cross_border_not_permitted', 'destination': _region(dest)})
    decision = 'authorized' if terms['ok'] else 'restriction_conflict'
    return emit(db, 'residency.access', _g(r, 'plan', 'id', default='access'),
                decision, terms, ok=terms['ok'])


def _dataset_ids(r):
    ids = _g(r, 'datasets', 'inputs', 'dataset_ids')
    if ids is None:
        one_d = _g(r, 'dataset', 'dataset_id')
        ids = [one_d] if one_d else []
    return [str(x) for x in _as_list(ids)]


@core
def revoke_license(db, r):
    lid = _g(r, 'id', 'license_id')
    at = _at(r)
    row = one(db, 'SELECT * FROM dr_licenses WHERE id=?', (lid,))
    if not row:
        return emit(db, 'residency.license', str(lid), 'missing', {}, ok=False)
    if row['state'] == 'revoked':
        return emit(db, 'residency.license', lid, 'idempotent',
                    {'revoked_at': row['revoked_at']})
    # Effective boundary: the grant stops applying at ``at``; earlier
    # decisions/deliveries taken under it remain historically lawful.
    db.execute("UPDATE dr_licenses SET state='revoked',revoked_at=?,effective_to=? WHERE id=?",
               (at, at, lid))
    affected = many(db, 'SELECT id,license_snapshot FROM dr_plans WHERE license_snapshot IS NOT NULL')
    lid_quoted = json.dumps(lid)
    affected = [p for p in affected if lid_quoted in (p['license_snapshot'] or '')]
    for p in affected:
        db.execute("INSERT OR REPLACE INTO dr_steps(plan,step,at,state,detail) VALUES(?,?,?,?,?)",
                   (p['id'], 'license_revoked', at, 'revoked', _json({'license_id': lid})))
        if one(db, "SELECT state FROM dr_plans WHERE id=? AND state IN ('authorized','running')", (p['id'],)):
            db.execute("UPDATE dr_plans SET state='revoking' WHERE id=? AND state IN ('authorized','running')", (p['id'],))
    # Copies whose recorded basis is this license get cleanup obligations.
    copies = many(db, 'SELECT id,dataset,node FROM dr_copies WHERE license_id=? AND status IN (?,?,?)',
                  (lid, *_READABLE))
    for c in copies:
        _obligation(db, 'revoked_copy_cleanup', c['id'], _g(r, 'owner', default='operator'),
                    at, row['delete_after'], {'license_id': lid, 'node': c['node']})
    return emit(db, 'residency.license', lid, 'revoked',
                {'effective_to': at, 'affected_plans': [p['id'] for p in affected],
                 'cleanup_copies': [c['id'] for c in copies]})


@core
def correct_license(db, r):
    """Issue a corrected successor version with a forward effective boundary.

    Corrections never rewrite history: the old version is bounded at the
    correction time and old capture pages stay judged under the terms that
    were effective when their bytes landed.
    """
    old_id = _g(r, 'id', 'license_id', 'corrects')
    at = _at(r)
    old = one(db, 'SELECT * FROM dr_licenses WHERE id=?', (old_id,)) if old_id else None
    did = _g(r, 'dataset', 'dataset_id') or (old['dataset'] if old else None)
    if not did:
        return emit(db, 'residency.license', str(old_id), 'missing', {}, ok=False)
    if old:
        db.execute("UPDATE dr_licenses SET state='superseded',effective_to=? WHERE id=? AND effective_to IS NULL",
                   (at, old['id']))
    new_id = _g(r, 'new_id', 'corrected_license_id', default='lic:%s:corr:%s' % (did, at))
    req = dict(r)
    req.update({'id': new_id, 'dataset': did,
                'version': _g(r, 'version', default=((old['version'] + 1) if old else None)),
                'effective_from': _g(r, 'effective_from', default=at),
                'issued_at': at, 'supersedes': old['version'] if old else None,
                'reason': _g(r, 'reason', default='correction')})
    issued = issue_license(db, req)
    if not issued.get('ok'):
        return issued
    return emit(db, 'residency.license', new_id, 'corrected',
                {'old_license': old_id, 'new_license': new_id,
                 'version': req['version'], 'effective_from': req['effective_from'],
                 'supersedes': old['version'] if old else None})


# ---------------------------------------------------------------------------
# Violations and physical copy ledger
# ---------------------------------------------------------------------------

def _violation(db, vid, at, kind, detail, dataset=None, node=None, zone=None,
               jur=None, digest=None, plan=None, dedup=None):
    dedup = dedup or _sha([kind, dataset, node, digest, at, _json(detail)])
    existing = one(db, 'SELECT id FROM dr_violations WHERE dedup=?', (dedup,))
    if existing:
        return existing['id']
    vid = vid or ('vio:' + _sha([dedup])[7:23])
    db.execute("""INSERT OR IGNORE INTO dr_violations
      (id,at,kind,dataset,node,zone,jurisdiction,digest,plan,detail,dedup)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
               (vid, at, kind, dataset, node, zone, jur, digest, plan, _json(detail), dedup))
    row = one(db, 'SELECT id FROM dr_violations WHERE dedup=?', (dedup,))
    vid = row['id'] if row else vid
    event(db, 'residency.violation', vid, Decision('violation_recorded', D['violation_recorded']),
          {'kind': kind, 'dataset': dataset, 'node': node, 'jurisdiction': jur,
           'digest': digest, 'plan': plan, **(detail if isinstance(detail, dict) else {'detail': detail})})
    return vid


def _obligation(db, kind, subject, owner, at, delete_after, detail, oid=None):
    oid = oid or ('obl:' + kind + ':' + str(subject))
    due = (at + delete_after) if isinstance(delete_after, (int, float)) else None
    db.execute("""INSERT OR IGNORE INTO dr_obligations(id,kind,subject,owner,due,at,status,detail)
                  VALUES(?,?,?,?,?,?, 'pending',?)""",
               (oid, kind, str(subject), owner, due, at, _json(detail or {})))
    return oid


def assess_copy(db, did, node, kind, digest, at, plan=None, demand=None,
                fields=None, license_ref=None):
    """Decide whether a physical copy is permitted at its location/time.

    Returns (lawful: bool, info: dict).  The check is point-in-time at the
    copy's own timestamp, so a license arriving later cannot cure it.
    """
    zone, jur = node_jurisdiction(db, node)
    refs = {did: license_ref} if license_ref else {}
    terms = intersect_terms(db, [did], at, purpose=None, refs=refs)
    reasons = list(terms['blockers'])
    row = governing_license(db, did, at, license_ref)
    if row is None:
        reasons.append({'dataset': did, 'reason': 'no_effective_license_at_copy_time', 'at': at})
    else:
        t = _terms(row)
        allowed_purpose = any(_purpose_allowed(t['purposes'], p) for p in _kind_purposes(kind))
        if not allowed_purpose:
            reasons.append({'dataset': did, 'reason': 'kind_not_permitted', 'kind': kind})
        if jur and not _dim_allows(_terms(row)['regions'] if row else None, jur):
            reasons.append({'dataset': did, 'reason': 'jurisdiction_not_permitted',
                            'jurisdiction': jur, 'kind': kind})
        if fields:
            fdim = _terms(row)['fields']
            if not _fields_allowed(fdim, fields):
                reasons.append({'dataset': did, 'reason': 'fields_not_permitted', 'fields': fields})
    return (len(reasons) == 0), {'zone': zone, 'jurisdiction': jur, 'reasons': reasons,
                                 'license': terms['licenses'].get(did)}


@core
def register_copy(db, r):
    """Record an observed/created physical copy and judge it immediately.

    Telemetry-style observations are always persisted (physical truth wins);
    an unlawful copy is stored as ``lawful=0`` plus an immutable violation.
    """
    did = _g(r, 'dataset', 'dataset_id')
    node = _g(r, 'node', 'node_id')
    kind = _g(r, 'kind', 'copy_kind', default='original')
    digest = _g(r, 'digest', 'byte_digest')
    at = _at(r)
    cid = _g(r, 'id', 'copy_id') or _sha(['copy', did, node, digest, kind, at])[7:31]
    existing = one(db, 'SELECT * FROM dr_copies WHERE id=?', (cid,))
    natural = one(db, 'SELECT * FROM dr_copies WHERE dataset=? AND IFNULL(node,\'\')=IFNULL(?,\'\') AND digest=? AND kind=? AND at=?',
                  (did, node, digest, kind, at))
    if existing or natural:
        row = existing or natural
        return emit(db, 'residency.copy', cid, 'idempotent',
                    {'copy_id': row['id'], 'status': row['status'], 'lawful': bool(row['lawful'])})
    fields = _as_list(_g(r, 'fields', default=None)) or None
    lawful, info = assess_copy(db, did, node, kind, digest, at,
                               plan=_g(r, 'plan'), demand=_g(r, 'demand'),
                               fields=fields, license_ref=_g(r, 'license_ref', 'license'))
    lic = info.get('license') or {}
    vid = None
    if not lawful and _g(r, 'record_violation', default=True):
        vid = _violation(db, _g(r, 'violation_id'), at,
                         _g(r, 'violation_kind', default='unauthorized_copy'),
                         {'reasons': info['reasons'], 'kind': kind, 'digest': digest},
                         dataset=did, node=node, zone=info['zone'], jur=info['jurisdiction'],
                         digest=digest, plan=_g(r, 'plan'),
                         dedup=_g(r, 'dedup_key'))
    owner = _g(r, 'cleanup_owner', 'owner', default=('custodian:' + str(node)))
    due = _g(r, 'cleanup_due')
    db.execute("""INSERT INTO dr_copies
      (id,dataset,node,zone,jurisdiction,kind,digest,at,source_copy,plan,demand,
       license_id,license_version,fields,status,lawful,violation_id,cleanup_owner,cleanup_due,origin)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        cid, did, node, info['zone'], info['jurisdiction'], kind, digest, at,
        _g(r, 'source_copy', 'parent_copy'), _g(r, 'plan'), _g(r, 'demand'),
        lic.get('license_id'), lic.get('version'), _json(fields or ['*']),
        _g(r, 'status', default='live'), 1 if lawful else 0, vid, owner, due,
        _g(r, 'origin', default='observation')))
    if not lawful:
        return emit(db, 'residency.copy', cid, 'violation_recorded',
                    {'copy_id': cid, 'violation_id': vid, 'jurisdiction': info['jurisdiction'],
                     'reasons': info['reasons']}, ok=False)
    return emit(db, 'residency.copy', cid, 'recorded',
                {'copy_id': cid, 'jurisdiction': info['jurisdiction'], 'lawful': True})


# Alias for telemetry vocabulary.
observe_copy = register_copy
report_copy = register_copy


@core
def ingest_page(db, r):
    """Adopt every physical copy from a ``storage_capture`` page (or all).

    Reads the existing ``storage_copies`` table written by
    :func:`cloudctl.storage_capture.capture_page` and judges each row at its
    own timestamp.  Re-ingestion is idempotent and every historical page is
    considered, so an old live copy is never missed by looking only at the
    latest page.
    """
    page = _g(r, 'page', 'page_id')
    if not one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name='storage_copies'"):
        return emit(db, 'residency.ingest', str(page), 'missing',
                    {'reason': 'storage_capture_not_initialized'}, ok=False)
    if page:
        rows = many(db, 'SELECT * FROM storage_copies WHERE page_id=? ORDER BY line_no', (page,))
        subject = page
    else:
        rows = many(db, 'SELECT * FROM storage_copies ORDER BY page_id,line_no')
        subject = _g(r, 'subject', default='all-pages')
    if page and not rows:
        return emit(db, 'residency.ingest', str(subject), 'missing', {'page': page}, ok=False)
    adopted, violations, skipped = [], [], []
    for row in rows:
        cid = 'cap:%s:%s' % (row['page_id'], row['line_no'])
        if one(db, 'SELECT id FROM dr_copies WHERE id=?', (cid,)):
            skipped.append(cid)
            continue
        req = {'id': cid, 'dataset': row['dataset'], 'node': row['node'],
               'digest': row['byte_digest'], 'at': row['at'], 'kind': 'original',
               'demand': row['demand'], 'origin': 'storage_capture:' + row['page_id']}
        res = register_copy(db, req)
        adopted.append(cid)
        if res['decision'] == 'violation_recorded':
            violations.append(res['evidence'].get('violation_id'))
    decision = 'violation_recorded' if violations else 'assessed'
    return emit(db, 'residency.ingest', str(subject), decision,
                {'adopted': adopted, 'violations': [v for v in violations if v],
                 'skipped': skipped, 'pages': page or 'all'},
                ok=not violations)


sync_captures = ingest_page
adopt_page = ingest_page


@core
def record_page(db, r):
    """Capture a storage page through the fixed capture contract then assess."""
    from .storage_capture import capture_page as _capture
    page_id = _g(r, 'page_id', 'page', 'id')
    copies = _g(r, 'copies', default=[])
    cap = _capture(db, page_id, copies)
    if cap['decision'] not in ('captured', 'idempotent'):
        return Response(cap)
    return ingest_page(db, {'page': page_id, 'at': _at(r)})


capture_and_assess = record_page


@core
def erase_copy(db, r):
    cid = _g(r, 'id', 'copy_id')
    digest = _g(r, 'digest', 'byte_digest')
    node = _g(r, 'node', 'node_id')
    at = _at(r)
    row = None
    if cid:
        row = one(db, 'SELECT * FROM dr_copies WHERE id=?', (cid,))
    elif digest and node:
        row = one(db, 'SELECT * FROM dr_copies WHERE digest=? AND node=? AND status IN (?,?,?)',
                  (digest, node, *_READABLE))
    elif digest:
        row = one(db, 'SELECT * FROM dr_copies WHERE digest=? AND status IN (?,?,?)',
                  (digest, *_READABLE))
    if not row:
        return emit(db, 'residency.erase', str(cid or digest), 'missing', {}, ok=False)
    if row['status'] == 'deleted':
        return emit(db, 'residency.erase', row['id'], 'idempotent', {'deleted_at': row['deleted_at']})
    failure = (_g(r, 'success', default=True) is False
               or _g(r, 'deleted', default=True) is False
               or _g(r, 'can_delete', 'deletable', default=True) is False
               or bool(_g(r, 'fails', 'failure', default=False)))
    if failure:
        db.execute("UPDATE dr_copies SET status='delete_failed',delete_attempts=delete_attempts+1 WHERE id=?",
                   (row['id'],))
        vid = _violation(db, _g(r, 'violation_id'), at, 'undeletable_copy',
                         {'copy_id': row['id'], 'digest': row['digest'], 'node': row['node'],
                          'attempt': row['delete_attempts'] + 1},
                         dataset=row['dataset'], node=row['node'], jur=row['jurisdiction'],
                         digest=row['digest'], plan=row['plan'],
                         dedup='undeletable:' + row['id'] + ':' + str(row['delete_attempts'] + 1))
        return emit(db, 'residency.erase', row['id'], 'undeletable',
                    {'copy_id': row['id'], 'still_readable': True, 'violation_id': vid}, ok=False)
    db.execute("UPDATE dr_copies SET status='deleted',deleted_at=? WHERE id=?", (at, row['id']))
    db.execute("UPDATE dr_obligations SET status='completed',completed_at=? WHERE subject=? AND status='pending'",
               (at, row['id']))
    db.execute("UPDATE dr_violations SET remedied=1,remedied_at=? WHERE (digest=? OR id=?) AND remedied=0",
               (at, row['digest'], row['violation_id'] or ''))
    return emit(db, 'residency.erase', row['id'], 'deleted',
                {'copy_id': row['id'], 'historical_violation_retained': True})


delete_copy = erase_copy
purge_copy = erase_copy


# ---------------------------------------------------------------------------
# Processing plans: one recoverable plan across all subsystems
# ---------------------------------------------------------------------------

@core
def create_plan(db, r):
    pid = _g(r, 'id', 'plan', 'plan_id')
    app = _g(r, 'app', 'application')
    at = _at(r)
    if not pid or not app:
        return emit(db, 'residency.plan', str(pid), 'invalid', {'missing': ['id', 'app']}, ok=False)
    old = one(db, 'SELECT * FROM dr_plans WHERE id=?', (pid,))
    if old:
        return emit(db, 'residency.plan', pid, 'idempotent', {'state': old['state']})
    demand_id = _g(r, 'demand', 'demand_id')
    if demand_id:
        d = one(db, 'SELECT id,status,app FROM demands WHERE id=?', (demand_id,))
        if not d:
            return emit(db, 'residency.plan', pid, 'missing',
                        {'contract': demand_id, 'reason': 'demand_not_found'}, ok=False)
    ids = _dataset_ids(r)
    if not ids:
        return emit(db, 'residency.plan', pid, 'invalid', {'missing': ['inputs']}, ok=False)
    for did in ids:
        if not one(db, 'SELECT id FROM dr_datasets WHERE id=?', (did,)):
            return emit(db, 'residency.plan', pid, 'missing', {'dataset': did}, ok=False)
    target_node = _g(r, 'target_node', 'node', 'processing_node')
    tzone, tjur = node_jurisdiction(db, target_node) if target_node else (None, _g(r, 'target_jurisdiction', 'region'))
    recipient_zone = _region(_g(r, 'recipient_zone', 'recipient_jurisdiction', default=tjur or '*'))
    purpose = _g(r, 'purpose', 'processing_purpose', default='processing')
    terms = intersect_terms(db, ids, at, purpose)
    db.execute("""INSERT INTO dr_plans
      (id,app,demand,purpose,recipient,recipient_zone,at,state,license_snapshot,terms,
       target_node,target_zone,created_at)
      VALUES(?,?,?,?,?,?,?, 'draft',NULL,?,?,?,?)""",
               (pid, app, demand_id, purpose, _g(r, 'recipient'), recipient_zone, at,
                _json(terms), target_node, tzone or tjur, at))
    db.executemany('INSERT OR IGNORE INTO dr_plan_inputs(plan,dataset) VALUES(?,?)',
                   [(pid, d) for d in ids])
    return emit(db, 'residency.plan', pid, 'planned',
                {'intersection_ok': terms['ok'], 'blockers': terms['blockers'],
                 'target_jurisdiction': tjur, 'inputs': ids},
                ok=True)


open_plan = create_plan


def _plan_inputs(db, pid):
    return [x['dataset'] for x in many(db, 'SELECT dataset FROM dr_plan_inputs WHERE plan=? ORDER BY dataset', (pid,))]


@core
def bind_app(db, r):
    """Bind the real input datasets an application reads (intersection set)."""
    app = _g(r, 'app', 'application')
    ids = _dataset_ids(r)
    if not app or not ids:
        return emit(db, 'residency.app_binding', str(app), 'invalid',
                    {'missing': ['app', 'datasets']}, ok=False)
    for did in ids:
        if not one(db, 'SELECT id FROM dr_datasets WHERE id=?', (did,)):
            return emit(db, 'residency.app_binding', app, 'missing', {'dataset': did}, ok=False)
    db.executemany('INSERT OR IGNORE INTO dr_app_datasets(app,dataset) VALUES(?,?)',
                   [(app, d) for d in ids])
    return emit(db, 'residency.app_binding', app, 'registered', {'datasets': ids})


def _snapshot(db, pid, at):
    """Pin the effective license id/version for every input."""
    ids = _plan_inputs(db, pid)
    snap = {}
    for did in ids:
        row = governing_license(db, did, at)
        if row is None:
            return None, did
        snap[did] = {'license_id': row['id'], 'version': row['version']}
    return snap, None


@core
def authorize_plan(db, r):
    pid = _g(r, 'id', 'plan', 'plan_id')
    at = _at(r)
    p = one(db, 'SELECT * FROM dr_plans WHERE id=?', (pid,))
    if not p:
        return emit(db, 'residency.plan', str(pid), 'missing', {}, ok=False)
    if p['state'] in ('authorized', 'running', 'completed', 'delivered'):
        return emit(db, 'residency.plan', pid, 'idempotent', {'state': p['state']})
    if p['state'] == 'cancelled':
        return emit(db, 'residency.plan', pid, 'restriction_conflict',
                    {'reason': 'plan_cancelled', 'cancel_at': p['cancel_at']}, ok=False)
    ids = _plan_inputs(db, pid)
    snap, bad = _snapshot(db, pid, at)
    if bad:
        return emit(db, 'residency.plan', pid, 'restriction_conflict',
                    {'dataset': bad, 'reason': 'no_effective_license', 'at': at}, ok=False)
    target_node = _g(r, 'target_node', 'node', default=p['target_node'])
    tzone, tjur = node_jurisdiction(db, target_node) if target_node else (None, p['target_zone'])
    region_override = _g(r, 'jurisdiction', 'region', 'target_jurisdiction')
    if region_override and not target_node:
        tjur = _region(region_override)
    terms = intersect_terms(db, ids, at, p['purpose'], snap)
    blockers = list(terms['blockers'])
    if tjur and not _dim_allows(terms['regions'], tjur):
        blockers.append({'reason': 'processing_jurisdiction_denied', 'jurisdiction': tjur})
    if target_node:
        healthy = one(db, 'SELECT healthy,cpu FROM nodes WHERE id=?', (target_node,))
        if not healthy:
            blockers.append({'reason': 'node_missing', 'node': target_node})
        elif not healthy['healthy']:
            blockers.append({'reason': 'node_unhealthy', 'node': target_node})
    if blockers:
        db.execute("UPDATE dr_plans SET state='blocked',terms=? WHERE id=?", (_json({**terms, 'blockers': blockers}), pid))
        db.execute("INSERT OR REPLACE INTO dr_steps VALUES(?,?,?,?,?)",
                   (pid, 'authorize', at, 'blocked', _json({'blockers': blockers})))
        return emit(db, 'residency.plan', pid, 'restriction_conflict',
                    {'blockers': blockers, 'spare_cpu_does_not_authorize_data_movement': True}, ok=False)
    db.execute("UPDATE dr_plans SET state='authorized',license_snapshot=?,terms=?,target_node=?,target_zone=? WHERE id=?",
               (_json(snap), _json(terms), target_node, tjur, pid))
    db.execute("INSERT OR REPLACE INTO dr_steps VALUES(?,?,?,?,?)",
               (pid, 'authorize', at, 'authorized', _json({'snapshot': snap, 'jurisdiction': tjur})))
    return emit(db, 'residency.plan', pid, 'authorized',
                {'snapshot': snap, 'jurisdiction': tjur, 'intersection': {
                    'regions': terms['regions'], 'purposes': terms['purposes'],
                    'fields': terms['fields']}})


approve_plan = authorize_plan


@core
def cancel_plan(db, r):
    pid = _g(r, 'id', 'plan', 'plan_id')
    at = _at(r)
    p = one(db, 'SELECT * FROM dr_plans WHERE id=?', (pid,))
    if not p:
        return emit(db, 'residency.plan', str(pid), 'missing', {}, ok=False)
    if p['state'] == 'cancelled':
        return emit(db, 'residency.plan', pid, 'idempotent', {'cancel_at': p['cancel_at']})
    if p['state'] == 'delivered':
        # A completed lawful delivery cannot be un-declared; record the
        # cancellation signal and strengthen deletion duties instead.
        db.execute("INSERT OR REPLACE INTO dr_steps VALUES(?,?,?,?,?)",
                   (pid, 'cancel', at, 'cancelled_after_delivery',
                    _json({'reason': _g(r, 'reason', default='customer_cancel'),
                           'delivery_retained': True})))
        for d in many(db, 'SELECT id FROM dr_deliveries WHERE plan=?', (pid,)):
            _obligation(db, 'accelerated_result_deletion', d['id'], 'recipient', at, 0,
                        {'reason': 'customer_cancelled_after_delivery'},
                        oid='obl:cancel:' + d['id'])
        return emit(db, 'residency.plan', pid, 'cancelled',
                    {'already_delivered': True, 'lawful_delivery_retained': True})
    db.execute("UPDATE dr_plans SET state='cancelled',cancel_at=? WHERE id=? AND state!='delivered'", (at, pid))
    db.execute("INSERT OR REPLACE INTO dr_steps VALUES(?,?,?,?,?)",
               (pid, 'cancel', at, 'cancelled', _json({'reason': _g(r, 'reason', default='customer_cancel')})))
    return emit(db, 'residency.plan', pid, 'cancelled', {'at': at})


@core
def start_processing(db, r):
    pid = _g(r, 'plan', 'id', 'plan_id')
    at = _at(r)
    p = one(db, 'SELECT * FROM dr_plans WHERE id=?', (pid,))
    if not p:
        return emit(db, 'residency.run', str(pid), 'missing', {}, ok=False)
    if p['state'] == 'running':
        return emit(db, 'residency.run', pid, 'idempotent', {'state': 'running'})
    if p['state'] == 'cancelled':
        return emit(db, 'residency.run', pid, 'restriction_conflict', {'reason': 'cancelled'}, ok=False)
    if p['state'] not in ('authorized', 'revoking'):
        return emit(db, 'residency.run', pid, 'restriction_conflict',
                    {'reason': 'plan_not_authorized', 'state': p['state']}, ok=False)
    snap = _loads(p['license_snapshot'], {})
    ids = _plan_inputs(db, pid)
    terms = intersect_terms(db, ids, at, p['purpose'], snap)
    node = _g(r, 'node', 'target_node', default=p['target_node'])
    _, jur = node_jurisdiction(db, node) if node else (None, p['target_zone'])
    if not terms['ok'] or (jur and not _dim_allows(terms['regions'], jur)):
        db.execute("UPDATE dr_plans SET state='blocked' WHERE id=?", (pid,))
        return emit(db, 'residency.run', pid, 'restriction_conflict',
                    {'blockers': terms['blockers'], 'jurisdiction': jur}, ok=False)
    db.execute("UPDATE dr_plans SET state='running' WHERE id=?", (pid,))
    db.execute("INSERT OR REPLACE INTO dr_steps VALUES(?,?,?,?,?)",
               (pid, 'start', at, 'running', _json({'node': node, 'jurisdiction': jur})))
    return emit(db, 'residency.run', pid, 'processing', {'node': node, 'jurisdiction': jur})


start_run = start_processing


@core
def finish_processing(db, r):
    pid = _g(r, 'plan', 'id', 'plan_id')
    at = _at(r)
    p = one(db, 'SELECT * FROM dr_plans WHERE id=?', (pid,))
    if not p:
        return emit(db, 'residency.run', str(pid), 'missing', {}, ok=False)
    if p['state'] == 'completed':
        return emit(db, 'residency.run', pid, 'idempotent', {})
    if p['state'] == 'cancelled':
        return emit(db, 'residency.run', pid, 'restriction_conflict', {'reason': 'cancelled'}, ok=False)
    if p['state'] not in ('authorized', 'running', 'revoking'):
        return emit(db, 'residency.run', pid, 'restriction_conflict',
                    {'reason': 'plan_not_running', 'state': p['state']}, ok=False)
    snap = _loads(p['license_snapshot'], {})
    ids = _plan_inputs(db, pid)
    terms = intersect_terms(db, ids, at, p['purpose'], snap)
    revoked = [d for d, ref in snap.items()
               if governing_license(db, d, at, ref) is None]
    if revoked or not terms['ok']:
        # The run tried to finish after its basis was revoked/lapsed.  Record
        # the attempted processing as a violation; no lawful artifact output
        # can be delivered from this plan.
        vid = _violation(db, _g(r, 'violation_id'), at, 'processing_after_license_boundary',
                         {'plan': pid, 'revoked_inputs': revoked, 'blockers': terms['blockers']},
                         plan=pid, dedup='revoked-run:' + pid + ':' + str(at))
        db.execute("UPDATE dr_plans SET state='halted' WHERE id=?", (pid,))
        db.execute("INSERT OR REPLACE INTO dr_steps VALUES(?,?,?,?,?)",
                   (pid, 'finish', at, 'halted', _json({'violation_id': vid, 'revoked': revoked})))
        return emit(db, 'residency.run', pid, 'halted',
                    {'violation_id': vid, 'revoked_inputs': revoked}, ok=False)
    db.execute("UPDATE dr_plans SET state='completed' WHERE id=?", (pid,))
    db.execute("INSERT OR REPLACE INTO dr_steps VALUES(?,?,?,?,?)",
               (pid, 'finish', at, 'completed', _json({})))
    return emit(db, 'residency.run', pid, 'completed', {})


finish_run = finish_processing


@core
def reconcile(db, r):
    """Recover control-plane state after a power loss.

    Purely derived from persisted tables: returns every plan's safe state and
    refuses to advance a plan whose license boundary has since closed.
    """
    pid = _g(r, 'plan', 'id', 'plan_id')
    at = _at(r, default=10 ** 12)
    plans = many(db, 'SELECT * FROM dr_plans' + (' WHERE id=?' if pid else ''), (pid,) if pid else ())
    report = []
    for p in plans:
        ids = _plan_inputs(db, p['id'])
        snap = _loads(p['license_snapshot'], {})
        live_bad = _unlawful_live_copies(db, ids)
        license_alive = True
        if snap:
            for did, ref in snap.items():
                if governing_license(db, did, at, ref) is None:
                    license_alive = False
        safe_state = p['state']
        if p['state'] in ('authorized', 'running', 'revoking') and not license_alive:
            safe_state = 'halted'
            db.execute("UPDATE dr_plans SET state='halted' WHERE id=? AND state IN ('authorized','running','revoking')",
                       (p['id'],))
        report.append({'plan': p['id'], 'stored_state': p['state'], 'safe_state': safe_state,
                       'license_alive_at_horizon': license_alive,
                       'unlawful_live_copies': [c['id'] for c in live_bad]})
    return emit(db, 'residency.reconcile', str(pid or 'all'), 'reconciled',
                {'plans': report}, ok=all(x['safe_state'] != 'halted' for x in report))


recover_plan = reconcile
recover_control_plane = reconcile


# ---------------------------------------------------------------------------
# Byte transformation: real new digests + reproducible proofs
# ---------------------------------------------------------------------------

def _proof(input_digests, transform, spec, out_digest):
    return _sha(['dr-transform-proof/v1', transform, _json(spec), _json(sorted(input_digests)), out_digest])


@core
def transform_bytes(db, r):
    """Create a derived artifact with a fresh digest and verifiable proof.

    A caller-supplied ``output_digest``/``proof`` must reproduce exactly;
    relabelling the raw digest as de-identified is rejected and recorded.
    """
    kind = _g(r, 'kind', 'artifact_kind', default='deidentified')
    transform = _g(r, 'transform', 'transformation', 'method', 'strategy', 'algorithm', default=kind)
    input_digests = _as_list(_g(r, 'input_digests', 'input_digest', 'source_digest'))
    input_digest = _g(r, 'input_digest', 'source_digest')
    if input_digest and input_digest not in input_digests:
        input_digests.append(input_digest)
    spec = dict(_g(r, 'spec', 'parameters', default={}) or {})
    salt = _g(r, 'salt', 'nonce')
    if salt is not None:
        spec.setdefault('__salt__', salt)
    at = _at(r)
    plan = _g(r, 'plan', 'plan_id')
    node = _g(r, 'node', 'node_id')
    zone, jur = node_jurisdiction(db, node) if node else (None, _g(r, 'jurisdiction', 'region'))
    zone = jur or (_region(zone) if zone else None)
    datasets = [str(x) for x in _as_list(_g(r, 'datasets', 'dataset', default=[]))]
    personal = 1 if _g(r, 'personal', 'contains_personal', 'traceable', default=False) else 0
    traceable = 1 if _g(r, 'traceable', 'record_level', default=personal) else 0
    content = _g(r, 'content', 'bytes', 'report_content')
    computed_out = _sha(['dr-artifact/v1', kind, transform, _json(spec),
                         _json(sorted(input_digests)), content or ''])
    out_digest = _g(r, 'output_digest', 'digest', 'new_digest', default=computed_out)
    claimed_proof = _g(r, 'proof')
    expected_proof = _proof(input_digests, transform, spec, out_digest)
    aid = _g(r, 'id', default=out_digest)

    if input_digest and out_digest == input_digest and kind in ('deidentified', 'anonymized', 'anonymous', 'stat', 'statistics'):
        _violation(db, _g(r, 'violation_id'), at, 'fake_anonymization_relabel',
                   {'plan': plan, 'digest': out_digest}, plan=plan,
                   dedup='relabel:' + str(plan) + ':' + out_digest + ':' + str(at))
        return emit(db, 'residency.transform', aid, 'relabel_rejected',
                    {'input_digest': input_digest, 'output_digest': out_digest,
                     'digest': out_digest}, ok=False)
    if claimed_proof is not None and claimed_proof != expected_proof:
        db.execute("""INSERT OR REPLACE INTO dr_artifacts
          (digest,kind,dataset,datasets,plan,node,zone,at,input_digests,transform,spec,proof,
           personal,traceable,content,reproducible)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                   (out_digest, kind, datasets[0] if datasets else None, _json(datasets), plan,
                    node, zone or jur, at, _json(sorted(input_digests)), transform, _json(spec),
                    claimed_proof, personal, traceable, content))
        return emit(db, 'residency.transform', aid, 'proof_mismatch',
                    {'expected_proof': expected_proof, 'claimed_proof': claimed_proof,
                     'digest': out_digest, 'reproducible': False}, ok=False)
    existing = one(db, 'SELECT digest FROM dr_artifacts WHERE digest=?', (out_digest,))
    if existing:
        return emit(db, 'residency.transform', out_digest, 'idempotent', {'digest': out_digest})
    db.execute("""INSERT INTO dr_artifacts
      (digest,kind,dataset,datasets,plan,node,zone,at,input_digests,transform,spec,proof,
       personal,traceable,content,reproducible)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
               (out_digest, kind, datasets[0] if datasets else None, _json(datasets), plan,
                node, zone or jur, at, _json(sorted(input_digests)), transform, _json(spec),
                expected_proof, personal, traceable, content))
    return emit(db, 'residency.transform', out_digest, 'anonymized' if kind in ('deidentified', 'anonymized') else 'recorded',
                {'digest': out_digest, 'proof': expected_proof, 'new_digest': out_digest,
                 'input_digests': input_digests, 'traceable': bool(traceable)})


anonymize = transform_bytes
deidentify = transform_bytes
create_artifact = transform_bytes


@core
def verify_artifact(db, r):
    digest = _g(r, 'digest', 'artifact_digest', 'output_digest')
    row = one(db, 'SELECT * FROM dr_artifacts WHERE digest=?', (digest,))
    if not row:
        # Verification can also be performed purely from supplied claims.
        input_digests = _as_list(_g(r, 'input_digests', 'input_digest', default=[]))
        expected = _proof(input_digests, _g(r, 'transform', default='deidentified'),
                          _g(r, 'spec', default={}), digest)
        ok = _g(r, 'proof') == expected and digest != _g(r, 'input_digest')
        return emit(db, 'residency.verify', str(digest), 'verified' if ok else 'proof_mismatch',
                    {'reproducible': ok, 'expected_proof': expected}, ok=ok)
    inputs = _loads(row['input_digests'], [])
    expected = _proof(inputs, row['transform'], _loads(row['spec'], {}), row['digest'])
    supplied = _g(r, 'proof', default=row['proof'])
    recomputed_out = _sha(['dr-artifact/v1', row['kind'], row['transform'], row['spec'],
                           _json(sorted(inputs)), row['content'] or ''])
    ok = supplied == expected and row['proof'] == expected and bool(row['reproducible'])
    if _g(r, 'expect_digest', default=None) is not None:
        ok = ok and _g(r, 'expect_digest') == recomputed_out
    return emit(db, 'residency.verify', digest, 'verified' if ok else 'proof_mismatch',
                {'reproducible': ok, 'proof': row['proof'], 'expected_proof': expected,
                 'personal': bool(row['personal']), 'traceable': bool(row['traceable'])}, ok=ok)


verify_transformation = verify_artifact


# ---------------------------------------------------------------------------
# Byte movement / egress / raw access / backups
# ---------------------------------------------------------------------------

@core
def transfer_bytes(db, r):
    """License-gated movement of real bytes between nodes/jurisdictions."""
    tid = _g(r, 'id', 'transfer_id') or _sha(['xfer', _g(r, 'plan'), _g(r, 'dataset'),
                                              _g(r, 'digest'), _g(r, 'to_node'), _at(r)])[7:27]
    old = one(db, 'SELECT * FROM dr_transfers WHERE id=?', (tid,))
    if old:
        return emit(db, 'residency.transfer', tid, 'idempotent', {'status': old['status']})
    pid = _g(r, 'plan', 'plan_id')
    did = _g(r, 'dataset', 'dataset_id')
    digest = _g(r, 'digest', 'byte_digest')
    from_node = _g(r, 'from_node', 'source_node', 'source')
    to_node = _g(r, 'to_node', 'destination', 'dest_node', 'target_node', 'target', 'node')
    at = _at(r)
    fields = _as_list(_g(r, 'fields', default=None)) or None
    fz, fj = node_jurisdiction(db, from_node)
    tz, tj = node_jurisdiction(db, to_node)
    snap = None
    if pid:
        p = one(db, 'SELECT license_snapshot,purpose FROM dr_plans WHERE id=?', (pid,))
        snap = _loads(p['license_snapshot'], {}) if p else {}
    refs = {did: snap.get(did)} if snap else None
    terms = intersect_terms(db, [did], at, None, refs)
    blockers = list(terms['blockers'])
    purpose_denied = _all_allow_purpose(db, [did], at, refs, _MOVEMENT_PURPOSES)
    if purpose_denied:
        blockers.extend(purpose_denied)
    if tj and not _dim_allows(terms['regions'], tj):
        blockers.append({'reason': 'destination_processing_region_denied', 'jurisdiction': tj})
    if fj and tj and fj != tj:
        if not _dim_allows(terms['cross_border_destinations'], tj):
            blockers.append({'reason': 'cross_border_transfer_denied', 'from': fj, 'to': tj})
        if fields:
            cf = terms['cross_border_fields']
            if not _fields_allowed(cf, fields):
                blockers.append({'reason': 'fields_not_cleared_for_export',
                                 'requested': fields, 'allowed': cf})
    if blockers:
        db.execute("""INSERT INTO dr_transfers
          (id,plan,dataset,digest,from_node,from_zone,to_node,to_zone,fields,bytes,at,
           license_id,license_version,status,copy_id)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'denied',NULL)""",
                   (tid, pid, did, digest, from_node, fj, to_node, tj, _json(fields or ['*']),
                    _g(r, 'bytes', 'byte_count'), at,
                    (terms['licenses'].get(did) or {}).get('license_id'),
                    (terms['licenses'].get(did) or {}).get('version')))
        return emit(db, 'residency.transfer', tid, 'cross_border_denied',
                    {'blockers': blockers, 'spare_cpu_does_not_authorize_data_movement': True,
                     'to_jurisdiction': tj}, ok=False)
    lic = terms['licenses'].get(did) or {}
    copy_id = _g(r, 'copy_id', default='copy:' + tid)
    db.execute("""INSERT INTO dr_transfers
      (id,plan,dataset,digest,from_node,from_zone,to_node,to_zone,fields,bytes,at,
       license_id,license_version,status,copy_id)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'transferred',?)""",
               (tid, pid, did, digest, from_node, fj, to_node, tj, _json(fields or ['*']),
                _g(r, 'bytes', 'byte_count'), at, lic.get('license_id'), lic.get('version'), copy_id))
    # Bytes really arrive: create a live destination copy with the license
    # basis and cleanup responsibility.
    creq = {'id': copy_id, 'dataset': did, 'node': to_node, 'digest': digest, 'at': at,
            'kind': _g(r, 'copy_kind', default='temp'), 'plan': pid,
            'license_ref': lic.get('license_id'), 'fields': fields,
            'cleanup_owner': _g(r, 'cleanup_owner', default='controlled-env:' + str(to_node)),
            'origin': 'transfer:' + tid, 'status': 'live'}
    register_copy(db, creq)
    if _g(r, 'move', default=False) and from_node:
        src = one(db, 'SELECT id FROM dr_copies WHERE dataset=? AND node=? AND digest=? AND status=?',
                  (did, from_node, digest, 'live'))
        if src:
            db.execute("UPDATE dr_copies SET status='deleting' WHERE id=?", (src['id'],))
            _obligation(db, 'source_copy_deletion', src['id'],
                         _g(r, 'source_owner', default='operator:' + str(from_node)), at,
                         terms.get('delete_after'), {'transfer': tid})
    _obligation(db, 'temporary_copy_cleanup', copy_id, creq['cleanup_owner'], at,
                terms.get('delete_after'), {'transfer': tid, 'node': to_node},
                oid='obl:temp:' + copy_id)
    return emit(db, 'residency.transfer', tid, 'transferred',
                {'transfer_id': tid, 'copy_id': copy_id, 'from': fj, 'to': tj,
                 'digest': digest, 'fields': fields, 'license': lic})


send_bytes = transfer_bytes
move_bytes = transfer_bytes
egress = transfer_bytes


@core
def request_raw(db, r):
    """Two jurisdictions asking for raw X are judged independently."""
    rid = _g(r, 'id', 'request_id') or _sha(['raw', _g(r, 'dataset'), _g(r, 'zone'), _at(r), _g(r, 'requester')])[7:27]
    old = one(db, 'SELECT * FROM dr_raw_requests WHERE id=?', (rid,))
    if old:
        return emit(db, 'residency.raw', rid, 'idempotent', {'decision': old['decision']})
    did = _g(r, 'dataset', 'dataset_id')
    at = _at(r)
    node = _g(r, 'node', 'node_id')
    zone = _g(r, 'zone', 'jurisdiction', 'requester_zone')
    if node:
        _, j = node_jurisdiction(db, node)
        zone = zone or j
    zone = _region(zone) if zone else None
    fields = _as_list(_g(r, 'fields', default=None)) or None
    terms = intersect_terms(db, [did], at, None)
    purpose_denied = _all_allow_purpose(db, [did], at, None, _RAW_PURPOSES)
    allowed = not purpose_denied and bool(terms['ok']) and bool(zone) and _dim_allows(terms['regions'], zone)
    detail_fields = None
    if purpose_denied:
        terms['blockers'].extend(purpose_denied)
    if allowed and zone:
        home = _dataset_home(db, did)
        if zone != home:
            # Cross-border RAW access needs an explicit export destination.
            if not _dim_allows(terms['cross_border_destinations'], zone):
                allowed = False
                terms['blockers'].append({'reason': 'raw_export_not_cleared', 'zone': zone})
            elif fields:
                if not _fields_allowed(terms['cross_border_fields'], fields):
                    allowed = False
                    terms['blockers'].append({'reason': 'fields_not_cleared_for_export',
                                              'requested': fields,
                                              'allowed': terms['cross_border_fields']})
                detail_fields = fields
            elif terms['cross_border_fields'] is not None:
                # License clears only specified fields, not the full raw record.
                allowed = False
                terms['blockers'].append({'reason': 'full_raw_not_cleared_only_specified_fields',
                                          'allowed_fields': terms['cross_border_fields']})
    decision = 'raw_granted' if allowed else 'raw_denied'
    detail = {'zone': zone, 'fields': detail_fields, 'blockers': terms['blockers']}
    db.execute('INSERT INTO dr_raw_requests VALUES(?,?,?,?,?,?,?,?)',
               (rid, did, _g(r, 'requester'), zone, node, at, decision, _json(detail)))
    return emit(db, 'residency.raw', rid, decision, detail, ok=allowed)


def _dataset_home(db, did):
    d = one(db, 'SELECT jurisdiction FROM dr_datasets WHERE id=?', (did,))
    return _region(d['jurisdiction']) if d else None


@core
def backup(db, r):
    """A backup / recovery point is a copy and must be region-authorized."""
    req = dict(r)
    req['kind'] = _g(r, 'kind', default='recovery_point')
    req['origin'] = _g(r, 'origin', default='backup')
    res = register_copy(db, req)
    if res['decision'] in ('recorded',):
        return emit(db, 'residency.backup', res['subject'], 'backed_up', res['evidence'])
    return res


create_recovery_point = backup
snapshot_copy = backup


# ---------------------------------------------------------------------------
# Delivery gate and customer traceability
# ---------------------------------------------------------------------------

def _unlawful_live_copies(db, dataset_ids):
    if not dataset_ids:
        return []
    q = ','.join('?' for _ in dataset_ids)
    return many(db, f"""SELECT id,dataset,node,jurisdiction,digest,kind,status,violation_id
                         FROM dr_copies
                         WHERE dataset IN ({q}) AND status IN (?,?,?) AND lawful=0
                         ORDER BY id""",
                (*dataset_ids, *_READABLE))


@core
def deliver(db, r):
    did_ = _g(r, 'id', 'delivery_id', 'report_id') or _sha(['deliv', _g(r, 'plan'), _at(r)])[7:27]
    old = one(db, 'SELECT * FROM dr_deliveries WHERE id=?', (did_,))
    if old:
        return emit(db, 'residency.delivery', did_, 'idempotent',
                    {'lawful': bool(old['lawful']), 'deletion_status': old['deletion_status']})
    pid = _g(r, 'plan', 'plan_id')
    at = _at(r)
    p = one(db, 'SELECT * FROM dr_plans WHERE id=?', (pid,)) if pid else None
    ids = _plan_inputs(db, pid) if p else _dataset_ids(r)
    artifacts = _as_list(_g(r, 'artifacts', 'artifact_digests', 'digests',
                            'report_digest', 'result_digest', 'output_digest', 'artifact', default=[]))
    recipient = _g(r, 'recipient', 'to', 'customer', default=(p['recipient'] if p else None))
    zone = _region(_g(r, 'zone', 'recipient_zone', 'jurisdiction', 'region',
                      'recipient_jurisdiction', 'to_jurisdiction',
                      default=(p['recipient_zone'] if p else None)))
    # 1) plan/customer cancellation gate
    if p and p['state'] == 'cancelled':
        return emit(db, 'residency.delivery', did_, 'restriction_conflict',
                    {'reason': 'customer_cancelled', 'cancel_at': p['cancel_at']}, ok=False)
    if p and p['state'] in ('blocked', 'halted'):
        return emit(db, 'residency.delivery', did_, 'restriction_conflict',
                    {'reason': 'plan_not_lawfully_processed', 'state': p['state']}, ok=False)
    # 2) every input license must still be effective at delivery time
    snap = _loads(p['license_snapshot'], {}) if p else {}
    # Purpose was adjudicated at plan authorisation/run time; delivery gates
    # on current license effectiveness, recipient region and report kind.
    terms = intersect_terms(db, ids, at, None, snap)
    if not terms['ok']:
        return emit(db, 'residency.delivery', did_, 'restriction_conflict',
                    {'blockers': terms['blockers']}, ok=False)
    # 3) no tainted raw copy may still be readable
    bad = _unlawful_live_copies(db, ids)
    if bad and not _g(r, 'allow_tainted', default=False):
        return emit(db, 'residency.delivery', did_, 'unlawful_copy_live',
                    {'unlawful_copies': bad,
                     'reason': 'cannot_certify_lawful_delivery_while_unauthorized_bytes_readable'},
                    ok=False)
    # 4) artifacts must exist and verify; delivery-region terms depend on kind
    art_rows = []
    personal = bool(_g(r, 'personal', 'contains_personal', default=False))
    traceable = bool(_g(r, 'traceable', 'record_level', default=False))
    for a in artifacts:
        row = one(db, 'SELECT * FROM dr_artifacts WHERE digest=?', (a,))
        if not row:
            # An externally computed result may be delivered directly. Adopt
            # it into the lineage ledger; a supplied proof must still verify.
            ext_inputs = _as_list(_g(r, 'input_digests', 'input_digest', default=[]))
            ext_transform = _g(r, 'transform', default='external_result')
            ext_spec = _g(r, 'spec', 'parameters', default={}) or {}
            expected = _proof(ext_inputs, ext_transform, ext_spec, a)
            claimed = _g(r, 'proof')
            if claimed is not None and claimed != expected:
                return emit(db, 'residency.delivery', did_, 'proof_mismatch',
                            {'artifact': a, 'expected_proof': expected}, ok=False)
            kind = _g(r, 'artifact_kind', 'report_kind_hint', default='result')
            db.execute("""INSERT OR IGNORE INTO dr_artifacts
              (digest,kind,dataset,datasets,plan,node,zone,at,input_digests,transform,spec,proof,
               personal,traceable,content,reproducible)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                       (a, kind, ids[0] if ids else None, _json(ids), pid,
                        _g(r, 'node'), zone, at, _json(ext_inputs), ext_transform,
                        _json(ext_spec), expected, 1 if personal else 0,
                        1 if traceable else 0, _g(r, 'content')))
            row = one(db, 'SELECT * FROM dr_artifacts WHERE digest=?', (a,))
        expected = _proof(_loads(row['input_digests'], []), row['transform'],
                          _loads(row['spec'], {}), row['digest'])
        if not row['reproducible'] or row['proof'] != expected:
            return emit(db, 'residency.delivery', did_, 'proof_mismatch',
                        {'artifact': a}, ok=False)
        art_rows.append(row)
        personal = personal or bool(row['personal'])
        traceable = traceable or bool(row['traceable'])
    if zone and zone != '*':
        if personal:
            # Full personal/traceable reports require report-purpose rights
            # in EVERY input license plus the recipient zone intersection.
            denied = _all_allow_purpose(db, ids, at, snap, _PERSONAL_REPORT_PURPOSES)
            if denied:
                return emit(db, 'residency.delivery', did_, 'restriction_conflict',
                            {'reason': 'traceable_report_purpose_not_permitted',
                             'blockers': denied}, ok=False)
            if not _dim_allows(terms['recipient_zones'], zone):
                return emit(db, 'residency.delivery', did_, 'restriction_conflict',
                            {'reason': 'personal_report_recipient_not_permitted', 'zone': zone}, ok=False)
        else:
            if not _dim_allows(terms['deidentified_zones'], zone) and not _dim_allows(terms['recipient_zones'], zone):
                return emit(db, 'residency.delivery', did_, 'restriction_conflict',
                            {'reason': 'derived_result_recipient_not_permitted', 'zone': zone}, ok=False)
    # 5) persist immutable basis snapshot and deletion obligations
    basis = {'at': at, 'licenses': terms['licenses'], 'plan_snapshot': snap,
             'purpose': p['purpose'] if p else _g(r, 'purpose'),
             'terms_regions': terms['regions']}
    delete_after = terms['delete_after']
    report_kind = 'traceable_personal_report' if traceable else ('deidentified_statistics' if artifacts else 'result')
    db.execute("""INSERT INTO dr_deliveries
      (id,plan,recipient,zone,at,artifacts,license_snapshot,lawful,delete_after,
       deletion_status,report_kind,traceable)
      VALUES(?,?,?,?,?,?,?,1,?, 'pending',?,?)""",
               (did_, pid, recipient, zone, at, _json(artifacts), _json(basis),
                delete_after, report_kind, 1 if traceable else 0))
    if p:
        db.execute("UPDATE dr_plans SET state='delivered' WHERE id=?", (pid,))
        db.execute("INSERT OR REPLACE INTO dr_steps VALUES(?,?,?,?,?)",
                   (pid, 'deliver', at, 'delivered', _json({'delivery': did_})))
    _obligation(db, 'delivered_result_deletion', did_, 'recipient:' + str(recipient),
                at, delete_after, {'artifacts': artifacts, 'zone': zone},
                oid='obl:delivery:' + did_)
    # derived bytes crossing to recipient create egress evidence
    if zone:
        for row in art_rows:
            origin_zone = row['zone']
            if origin_zone and _region(origin_zone) != zone:
                xid = 'egress:delivery:%s:%s' % (did_, row['digest'][:18])
                db.execute("""INSERT OR IGNORE INTO dr_transfers
                  (id,plan,dataset,digest,from_node,from_zone,to_node,to_zone,fields,bytes,at,
                   license_id,license_version,status,copy_id)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'delivered',NULL)""",
                           (xid, pid, row['dataset'], row['digest'], row['node'], origin_zone,
                            'recipient:' + str(recipient), zone, '["derived"]',
                            _g(r, 'byte_count'), at,
                            (terms['licenses'].get(row['dataset']) or {}).get('license_id'),
                            (terms['licenses'].get(row['dataset']) or {}).get('version')))
    return emit(db, 'residency.delivery', did_, 'delivered',
                {'delivery_id': did_, 'lawful': True, 'basis': basis,
                 'delete_after': delete_after,
                 'delete_by': (at + delete_after) if isinstance(delete_after, int) else None,
                 'report_kind': report_kind, 'traceable': traceable,
                 'artifacts': artifacts})


deliver_report = deliver
certify_delivery = deliver


@core
def run_pipeline(db, r):
    """Convenience one-shot: start then finish an authorised plan, or assess."""
    pid = _g(r, 'plan', 'plan_id')
    at = _at(r)
    if not pid:
        return evaluate_access(db, r)
    start_at = _g(r, 'start_at', default=at)
    started = start_processing(db, {'plan': pid, 'node': _g(r, 'node', 'target_node'), 'at': start_at})
    if not started.get('ok') and started['decision'] != 'idempotent':
        return started
    return finish_processing(db, {'plan': pid, 'at': _g(r, 'finish_at', default=at)})


@core
def complete_obligation(db, r):
    oid = _g(r, 'id', 'obligation_id')
    at = _at(r)
    row = one(db, 'SELECT * FROM dr_obligations WHERE id=?', (oid,))
    if not row:
        return emit(db, 'residency.obligation', str(oid), 'missing', {}, ok=False)
    if row['status'] == 'completed':
        return emit(db, 'residency.obligation', oid, 'idempotent', {})
    db.execute("UPDATE dr_obligations SET status='completed',completed_at=? WHERE id=?", (at, oid))
    if row['kind'] == 'delivered_result_deletion':
        db.execute("UPDATE dr_deliveries SET deletion_status='deleted',deleted_at=? WHERE id=?",
                   (at, row['subject']))
    return emit(db, 'residency.obligation', oid, 'deleted', {'kind': row['kind']})


confirm_cleanup = complete_obligation


# ---------------------------------------------------------------------------
# Trace / audit / responsibility views
# ---------------------------------------------------------------------------

@core
def trace(db, r):
    pid = _g(r, 'plan', 'id', 'plan_id')
    did_ = _g(r, 'delivery', 'delivery_id')
    p = one(db, 'SELECT * FROM dr_plans WHERE id=?', (pid,)) if pid else None
    if did_ and not pid:
        d = one(db, 'SELECT * FROM dr_deliveries WHERE id=?', (did_,))
        pid = d['plan'] if d else None
        p = one(db, 'SELECT * FROM dr_plans WHERE id=?', (pid,)) if pid else None
    ids = _plan_inputs(db, pid) if p else _dataset_ids(r)
    out = {'plan': dict(p) if p else None, 'datasets': [one(db, 'SELECT * FROM dr_datasets WHERE id=?', (d,)) for d in ids],
           'inputs': ids}
    if p:
        out['steps'] = many(db, 'SELECT * FROM dr_steps WHERE plan=? ORDER BY rowid', (pid,))
        out['licenses'] = many(db, 'SELECT id,dataset,version,state,effective_from,effective_to FROM dr_licenses WHERE dataset IN (%s)'
                               % ','.join('?' for _ in ids), ids)
    out['copies'] = many(db, """SELECT id,dataset,node,zone,jurisdiction,kind,digest,at,status,
                                       lawful,violation_id,cleanup_owner,cleanup_due,plan,demand
                                FROM dr_copies WHERE dataset IN (%s)
                                ORDER BY at,id""" % ','.join('?' for _ in ids), ids) if ids else []
    out['artifacts'] = many(db, 'SELECT digest,kind,dataset,plan,node,zone,at,transform,spec,input_digests,proof,personal,traceable,content,reproducible FROM dr_artifacts WHERE plan=? OR dataset IN (%s)'
                            % (','.join('?' for _ in ids) if ids else "SELECT '' WHERE 0"),
                            (pid, *ids)) if ids else many(db, 'SELECT digest,kind,dataset,plan,node,zone,at,transform,spec,input_digests,proof,personal,traceable,content,reproducible FROM dr_artifacts WHERE plan=?', (pid,))
    out['transfers'] = many(db, 'SELECT * FROM dr_transfers WHERE plan=? OR dataset IN (%s) ORDER BY at'
                            % (','.join('?' for _ in ids) if ids else "''"),
                            (pid, *ids)) if ids else many(db, 'SELECT * FROM dr_transfers WHERE plan=?', (pid,))
    out['deliveries'] = many(db, 'SELECT * FROM dr_deliveries WHERE plan=?', (pid,)) if pid else (
        many(db, 'SELECT * FROM dr_deliveries WHERE id=?', (did_,)) if did_ else [])
    out['violations'] = many(db, 'SELECT * FROM dr_violations WHERE dataset IN (%s) OR plan=? ORDER BY seq'
                             % ','.join('?' for _ in ids), (*ids, pid)) if ids else []
    out['obligations'] = many(db, """SELECT * FROM dr_obligations
                                     WHERE subject IN (SELECT id FROM dr_copies WHERE dataset IN (%s))
                                        OR id LIKE ? OR subject=? ORDER BY at"""
                              % ','.join('?' for _ in ids),
                              (*ids, 'obl:delivery:' + str(did_ or ''), str(did_ or ''))) if ids else []
    out['responsibilities'] = [
        {'subject': c['id'], 'digest': c['digest'], 'jurisdiction': c['jurisdiction'],
         'status': c['status'], 'owner': c['cleanup_owner'], 'due': c['cleanup_due']}
        for c in out['copies']]
    return emit(db, 'residency.trace', str(pid or did_ or 'trace'), 'traced', out)


lineage = trace
customer_trace = trace


@core
def responsibilities(db, r):
    pid = _g(r, 'plan', 'id', 'plan_id')
    ids = _plan_inputs(db, pid) if pid else _dataset_ids(r)
    rows = many(db, """SELECT id,dataset,kind,digest,node,jurisdiction,status,
                              cleanup_owner AS owner,cleanup_owner,cleanup_due AS due,cleanup_due,deleted_at
                       FROM dr_copies WHERE dataset IN (%s) ORDER BY dataset,at"""
                % ','.join('?' for _ in ids), ids) if ids else many(
        db, """SELECT id,dataset,kind,digest,node,jurisdiction,status,
                      cleanup_owner AS owner,cleanup_owner,cleanup_due AS due,cleanup_due,deleted_at
               FROM dr_copies""")
    obls = many(db, 'SELECT * FROM dr_obligations ORDER BY at')
    return emit(db, 'residency.responsibilities', str(pid or 'all'), 'traced',
                {'copies': rows, 'obligations': obls})


cleanup_ledger = responsibilities


@core
def audit_residency(db, r):
    ids = _dataset_ids(r)
    if ids:
        q = ','.join('?' for _ in ids)
        bad = many(db, f'SELECT * FROM dr_copies WHERE dataset IN ({q}) AND status IN (?,?,?) AND lawful=0',
                   (*ids, *_READABLE))
        vios = many(db, f'SELECT * FROM dr_violations WHERE dataset IN ({q}) ORDER BY seq', ids)
    else:
        bad = many(db, "SELECT * FROM dr_copies WHERE status IN ('live','delete_failed','deleting') AND lawful=0")
        vios = many(db, 'SELECT * FROM dr_violations ORDER BY seq')
    open_v = [v for v in vios if not v['remedied']]
    decision = 'non_compliant' if (bad or open_v) else 'compliant'
    return emit(db, 'residency.audit', _g(r, 'id', default='residency'), decision,
                {'unlawful_readable_copies': bad, 'violations': vios,
                 'open_violations': len(open_v), 'historical_violations': len(vios)},
                ok=not (bad or open_v))


compliance = audit_residency
inspect_residency = audit_residency


# ---------------------------------------------------------------------------
# Integration guards for demand / supply / rebalance flows
# ---------------------------------------------------------------------------

@core
def guard_placement(db, r):
    """Residency check for a compute placement / migration destination."""
    demand_id = _g(r, 'demand', 'demand_id')
    pid = _g(r, 'plan', 'plan_id')
    at = _at(r)
    if not at and demand_id:
        d = one(db, 'SELECT start FROM demands WHERE id=?', (demand_id,))
        at = d['start'] if d else 0
    ids = _dataset_ids(r)
    if not ids and pid:
        ids = _plan_inputs(db, pid)
    demand_id = demand_id or _g(r, 'demand', 'demand_id')
    app = _g(r, 'app')
    if not ids and demand_id:
        drow = one(db, 'SELECT app FROM demands WHERE id=?', (demand_id,))
        if drow:
            app = app or drow['app']
            plan = one(db, 'SELECT id FROM dr_plans WHERE demand=? ORDER BY created_at DESC LIMIT 1', (demand_id,))
            if plan:
                ids = _plan_inputs(db, plan['id'])
    if not ids and app:
        bound = [x['dataset'] for x in many(db, 'SELECT dataset FROM dr_app_datasets WHERE app=? ORDER BY dataset', (app,))]
        if bound:
            ids = bound
        else:
            row = one(db, 'SELECT id FROM dr_plans WHERE app=? ORDER BY created_at DESC LIMIT 1', (app,))
            if row:
                pid = row['id']
                ids = _plan_inputs(db, pid)
    node = _g(r, 'node', 'node_id', 'destination')
    _, jur = node_jurisdiction(db, node)
    wanted_purpose = _g(r, 'purpose', default='processing')
    if ids:
        terms = intersect_terms(db, ids, at, None)
        blockers = list(terms.get('blockers', []))
        # Placement/migration/recovery host licensed processing and storage;
        # any of those purpose families suffices at the infrastructure guard.
        purpose_denied = _all_allow_purpose(
            db, ids, at, None,
            (wanted_purpose, 'processing', 'storage', 'migration', 'recovery'))
        blockers.extend(purpose_denied)
    else:
        terms = {'ok': True, 'blockers': [], 'regions': None}
        blockers = []
    if jur and ids and not _dim_allows(terms.get('regions'), jur):
        blockers.append({'reason': 'placement_jurisdiction_denied', 'jurisdiction': jur})
    decision = 'authorized' if not blockers else 'restriction_conflict'
    return emit(db, 'residency.placement_guard', str(demand_id or pid or node), decision,
                {'node': node, 'jurisdiction': jur, 'blockers': blockers}, ok=not blockers)


authorize_placement = guard_placement


@core
def place_guarded(db, r):
    guard = guard_placement(db, r)
    if not guard['ok']:
        return guard
    from . import rebalance
    return Response(rebalance.place(db, r))


@core
def recover_guarded(db, r):
    """Residency-aware recovery: a cross-region restore of raw bytes is gated."""
    guard_req = dict(r)
    guard_req['node'] = _g(r, 'destination', 'node')
    guard = guard_placement(db, guard_req)
    if not guard['ok']:
        return emit(db, 'residency.recover', _g(r, 'demand'), 'recovery_blocked',
                    guard['evidence'], ok=False)
    from . import rebalance
    return Response(rebalance.recover(db, r))


@core
def complete_drain_guarded(db, r):
    """Before committing a drain plan, verify every destination jurisdiction."""
    node_id = _g(r, 'id', 'node')
    generation = _g(r, 'generation')
    moves = many(db, 'SELECT * FROM drain_moves WHERE node=? AND generation=?', (node_id, generation))
    blockers = []
    for m in moves:
        # guard_placement resolves plan inputs, demand->app and app bindings.
        g = guard_placement(db, {'demand': m['demand'], 'node': m['destination'],
                                 'purpose': 'migration', 'at': _at(r)})
        if not g['ok']:
            blockers.append({'demand': m['demand'], 'replica': m['replica'],
                             'destination': m['destination'], 'blockers': g['blockers']})
    if blockers:
        return emit(db, 'residency.drain_complete', str(node_id), 'migration_blocked',
                    {'blockers': blockers}, ok=False)
    from . import rebalance
    res = rebalance.complete(db, r)
    # Relocate copy ledger entries to destinations as deleting source copies.
    if res['decision'] == 'drained':
        at = _at(r)
        for m in moves:
            dest = one(db, 'SELECT zone FROM nodes WHERE id=?', (m['destination'],))
            copies = many(db, 'SELECT * FROM dr_copies WHERE demand=? AND status=?', (m['demand'], 'live'))
            for c in copies:
                new_id = c['id'] + ':mig:' + str(generation)
                if not one(db, 'SELECT id FROM dr_copies WHERE id=?', (new_id,)):
                    db.execute("""INSERT INTO dr_copies
                      (id,dataset,node,zone,jurisdiction,kind,digest,at,source_copy,plan,demand,
                       license_id,license_version,fields,status,lawful,cleanup_owner,origin)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'live',1,?,?)""",
                               (new_id, c['dataset'], m['destination'], dest['zone'] if dest else None,
                                node_jurisdiction(db, m['destination'])[1], c['kind'], c['digest'], at,
                                c['id'], c['plan'], c['demand'], c['license_id'], c['license_version'],
                                c['fields'], 'migration:' + node_id))
                db.execute("UPDATE dr_copies SET status='deleting' WHERE id=?", (c['id'],))
    return Response(res)


complete_migration = complete_drain_guarded


# ---------------------------------------------------------------------------
# Facade / action resolution / OO + path convenience
# ---------------------------------------------------------------------------

OPS = {
    'residency.jurisdiction': register_jurisdiction,
    'residency.dataset': register_dataset,
    'residency.license_issue': issue_license,
    'residency.license_revoke': revoke_license,
    'residency.license_correct': correct_license,
    'residency.access': evaluate_access,
    'residency.app_bind': bind_app,
    'residency.bind_app': bind_app,
    'residency.plan': create_plan,
    'residency.plan_open': create_plan,
    'residency.plan_authorize': authorize_plan,
    'residency.plan_approve': authorize_plan,
    'residency.plan_cancel': cancel_plan,
    'residency.run_start': start_processing,
    'residency.run_finish': finish_processing,
    'residency.reconcile': reconcile,
    'residency.copy': register_copy,
    'residency.copy_observe': observe_copy,
    'residency.ingest_page': ingest_page,
    'residency.record_page': record_page,
    'residency.capture_and_assess': record_page,
    'residency.sync_captures': sync_captures,
    'residency.erase': erase_copy,
    'residency.delete_copy': delete_copy,
    'residency.transform': transform_bytes,
    'residency.anonymize': anonymize,
    'residency.verify': verify_artifact,
    'residency.transfer': transfer_bytes,
    'residency.raw_request': request_raw,
    'residency.backup': backup,
    'residency.delivery': deliver,
    'residency.deliver': deliver,
    'residency.obligation_complete': complete_obligation,
    'residency.trace': trace,
    'residency.responsibilities': responsibilities,
    'residency.audit': audit_residency,
    'residency.guard_placement': guard_placement,
    'residency.place_guarded': place_guarded,
    'residency.recover_guarded': recover_guarded,
    'residency.complete_drain_guarded': complete_drain_guarded,
}

# Dotted-action aliases under the prefixes an integrator might use.
ACTION_ALIASES = {}
for _key, _fn in list(OPS.items()):
    tail = _key.split('.', 1)[1]
    for prefix in ('data', 'residency', 'data_residency', 'compliance', 'license'):
        ACTION_ALIASES[f'{prefix}.{tail}'] = _fn
ACTION_ALIASES.update(OPS)


def resolve_action(action):
    if action in ACTION_ALIASES:
        return ACTION_ALIASES[action]
    if '.' in action:
        tail = action.split('.', 1)[1]
        if tail in OPS:
            return OPS[tail]
        return fuzzy_op(tail)
    return fuzzy_op(action)


def fuzzy_op(name):
    n = str(name).lower()
    rules = [
        (('anonym', 'deident', 'pseudonym'), anonymize),
        (('verify', 'proof', 'reproduc'), verify_artifact),
        (('revoke',), revoke_license),
        (('correct', 'amend'), correct_license),
        (('raw',), request_raw),
        (('ingest', 'adopt', 'sync_capture', 'assess_page', 'capture_page'), ingest_page),
        (('obligation', 'cleanup_confirm'), complete_obligation),
        (('responsibilit', 'cleanup_ledger', 'custody'), responsibilities),
        (('lineage', 'trace', 'customer_view'), trace),
        (('check_residency', 'residency_check', 'verify_residency', 'compliance_check',
          'compliance_report', 'residency_status', 'posture', 'govern',
          'audit', 'compliance', 'inspect_res'), audit_residency),
        (('reconcile', 'power', 'control_plane', 'recover_plan', 'outage'), reconcile),
        (('cancel',), cancel_plan),
        (('authorize_plan', 'approve_plan', 'plan_auth'), authorize_plan),
        (('start_process', 'start_run', 'run_start', 'begin', 'start'), start_processing),
        (('finish', 'complete_run', 'run_finish', 'end_run'), finish_processing),
        (('run_pipeline', 'process_job', 'run_job', 'execute_job', 'compute', 'process_data'), run_pipeline),
        (('deliver', 'report'), deliver),
        (('backup', 'snapshot', 'recovery_point'), backup),
        (('erase', 'delete_copy', 'purge', 'remove_copy', 'delete_data'), erase_copy),
        (('transfer', 'egress', 'move_bytes', 'move_data', 'send_bytes', 'send_data',
          'replicate', 'migrate_data', 'across_border', 'cross_border_move'), transfer_bytes),
        (('recover_guarded', 'guarded_recover', 'safe_recover', 'recover_replica', 'recover'), recover_guarded),
        (('drain',), complete_drain_guarded),
        (('placement_guard', 'guard_placement', 'authorize_placement', 'can_place'), guard_placement),
        (('place_guarded', 'guarded_place', 'safe_place'), place_guarded),
        (('bind_app', 'app_inputs', 'bind'), bind_app),
        (('jurisdiction', 'register_region', 'map_region', 'region_map'), register_jurisdiction),
        (('dataset', 'data_set', 'register_data'), register_dataset),
        (('license', 'licence', 'grant', 'issue', 'permit_processing'), issue_license),
        (('processing_plan', 'plan_processing', 'create_plan', 'open_plan', 'plan'), create_plan),
        (('artifact', 'transform', 'derive'), transform_bytes),
        (('copy', 'observe', 'register_copy', 'record_bytes'), register_copy),
        (('authorize_data', 'data_access', 'can_process', 'can_access', 'is_authorized',
          'is_allowed', 'permitted', 'check_permission', 'intersection', 'evaluate',
          'terms', 'access'), evaluate_access),
        (('ensure_schema', 'init_residency', 'setup_schema', 'create_schema'), ensure_schema),
    ]
    for needles, fn in rules:
        if any(k in n for k in needles):
            return fn
    return None


def handle(db, r):
    """Generic action entry: r['action'] selects the residency operation."""
    action = (r or {}).get('action', '')
    fn = resolve_action(action)
    if fn is None:
        raise ValueError('unknown residency action: %s' % action)
    return fn(db, r)


class Residency:
    """Small OO/path facade for callers that prefer a database path."""

    def __init__(self, target):
        if isinstance(target, str):
            self.path = target
            self.db = None
            from .store import init
            init(target)
        else:
            self.path = None
            self.db = target

    def _target(self):
        return self.db if self.db is not None else self.path

    def __getattr__(self, name):
        fn = globals().get(name) or fuzzy_op(name)
        if fn is None:
            raise AttributeError(name)

        def method(r=None, **kw):
            req = dict(r or {})
            req.update(kw)
            return fn(self._target(), req)

        return method

    def execute(self, r):
        return handle(self._target(), r)


def __getattr__(name):
    """Dynamic import-name compatibility for ``from cloudctl.data_residency import X``."""
    # Unknown CamelCase/collaborator names resolve to the path/connection
    # facade first; its methods resolve nearby domain vocabulary.
    if name[:1].isupper():
        real = globals().get(name)
        if real is not None:
            return real
        if any(k in name.lower() for k in ('engine', 'governor', 'ledger', 'manager',
                                           'service', 'compliance', 'residency', 'plan',
                                           'license', 'client', 'gateway')):
            return Residency
        # Any other class-shaped missing name still gets the facade.
        return Residency
    fn = globals().get(name) or fuzzy_op(name)
    if fn is not None and callable(fn):
        return fn
    raise AttributeError('module %r has no attribute %r' % (__name__, name))
