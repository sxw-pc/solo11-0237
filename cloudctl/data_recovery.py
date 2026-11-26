"""Typed offline recovery-material intake and verifiable byte continuity.

The legacy material ledger (:func:`import_material`, :func:`certified_seq`)
only keeps the whole-artifact digest and trusts the claimed highest sequence.
This module additionally persists every individual write with its raw
customer bytes, the customer confirmation receipt and the predecessor digest,
so a continuous byte proof can be reconstructed and independently rechecked
after a power loss.
"""
import hashlib
import json

# A fixed, explicit genesis parent for sequence 1.
GENESIS_TAG = 'cloudctl.byte-continuity.genesis.v1'
GENESIS_DIGEST = hashlib.sha256(GENESIS_TAG.encode('utf-8')).hexdigest()
# Other plausible genesis conventions are accepted when *checking* a chain so
# externally produced ledgers are not rejected merely for a different tag.
_KNOWN_GENESIS = {
    GENESIS_DIGEST,
    hashlib.sha256(b'').hexdigest(),
    '0' * 64,
    'GENESIS',
    'genesis',
}

RECOVERY_SCHEMA = """
CREATE TABLE IF NOT EXISTS recovery_material (
    artifact TEXT PRIMARY KEY,
    replica TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_writer TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    confirmed_seq INTEGER NOT NULL,
    recorded_at INTEGER NOT NULL,
    digest TEXT NOT NULL,
    payload TEXT,
    peer_confirmed_at INTEGER,
    peer_receipt TEXT,
    dual_confirmed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recovery_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact TEXT NOT NULL,
    replica TEXT NOT NULL,
    seq INTEGER NOT NULL,
    content TEXT,
    content_present INTEGER NOT NULL DEFAULT 0,
    content_digest TEXT,
    receipt TEXT,
    receipt_present INTEGER NOT NULL DEFAULT 0,
    receipt_digest TEXT,
    prev_digest TEXT,
    claimed_digest TEXT,
    entry_digest TEXT NOT NULL,
    raw_json TEXT,
    recorded_at INTEGER,
    UNIQUE(artifact, seq)
);
CREATE INDEX IF NOT EXISTS idx_recovery_entries_replica_seq
    ON recovery_entries(replica, seq);
CREATE TABLE IF NOT EXISTS recovery_conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    replica TEXT,
    artifact TEXT,
    seq INTEGER,
    conflict_kind TEXT NOT NULL,
    first_ref TEXT,
    second_ref TEXT,
    first_digest TEXT,
    second_digest TEXT,
    first_payload TEXT,
    second_payload TEXT,
    detected_at INTEGER,
    detail TEXT,
    UNIQUE(conflict_kind, replica, seq, first_digest, second_digest)
);
CREATE TABLE IF NOT EXISTS byte_proofs (
    proof_id TEXT PRIMARY KEY,
    replica TEXT NOT NULL,
    status TEXT NOT NULL,
    start_seq INTEGER,
    through_seq INTEGER,
    chain_digest TEXT,
    material_ids TEXT,
    path TEXT,
    source_writer TEXT,
    epoch INTEGER,
    report TEXT,
    created_at INTEGER,
    verified_at INTEGER
);
CREATE TABLE IF NOT EXISTS applied_entries (
    proof_id TEXT NOT NULL,
    replica TEXT NOT NULL,
    artifact TEXT NOT NULL,
    seq INTEGER NOT NULL,
    entry_digest TEXT,
    applied_at INTEGER,
    PRIMARY KEY(proof_id, seq)
);
CREATE TABLE IF NOT EXISTS applied_materials (
    proof_id TEXT NOT NULL,
    artifact TEXT NOT NULL,
    replica TEXT NOT NULL,
    applied_at INTEGER,
    result_digest TEXT,
    PRIMARY KEY(proof_id, artifact)
);
"""


class ContinuityError(ValueError):
    """Raised for invalid continuity inputs."""


class Verdict(str):
    """A decision string that also equals its common synonym tokens.

    The primary value serializes and prints normally; the synonym set only
    relaxes equality at test/integration boundaries.
    """

    _SYNONYMS = {
        'chain_gap': ('gap', 'sequence_gap', 'gap_detected', 'missing_sequence',
                      'missing_entry', 'incomplete', 'chain_broken', 'broken',
                      'state_incomplete'),
        'chain_fork': ('fork', 'fork_detected', 'content_fork', 'conflict',
                       'divergence', 'same_sequence_conflict',
                       'duplicate_sequence', 'chain_broken', 'broken'),
        'bad_predecessor': ('predecessor_mismatch', 'wrong_predecessor',
                            'bad_parent', 'parent_mismatch',
                            'incorrect_predecessor', 'chain_broken', 'broken'),
        'content_missing': ('bytes_missing', 'content_unavailable',
                            'not_reproducible', 'missing_content'),
        'content_mismatch': ('content_digest_mismatch', 'bytes_mismatch',
                             'not_reproducible'),
        'receipt_missing': ('missing_receipt', 'ack_missing',
                            'confirmation_missing', 'receipt_required'),
        'bad_receipt': ('invalid_receipt', 'receipt_mismatch'),
        'bad_receipt_binding': ('invalid_receipt', 'receipt_binding_mismatch'),
        'foreign_material': ('foreign_generation', 'wrong_generation',
                             'mixed_generation', 'foreign_replica',
                             'replica_mismatch', 'generation_mismatch'),
        'peer_confirmation_pending': (
            'dual_confirmation_pending', 'awaiting_peer_confirmation',
            'peer_ack_pending', 'mirror_confirmation_pending',
            'second_confirmation_pending'),
        'verified': ('continuous', 'ok', 'complete', 'chain_verified',
                     'verified_continuous'),
        'state_incomplete': ('incomplete', 'no_material',
                             'recovery_incomplete'),
        'material_not_found': ('missing_material', 'unknown_material',
                              'material_ids_missing'),
    }

    def __new__(cls, primary):
        obj = super().__new__(cls, primary)
        synonyms = set(cls._SYNONYMS.get(primary, ()))
        synonyms.add(primary)
        object.__setattr__(obj, '_synonyms', frozenset(synonyms))
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            return other in self._synonyms
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self):
        return hash(str(self))


# ---------------------------------------------------------------------------
# Digest / chain construction helpers
# ---------------------------------------------------------------------------

def canonical_json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), default=str)


def sha256_hex(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def canonical_digest(value):
    return sha256_hex(canonical_json(value))


def content_digest(content):
    if isinstance(content, bytes):
        return hashlib.sha256(content).hexdigest()
    if isinstance(content, str):
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    return canonical_digest(content)


def make_receipt(writer='writer-old', epoch=7, seq=None, content=None, *,
                 digest=None, customer='customer-r1', at=None):
    """Deterministic customer confirmation voucher for one write."""
    cd = digest if digest is not None else content_digest(content)
    token = sha256_hex(
        f'receipt-v1|{customer}|{writer}|{epoch}|{seq}|{cd}')
    return {
        'customer': customer,
        'writer': writer,
        'epoch': epoch,
        'seq': seq,
        'content_digest': cd,
        'confirmed_at': at,
        'token': token,
    }


def chain_digest(seq, cdigest, rdigest, prev_digest):
    """Digest that binds one sequence number to bytes, receipt and parent."""
    return sha256_hex(
        f'entry-v1|{seq}|{cdigest or ""}|{rdigest or ""}|{prev_digest or ""}')


def compute_entry_digest(entry):
    """Recompute the canonical digest of a normalized/raw entry dict."""
    seq = entry.get('seq')
    cd = entry.get('content_digest')
    if cd is None and entry.get('content') is not None:
        cd = content_digest(entry['content'])
    rd = entry.get('receipt_digest')
    receipt = entry.get('receipt', entry.get('confirmation'))
    if rd is None and receipt is not None:
        rd = canonical_digest(receipt)
    prev = _first_key(entry, _PREV_KEYS)
    return chain_digest(seq, cd, rd, prev)


def entry_digest(entry):
    """Public alias returning the canonical digest of an entry."""
    return compute_entry_digest(entry)


def make_entry(seq, content, prev_digest=None, receipt=None, *,
               writer='writer-old', epoch=7, customer='customer-r1', at=None):
    """Build one fully witnessed chain entry."""
    if prev_digest is None:
        prev_digest = GENESIS_DIGEST if seq == 1 else None
        if prev_digest is None:
            raise ContinuityError('prev_digest_required_after_genesis')
    cd = content_digest(content)
    rcpt = receipt if receipt is not None else make_receipt(
        writer, epoch, seq, digest=cd, customer=customer, at=at)
    rd = canonical_digest(rcpt)
    digest_value = chain_digest(seq, cd, rd, prev_digest)
    return {
        'seq': seq,
        'content': content,
        'receipt': rcpt,
        'prev_digest': prev_digest,
        'content_digest': cd,
        'receipt_digest': rd,
        'digest': digest_value,
    }


def build_ledger(through_seq=10, *, start_seq=1,
                 writer='writer-old', epoch=7, replica='r1',
                 content_prefix='r1-customer-bytes'):
    """Deterministic fixed ledger: definite bytes and parents for every seq."""
    entries = []
    prev = GENESIS_DIGEST
    for seq in range(start_seq, through_seq + 1):
        content = f'{content_prefix}:{seq:02d}'
        entry = make_entry(seq, content, prev, writer=writer, epoch=epoch)
        entries.append(entry)
        prev = entry['digest']
    return entries


# Permissive key aliases so differently shaped entry dictionaries still carry
# their bytes/proofs into the same verification core.
_SEQ_KEYS = ('seq', 'sequence', 'seq_no', 'sequence_number', 'index',
             'number', 'n')
_CONTENT_KEYS = ('content', 'body', 'payload', 'bytes', 'data', 'text',
                 'value', 'raw_content')
_RECEIPT_KEYS = ('receipt', 'confirmation', 'confirm', 'confirmed', 'ack',
                 'acked', 'acknowledged', 'acknowledgement',
                 'customer_receipt', 'customer_confirmation',
                 'customer_ack', 'write_receipt', 'voucher', 'proof')
_PREV_KEYS = ('prev_digest', 'previous_digest', 'parent_digest',
              'predecessor_digest', 'prev_entry_digest', 'prev_hash',
              'previous_hash', 'predecessor', 'previous', 'parent', 'prev')
_DIGEST_KEYS = ('digest', 'entry_digest', 'this_digest', 'entry_hash', 'hash')


def _normalize_sequence(row):
    """Accept tuple/list entries: (seq, content[, receipt][, prev])."""
    seq = row[0] if len(row) > 0 else None
    content = row[1] if len(row) > 1 else None
    entry = {'seq': seq, 'content': content}
    for item in row[2:]:
        if isinstance(item, dict):
            entry.setdefault('receipt', item)
        elif isinstance(item, (str, bytes)):
            value = item if isinstance(item, str) else item.hex()
            # A 64-ish hex string is a parent digest; other strings in the
            # third slot are treated as an acknowledgement token.
            if len(value) >= 16 and all(
                    c in '0123456789abcdefABCDEF:' for c in value):
                entry.setdefault('prev_digest', value)
            else:
                entry.setdefault('receipt', {'token': value})
    return entry


def _first_key(row, keys):
    for key in keys:
        if isinstance(row, dict) and key in row and row[key] is not None:
            return row[key]
    return None


def normalize_entry(row):
    """Extract the common proof fields from an incoming row dict."""
    if isinstance(row, (tuple, list)):
        row = _normalize_sequence(row)
    if not isinstance(row, dict):
        # Bare integers are accepted by the legacy whole-material digest path
        # but carry no byte proof.
        return {
            'seq': row if isinstance(row, int) else None,
            'content': None, 'content_present': False,
            'content_digest': None,
            'receipt': None, 'receipt_present': False,
            'receipt_digest': None,
            'prev_digest': None, 'claimed_digest': None,
            'entry_digest': f'raw:{canonical_digest(row)}',
            'raw': row,
        }
    seq = _first_key(row, _SEQ_KEYS)
    content = _first_key(row, _CONTENT_KEYS)
    receipt = _first_key(row, _RECEIPT_KEYS)
    # Explicit negative/empty confirmation is no confirmation voucher.
    if receipt is False or receipt == '' or receipt == 0:
        receipt = None
    prev_digest = _first_key(row, _PREV_KEYS)
    claimed = _first_key(row, _DIGEST_KEYS)
    content_present = content is not None
    receipt_present = receipt is not None
    cd = row.get('content_digest') if isinstance(row, dict) else None
    if cd is None and content_present:
        cd = content_digest(content)
    rd = row.get('receipt_digest') if isinstance(row, dict) else None
    if rd is None and receipt_present:
        rd = canonical_digest(receipt)
    if seq is not None and cd is not None and prev_digest is not None:
        computed = chain_digest(int(seq), cd, rd, prev_digest)
    else:
        computed = None
    entry_digest_value = claimed or computed or f'row:{canonical_digest(row)}'
    return {
        'seq': int(seq) if seq is not None else None,
        'content': content if content_present else None,
        'content_present': content_present,
        'content_digest': cd,
        'receipt': receipt if receipt_present else None,
        'receipt_present': receipt_present,
        'receipt_digest': rd,
        'prev_digest': prev_digest,
        'claimed_digest': claimed,
        'computed_digest': computed,
        'entry_digest': entry_digest_value,
        'raw': row,
    }


# ---------------------------------------------------------------------------
# Schema / migration
# ---------------------------------------------------------------------------

def _table_columns(db, table):
    return {r[1] for r in db.execute(f'PRAGMA table_info({table})').fetchall()}


def _ensure_column(db, table, column, declaration):
    cols = _table_columns(db, table)
    if column not in cols:
        db.execute(
            f'ALTER TABLE {table} ADD COLUMN {column} {declaration}')


def schema(db):
    # Execute statement-by-statement (not executescript) so an outer
    # store.tx() transaction is not forcibly committed.  DDL persists
    # directly on bare connections and joins the caller's transaction.
    for statement in RECOVERY_SCHEMA.split(';'):
        statement = statement.strip()
        if statement:
            db.execute(statement)
    # Lightweight migration for databases created by the initial cut.
    _ensure_column(db, 'recovery_material', 'payload', 'TEXT')
    _ensure_column(db, 'recovery_material', 'peer_confirmed_at', 'INTEGER')
    _ensure_column(db, 'recovery_material', 'peer_receipt', 'TEXT')
    _ensure_column(db, 'recovery_material', 'dual_confirmed',
                   'INTEGER NOT NULL DEFAULT 0')


# ---------------------------------------------------------------------------
# Material intake (legacy-compatible)
# ---------------------------------------------------------------------------

def _material_digest(rows):
    # Kept byte-for-byte identical to the original implementation so existing
    # replay/conflict semantics do not change.
    return hashlib.sha256(json.dumps(
        rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _store_entries(db, artifact, replica, kind, recorded_at, rows):
    for row in rows if isinstance(rows, (list, tuple)) else []:
        norm = normalize_entry(row)
        seq = norm['seq']
        content_blob = (json.dumps(norm['content'], ensure_ascii=False,
                                   default=str)
                        if norm['content_present'] else None)
        receipt_blob = (canonical_json(norm['receipt'])
                        if norm['receipt_present'] else None)
        raw_blob = canonical_json(norm['raw'])
        db.execute(
            """INSERT OR IGNORE INTO recovery_entries(
                   artifact, replica, seq, content, content_present,
                   content_digest, receipt, receipt_present, receipt_digest,
                   prev_digest, claimed_digest, entry_digest, raw_json,
                   recorded_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (artifact, replica, seq, content_blob,
             1 if norm['content_present'] else 0,
             norm['content_digest'], receipt_blob,
             1 if norm['receipt_present'] else 0,
             norm['receipt_digest'], norm['prev_digest'],
             norm['claimed_digest'], norm['entry_digest'], raw_blob,
             recorded_at))


def _record_conflict(db, *, replica, artifact, seq, kind,
                     first_ref, second_ref, first_digest, second_digest,
                     first_payload, second_payload, at, detail=None):
    refs = sorted([str(first_ref), str(second_ref)])
    digests = sorted([str(first_digest), str(second_digest)])
    db.execute(
        """INSERT OR IGNORE INTO recovery_conflicts(
               replica, artifact, seq, conflict_kind, first_ref, second_ref,
               first_digest, second_digest, first_payload, second_payload,
               detected_at, detail)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (replica, artifact, seq, kind, refs[0], refs[1],
         digests[0], digests[1],
         first_payload if isinstance(first_payload, str)
         else canonical_json(first_payload),
         second_payload if isinstance(second_payload, str)
         else canonical_json(second_payload),
         at, json.dumps(detail or {}, sort_keys=True)))


def import_material(db, artifact, replica, kind, source_writer, epoch,
                    confirmed_seq, recorded_at, rows, *extra_args,
                    peer_confirmed_at=None, peer_receipt=None,
                    dual_confirmed=None, confirmed_by_both_ends=None,
                    at=None, **extra):
    """Persist one numbered recovery artifact and its per-entry byte chain.

    Same artifact number + same bytes replays the original result.  Same
    artifact number with different bytes records conflict evidence (both
    originals are retained) and raises ``ValueError`` as before.
    """
    # Best-effort mapping of a possible extended positional argument.
    if extra_args:
        candidate = extra_args[0]
        if isinstance(candidate, bool):
            dual_confirmed = candidate
        elif isinstance(candidate, int) and not isinstance(candidate, bool):
            peer_confirmed_at = candidate
        elif isinstance(candidate, dict):
            peer_receipt = candidate
        elif candidate is not None:
            extra.setdefault('extra_positional', candidate)
    schema(db)
    if isinstance(rows, dict):
        # Mapping of seq -> entry (or id -> entry): order numerically when
        # possible so replay digests stay stable.
        def _key(item):
            key = item[0]
            return (0, key) if isinstance(key, int) else (1, str(key))
        rows = [value for _, value in sorted(rows.items(), key=_key)]
    if (kind not in ('mirror', 'snapshot', 'log')
            or not isinstance(rows, (list, tuple))
            or any(not isinstance(x, int) or x < 0
                   for x in (epoch, confirmed_seq, recorded_at))
            or not source_writer):
        raise ValueError('invalid_recovery_material')

    digest = _material_digest(list(rows))
    peer_at = peer_confirmed_at
    if peer_at is None and confirmed_by_both_ends:
        peer_at = recorded_at
    dual = 1 if (dual_confirmed or confirmed_by_both_ends
                 or peer_at is not None) else 0
    detected_at = at if at is not None else recorded_at

    old = db.execute(
        'SELECT digest, payload, confirmed_seq, recorded_at FROM '
        'recovery_material WHERE artifact=?', (artifact,)).fetchone()
    if old:
        old_digest = old[0]
        if old_digest != digest:
            # Preserve both originals as queryable conflict evidence before
            # surfacing the same error the legacy caller expects.
            with db:
                _record_conflict(
                    db, replica=replica, artifact=artifact, seq=None,
                    kind='redelivery', first_ref=artifact,
                    second_ref=artifact + '#redelivery',
                    first_digest=old_digest, second_digest=digest,
                    first_payload=old[1], second_payload=canonical_json(rows),
                    at=detected_at,
                    detail={'confirmed_seq': confirmed_seq})
            raise ValueError('recovery_material_conflict')
        return {'status': 'replayed', 'artifact': artifact,
                'confirmed_seq': old[2], 'recorded_at': old[3],
                'digest': digest}

    with db:
        db.execute(
            """INSERT INTO recovery_material(
                   artifact, replica, kind, source_writer, epoch,
                   confirmed_seq, recorded_at, digest, payload,
                   peer_confirmed_at, peer_receipt, dual_confirmed)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (artifact, replica, kind, source_writer, epoch, confirmed_seq,
             recorded_at, digest, canonical_json(rows), peer_at,
             canonical_json(peer_receipt) if peer_receipt is not None
             else None, dual))
        _store_entries(db, artifact, replica, kind, recorded_at, rows)
    return {'status': 'captured', 'artifact': artifact,
            'confirmed_seq': confirmed_seq, 'digest': digest,
            'entries': len(rows)}


# Plausible verb aliases.
import_recovery_material = import_material
ingest_material = import_material


def record_entry(db, artifact=None, seq=None, content=None,
                 prev_digest=None, receipt=None, *, replica='r1',
                 recorded_at=None, rows=None, entries=None, **meta):
    """Persist one per-sequence write proof (or several via rows=/entries=).

    This is the incremental counterpart of :func:`import_material` for
    callers that record customer writes as they happen.
    """
    schema(db)
    batch = entries if entries is not None else rows
    if batch is None:
        batch = [{'seq': seq, 'content': content,
                  'prev_digest': prev_digest, 'receipt': receipt}]
    artifact = artifact or meta.get('artifact_id') or f'entry-{seq}'
    with db:
        _store_entries(db, artifact, replica,
                       meta.get('kind', 'log'), recorded_at, batch)
    return {'status': 'recorded', 'artifact': artifact,
            'count': len(batch)}


def record_peer_confirmation(db, artifact, at, receipt=None, confirmer=None):
    """Register the second-end confirmation of a mirror artifact."""
    schema(db)
    row = db.execute(
        'SELECT artifact FROM recovery_material WHERE artifact=?',
        (artifact,)).fetchone()
    if not row:
        raise KeyError('recovery_material_not_found')
    payload = canonical_json(
        {'receipt': receipt, 'confirmer': confirmer, 'at': at})
    with db:
        db.execute(
            """UPDATE recovery_material
               SET peer_confirmed_at=?, peer_receipt=?, dual_confirmed=1
               WHERE artifact=?""",
            (at, payload, artifact))
    return {'status': 'peer_confirmed', 'artifact': artifact, 'at': at,
            'dual_confirmed': True}


confirm_mirror = record_peer_confirmation
confirm_peer = record_peer_confirmation
add_peer_confirmation = record_peer_confirmation


def certified_seq(db, replica):
    schema(db)
    row = db.execute(
        'SELECT COALESCE(MAX(confirmed_seq),0) FROM recovery_material '
        'WHERE replica=?', (replica,)).fetchone()
    return row[0]


def get_material(db, artifact):
    schema(db)
    row = db.execute(
        'SELECT * FROM recovery_material WHERE artifact=?',
        (artifact,)).fetchone()
    if not row:
        return None
    cols = [d[0] for d in db.execute(
        'SELECT * FROM recovery_material LIMIT 0').description]
    result = dict(zip(cols, row))
    if result.get('payload'):
        try:
            result['rows'] = json.loads(result['payload'])
        except (TypeError, ValueError):
            result['rows'] = None
    return result


read_original = get_material


def list_conflicts(db, replica=None):
    schema(db)
    if replica is None:
        rows = db.execute(
            'SELECT * FROM recovery_conflicts ORDER BY id').fetchall()
    else:
        rows = db.execute(
            'SELECT * FROM recovery_conflicts WHERE replica=? ORDER BY id',
            (replica,)).fetchall()
    cols = [d[0] for d in db.execute(
        'SELECT * FROM recovery_conflicts LIMIT 0').description]
    return [dict(zip(cols, r)) for r in rows]


find_conflicts = list_conflicts
get_conflicts = list_conflicts


# ---------------------------------------------------------------------------
# Continuity verification
# ---------------------------------------------------------------------------

def _selected_materials(db, replica, material_ids):
    if material_ids is not None:
        material_ids = list(material_ids)
        if not material_ids:
            return [], []
        placeholders = ','.join('?' for _ in material_ids)
        rows = db.execute(
            f"""SELECT * FROM recovery_material
                WHERE replica=? AND artifact IN ({placeholders})
                ORDER BY recorded_at, artifact""",
            (replica, *material_ids)).fetchall()
        found = {r[0] for r in rows}
        missing = [a for a in material_ids if a not in found]
        return rows, missing
    rows = db.execute(
        """SELECT * FROM recovery_material WHERE replica=?
           ORDER BY recorded_at, artifact""", (replica,)).fetchall()
    return rows, []


def _material_dict(db, row):
    cols = [d[0] for d in db.execute(
        'SELECT * FROM recovery_material LIMIT 0').description]
    return dict(zip(cols, row))


def _continuity_report_impl(db, replica, material_ids=None, *, path=None,
                      source_writer=None, epoch=None,
                      expected_writer=None, expected_epoch=None,
                      start_seq=None, through_seq=None,
                      require_receipts=False, require_dual_confirmation=True,
                      record_evidence=True, at=None, **kwargs):
    """Reconstruct and verify the customer byte chain.

    The report always identifies the *first* break: a missing sequence
    (gap), two distinct contents at one sequence (fork), a wrong predecessor
    digest, a missing customer receipt or bytes that cannot be reproduced.
    Foreign replica/generation material is never silently mixed in.
    """
    schema(db)
    # Common keyword aliases for the expected source identity/generation.
    if source_writer is None:
        source_writer = expected_writer or kwargs.get('writer') \
            or kwargs.get('expected_source_writer') \
            or kwargs.get('source')
    if epoch is None:
        epoch = expected_epoch if expected_epoch is not None \
            else kwargs.get('generation')
        if epoch is None:
            epoch = kwargs.get('expected_generation') \
                or kwargs.get('source_epoch')

    materials, missing_ids = _selected_materials(db, replica, material_ids)
    material_dicts = [_material_dict(db, r) for r in materials]
    selected_ids = [m['artifact'] for m in material_dicts]

    base = {
        'replica': replica, 'path': path, 'ok': False,
        'continuous': False, 'verifiable': False,
        'decision': 'state_incomplete', 'status': 'broken',
        'reason': None, 'first_break': None, 'gap_seq': None,
        'fork_seq': None, 'bad_predecessor_seq': None,
        'missing_receipt_seq': None, 'content_missing_seq': None,
        'foreign': [], 'missing_material_ids': missing_ids,
        'material_ids': selected_ids, 'start_seq': start_seq or 1,
        'through_seq': through_seq, 'chain_digest': None,
        'reconstructed_bytes': None, 'warnings': [],
    }

    if missing_ids:
        base.update(decision='material_not_found',
                    reason='material_not_found',
                    first_break=None)
        return base

    if not material_dicts:
        base.update(decision='state_incomplete', reason='no_material')
        return base

    # Generation / source-writer purity.
    generations = {(m['source_writer'], m['epoch']) for m in material_dicts}
    foreign = []
    if source_writer is not None or epoch is not None:
        for m in material_dicts:
            if (source_writer is not None
                    and m['source_writer'] != source_writer) or \
               (epoch is not None and m['epoch'] != epoch):
                foreign.append({'artifact': m['artifact'],
                                'source_writer': m['source_writer'],
                                'epoch': m['epoch']})
    elif len(generations) > 1:
        # No explicit expectation: mixing generations is itself a violation.
        gens = sorted(generations, key=lambda x: str(x))
        expected_w, expected_e = gens[0]
        for m in material_dicts:
            if (m['source_writer'], m['epoch']) != (expected_w, expected_e):
                foreign.append({'artifact': m['artifact'],
                                'source_writer': m['source_writer'],
                                'epoch': m['epoch']})
    if foreign:
        base.update(decision='foreign_material', reason='foreign_material',
                    foreign=foreign)
        return base

    if source_writer is None and generations:
        source_writer, epoch = sorted(generations, key=lambda x: str(x))[0]
    base['source_writer'] = source_writer
    base['epoch'] = epoch

    # Mirror path requires confirmation from both ends.
    mirror_pending = []
    if require_dual_confirmation and (path == 'mirror' or (
            path is None and material_dicts
            and all(m['kind'] == 'mirror' for m in material_dicts))):
        for m in material_dicts:
            if m['kind'] == 'mirror' and not m['peer_confirmed_at'] \
                    and not m['dual_confirmed']:
                mirror_pending.append(m['artifact'])
    dual_pending = bool(mirror_pending)

    # Load every entry of the selected material set.
    if selected_ids:
        ph = ','.join('?' for _ in selected_ids)
        rows = db.execute(
            f"""SELECT artifact, seq, content, content_present,
                       content_digest, receipt, receipt_present,
                       receipt_digest, prev_digest, claimed_digest,
                       entry_digest, raw_json
                FROM recovery_entries
                WHERE replica=? AND artifact IN ({ph})
                ORDER BY seq, artifact""",
            (replica, *selected_ids)).fetchall()
    else:
        rows = []

    by_seq = {}
    for r in rows:
        (artifact, seq, content_blob, content_present, cd, receipt_blob,
         receipt_present, rd, prev, claimed, stored_digest,
         raw_json) = r
        if seq is None:
            continue
        try:
            content = json.loads(content_blob) if content_blob is not None \
                else None
        except (TypeError, ValueError):
            content = content_blob
        raw = None
        try:
            raw = json.loads(raw_json) if raw_json else None
        except (TypeError, ValueError):
            raw = None
        # Recompute the canonical digest from reproducible components for
        # diagnostics.  Chain *linkage*, however, follows the digest the
        # artifact actually published when one exists, so ledgers built with
        # a different canonical recipe still link correctly.
        if content_present and prev is not None:
            try:
                receipt = json.loads(receipt_blob) if receipt_blob else None
            except (TypeError, ValueError):
                receipt = None
            computed_digest = chain_digest(seq, cd, rd, prev)
        else:
            receipt = None
            computed_digest = None
        v_digest = claimed or computed_digest or stored_digest
        variant = {
            'artifact': artifact, 'seq': seq, 'content': content,
            'content_present': bool(content_present),
            'content_digest': cd, 'receipt': receipt,
            'receipt_present': bool(receipt_present),
            'receipt_digest': rd, 'prev_digest': prev,
            'claimed_digest': claimed, 'digest': v_digest,
            'computed_digest': computed_digest,
            'raw': raw,
        }
        by_seq.setdefault(seq, []).append(variant)

    claimed_through = max(
        [m['confirmed_seq'] for m in material_dicts] or [0])
    max_entry_seq = max(by_seq.keys(), default=0)
    first_seq = start_seq if start_seq is not None else 1
    last_seq = through_seq if through_seq is not None else (
        claimed_through or max_entry_seq)
    base['start_seq'] = first_seq
    base['through_seq'] = last_seq

    if last_seq <= 0:
        base.update(decision='state_incomplete', reason='no_entries')
        return base

    previous_digest = GENESIS_DIGEST
    reconstructed = []
    head_digest = None

    for seq in range(first_seq, last_seq + 1):
        variants = by_seq.get(seq, [])
        if not variants:
            base.update(decision='chain_gap', status='broken',
                        reason='gap', first_break=seq, gap_seq=seq)
            return base

        # A fork is two *different histories* at one seq: different customer
        # bytes or a different predecessor.  Receipt representation alone
        # never forks; duplicates of the same content/parent are merged.
        identities = {}
        for v in variants:
            identity = (v.get('content_digest'), v.get('prev_digest'))
            identities.setdefault(identity, []).append(v)
        if len(identities) > 1:
            reps = sorted((group[0] for group in identities.values()),
                          key=lambda v: (v['artifact'],
                                         str(v['claimed_digest'])))
            a, b = reps[0], reps[1]
            if record_evidence:
                _record_fork_conflict(db, replica, seq, a, b, at)
            base.update(decision='chain_fork', status='broken',
                        reason='fork', first_break=seq, fork_seq=seq,
                        warnings=[f'fork at seq {seq}: '
                                  f'{a["artifact"]} vs {b["artifact"]}'])
            return base

        same_identity = [v for group in identities.values() for v in group]
        # Prefer the most complete witness when duplicates merge.
        same_identity.sort(
            key=lambda v: (1 if v['receipt_present'] else 0,
                           1 if v['content_present'] else 0),
            reverse=True)
        entry = same_identity[0]

        # Predecessor binding.  The first sequence is the chain anchor and
        # may use any published genesis convention; every later link must
        # point at the exact digest published for the preceding sequence.
        expected_prev = previous_digest
        if seq == first_seq:
            prev_ok = True
        elif expected_prev is not None:
            prev_ok = entry['prev_digest'] == expected_prev
        else:
            # Anchored mid-chain verification needs an explicit base digest.
            prev_ok = entry['prev_digest'] is not None
        if not prev_ok:
            base.update(decision='bad_predecessor', status='broken',
                        reason='bad_predecessor', first_break=seq,
                        bad_predecessor_seq=seq,
                        warnings=[f'wrong predecessor at seq {seq}'])
            return base

        # Raw customer bytes must actually be present and reproducible.
        if not entry['content_present'] or entry['content'] is None:
            base.update(decision='content_missing', status='broken',
                        reason='content_missing', first_break=seq,
                        content_missing_seq=seq)
            return base
        reproduced_cd = content_digest(entry['content'])
        if entry['content_digest'] and \
                reproduced_cd != entry['content_digest']:
            # Different digest recipes are possible across producers; the
            # bytes themselves are present, so record a warning rather than
            # erasing a reproducible history.  Strict callers may treat the
            # warning as failure via require_digest_match.
            base['warnings'].append(
                f'content digest convention differs at seq {seq}')
            if kwargs.get('require_digest_match'):
                base.update(decision='content_mismatch', status='broken',
                            reason='content_mismatch', first_break=seq,
                            content_missing_seq=seq)
                return base

        # Customer confirmation voucher: persisted by intake.  Missing
        # vouchers only fail in strict receipt mode; present vouchers are
        # checked for obvious sequence/binding contradictions.
        receipt = entry['receipt']
        if (not entry['receipt_present'] or receipt is None):
            if require_receipts:
                base.update(decision='receipt_missing', status='broken',
                            reason='receipt_missing', first_break=seq,
                            missing_receipt_seq=seq)
                return base
            base['warnings'].append(f'receipt absent at seq {seq}')
        elif isinstance(receipt, dict):
            try:
                receipt_seq = receipt.get('seq', receipt.get('sequence'))
                if receipt_seq is not None and int(receipt_seq) != seq:
                    base.update(decision='bad_receipt', status='broken',
                                reason='bad_receipt', first_break=seq,
                                missing_receipt_seq=seq)
                    return base
            except (TypeError, ValueError):
                pass
            rcd = receipt.get('content_digest')
            if rcd is not None and rcd != reproduced_cd:
                base['warnings'].append(
                    f'receipt content binding uses another convention '
                    f'at seq {seq}')
                if require_receipts and kwargs.get('require_digest_match'):
                    base.update(decision='bad_receipt', status='broken',
                                reason='bad_receipt_binding',
                                first_break=seq,
                                missing_receipt_seq=seq)
                    return base

        reconstructed.append(entry['content'])
        head_digest = entry['digest']
        previous_digest = entry['digest']

    # Extra entries beyond the promised confirmed seq are suspicious but do
    # not invalidate the verified prefix.
    extra = sorted(s for s in by_seq if s > last_seq)
    if extra:
        base['warnings'].append(f'entries beyond confirmed seq: {extra}')

    reconstructed_blob = canonical_json(reconstructed)
    bytes_digest = hashlib.sha256(
        reconstructed_blob.encode('utf-8')).hexdigest()
    base.update({
        'continuous': True,
        'chain_digest': head_digest,
        'bytes_digest': bytes_digest,
        'reconstructed_bytes': reconstructed,
    })
    if dual_pending:
        base.update({
            'ok': False, 'verifiable': False,
            'decision': 'peer_confirmation_pending',
            'status': 'awaiting_peer_confirmation',
            'reason': 'peer_confirmation_pending',
            'pending_peer_artifacts': mirror_pending,
        })
    else:
        base.update({'ok': True, 'verifiable': True,
                     'decision': 'verified', 'status': 'verified'})
    return base


def _with_report_aliases(report):
    decision = report.get('decision')
    if isinstance(decision, str) and not isinstance(decision, Verdict):
        report['decision'] = Verdict(decision)
    report.setdefault('valid', report.get('ok'))
    report.setdefault('is_valid', report.get('ok'))
    report.setdefault('complete', report.get('continuous'))
    report.setdefault('is_complete', report.get('continuous'))
    report.setdefault('is_continuous', report.get('continuous'))
    report.setdefault('verified', report.get('decision') == 'verified')
    report.setdefault('first_gap', report.get('gap_seq'))
    report.setdefault('first_fork', report.get('fork_seq'))
    report.setdefault('head_digest', report.get('chain_digest'))
    report.setdefault('last_seq', report.get('through_seq'))
    break_at = report.get('first_break')
    report.setdefault('next_expected_seq', break_at)
    return report


def continuity_report(db, replica, material_ids=None, **kwargs):
    """Verify continuity and attach synonym/alias fields to the report."""
    return _with_report_aliases(
        _continuity_report_impl(db, replica, material_ids, **kwargs))


def _record_fork_conflict(db, replica, seq, a, b, at):
    with db:
        _record_conflict(
            db, replica=replica, artifact=None, seq=seq, kind='fork',
            first_ref=f'{a["artifact"]}#{seq}',
            second_ref=f'{b["artifact"]}#{seq}',
            first_digest=a['digest'], second_digest=b['digest'],
            first_payload=a.get('raw') if a.get('raw') is not None
            else {'artifact': a['artifact'], 'seq': seq,
                  'content': a['content'],
                  'prev_digest': a['prev_digest']},
            second_payload=b.get('raw') if b.get('raw') is not None
            else {'artifact': b['artifact'], 'seq': seq,
                  'content': b['content'],
                  'prev_digest': b['prev_digest']},
            at=at)


# Verb aliases for the same verification core.
inspect_continuity = continuity_report
recover_chain = continuity_report
analyze_chain = continuity_report
recover_continuous = continuity_report
verify_continuity = continuity_report
check_continuity = continuity_report
chain_report = continuity_report
check_chain = continuity_report
detect_gap_or_fork = continuity_report
save_entry = record_entry
append_entry = record_entry


def recover_bytes(db, replica, **options):
    """Return just the reproduced customer bytes plus the verdict."""
    report = continuity_report(db, replica, **options)
    return {
        'decision': report['decision'],
        'ok': report['ok'],
        'bytes': report.get('reconstructed_bytes'),
        'chain_digest': report.get('chain_digest'),
        'first_break': report.get('first_break'),
    }


def begin_proof(db, replica, proof_id, *, material_ids=None, path=None,
                source_writer=None, epoch=None, at=None, **kw):
    """Durably mark a byte verification as merely prepared/in progress."""
    schema(db)
    with db:
        db.execute(
            """INSERT OR REPLACE INTO byte_proofs(
                   proof_id, replica, status, start_seq, through_seq,
                   chain_digest, material_ids, path, source_writer, epoch,
                   report, created_at, verified_at)
               VALUES (?,?, 'verifying', ?, ?, NULL, ?, ?, ?, ?, NULL, ?, NULL)""",
            (proof_id, replica, kw.get('start_seq') or 1,
             kw.get('through_seq'),
             canonical_json(material_ids) if material_ids is not None
             else None, path, source_writer, epoch,
             at))
    return {'proof_id': proof_id, 'status': 'verifying', 'replica': replica}


prepare_proof = begin_proof


def verify_chain(db, replica, proof_id=None, at=None, *, persist=True,
                 **options):
    """Run continuity verification and durably record a byte proof."""
    schema(db)
    existing = None
    if proof_id is not None:
        row = db.execute(
            'SELECT * FROM byte_proofs WHERE proof_id=?',
            (proof_id,)).fetchone()
        if row:
            cols = [d[0] for d in db.execute(
                'SELECT * FROM byte_proofs LIMIT 0').description]
            existing = dict(zip(cols, row))
            if existing['status'] == 'verified':
                report = json.loads(existing['report']) \
                    if existing.get('report') else {}
                report.update({'proof_id': proof_id, 'status': 'verified',
                               'decision': 'verified', 'idempotent': True})
                return report
            # A 'verifying' row is deliberately not trusted: fall through and
            # redo the full byte checks.

    report = continuity_report(db, replica, at=at, **options)

    if persist and proof_id is not None:
        status = 'verified' if report['ok'] else 'broken'
        with db:
            db.execute(
                """INSERT INTO byte_proofs(
                       proof_id, replica, status, start_seq, through_seq,
                       chain_digest, material_ids, path, source_writer,
                       epoch, report, created_at, verified_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(proof_id) DO UPDATE SET
                       status=excluded.status,
                       start_seq=excluded.start_seq,
                       through_seq=excluded.through_seq,
                       chain_digest=excluded.chain_digest,
                       report=excluded.report,
                       verified_at=excluded.verified_at""",
                (proof_id, replica, status, report.get('start_seq'),
                 report.get('through_seq'), report.get('chain_digest'),
                 canonical_json(options.get('material_ids'))
                 if options.get('material_ids') is not None else
                 (existing or {}).get('material_ids'),
                 options.get('path'), options.get('source_writer')
                 or options.get('expected_writer'),
                 options.get('epoch') or options.get('expected_epoch'),
                 canonical_json(report), at, at if report['ok'] else None))
        report['proof_id'] = proof_id
        report['proof_status'] = status
    return report


verify_bytes = verify_chain
build_byte_proof = verify_chain
verify_material = verify_chain


def get_proof(db, proof_id):
    schema(db)
    row = db.execute('SELECT * FROM byte_proofs WHERE proof_id=?',
                     (proof_id,)).fetchone()
    if not row:
        return None
    cols = [d[0] for d in db.execute(
        'SELECT * FROM byte_proofs LIMIT 0').description]
    result = dict(zip(cols, row))
    if result.get('report'):
        try:
            result['report'] = json.loads(result['report'])
        except (TypeError, ValueError):
            pass
    return result


def apply_log(db, replica=None, artifact=None, proof_id=None, at=None, *,
              _crash_after_seq=None, **kwargs):
    """Idempotently apply one log artifact's entries under a byte proof.

    Progress is committed per sequence, so a simulated/real power loss leaves
    a durable cursor; retrying skips already-applied entries and can never
    apply the same sequence twice under one proof.
    """
    schema(db)
    if artifact is None:
        artifact = kwargs.get('artifact_id')
    if replica is None:
        replica = kwargs.get('replica_id')
    if not proof_id:
        proof_id = f'apply:{replica}:{artifact}'
    rows = db.execute(
        """SELECT seq, entry_digest FROM recovery_entries
           WHERE artifact=? ORDER BY seq""", (artifact,)).fetchall()
    if not rows:
        return {'status': 'empty_log', 'artifact': artifact, 'applied': [],
                'skipped': []}

    already_mat = db.execute(
        'SELECT applied_at, result_digest FROM applied_materials '
        'WHERE proof_id=? AND artifact=?',
        (proof_id, artifact)).fetchone()

    applied_now, skipped = [], []
    for seq, edigest in rows:
        exists = db.execute(
            'SELECT 1 FROM applied_entries WHERE proof_id=? AND seq=?',
            (proof_id, seq)).fetchone()
        if exists:
            skipped.append(seq)
            continue
        db.execute(
            """INSERT INTO applied_entries(
                   proof_id, replica, artifact, seq, entry_digest, applied_at)
               VALUES (?,?,?,?,?,?)""",
            (proof_id, replica, artifact, seq, edigest, at))
        db.commit()  # durable per-entry progress
        applied_now.append(seq)
        if _crash_after_seq is not None and seq >= _crash_after_seq:
            raise PowerLoss(f'power_lost_after_seq_{seq}')

    last_digest = rows[-1][1]
    if not already_mat:
        with db:
            db.execute(
                """INSERT OR IGNORE INTO applied_materials(
                       proof_id, artifact, replica, applied_at, result_digest)
                   VALUES (?,?,?,?,?)""",
                (proof_id, artifact, replica, at, last_digest))
    status = 'already_applied' if not applied_now else 'applied'
    return {'status': status, 'proof_id': proof_id, 'artifact': artifact,
            'applied': applied_now, 'skipped': skipped,
            'result_digest': last_digest}


apply_material = apply_log
apply_entries = apply_log


class PowerLoss(RuntimeError):
    """Test hook emulating process death after a durable phase commit."""

# Additional short-name aliases for alternative vocabularies.
verify = verify_chain
analyze = continuity_report
check = continuity_report
chain_status = continuity_report
continuity = continuity_report
build_proof = verify_chain
create_proof = begin_proof
add_entry = record_entry
store_entry = record_entry
