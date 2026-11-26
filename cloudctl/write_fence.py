"""Write-authority handoff over a verified byte chain.

The legacy :func:`claim` keeps its max-sequence behaviour for the original
seed test.  The continuous-recovery flow is an explicit, durable state
machine::

    prepared -> verified -> sealed -> installed -> issued

Every transition is its own committed transaction.  Reopening a database
after power loss can therefore tell a merely ``prepared`` handoff from one
that has reached the committed/``issued`` state, and :func:`resume_handoff`
continues from the durable phase without skipping byte verification.

The old writer epoch is sealed irreversibly before the new fence number is
issued; late old-writer acknowledgements or writes can never regain authority.
"""
import json

from .data_recovery import (
    PowerLoss,
    begin_proof,
    certified_seq,
    continuity_report,
    get_proof,
    schema as recovery_schema,
    verify_chain,
)

FENCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS writer_fences (
    replica TEXT PRIMARY KEY,
    fence_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    required_seq INTEGER NOT NULL,
    target_writer TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'issued',
    handoff_id TEXT
);
CREATE TABLE IF NOT EXISTS writer_seals (
    replica TEXT PRIMARY KEY,
    old_writer TEXT,
    old_epoch INTEGER,
    proof_id TEXT,
    sealed_at INTEGER NOT NULL,
    irreversible INTEGER NOT NULL DEFAULT 1,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS fence_handoffs (
    handoff_id TEXT PRIMARY KEY,
    replica TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    fence_id TEXT NOT NULL,
    target_writer TEXT NOT NULL,
    path TEXT,
    proof_id TEXT,
    material_ids TEXT,
    old_writer TEXT,
    old_epoch INTEGER,
    status TEXT NOT NULL,
    request_key TEXT,
    prepared_at INTEGER,
    verified_at INTEGER,
    sealed_at INTEGER,
    installed_at INTEGER,
    issued_at INTEGER,
    target_receipt TEXT,
    target_receipt_at INTEGER,
    target_receipt_state TEXT,
    superseded_by TEXT,
    mirror_slot TEXT,
    chain_digest TEXT,
    bytes_digest TEXT,
    through_seq INTEGER,
    last_report TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_fence_handoffs_replica
    ON fence_handoffs(replica, epoch);
CREATE TABLE IF NOT EXISTS handoff_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    handoff_id TEXT NOT NULL,
    replica TEXT,
    at INTEGER,
    phase TEXT NOT NULL,
    decision TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS mirror_slot_occupancy (
    slot INTEGER PRIMARY KEY CHECK(slot = 1),
    occupied_by_proof TEXT,
    handoff_id TEXT,
    occupied_at INTEGER
);
"""

# Durable phase order.  "issued" is the only committed executable state.
PHASES = ('prepared', 'verified', 'sealed', 'installed', 'issued')
_ACTIVE_STATUSES = ('prepared', 'verifying', 'verified', 'sealed',
                    'installed')
_DEAD_STATUSES = ('cancelled', 'superseded', 'invalidated')


def _columns(db, table):
    return {r[1] for r in db.execute(f'PRAGMA table_info({table})').fetchall()}


def _ensure_column(db, table, column, declaration):
    if column not in _columns(db, table):
        db.execute(
            f'ALTER TABLE {table} ADD COLUMN {column} {declaration}')


def schema(db):
    recovery_schema(db)
    for statement in FENCE_SCHEMA.split(';'):
        statement = statement.strip()
        if statement:
            db.execute(statement)
    _ensure_column(db, 'writer_fences', 'status',
                   "TEXT NOT NULL DEFAULT 'issued'")
    _ensure_column(db, 'writer_fences', 'handoff_id', 'TEXT')


def _event(db, handoff_id, replica, at, phase, decision=None, detail=None):
    db.execute(
        """INSERT INTO handoff_events(
               handoff_id, replica, at, phase, decision, detail)
           VALUES (?,?,?,?,?,?)""",
        (handoff_id, replica, at, phase, decision,
         json.dumps(detail or {}, sort_keys=True, default=str)))


def _handoff_dict(db, row):
    cols = [d[0] for d in db.execute(
        'SELECT * FROM fence_handoffs LIMIT 0').description]
    return dict(zip(cols, row))


def get_handoff(db, handoff_id):
    schema(db)
    row = db.execute('SELECT * FROM fence_handoffs WHERE handoff_id=?',
                     (handoff_id,)).fetchone()
    return _handoff_dict(db, row) if row else None


handoff_status = get_handoff


def latest_handoff(db, replica, epoch=None):
    schema(db)
    if epoch is None:
        row = db.execute(
            'SELECT * FROM fence_handoffs WHERE replica=? '
            'ORDER BY prepared_at DESC, rowid DESC LIMIT 1',
            (replica,)).fetchone()
    else:
        row = db.execute(
            'SELECT * FROM fence_handoffs WHERE replica=? AND epoch=? '
            'ORDER BY prepared_at DESC, rowid DESC LIMIT 1',
            (replica, epoch)).fetchone()
    return _handoff_dict(db, row) if row else None


# ---------------------------------------------------------------------------
# Legacy coarse claim (unchanged decision contract)
# ---------------------------------------------------------------------------

def claim(db, replica, required_seq, new_epoch, target_writer, at, *,
          material_ids=None, proof_id=None, strict=None,
          old_writer=None, old_epoch=None, **kwargs):
    schema(db)
    # An irreversible seal fences the old identity/generation even through
    # the legacy coarse entry point.
    seal = get_seal(db, replica)
    if seal is not None:
        if (seal.get('old_writer') is not None
                and target_writer == seal['old_writer']) or (
                    seal.get('old_epoch') is not None
                    and new_epoch <= seal['old_epoch']):
            return {'decision': 'old_writer_sealed', 'replica': replica,
                    'epoch': new_epoch, 'target_writer': target_writer}
    if certified_seq(db, replica) < required_seq:
        return {'decision': 'state_incomplete', 'replica': replica}

    # When per-entry customer bytes/receipts exist, a max-sequence claim is
    # no longer enough: require a continuous byte proof.  Coarse legacy
    # artifacts (digest-only seed rows) keep the original max-seq behaviour.
    rich = db.execute(
        'SELECT COUNT(*) FROM recovery_entries WHERE replica=? '
        'AND content_present=1', (replica,)).fetchone()[0]
    if proof_id is not None:
        proof = get_proof(db, proof_id)
        if proof is None or proof['status'] != 'verified':
            return {'decision': 'proof_incomplete', 'replica': replica,
                    'proof_id': proof_id}
    if strict is True or (rich and strict is not False):
        if rich or material_ids is not None or proof_id is not None \
                or strict is True:
            report = continuity_report(
                db, replica, material_ids=material_ids, at=at,
                through_seq=required_seq,
                require_dual_confirmation=False,
                expected_writer=old_writer
                or (seal or {}).get('old_writer'),
                expected_epoch=old_epoch
                if old_epoch is not None else (seal or {}).get('old_epoch'))
            if not report.get('ok'):
                return {'decision': report.get('decision',
                                                'state_incomplete'),
                        'state': 'state_incomplete', 'replica': replica,
                        'first_break': report.get('first_break'),
                        'reason': report.get('reason'),
                        'report': report}
            # Seal the source generation before delivering the new number.
            if seal is None:
                src_writer = old_writer or report.get('source_writer')
                src_epoch = old_epoch if old_epoch is not None \
                    else report.get('epoch')
                db.execute(
                    """INSERT OR IGNORE INTO writer_seals(
                           replica, old_writer, old_epoch, proof_id,
                           sealed_at, irreversible, detail)
                       VALUES (?,?,?,?,?,1,'{"via":"claim"}')""",
                    (replica, src_writer, src_epoch, proof_id, at))

    old = db.execute(
        'SELECT epoch FROM writer_fences WHERE replica=? AND status=?',
        (replica, 'issued')).fetchone()
    if old and new_epoch <= old[0]:
        return {'decision': 'stale_epoch', 'replica': replica}
    fence_id = f'{replica}:{new_epoch}'
    with db:
        db.execute(
            """INSERT INTO writer_fences(
                   replica, fence_id, epoch, required_seq, target_writer,
                   issued_at, status, handoff_id)
               VALUES (?,?,?,?,?,?, 'issued', NULL)
               ON CONFLICT(replica) DO UPDATE SET
                   fence_id=excluded.fence_id,
                   epoch=excluded.epoch,
                   required_seq=excluded.required_seq,
                   target_writer=excluded.target_writer,
                   issued_at=excluded.issued_at,
                   status='issued',
                   handoff_id=NULL""",
            (replica, fence_id, new_epoch, required_seq,
             target_writer, at))
    return {'decision': 'granted', 'replica': replica,
            'fence_id': fence_id, 'epoch': new_epoch}


# ---------------------------------------------------------------------------
# Executable authority lookup
# ---------------------------------------------------------------------------

def active_fence(db, replica):
    """Return the executable issued fence, ignoring prepared/provisional rows."""
    schema(db)
    row = db.execute(
        """SELECT replica, fence_id, epoch, required_seq, target_writer,
                  issued_at, status, handoff_id
           FROM writer_fences
           WHERE replica=? AND status='issued'""",
        (replica,)).fetchone()
    if not row:
        return None
    keys = ('replica', 'fence_id', 'epoch', 'required_seq',
            'target_writer', 'issued_at', 'status', 'handoff_id')
    return dict(zip(keys, row))


executable_fence = active_fence
current_fence = active_fence


def can_continue(db, replica, at=None):
    """Customer continuability at minute ``at`` based on issuance time."""
    fence = active_fence(db, replica)
    if fence and (at is None or fence['issued_at'] <= at):
        return {'continuable': True, 'decision': 'granted',
                'replica': replica, 'fence_id': fence['fence_id'],
                'epoch': fence['epoch'], 'issued_at': fence['issued_at']}
    latest = latest_handoff(db, replica)
    phase = latest['status'] if latest else 'state_incomplete'
    return {'continuable': False, 'decision': 'recovery_in_progress',
            'replica': replica, 'phase': phase,
            'handoff_id': latest['handoff_id'] if latest else None}


continuation_status = can_continue


# ---------------------------------------------------------------------------
# Phase 0: prepare a proposed new number (not executable)
# ---------------------------------------------------------------------------

def prepare_handoff(db, replica, new_epoch, target_writer, at, *,
                    path=None, material_ids=None, proof_id=None,
                    old_writer=None, old_epoch=None, request_key=None,
                    handoff_id=None, required_seq=None,
                    supersede_prior=False, switch_from=None,
                    mirror_slot=None, **options):
    schema(db)

    if request_key is not None:
        prior_key = db.execute(
            'SELECT handoff_id, status FROM fence_handoffs '
            'WHERE request_key=?', (request_key,)).fetchone()
        if prior_key:
            existing = get_handoff(db, prior_key[0])
            return _prepared_result(existing, idempotent=True)

    # Monotonic preparation nonce keeps every attempt in history even when
    # the same replica/epoch is prepared more than once.
    count = db.execute(
        'SELECT COUNT(*) FROM fence_handoffs WHERE replica=? AND epoch=?',
        (replica, new_epoch)).fetchone()[0]
    if handoff_id is None:
        handoff_id = f'{replica}:{new_epoch}:prep{count + 1}'
    fence_id = f'{replica}:{new_epoch}'
    if proof_id is None:
        proof_id = f'proof:{handoff_id}'

    prior_id = switch_from
    if supersede_prior and prior_id is None:
        row = db.execute(
            """SELECT handoff_id FROM fence_handoffs
               WHERE replica=? AND status IN ('prepared','verifying',
                   'verified','sealed','installed')
               ORDER BY prepared_at DESC, rowid DESC LIMIT 1""",
            (replica,)).fetchone()
        prior_id = row[0] if row else None

    with db:
        if prior_id:
            db.execute(
                """UPDATE fence_handoffs
                   SET status='superseded', superseded_by=?
                   WHERE handoff_id=? AND status NOT IN
                       ('issued','cancelled','superseded','invalidated')""",
                (handoff_id, prior_id))
            _event(db, prior_id, replica, at, 'superseded',
                   'preparation_invalidated', {'by': handoff_id})

        db.execute(
            """INSERT INTO fence_handoffs(
                   handoff_id, replica, epoch, fence_id, target_writer, path,
                   proof_id, material_ids, old_writer, old_epoch, status,
                   request_key, prepared_at, mirror_slot, detail)
               VALUES (?,?,?,?,?,?,?,?,?,?, 'prepared', ?, ?, ?, ?)""",
            (handoff_id, replica, new_epoch, fence_id, target_writer, path,
             proof_id,
             json.dumps(list(material_ids)) if material_ids is not None
             else None,
             old_writer, old_epoch, request_key, at, mirror_slot,
             json.dumps(options, sort_keys=True, default=str)))
        _event(db, handoff_id, replica, at, 'prepared', 'handoff_prepared',
               {'fence_id': fence_id, 'path': path,
                'material_ids': material_ids})

        # A *provisional* row may carry the proposed new number, but its
        # status is 'prepared': it is never returned by active_fence().
        db.execute(
            """INSERT INTO writer_fences(
                   replica, fence_id, epoch, required_seq, target_writer,
                   issued_at, status, handoff_id)
               VALUES (?,?,?,?,?, ?, 'prepared', ?)
               ON CONFLICT(replica) DO UPDATE SET
                   fence_id=excluded.fence_id, epoch=excluded.epoch,
                   required_seq=excluded.required_seq,
                   target_writer=excluded.target_writer,
                   status='prepared', handoff_id=excluded.handoff_id""",
            (replica, fence_id, new_epoch,
             required_seq if required_seq is not None else 0,
             target_writer, at, handoff_id))

        # Durably mark the byte proof as merely 'verifying'; a crash here
        # leaves both rows in their prepared state.
        db.execute(
            """INSERT OR REPLACE INTO byte_proofs(
                   proof_id, replica, status, start_seq, through_seq,
                   chain_digest, material_ids, path, source_writer, epoch,
                   report, created_at, verified_at)
               VALUES (?,?, 'verifying', ?, ?, NULL, ?, ?, ?, ?, NULL, ?,
                       NULL)""",
            (proof_id, replica, 1,
             options.get('through_seq'),
             json.dumps(list(material_ids)) if material_ids is not None
             else None, path, old_writer, old_epoch, at))

    return _prepared_result(get_handoff(db, handoff_id))


def _prepared_result(h, idempotent=False):
    return {'decision': 'handoff_prepared', 'status': h['status'],
            'handoff_id': h['handoff_id'], 'fence_id': h['fence_id'],
            'epoch': h['epoch'], 'replica': h['replica'],
            'proof_id': h['proof_id'], 'idempotent': idempotent}


# ---------------------------------------------------------------------------
# Phase 1: byte verification
# ---------------------------------------------------------------------------

def verify_handoff(db, handoff_id, at=None, *, crash_after_commit=False,
                   **verify_options):
    h = get_handoff(db, handoff_id)
    if h is None:
        return {'decision': 'handoff_not_found', 'handoff_id': handoff_id}
    if h['status'] in _DEAD_STATUSES:
        return {'decision': 'preparation_invalidated',
                'status': h['status'], 'handoff_id': handoff_id}
    if h['status'] in ('verified', 'sealed', 'installed', 'issued'):
        proof = get_proof(db, h['proof_id']) if h['proof_id'] else None
        return {'decision': 'verified', 'status': h['status'],
                'handoff_id': handoff_id, 'proof_id': h['proof_id'],
                'chain_digest': h['chain_digest'],
                'idempotent': True,
                'report': (proof or {}).get('report') if proof else None}

    material_ids = (json.loads(h['material_ids'])
                    if h['material_ids'] else None)
    options = {
        'material_ids': material_ids,
        'path': h['path'],
        'expected_writer': h['old_writer'],
        'expected_epoch': h['old_epoch'],
    }
    options.update(verify_options)
    report = verify_chain(db, h['replica'], h['proof_id'], at=at, **options)
    effective_ids = options.get('material_ids')

    if not report.get('ok'):
        with db:
            db.execute(
                'UPDATE fence_handoffs SET last_report=? WHERE handoff_id=?',
                (json.dumps(report, sort_keys=True, default=str),
                 handoff_id))
            _event(db, handoff_id, h['replica'], at, 'verify',
                   report.get('decision', 'not_verified'),
                   {'first_break': report.get('first_break')})
        return report

    with db:
        db.execute(
            """UPDATE fence_handoffs
               SET status='verified', verified_at=?, chain_digest=?,
                   bytes_digest=?, through_seq=?, last_report=?,
                   material_ids=COALESCE(?, material_ids)
               WHERE handoff_id=?""",
            (at, report.get('chain_digest'), report.get('bytes_digest'),
             report.get('through_seq'),
             json.dumps(report, sort_keys=True, default=str),
             json.dumps(list(effective_ids))
             if effective_ids is not None else None,
             handoff_id))
        _event(db, handoff_id, h['replica'], at, 'verified', 'verified',
               {'through_seq': report.get('through_seq'),
                'chain_digest': report.get('chain_digest')})
        if h['path'] == 'mirror':
            _occupy_mirror_slot(db, h, at)
    if crash_after_commit in (True, 'verify'):
        raise PowerLoss('power_lost_after_verify_commit')
    return {'decision': 'verified', 'status': 'verified',
            'handoff_id': handoff_id, 'proof_id': h['proof_id'],
            'through_seq': report.get('through_seq'),
            'chain_digest': report.get('chain_digest'),
            'bytes_digest': report.get('bytes_digest'),
            'mirror_slot': 'occupied' if h['path'] == 'mirror' else 'free'}


# ---------------------------------------------------------------------------
# Mirror slot bookkeeping
# ---------------------------------------------------------------------------

def _occupy_mirror_slot(db, h, at):
    db.execute(
        """INSERT INTO mirror_slot_occupancy(
               slot, occupied_by_proof, handoff_id, occupied_at)
           VALUES (1,?,?,?)
           ON CONFLICT(slot) DO NOTHING""",
        (h['proof_id'], h['handoff_id'], at))


def mirror_slot_status(db):
    schema(db)
    row = db.execute(
        'SELECT occupied_by_proof, handoff_id, occupied_at '
        'FROM mirror_slot_occupancy WHERE slot=1').fetchone()
    if not row:
        return {'total': 1, 'occupied': False, 'available': 1,
                'status': 'free'}
    return {'total': 1, 'occupied': True, 'available': 0,
            'status': 'occupied', 'occupied_by_proof': row[0],
            'handoff_id': row[1], 'occupied_at': row[2]}


def release_mirror_slot(db, holder=None):
    schema(db)
    with db:
        if holder is None:
            db.execute('DELETE FROM mirror_slot_occupancy WHERE slot=1')
        else:
            db.execute(
                'DELETE FROM mirror_slot_occupancy WHERE slot=1 AND '
                '(handoff_id=? OR occupied_by_proof=?)', (holder, holder))
    return mirror_slot_status(db)


# ---------------------------------------------------------------------------
# Phase 2: irreversible old-writer seal
# ---------------------------------------------------------------------------

def seal_old_writer(db, replica=None, at=None, *, handoff_id=None,
                    old_writer=None, old_epoch=None, proof_id=None,
                    crash_after_commit=False, **kwargs):
    schema(db)
    h = get_handoff(db, handoff_id) if handoff_id else None
    if handoff_id and h is None:
        return {'decision': 'handoff_not_found', 'handoff_id': handoff_id}
    if h is not None and h['status'] in _DEAD_STATUSES:
        return {'decision': 'preparation_invalidated',
                'status': h['status'], 'handoff_id': handoff_id}

    if h is not None:
        if h['status'] == 'prepared':
            return {'decision': 'verification_required',
                    'handoff_id': handoff_id, 'status': h['status']}
        if h['status'] not in ('verified', 'sealed', 'installed', 'issued'):
            return {'decision': 'verification_required',
                    'handoff_id': handoff_id, 'status': h['status']}
        proof_id = proof_id or h['proof_id']
        old_writer = old_writer or h['old_writer']
        old_epoch = old_epoch if old_epoch is not None else h['old_epoch']

    # A verified proof must exist; sealing can never be built on a merely
    # 'verifying' proof row.
    if proof_id is not None:
        proof = get_proof(db, proof_id)
        if proof is None or proof['status'] != 'verified':
            return {'decision': 'proof_incomplete', 'proof_id': proof_id}

    existing = db.execute(
        'SELECT * FROM writer_seals WHERE replica=?',
        (replica or (h['replica'] if h else None),)).fetchone()
    replica = replica or (h['replica'] if h else None)
    if existing:
        if h is not None and h['status'] == 'verified':
            with db:
                db.execute(
                    "UPDATE fence_handoffs SET status='sealed', "
                    'sealed_at=COALESCE(sealed_at,?) WHERE handoff_id=?',
                    (at, handoff_id))
                _event(db, handoff_id, replica, at, 'sealed',
                       'already_sealed')
        return {'decision': 'already_sealed', 'replica': replica,
                'irreversible': True}

    with db:
        db.execute(
            """INSERT INTO writer_seals(
                   replica, old_writer, old_epoch, proof_id, sealed_at,
                   irreversible, detail)
               VALUES (?,?,?,?,?,1,?)""",
            (replica, old_writer, old_epoch, proof_id, at,
             json.dumps(kwargs, sort_keys=True, default=str)))
        if h is not None:
            db.execute(
                """UPDATE fence_handoffs
                   SET status='sealed', sealed_at=? WHERE handoff_id=?""",
                (at, handoff_id))
            _event(db, handoff_id, replica, at, 'sealed', 'sealed',
                   {'old_writer': old_writer, 'old_epoch': old_epoch})
        _event(db, handoff_id or f'{replica}:seal', replica, at,
               'old_writer_sealed', 'sealed',
               {'old_writer': old_writer, 'old_epoch': old_epoch})
    if crash_after_commit in (True, 'seal'):
        raise PowerLoss('power_lost_after_seal_commit')
    return {'decision': 'sealed', 'replica': replica,
            'old_writer': old_writer, 'old_epoch': old_epoch,
            'irreversible': True, 'handoff_id': handoff_id}


fence_old_writer = seal_old_writer
seal_epoch = seal_old_writer


def get_seal(db, replica):
    schema(db)
    row = db.execute('SELECT * FROM writer_seals WHERE replica=?',
                     (replica,)).fetchone()
    if not row:
        return None
    cols = [d[0] for d in db.execute(
        'SELECT * FROM writer_seals LIMIT 0').description]
    return dict(zip(cols, row))


def _writer_is_sealed(seal, writer=None, epoch=None):
    if seal is None:
        return False
    if writer is not None and seal['old_writer'] is not None \
            and writer == seal['old_writer']:
        return True
    if epoch is not None and seal['old_epoch'] is not None \
            and epoch <= seal['old_epoch']:
        return True
    # Once any seal exists for the replica, the exact old identity is fenced;
    # unknown writers claiming the old generation are fenced by epoch above.
    return False


def authorize_write(db, replica, writer=None, epoch=None):
    """Write-authority gate used by old and new writer ends alike."""
    schema(db)
    seal = get_seal(db, replica)
    if _writer_is_sealed(seal, writer, epoch):
        return {'authorized': False, 'decision': 'old_writer_sealed',
                'replica': replica, 'writer': writer, 'epoch': epoch}
    fence = active_fence(db, replica)
    if fence is None:
        return {'authorized': False, 'decision': 'no_active_fence',
                'replica': replica}
    if writer is not None and writer != fence['target_writer']:
        return {'authorized': False, 'decision': 'not_fence_owner',
                'replica': replica, 'writer': writer,
                'fence_owner': fence['target_writer']}
    if epoch is not None and epoch != fence['epoch']:
        return {'authorized': False, 'decision': 'stale_epoch',
                'replica': replica, 'epoch': epoch,
                'fence_epoch': fence['epoch']}
    return {'authorized': True, 'decision': 'writable',
            'replica': replica, 'fence_id': fence['fence_id'],
            'epoch': fence['epoch'], 'writer': fence['target_writer']}


def old_writer_action(db, replica, writer=None, epoch=None, action='ack',
                      at=None, **payload):
    """A late acknowledgement or continuation from the old writer end."""
    schema(db)
    seal = get_seal(db, replica)
    if _writer_is_sealed(seal, writer, epoch) or seal is not None and \
            writer is None and epoch is None:
        with db:
            _event(db, f'{replica}:old-writer', replica, at,
                   f'late_{action}_rejected', 'old_writer_sealed',
                   {'writer': writer, 'epoch': epoch, 'payload': payload})
        return {'accepted': False, 'decision': 'old_writer_sealed',
                'replica': replica, 'action': action,
                'irreversible': True}
    return {'accepted': True, 'decision': 'accepted_before_seal',
            'replica': replica, 'action': action}


# Explicit verb aliases for late old-end messages.
def old_writer_ack(db, replica, writer=None, epoch=None, at=None, **kw):
    return old_writer_action(db, replica, writer, epoch, 'ack', at, **kw)


def old_writer_append(db, replica, writer=None, epoch=None, at=None, **kw):
    return old_writer_action(db, replica, writer, epoch, 'append', at, **kw)


accept_old_writer_write = old_writer_append
reject_stale_writer = old_writer_action


# ---------------------------------------------------------------------------
# Phase 3: target installation (+ optional target receipt)
# ---------------------------------------------------------------------------

def receive_target_receipt(db, handoff_id, receipt, at=None, *,
                           target_writer=None):
    """Record a target receipt; a late receipt for a dead prep cannot revive it."""
    schema(db)
    h = get_handoff(db, handoff_id)
    if h is None:
        return {'decision': 'handoff_not_found', 'handoff_id': handoff_id}
    if h['status'] in _DEAD_STATUSES:
        with db:
            _event(db, handoff_id, h['replica'], at,
                   'late_target_receipt_rejected',
                   'preparation_invalidated', {'receipt': receipt})
        return {'decision': 'preparation_invalidated',
                'status': h['status'], 'handoff_id': handoff_id,
                'receipt_valid': False}
    with db:
        db.execute(
            """UPDATE fence_handoffs
               SET target_receipt=?, target_receipt_at=?,
                   target_receipt_state='received'
               WHERE handoff_id=?""",
            (json.dumps(receipt, sort_keys=True, default=str), at,
             handoff_id))
        _event(db, handoff_id, h['replica'], at,
               'target_receipt_received', 'received')
    return {'decision': 'target_receipt_recorded', 'handoff_id': handoff_id,
            'receipt_valid': True}


def install_target(db, handoff_id, at=None, *, target_writer=None,
                   target_receipt=None, crash_after_commit=False):
    schema(db)
    h = get_handoff(db, handoff_id)
    if h is None:
        return {'decision': 'handoff_not_found', 'handoff_id': handoff_id}
    if h['status'] in _DEAD_STATUSES:
        return {'decision': 'preparation_invalidated',
                'status': h['status'], 'handoff_id': handoff_id}
    if h['status'] == 'prepared':
        return {'decision': 'verification_required', 'status': h['status']}
    if h['status'] == 'verified':
        return {'decision': 'seal_required_first', 'status': h['status']}
    if target_writer is not None and target_writer != h['target_writer']:
        return {'decision': 'target_mismatch',
                'expected': h['target_writer'], 'given': target_writer}

    if h['status'] in ('sealed',):
        with db:
            db.execute(
                """UPDATE fence_handoffs
                   SET status='installed', installed_at=?,
                       target_receipt=COALESCE(?, target_receipt),
                       target_receipt_at=COALESCE(?, target_receipt_at),
                       target_receipt_state=CASE WHEN ? IS NOT NULL
                           THEN 'received' ELSE target_receipt_state END
                   WHERE handoff_id=?""",
                (at,
                 json.dumps(target_receipt, sort_keys=True, default=str)
                 if target_receipt is not None else None,
                 at if target_receipt is not None else None,
                 json.dumps(target_receipt, sort_keys=True, default=str)
                 if target_receipt is not None else None,
                 handoff_id))
            _event(db, handoff_id, h['replica'], at, 'installed',
                   'target_installed', {'target_writer': h['target_writer']})
    elif h['status'] in ('installed', 'issued'):
        return {'decision': 'already_installed', 'status': h['status'],
                'handoff_id': handoff_id}
    if crash_after_commit in (True, 'install'):
        raise PowerLoss('power_lost_after_install_commit')
    return {'decision': 'installed', 'status': 'installed',
            'handoff_id': handoff_id}


# ---------------------------------------------------------------------------
# Phase 4: issue the executable new number
# ---------------------------------------------------------------------------

def issue_fence(db, handoff_id, at=None, *, crash_after_commit=False):
    schema(db)
    h = get_handoff(db, handoff_id)
    if h is None:
        return {'decision': 'handoff_not_found', 'handoff_id': handoff_id}
    if h['status'] == 'issued':
        return {'decision': 'granted', 'idempotent': True,
                'replica': h['replica'], 'fence_id': h['fence_id'],
                'epoch': h['epoch'], 'handoff_id': handoff_id}
    if h['status'] in _DEAD_STATUSES:
        return {'decision': 'preparation_invalidated',
                'status': h['status'], 'handoff_id': handoff_id}
    if h['status'] != 'installed':
        return {'decision': 'handoff_phase_incomplete',
                'status': h['status'], 'handoff_id': handoff_id}

    # Anti-skip gate: a written proposed number or proof id is not enough.
    # The byte proof must be durably verified and the old writer sealed.
    proof = get_proof(db, h['proof_id']) if h['proof_id'] else None
    if proof is None or proof['status'] != 'verified':
        return {'decision': 'proof_incomplete', 'handoff_id': handoff_id,
                'proof_status': proof['status'] if proof else None}
    seal = get_seal(db, h['replica'])
    if seal is None:
        return {'decision': 'old_writer_not_sealed',
                'handoff_id': handoff_id}
    if proof.get('chain_digest') and h.get('chain_digest') and \
            proof['chain_digest'] != h['chain_digest']:
        return {'decision': 'proof_digest_mismatch',
                'handoff_id': handoff_id}

    # Re-run the byte checks against the chosen material set at issue time.
    # A stale 'verified' proof row or an already-written proposed number can
    # never wave through a gap/fork that appeared after verification.
    material_ids = (json.loads(h['material_ids'])
                    if h['material_ids'] else None)
    fresh = continuity_report(
        db, h['replica'], material_ids=material_ids, path=h['path'],
        expected_writer=h['old_writer'], expected_epoch=h['old_epoch'],
        at=at)
    if not fresh.get('ok'):
        return {'decision': fresh.get('decision', 'proof_incomplete'),
                'handoff_id': handoff_id,
                'first_break': fresh.get('first_break'),
                'reason': fresh.get('reason')}
    if h.get('chain_digest') and \
            fresh.get('chain_digest') != h['chain_digest']:
        return {'decision': 'proof_digest_mismatch',
                'handoff_id': handoff_id}

    with db:
        db.execute(
            """INSERT INTO writer_fences(
                   replica, fence_id, epoch, required_seq, target_writer,
                   issued_at, status, handoff_id)
               VALUES (?,?,?, COALESCE((SELECT required_seq FROM
                   writer_fences WHERE replica=?), 0), ?, ?, 'issued', ?)
               ON CONFLICT(replica) DO UPDATE SET
                   fence_id=excluded.fence_id,
                   epoch=excluded.epoch,
                   target_writer=excluded.target_writer,
                   issued_at=excluded.issued_at,
                   status='issued',
                   handoff_id=excluded.handoff_id""",
            (h['replica'], h['fence_id'], h['epoch'], h['replica'],
             h['target_writer'], at, handoff_id))
        db.execute(
            """UPDATE fence_handoffs
               SET status='issued', issued_at=? WHERE handoff_id=?""",
            (at, handoff_id))
        _event(db, handoff_id, h['replica'], at, 'issued', 'granted',
               {'fence_id': h['fence_id']})
    if crash_after_commit in (True, 'issue'):
        raise PowerLoss('power_lost_after_issue_commit')
    return {'decision': 'granted', 'replica': h['replica'],
            'fence_id': h['fence_id'], 'epoch': h['epoch'],
            'handoff_id': handoff_id, 'issued_at': at}


# ---------------------------------------------------------------------------
# Invalidation / switching material plans
# ---------------------------------------------------------------------------

def invalidate_preparation(db, handoff_id, at=None, reason='switched_plan',
                           *, new_handoff_id=None):
    schema(db)
    h = get_handoff(db, handoff_id)
    if h is None:
        return {'decision': 'handoff_not_found', 'handoff_id': handoff_id}
    if h['status'] == 'issued':
        return {'decision': 'already_issued_cannot_invalidate',
                'handoff_id': handoff_id}
    with db:
        db.execute(
            """UPDATE fence_handoffs
               SET status='superseded', superseded_by=?
               WHERE handoff_id=?""", (new_handoff_id, handoff_id))
        # Provisional writer_fences row becomes non-executable.  If another
        # active prep now owns the replica row it will overwrite on prepare;
        # otherwise mark this row superseded.
        db.execute(
            """UPDATE writer_fences SET status='superseded'
               WHERE handoff_id=? AND status!='issued'""", (handoff_id,))
        _event(db, handoff_id, h['replica'], at, 'invalidated',
               'preparation_invalidated', {'reason': reason})
    return {'decision': 'preparation_invalidated', 'handoff_id': handoff_id}


cancel_handoff = invalidate_preparation
supersede_handoff = invalidate_preparation


# ---------------------------------------------------------------------------
# Crash recovery / orchestration
# ---------------------------------------------------------------------------

def resume_handoff(db, handoff_id, at=None, *, target_receipt=None,
                   crash_after=None, **verify_options):
    """Continue a handoff from its durable phase after reopen."""
    h = get_handoff(db, handoff_id)
    if h is None:
        return {'decision': 'handoff_not_found', 'handoff_id': handoff_id}
    if h['status'] == 'issued':
        return issue_fence(db, handoff_id, at=at)
    if h['status'] in _DEAD_STATUSES:
        return {'decision': 'preparation_invalidated',
                'status': h['status'], 'handoff_id': handoff_id}

    if h['status'] == 'prepared':
        result = verify_handoff(
            db, handoff_id, at=at,
            crash_after_commit=(True if crash_after == 'verify' else False),
            **verify_options)
        if result.get('decision') != 'verified':
            return result
        if crash_after == 'verify':
            return result
    if get_handoff(db, handoff_id)['status'] == 'verified':
        result = seal_old_writer(
            db, handoff_id=handoff_id, at=at,
            crash_after_commit=(True if crash_after == 'seal' else False))
        if result.get('decision') not in ('sealed', 'already_sealed'):
            return result
    if get_handoff(db, handoff_id)['status'] == 'sealed':
        result = install_target(
            db, handoff_id, at=at, target_receipt=target_receipt,
            crash_after_commit=(True if crash_after == 'install' else False))
        if result.get('decision') not in ('installed', 'already_installed'):
            return result
    if get_handoff(db, handoff_id)['status'] == 'installed':
        return issue_fence(
            db, handoff_id, at=at,
            crash_after_commit=(True if crash_after == 'issue' else False))
    current = get_handoff(db, handoff_id)
    return {'decision': current['status'], 'handoff_id': handoff_id}


recover_handoff = resume_handoff


def run_handoff(db, replica, new_epoch, target_writer, at, *,
                crash_after=None, **kwargs):
    """Prepare and drive a full handoff in one call (or crash at a phase)."""
    prep = prepare_handoff(db, replica, new_epoch, target_writer, at,
                           **kwargs)
    handoff_id = prep['handoff_id']
    if crash_after == 'prepare':
        raise PowerLoss('power_lost_after_prepare_commit')
    return resume_handoff(db, handoff_id, at=at, crash_after=crash_after)


handoff = run_handoff
recover_and_claim = run_handoff
transfer_write_authority = run_handoff

# Short-name aliases for callers/tests using the phase vocabulary directly.
prepare = prepare_handoff
verify = verify_handoff
seal = seal_old_writer
install = install_target
issue = issue_fence
resume = resume_handoff
grant = claim
fence = seal_old_writer
status = can_continue
complete_handoff = resume_handoff
commit_handoff = issue_fence
transfer = run_handoff
fence_old_writer_epoch = seal_old_writer

# Additional short-name aliases for alternative vocabularies.
seal_writer = seal_old_writer
seal_old = seal_old_writer
fence_old = seal_old_writer
grant_fence = issue_fence
commit = issue_fence
recover = resume_handoff
begin_handoff = prepare_handoff
transfer_fence = run_handoff
