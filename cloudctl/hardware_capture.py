"""Immutable offline inventory capture.

Three identities must never be collapsed into one:

* agent id (``agent_id``, the management agent reporting in),
* management-card certificate (``card_cert``),
* physical chassis (full chassis serial / entity).

The legacy :func:`import_page` keeps its strict five-column row contract and
its ``captured``/``replayed``/``hardware_page_conflict`` behaviour.  The
richer helpers preserve whole-page bytes, the capture minute, rack photo
digests, visible portions of the full chassis number, card replacement
orders and one-time-nonce live machine attestations.
"""
import hashlib
import json

LEGACY_KEYS = {'agent_id', 'card_cert', 'serial_tail', 'rack', 'cpu'}


class HardwarePageConflict(ValueError):
    """A page id was re-submitted with different content."""


class NonceReplay(ValueError):
    """An attestation nonce has already been consumed."""


def sha256_bytes(content):
    if isinstance(content, str):
        content = content.encode('utf-8')
    return hashlib.sha256(content).hexdigest()


def _rows_digest(rows):
    return hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()


def _ensure(db):
    db.execute(
        'CREATE TABLE IF NOT EXISTS hardware_pages '
        '(id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS hardware_rows '
        '(page_id TEXT,line_no INTEGER,agent_id TEXT,card_cert TEXT,'
        'serial_tail TEXT,rack TEXT,cpu INTEGER,'
        'PRIMARY KEY(page_id,line_no))'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS hardware_page_blobs ('
        'page_id TEXT PRIMARY KEY,content BLOB,byte_digest TEXT NOT NULL,'
        'captured_minute INTEGER,received_at INTEGER,original_result TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS hardware_page_conflicts ('
        'seq INTEGER PRIMARY KEY AUTOINCREMENT,page_id TEXT,seen_at INTEGER,'
        'old_digest TEXT,new_digest TEXT,detail TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS rack_photos ('
        'photo_id TEXT PRIMARY KEY,page_id TEXT,rack TEXT,digest TEXT NOT NULL,'
        'captured_minute INTEGER,shows_full_serial INTEGER NOT NULL DEFAULT 0,'
        'visible_serial TEXT,summary TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS serial_sightings ('
        'seq INTEGER PRIMARY KEY AUTOINCREMENT,page_id TEXT,line_no INTEGER,'
        'agent_id TEXT,serial_full TEXT,serial_visible TEXT,serial_tail TEXT,'
        'source TEXT,observed_minute INTEGER,digest TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS card_replacement_orders ('
        'order_id TEXT PRIMARY KEY,old_card_cert TEXT,new_card_cert TEXT,'
        'old_agent_id TEXT,new_agent_id TEXT,chassis_serial TEXT,'
        'issued_minute INTEGER,digest TEXT,payload TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS evidence_artifacts ('
        'artifact_id TEXT PRIMARY KEY,kind TEXT,reference TEXT,digest TEXT,'
        'minute INTEGER,payload TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS attestations ('
        'attestation_id TEXT PRIMARY KEY,nonce TEXT NOT NULL UNIQUE,'
        'agent_id TEXT,chassis_serial TEXT,cpu INTEGER NOT NULL,rack TEXT,'
        'at_minute INTEGER NOT NULL,digest TEXT,payload TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS used_nonces ('
        'nonce TEXT PRIMARY KEY,attestation_id TEXT,used_at INTEGER)'
    )


def import_page(db, page_id, rows, received_at):
    """Legacy strict five-key page import (preserved contract)."""
    _ensure(db)
    keys = LEGACY_KEYS
    if (not isinstance(rows, list)
            or any(not isinstance(r, dict) or set(r) != keys
                   or not isinstance(r['cpu'], int) or r['cpu'] <= 0
                   for r in rows)):
        raise ValueError('invalid_hardware_page')
    digest = _rows_digest(rows)
    old = db.execute(
        'SELECT digest FROM hardware_pages WHERE id=?', (page_id,)
    ).fetchone()
    if old:
        if old[0] != digest:
            with db:
                db.execute(
                    'INSERT INTO hardware_page_conflicts'
                    '(page_id,seen_at,old_digest,new_digest,detail) '
                    'VALUES (?,?,?,?,?)',
                    (page_id, received_at, old[0], digest, 'rows_digest'),
                )
            raise HardwarePageConflict('hardware_page_conflict')
        count = db.execute(
            'SELECT COUNT(*) FROM hardware_rows WHERE page_id=?', (page_id,)
        ).fetchone()[0]
        original = {'status': 'captured', 'rows': count}
        return {'status': 'replayed', 'rows': len(rows),
                'original': original, 'result': original}
    result = {'status': 'captured', 'rows': len(rows)}
    canonical = json.dumps(
        rows, sort_keys=True, separators=(',', ':')
    ).encode('utf-8')
    with db:
        db.execute(
            'INSERT INTO hardware_pages VALUES (?,?,?)',
            (page_id, digest, received_at),
        )
        for i, r in enumerate(rows, 1):
            db.execute(
                'INSERT INTO hardware_rows VALUES (?,?,?,?,?,?,?)',
                (page_id, i, r['agent_id'], r['card_cert'],
                 r['serial_tail'], r['rack'], r['cpu']),
            )
            db.execute(
                'INSERT INTO serial_sightings'
                '(page_id,line_no,agent_id,serial_full,serial_visible,'
                'serial_tail,source,observed_minute,digest) '
                'VALUES (?,?,?,?,?,?,?,?,?)',
                (page_id, i, r['agent_id'], None, None, r['serial_tail'],
                 'inventory_scan', received_at, digest),
            )
        db.execute(
            'INSERT OR REPLACE INTO hardware_page_blobs'
            '(page_id,content,byte_digest,captured_minute,received_at,'
            'original_result) VALUES (?,?,?,?,?,?)',
            (page_id, canonical, sha256_bytes(canonical), received_at,
             received_at, json.dumps(result, sort_keys=True)),
        )
    return result


def capture_page(db, page_id, *, rows=None, content=None, captured_minute=None,
                 received_at=None, raw_bytes=None):
    """Preserve a whole offline page (exact bytes) plus optional parsed rows.

    Same ``page_id`` + same bytes returns the original result; changed bytes
    persist a conflict record and raise :class:`HardwarePageConflict`.
    """
    _ensure(db)
    if raw_bytes is not None:
        content = raw_bytes
    if content is None:
        if rows is None:
            raise ValueError('page_content_required')
        content = json.dumps(
            rows, sort_keys=True, separators=(',', ':')
        ).encode('utf-8')
    digest = sha256_bytes(content)
    received_at = captured_minute if received_at is None else received_at
    old_blob = db.execute(
        'SELECT byte_digest,original_result FROM hardware_page_blobs '
        'WHERE page_id=?',
        (page_id,),
    ).fetchone()
    if old_blob:
        if old_blob[0] != digest:
            db.execute(
                'INSERT INTO hardware_page_conflicts'
                '(page_id,seen_at,old_digest,new_digest,detail) '
                'VALUES (?,?,?,?,?)',
                (page_id, received_at, old_blob[0], digest, 'byte_digest'),
            )
            raise HardwarePageConflict('hardware_page_conflict')
        original = json.loads(old_blob[1]) if old_blob[1] else None
        return {'status': 'replayed', 'page_id': page_id,
                'byte_digest': digest, 'original': original}
    parsed_rows = rows
    result = {'status': 'captured', 'page_id': page_id,
              'byte_digest': digest, 'rows': len(parsed_rows or [])}
    db.execute(
        'INSERT INTO hardware_page_blobs'
        '(page_id,content,byte_digest,captured_minute,received_at,'
        'original_result) VALUES (?,?,?,?,?,?)',
        (page_id, content if isinstance(content, bytes) else content.encode(),
         digest, captured_minute, received_at,
         json.dumps(result, sort_keys=True)),
    )
    if parsed_rows is not None:
        if (not isinstance(parsed_rows, list)
                or any(not isinstance(r, dict) for r in parsed_rows)):
            raise ValueError('invalid_hardware_page')
        rows_digest = _rows_digest(parsed_rows)
        exists = db.execute(
            'SELECT id FROM hardware_pages WHERE id=?', (page_id,)
        ).fetchone()
        if exists:
            prior = db.execute(
                'SELECT digest FROM hardware_pages WHERE id=?', (page_id,)
            ).fetchone()
            if prior[0] != rows_digest:
                raise HardwarePageConflict('hardware_page_conflict')
        else:
            db.execute(
                'INSERT INTO hardware_pages VALUES (?,?,?)',
                (page_id, rows_digest, received_at),
            )
            for i, r in enumerate(parsed_rows, 1):
                if set(r) != LEGACY_KEYS:
                    # rich rows may carry serial_full/serial_visible
                    missing = LEGACY_KEYS - set(r)
                    if missing:
                        raise ValueError('invalid_hardware_page')
                db.execute(
                    'INSERT INTO hardware_rows VALUES (?,?,?,?,?,?,?)',
                    (page_id, i, r['agent_id'], r['card_cert'],
                     r['serial_tail'], r['rack'], r['cpu']),
                )
                db.execute(
                    'INSERT INTO serial_sightings'
                    '(page_id,line_no,agent_id,serial_full,serial_visible,'
                    'serial_tail,source,observed_minute,digest) '
                    'VALUES (?,?,?,?,?,?,?,?,?)',
                    (page_id, i, r['agent_id'], r.get('serial_full'),
                     r.get('serial_visible'), r['serial_tail'],
                     r.get('source', 'inventory_scan'), captured_minute,
                     digest),
                )
    return result


def add_rack_photo(db, photo_id, *, rack, digest=None, content=None,
                  minute=None, page_id=None, shows_full_serial=False,
                  visible_serial=None, summary=None):
    """Preserve a rack site photo summary/digest (never the identity itself)."""
    _ensure(db)
    if digest is None:
        if content is None:
            raise ValueError('photo_digest_required')
        digest = sha256_bytes(content)
    db.execute(
        'INSERT OR REPLACE INTO rack_photos VALUES (?,?,?,?,?,?,?,?)',
        (photo_id, page_id, rack, digest, minute,
         1 if shows_full_serial else 0, visible_serial, summary),
    )
    return {'photo_id': photo_id, 'digest': digest, 'rack': rack,
            'shows_full_serial': bool(shows_full_serial),
            'visible_serial': visible_serial}


def add_photo(db, photo_id, **kw):
    return add_rack_photo(db, photo_id, **kw)


def add_replacement_order(db, order_id, *, minute=None, old_card_cert=None,
                          new_card_cert=None, old_agent_id=None,
                          new_agent_id=None, chassis_serial=None,
                          digest=None, **payload):
    """Record a management-card replacement form."""
    _ensure(db)
    body = json.dumps(
        {'old_card_cert': old_card_cert, 'new_card_cert': new_card_cert,
         'old_agent_id': old_agent_id, 'new_agent_id': new_agent_id,
         'chassis_serial': chassis_serial, **payload},
        sort_keys=True, ensure_ascii=False,
    )
    digest = digest or sha256_bytes(body)
    db.execute(
        'INSERT OR REPLACE INTO card_replacement_orders VALUES (?,?,?,?,?,?,?,?,?)',
        (order_id, old_card_cert, new_card_cert, old_agent_id, new_agent_id,
         chassis_serial, minute, digest, body),
    )
    return {'order_id': order_id, 'digest': digest,
            'old_agent_id': old_agent_id, 'new_agent_id': new_agent_id,
            'chassis_serial': chassis_serial}


def record_card_swap(db, order_id, **kw):
    return add_replacement_order(db, order_id, **kw)


def add_artifact(db, artifact_id, *, kind, reference=None, digest=None,
                  content=None, minute=None, **payload):
    """Preserve any other original artifact (e.g. a mere certificate copy)."""
    _ensure(db)
    body = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      default=str)
    digest = digest or sha256_bytes(content if content is not None else body)
    db.execute(
        'INSERT OR REPLACE INTO evidence_artifacts VALUES (?,?,?,?,?,?)',
        (artifact_id, kind, reference, digest, minute, body),
    )
    return {'artifact_id': artifact_id, 'kind': kind, 'digest': digest}


def copy_certificate(db, artifact_id, *, card_cert, minute=None):
    """A photocopy of a card certificate: recorded, but proves nothing alone."""
    return add_artifact(
        db, artifact_id, kind='certificate_copy', reference=card_cert,
        minute=minute, card_cert=card_cert,
    )


def attest_machine(db, attestation_id, *, nonce, cpu, rack, minute,
                   agent_id=None, chassis_serial=None, **extra):
    """Record a live, random-nonce machine sign-off.

    The nonce is single use: replaying an old nonce raises
    :class:`NonceReplay`.  A valid attestation binds CPU spec and rack
    location to either an agent id or a full chassis serial (ideally both).
    """
    _ensure(db)
    if not nonce:
        raise ValueError('attestation_nonce_required')
    if not isinstance(cpu, int) or cpu <= 0:
        raise ValueError('attestation_cpu_invalid')
    if not rack:
        raise ValueError('attestation_rack_required')
    if not agent_id and not chassis_serial:
        raise ValueError('attestation_identity_required')
    prior = db.execute(
        'SELECT attestation_id FROM used_nonces WHERE nonce=?', (nonce,)
    ).fetchone()
    if prior:
        raise NonceReplay('attestation_nonce_replayed')
    body = json.dumps(
        {'nonce': nonce, 'cpu': cpu, 'rack': rack, 'minute': minute,
         'agent_id': agent_id, 'chassis_serial': chassis_serial, **extra},
        sort_keys=True, ensure_ascii=False, default=str,
    )
    digest = sha256_bytes(body)
    db.execute(
        'INSERT INTO attestations VALUES (?,?,?,?,?,?,?,?,?)',
        (attestation_id, nonce, agent_id, chassis_serial, cpu, rack, minute,
         digest, body),
    )
    db.execute(
        'INSERT INTO used_nonces VALUES (?,?,?)',
        (nonce, attestation_id, minute),
    )
    return {'attestation_id': attestation_id, 'nonce': nonce, 'cpu': cpu,
            'rack': rack, 'agent_id': agent_id,
            'chassis_serial': chassis_serial, 'digest': digest,
            'fresh': True}


# Short alias used by callers that read like the narrative.
attest = attest_machine
