"""Capacity certificates.

:func:`issue` is the legacy agent-rollup certificate: it sums CPU by agent id
and therefore signs 16 CPU for N1+N2.  It is preserved verbatim for the
seed behaviour.

The versioned helpers (:func:`issue_version` / :func:`issue_replacement`)
only sign entity-proven physical capacity, pin every original artifact they
rely on together with the compatible chassis interpretation, and record an
under-delivery obligation against any superseded customer certificate.
Issued rows are immutable: late evidence creates a new version, never an
in-place rewrite.
"""
import json

from .store import one, many
from . import identity


def _ensure_legacy(db):
    db.execute(
        'CREATE TABLE IF NOT EXISTS capacity_certificates '
        '(id TEXT PRIMARY KEY,claimed_cpu INTEGER NOT NULL,'
        'agent_count INTEGER NOT NULL)'
    )


def issue(db, certificate_id):
    """Legacy: summarize healthy inventory rows by agent id and sign them."""
    _ensure_legacy(db)
    rows = db.execute(
        'SELECT agent_id,MAX(cpu) FROM hardware_rows GROUP BY agent_id'
    ).fetchall()
    total = sum(x[1] for x in rows)
    with db:
        db.execute('INSERT INTO capacity_certificates VALUES (?,?,?)',
                   (certificate_id, total, len(rows)))
    return {'certificate_id': certificate_id, 'claimed_cpu': total,
            'agent_count': len(rows)}


# ---------------------------------------------------------------------------
# Versioned, evidence-pinned certificates
# ---------------------------------------------------------------------------

def _ensure(db):
    _ensure_legacy(db)
    db.execute(
        'CREATE TABLE IF NOT EXISTS capacity_certificates_v2 ('
        'certificate_id TEXT PRIMARY KEY,series TEXT NOT NULL,version INTEGER '
        'NOT NULL,claimed_cpu INTEGER NOT NULL,interpretation_id TEXT,'
        'interpretation_kind TEXT,basis TEXT NOT NULL,supersedes TEXT,'
        'issued_minute INTEGER,kind TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS certificate_dependencies ('
        'certificate_id TEXT,ref_kind TEXT,ref_id TEXT,digest TEXT,'
        'PRIMARY KEY(certificate_id,ref_kind,ref_id))'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS certificate_obligations ('
        'obligation_id TEXT PRIMARY KEY,old_certificate_id TEXT NOT NULL,'
        'new_certificate_id TEXT,claimed_cpu INTEGER,covered_cpu INTEGER,'
        'shortfall_cpu INTEGER NOT NULL,status TEXT NOT NULL,'
        'created_minute INTEGER,fulfilled_by TEXT,fulfilled_minute INTEGER,'
        'note TEXT)'
    )


def _all_dependencies(db):
    """Collect every preserved original artifact + digest as the basis."""
    deps = []
    if identity.store_table(db, 'hardware_pages'):
        for r in many(db, 'SELECT id,digest FROM hardware_pages ORDER BY id'):
            deps.append(('inventory_page', r['id'], r['digest']))
    if identity.store_table(db, 'hardware_page_blobs'):
        for r in many(db,
                      'SELECT page_id,byte_digest FROM hardware_page_blobs '
                      'ORDER BY page_id'):
            deps.append(('page_bytes', r['page_id'], r['byte_digest']))
    if identity.store_table(db, 'rack_photos'):
        for r in many(db, 'SELECT photo_id,digest FROM rack_photos ORDER BY photo_id'):
            deps.append(('rack_photo', r['photo_id'], r['digest']))
    if identity.store_table(db, 'card_replacement_orders'):
        for r in many(db, 'SELECT order_id,digest FROM card_replacement_orders '
                          'ORDER BY order_id'):
            deps.append(('replacement_order', r['order_id'], r['digest']))
    if identity.store_table(db, 'attestations'):
        for r in many(db, 'SELECT attestation_id,digest FROM attestations '
                          'ORDER BY attestation_id'):
            deps.append(('live_attestation', r['attestation_id'], r['digest']))
    if identity.store_table(db, 'evidence_artifacts'):
        for r in many(db, 'SELECT artifact_id,digest FROM evidence_artifacts '
                          'ORDER BY artifact_id'):
            deps.append(('artifact', r['artifact_id'], r['digest']))
    return deps


def load_certificate(db, certificate_id):
    _ensure(db)
    row = one(db, 'SELECT * FROM capacity_certificates_v2 WHERE certificate_id=?',
              (certificate_id,))
    if row:
        row['basis'] = json.loads(row['basis']) if row['basis'] else {}
        row['dependencies'] = many(
            db,
            'SELECT ref_kind,ref_id,digest FROM certificate_dependencies '
            'WHERE certificate_id=? ORDER BY ref_kind,ref_id',
            (certificate_id,),
        )
        row['legacy'] = False
        return row
    old = one(db, 'SELECT * FROM capacity_certificates WHERE id=?',
              (certificate_id,))
    if old:
        return {'certificate_id': certificate_id,
                'claimed_cpu': old['claimed_cpu'],
                'agent_count': old['agent_count'], 'legacy': True,
                'dependencies': [], 'basis': {}}
    return None


get_certificate = load_certificate


def issue_version(db, certificate_id, *, minute=None, series='capacity',
                  interpretation_id=None, claimed_cpu=None, kind='proven_current',
                  supersedes=None, extra_basis=None, status_note=None):
    """Sign a new immutable version pinned to current originals/proof."""
    _ensure(db)
    identity._ensure(db)
    if one(db, 'SELECT 1 FROM capacity_certificates_v2 WHERE certificate_id=?',
           (certificate_id,)):
        prior = load_certificate(db, certificate_id)
        return {'status': 'idempotent', **{k: prior[k] for k in
                ('certificate_id', 'claimed_cpu', 'version', 'series')}}
    if claimed_cpu is None:
        claimed_cpu = identity.proven_cpu(db)
    interp_kind = None
    if interpretation_id:
        interp = identity.get_interpretation(db, interpretation_id)
        if interp:
            interp_kind = interp['kind']
    # Always pin the interpretation picture: an explicit one when supplied,
    # otherwise every still-compatible interpretation plus any confirmed one.
    all_interps = identity.interpretations(db)
    compatible = [
        {'id': i['interpretation_id'], 'kind': i['kind'],
         'status': i['status'], 'provable_cpu': i['provable_cpu']}
        for i in all_interps if i['status'] == 'compatible'
    ]
    confirmed = [i for i in all_interps if i['status'] == 'confirmed']
    if not interpretation_id and len(confirmed) == 1:
        interpretation_id = confirmed[0]['interpretation_id']
        interp_kind = confirmed[0]['kind']
    version = (one(db,
                   'SELECT COALESCE(MAX(version),0)+1 v '
                   'FROM capacity_certificates_v2 WHERE series=?',
                   (series,)) or {'v': 1})['v']
    deps = _all_dependencies(db)
    basis = {'artifacts': [{'kind': k, 'id': i, 'digest': d}
                           for k, i, d in deps],
             'proven_cpu': claimed_cpu,
             'interpretation_id': interpretation_id,
             'interpretation_kind': interp_kind,
             'compatible_interpretations': compatible,
             'confirmed_interpretations': [i['interpretation_id']
                                           for i in confirmed],
             'proven_chassis': [
                 {'id': c['chassis_id'], 'cpu': c['cpu'],
                  'proof_level': c['proof_level'],
                  'serial_full': c['serial_full']}
                 for c in identity.proven_chassis(db)],
             'quarantined_agents': sorted(identity.quarantined_ids(db)),
             'note': status_note}
    if extra_basis:
        basis.update(extra_basis)
    db.execute(
        'INSERT INTO capacity_certificates_v2 VALUES (?,?,?,?,?,?,?,?,?,?)',
        (certificate_id, series, version, claimed_cpu, interpretation_id,
         interp_kind, json.dumps(basis, sort_keys=True, ensure_ascii=False),
         supersedes, minute, kind),
    )
    for k, i, d in deps:
        db.execute(
            'INSERT OR IGNORE INTO certificate_dependencies VALUES (?,?,?,?)',
            (certificate_id, k, i, d),
        )
    return {'status': 'issued', 'certificate_id': certificate_id,
            'series': series, 'version': version,
            'claimed_cpu': claimed_cpu,
            'interpretation_id': interpretation_id,
            'interpretation_kind': interp_kind,
            'supersedes': supersedes,
            'dependencies': [{'kind': k, 'id': i, 'digest': d}
                              for k, i, d in deps]}


issue_safe = issue_version


def _claimed_of(db, cert_id):
    cert = load_certificate(db, cert_id)
    return cert['claimed_cpu'] if cert else None


def issue_replacement(db, new_certificate_id, old_certificate_id, *,
                      obligation_id=None, minute=None, **kw):
    """Issue a new version and record the old certificate's shortfall."""
    _ensure(db)
    old_claimed = _claimed_of(db, old_certificate_id)
    if old_claimed is None:
        raise ValueError('unknown_certificate')
    result = issue_version(
        db, new_certificate_id, minute=minute,
        supersedes=old_certificate_id, **kw
    )
    new_claimed = result['claimed_cpu']
    shortfall = max(0, old_claimed - new_claimed)
    ob_id = obligation_id or f'ob:{old_certificate_id}->{new_certificate_id}'
    status = 'open' if shortfall > 0 else 'secured'
    db.execute(
        'INSERT OR REPLACE INTO certificate_obligations VALUES (?,?,?,?,?,?,?,?,?,?,?)',
        (ob_id, old_certificate_id, new_certificate_id, old_claimed,
         new_claimed, shortfall, status, minute, None, None,
         kw.get('note')),
    )
    obligation = one(db,
                     'SELECT * FROM certificate_obligations WHERE obligation_id=?',
                     (ob_id,))
    return {**result, 'obligation': obligation}


replace_certificate = issue_replacement


def obligations(db, *, status=None, old_certificate_id=None):
    _ensure(db)
    q = 'SELECT * FROM certificate_obligations WHERE 1=1'
    params = []
    if status:
        q += ' AND status=?'
        params.append(status)
    if old_certificate_id:
        q += ' AND old_certificate_id=?'
        params.append(old_certificate_id)
    q += ' ORDER BY obligation_id'
    return many(db, q, tuple(params))


def open_obligation_cpu(db, old_certificate_id=None):
    _ensure(db)
    q = ("SELECT COALESCE(SUM(shortfall_cpu),0) n "
         "FROM certificate_obligations WHERE status='open'")
    params = []
    if old_certificate_id:
        q += ' AND old_certificate_id=?'
        params.append(old_certificate_id)
    return one(db, q, tuple(params))['n']


def fulfill_obligation(db, obligation_id, *, by_certificate_id, minute=None):
    _ensure(db)
    ob = one(db, 'SELECT * FROM certificate_obligations WHERE obligation_id=?',
             (obligation_id,))
    if not ob:
        return {'obligation_id': obligation_id, 'decision': 'missing'}
    db.execute(
        "UPDATE certificate_obligations SET status='fulfilled',"
        'fulfilled_by=?,fulfilled_minute=? WHERE obligation_id=?',
        (by_certificate_id, minute, obligation_id),
    )
    return {'obligation_id': obligation_id, 'decision': 'fulfilled',
            'fulfilled_by': by_certificate_id}


def cover_obligations(db, new_certificate_id, *, minute=None):
    """Cover open obligations of the same series once a strong cert exists."""
    _ensure(db)
    cert = load_certificate(db, new_certificate_id)
    covered = []
    if not cert:
        return covered
    opens = obligations(db, status='open')
    for ob in opens:
        old = load_certificate(db, ob['old_certificate_id'])
        # The new certificate makes the old customer promise good when it
        # reaches at least the amount the old certificate claimed.
        if cert['claimed_cpu'] >= (old['claimed_cpu']
                                   if old else ob['claimed_cpu']):
            fulfill_obligation(db, ob['obligation_id'],
                               by_certificate_id=new_certificate_id,
                               minute=minute)
            covered.append(ob['obligation_id'])
    return covered


def receive_late_evidence(db, old_certificate_id, new_certificate_id, *,
                          minute=None, **issue_kw):
    """Late original arrived: append a new version + obligation, never rewrite."""
    return issue_replacement(
        db, new_certificate_id, old_certificate_id, minute=minute, **issue_kw
    )


reassess = receive_late_evidence
reissue = issue_replacement
new_version = issue_replacement
remedy_records = obligations
remedies = obligations
open_shortfall = open_obligation_cpu


def shortfall_cpu(db, old_certificate_id=None):
    return open_obligation_cpu(db, old_certificate_id)


def certificate_dependencies(db, certificate_id):
    _ensure(db)
    return many(
        db,
        'SELECT ref_kind,ref_id,digest FROM certificate_dependencies '
        'WHERE certificate_id=? ORDER BY ref_kind,ref_id',
        (certificate_id,),
    )


def remedy_history(db, old_certificate_id):
    _ensure(db)
    return obligations(db, old_certificate_id=old_certificate_id)
