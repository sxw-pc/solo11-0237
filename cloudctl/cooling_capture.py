"""Offline cooling-loop flow and temperature meter pages.

A page is an immutable batch of raw meter rows.  Pages are content-addressed
by digest: re-sending the same id with the same rows is idempotent, while the
same id with different rows is a hard conflict -- raw evidence can never be
silently overwritten.

Calibration pages describe one common zero-point bias for a whole batch of
meters.  A batch bias is applied uniformly to every meter in the batch
(main header and every branch); there is deliberately no per-meter override,
so the same water cannot be counted twice by picking a favourable error for
each loop.  Return and bypass meters are never treated as supply.
"""
import hashlib
import json
import sqlite3

FRESHNESS_WINDOW = 1          # a sample older than at-1 is stale
DEFAULT_BALANCE_TOLERANCE = 5  # site meter agreement tolerance, L/min


def _digest(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()


def import_page(db, page_id, rows, received_at):
    db.execute('CREATE TABLE IF NOT EXISTS cooling_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL,received_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS cooling_rows (page_id TEXT,line_no INTEGER,meter TEXT,loop TEXT,tick INTEGER,flow_lpm INTEGER,temp_c INTEGER,PRIMARY KEY(page_id,line_no))')
    keys = {'meter', 'loop', 'tick', 'flow_lpm', 'temp_c'}
    if not isinstance(rows, list) or any(
        not isinstance(r, dict) or set(r) != keys
        or not isinstance(r['tick'], int) or not isinstance(r['flow_lpm'], int)
        or not isinstance(r['temp_c'], int) or r['flow_lpm'] < 0
        for r in rows
    ):
        raise ValueError('invalid_cooling_page')
    digest = _digest(rows)
    old = db.execute('SELECT digest FROM cooling_pages WHERE id=?', (page_id,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('cooling_page_conflict')
        return {'status': 'replayed', 'rows': len(rows)}
    with db:
        db.execute('INSERT INTO cooling_pages VALUES (?,?,?)', (page_id, digest, received_at))
        for i, r in enumerate(rows, 1):
            db.execute('INSERT INTO cooling_rows VALUES (?,?,?,?,?,?,?)',
                       (page_id, i, r['meter'], r['loop'], r['tick'], r['flow_lpm'], r['temp_c']))
    return {'status': 'captured', 'rows': len(rows)}


def import_calibration(db, cal_id, meters, bias_lpm, effective_at, received_at, batch_id=None):
    """Record a common zero-point calibration for a batch of meters.

    ``bias_lpm`` is the common over-reading: a positive value means every
    listed meter reports that many L/min too high, so corrected flow is
    ``raw - bias_lpm`` for the main header and every branch alike.
    """
    db.execute('CREATE TABLE IF NOT EXISTS cooling_calibrations ('
               'cal_id TEXT PRIMARY KEY,batch_id TEXT,bias_lpm INTEGER NOT NULL,'
               'meters TEXT NOT NULL,effective_at INTEGER NOT NULL,'
               'received_at INTEGER NOT NULL,digest TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS cooling_corrections ('
               'cal_id TEXT,meter TEXT,tick INTEGER,raw_flow INTEGER,'
               'corrected_flow INTEGER,PRIMARY KEY(cal_id,meter,tick))')
    if (not isinstance(meters, list) or not meters
            or any(not isinstance(m, str) for m in meters)
            or not isinstance(bias_lpm, int) or not isinstance(effective_at, int)):
        raise ValueError('invalid_calibration')
    meters = list(meters)
    batch_id = batch_id or cal_id
    payload = {'meters': sorted(meters), 'bias_lpm': bias_lpm,
               'effective_at': effective_at, 'batch_id': batch_id}
    digest = _digest(payload)
    old = db.execute('SELECT digest FROM cooling_calibrations WHERE cal_id=?', (cal_id,)).fetchone()
    if old:
        if old[0] != digest:
            raise ValueError('calibration_conflict')
        return {'status': 'replayed', 'cal_id': cal_id, 'meters': len(meters)}
    with db:
        db.execute('INSERT INTO cooling_calibrations VALUES (?,?,?,?,?,?,?)',
                   (cal_id, batch_id, bias_lpm, json.dumps(meters),
                    effective_at, received_at, digest))
    return {'status': 'captured', 'cal_id': cal_id, 'meters': len(meters),
            'bias_lpm': bias_lpm, 'batch_id': batch_id}


def active_calibration(db, meter, at):
    """Latest calibration covering ``meter`` effective at or before ``at``."""
    try:
        rows = db.execute('SELECT cal_id,batch_id,bias_lpm,meters,effective_at '
                          'FROM cooling_calibrations WHERE effective_at<=? '
                          'ORDER BY effective_at DESC, cal_id DESC', (at,)).fetchall()
    except sqlite3.OperationalError:
        return None
    for cal_id, batch_id, bias, meters_json, effective_at in rows:
        if meter in json.loads(meters_json):
            return {'cal_id': cal_id, 'batch_id': batch_id, 'bias_lpm': bias,
                    'meters': json.loads(meters_json), 'effective_at': effective_at}
    return None


def latest_row(db, meter, at):
    try:
        return db.execute('SELECT page_id,meter,loop,tick,flow_lpm,temp_c FROM cooling_rows '
                          'WHERE meter=? AND tick<=? ORDER BY tick DESC LIMIT 1',
                          (meter, at)).fetchone()
    except sqlite3.OperationalError:
        return None


def evaluate_meter(db, meter, at):
    """Return the fresh, uniformly-corrected reading for one meter.

    Materialises the applied correction into ``cooling_corrections`` so every
    correction is traceable after a restart.  A missing or stale sample is
    reported explicitly so callers can never inherit an old good reading.
    """
    row = latest_row(db, meter, at)
    if row is None:
        return {'meter': meter, 'available': False, 'fresh': False,
                'tick': None, 'raw_flow': None, 'corrected_flow': None,
                'temp_c': None, 'cal_id': None, 'bias_lpm': 0}
    _, _, loop, tick, raw_flow, temp_c = row
    cal = active_calibration(db, meter, at)
    bias = cal['bias_lpm'] if cal else 0
    corrected = max(0, raw_flow - bias)
    if cal:
        with db:
            db.execute('INSERT OR IGNORE INTO cooling_corrections VALUES (?,?,?,?,?)',
                       (cal['cal_id'], meter, tick, raw_flow, corrected))
    return {'meter': meter, 'loop': loop, 'available': True,
            'fresh': tick >= at - FRESHNESS_WINDOW, 'tick': tick,
            'raw_flow': raw_flow, 'corrected_flow': corrected, 'temp_c': temp_c,
            'cal_id': cal['cal_id'] if cal else None, 'bias_lpm': bias}


def supply_balance(db, main_meter, branch_meters, at,
                   tolerance=DEFAULT_BALANCE_TOLERANCE):
    """Cross-check physical flow using supply meters only.

    Return/bypass meters are not part of the split and must never be passed in
    here.  All readings use the same batch calibration, so a common zero bias
    moves header and branches together; residual imbalance beyond the site
    tolerance means the pages are physically inconsistent.
    """
    readings = [evaluate_meter(db, m, at) for m in [main_meter, *branch_meters]]
    main_reading, branch_readings = readings[0], readings[1:]
    if not all(r['available'] and r['fresh'] for r in readings):
        return {'ok': False, 'reason': 'sample_missing_or_stale',
                'main': main_reading, 'branches': branch_readings,
                'imbalance': None, 'tolerance': tolerance}
    branches_sum = sum(r['corrected_flow'] for r in branch_readings)
    imbalance = main_reading['corrected_flow'] - branches_sum
    return {'ok': abs(imbalance) <= tolerance,
            'reason': 'balanced' if abs(imbalance) <= tolerance else 'mass_balance',
            'main': main_reading, 'branches': branch_readings,
            'branches_sum': branches_sum, 'imbalance': imbalance,
            'tolerance': tolerance}
