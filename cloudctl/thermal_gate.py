"""Cooling release tickets.

The header-level ticket only proves the shared main has water; it can never by
itself prove a branch cabinet is safe.  ``header_ticket`` keeps the original
provisional semantics but carries the corrected reading and calibration
evidence so ``cabinet_gate`` can record it as one input among many.
"""
import sqlite3

from .cooling_capture import evaluate_meter

HEADER_MIN_FLOW = 80
MAX_RETURN_TEMP = 30


def release(db, loop, at):
    db.execute('CREATE TABLE IF NOT EXISTS thermal_releases (loop TEXT,at INTEGER,flow_lpm INTEGER,temp_c INTEGER)')
    try:
        row = db.execute('SELECT flow_lpm,temp_c FROM cooling_rows WHERE loop=? ORDER BY tick DESC LIMIT 1', (loop,)).fetchone()
    except sqlite3.OperationalError:
        row = None
    if not row or row[0] < HEADER_MIN_FLOW or row[1] > MAX_RETURN_TEMP:
        return {'decision': 'hold', 'loop': loop}
    with db:
        db.execute('INSERT INTO thermal_releases VALUES (?,?,?,?)', (loop, at, row[0], row[1]))
    return {'decision': 'released', 'loop': loop, 'flow_lpm': row[0]}


def header_ticket(db, main_meter, at):
    """Header cooling ticket with corrected, freshness-checked evidence."""
    db.execute('CREATE TABLE IF NOT EXISTS thermal_header_tickets ('
               'at INTEGER,meter TEXT,decision TEXT,raw_flow INTEGER,'
               'corrected_flow INTEGER,temp_c INTEGER,cal_id TEXT,PRIMARY KEY(at,meter))')
    reading = evaluate_meter(db, main_meter, at)
    if not reading['available'] or not reading['fresh']:
        decision, reason = 'hold', 'sample_missing_or_stale'
    elif reading['corrected_flow'] < HEADER_MIN_FLOW:
        decision, reason = 'hold', 'header_flow_low'
    elif reading['temp_c'] > MAX_RETURN_TEMP:
        decision, reason = 'hold', 'return_temp_high'
    else:
        decision, reason = 'released', 'header_flow_ok'
    with db:
        db.execute('INSERT OR IGNORE INTO thermal_header_tickets VALUES (?,?,?,?,?,?,?)',
                   (at, main_meter, decision, reading['raw_flow'],
                    reading['corrected_flow'], reading['temp_c'], reading['cal_id']))
    return {'decision': decision, 'reason': reason, 'meter': main_meter,
            'reading': reading}
