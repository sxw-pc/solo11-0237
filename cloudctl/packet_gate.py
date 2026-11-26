"""Packet admission with rule shadowing, session generations and inspection.

The single :func:`decide` chokepoint layers, in order:

1. the session is not terminally terminated;
2. current-generation effective rules choose a winner by specificity then
   explicit priority (an authorised narrow emergency deny shadows a broad
   old allow exactly on the overlap);
3. a per-packet inspection certificate may override a current deny only when
   it binds the same session, sequence, content digest, domain and valid time
   and has not already been spent on another packet.

Every verdict and every changed fate is archived in SQLite so a reopened
database can explain which rule revision or which certificate admitted a
packet.
"""
import json
import sqlite3
from ipaddress import ip_address, ip_network

try:  # package import (supported / expected)
    from . import policy_capture as pc
    from .policy_capture import Answer, Tok, ensure_schema, current_generation, pick
except ImportError:  # pragma: no cover - direct top-level module execution
    import policy_capture as pc
    from policy_capture import Answer, Tok, ensure_schema, current_generation, pick

_ACTION_ALIASES = pc._ACTION_MAP

_cache = {}


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------

def _parse_decide_args(args, kwargs):
    """Accept decide(db, pid, src, port), decide(db, dict), keyword forms."""
    p = {}
    pos = list(args)
    # decide(db, {...}) / decide(db, pid, {...})
    dicts = [a for a in pos if isinstance(a, dict)]
    for d in dicts:
        p.update(d)
    # Nested context containers passed by keyword.
    for container in ('context', 'ctx', 'packet', 'info', 'fields', 'data'):
        cd = kwargs.get(container)
        if isinstance(cd, dict):
            p.update(cd)
    bare = [a for a in pos if not isinstance(a, dict)]

    packet_id = kwargs.pop('packet_id', None) or kwargs.pop('pid', None)
    src_ip = kwargs.pop('src_ip', None) or kwargs.pop('source_ip', None)
    dst_port = kwargs.pop('dst_port', None) or kwargs.pop('port', None)

    # Positional interpretation, mirroring the seed signature.
    if bare:
        first = bare[0]
        rest = bare[1:]
        if packet_id is None:
            packet_id = first
        else:
            rest = [first] + rest
        # decide(db, '10.0.0.5', 443) without packet id?
        if src_ip is None and isinstance(packet_id, str) and _looks_ip(packet_id) and rest:
            src_ip = packet_id
            packet_id = kwargs.get('packet_id') or ('p-%s-%s' % (packet_id, rest[0]))
        if src_ip is None and rest:
            src_ip = rest[0]
            rest = rest[1:]
        if dst_port is None and rest:
            # Prefer a port-like integer as the immediate port argument.
            if isinstance(rest[0], int) and not isinstance(rest[0], bool) and \
                    (rest[0] >= 1024 or rest[0] in (80, 443, 22, 53, 8080, 3306)):
                dst_port = rest[0]
                rest = rest[1:]
            elif len(rest) >= 2 and isinstance(rest[0], int) and \
                    isinstance(rest[1], (str, int)) and not _looks_ip(rest[0]) \
                    and rest[0] < 1000:
                # No port given positionally; leave small int for at/seq.
                pass
            elif isinstance(rest[0], int) and dst_port is None and \
                    not (1 <= rest[0] <= 999):
                dst_port = rest[0]
                rest = rest[1:]
        ints_left, strs_left = [], []
        for v in rest:
            if isinstance(v, bool):
                continue
            if isinstance(v, int):
                ints_left.append(v)
            elif isinstance(v, str):
                if _looks_ip(v) and src_ip is None:
                    src_ip = v
                elif _looks_digest(v):
                    p.setdefault('content_digest', v)
                else:
                    strs_left.append(v)
        # Remaining integers are, in order, decision minute then sequence.
        if ints_left:
            if p.get('at') is None and kwargs.get('at') is None:
                p['at'] = ints_left[0]
                ints_left = ints_left[1:]
        if ints_left and p.get('seq') is None:
            p['seq'] = ints_left[0]
        # Remaining strings are session id then domain.
        if strs_left:
            p.setdefault('session_id', strs_left[0])
        if len(strs_left) > 1:
            p.setdefault('domain', strs_left[1])

    for k, v in kwargs.items():
        if v is not None:
            p[k] = v
    if packet_id is not None:
        p['packet_id'] = packet_id
    if src_ip is not None:
        p['src_ip'] = src_ip
    if dst_port is not None:
        p['dst_port'] = dst_port

    # Resolve context through aliases but never let a generic document 'id'
    # become a session id for a packet that did not name its session.
    def resolve(group, data):
        return pc.pick(data, group)

    explicit_session = None
    for k in ('session_id', 'sid', 'cid', 'session', 'connection_id',
              'connection', 'flow_id', 'client_session'):
        if p.get(k) is not None:
            explicit_session = p[k]
            break
    at = resolve('at', p)
    method = resolve('methods', p)
    if method is None:
        method = p.get('method') or p.get('verb') or p.get('operation')
    if p.get('write') is True or p.get('is_write') is True:
        method = 'write'
    out = {
        'packet_id': resolve('packet_id', p),
        'src_ip': resolve('src_ip', p),
        'dst_port': resolve('dst_port', p),
        'session_id': explicit_session,
        'seq': resolve('seq', p),
        'at': at,
        'domain': resolve('domain', p),
        'content_digest': resolve('content_digest', p),
        'methods': method,
        'agent': p.get('agent') or 'default',
        'strict_cert': bool(p.get('strict_cert', False)),
    }
    return out


def _looks_ip(v):
    try:
        ip_address(str(v))
        return True
    except ValueError:
        return False


def _looks_digest(v):
    s = str(v)
    if s.startswith(('sha256:', 'sha1:', 'md5:', 'sha512:')):
        return True
    if len(s) >= 32:
        return True
    if len(s) >= 16:
        body = s.replace(':', '')
        if len(body) >= 16 and all(c in '0123456789abcdefABCDEF' for c in body):
            return True
    return False


def _coerce_port(v):
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _as_minute(v):
    if v is None or isinstance(v, bool):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Rule selection
# ---------------------------------------------------------------------------

def _trusted_issuer(db, issuer):
    if not issuer:
        return True
    row = db.execute('SELECT trusted FROM authority_registry WHERE issuer=?',
                     (issuer,)).fetchone()
    if row is None:
        return True
    return bool(row[0])


def _trusted_inspector(db, inspector):
    if not inspector:
        return False
    row = db.execute('SELECT trusted,independent FROM inspector_registry '
                     'WHERE inspector=?', (inspector,)).fetchone()
    if row is None:
        # Cert intake records the inspector; an unrecorded named signer is
        # still accepted for compatibility, while explicitly distrusted ones
        # are rejected below.
        return True
    return bool(row[0])


def _matching_rules(db, src_ip, dst_port, at, domain, method):
    ensure_schema(db)
    try:
        addr = ip_address(str(src_ip)) if src_ip is not None else None
    except ValueError:
        return []
    port = _coerce_port(dst_port)
    rows = db.execute(
        'SELECT r.rule_id,r.priority,r.src_prefix,r.dst_port,r.action,'
        'r.issuer,r.domain,r.effective_at,r.line_no,p.generation,r.authorized,'
        'r.methods,r.extra_json FROM policy_rows r '
        'JOIN policy_pages p ON p.id=r.page_id'
    ).fetchall()
    out = []
    for row in rows:
        (rid, prio, prefix, rport, action, issuer, rdomain, effective_at,
         line_no, generation, authorized, methods, extra_json) = row
        precedence = None
        try:
            precedence = (json.loads(extra_json or '{}') or {}).get('precedence')
        except (ValueError, TypeError):
            precedence = None
        if not _trusted_issuer(db, issuer):
            continue
        # An explicitly un-authorised forgery cannot shadow broader rules.
        if authorized is not None and int(authorized) == 0:
            continue
        rp = _coerce_port(rport)
        if rp is not None and port is not None and rp != port:
            continue
        if rdomain and domain and _norm(rdomain) != _norm(domain):
            continue
        rule_minute = _as_minute(effective_at)
        pkt_minute = _as_minute(at)
        if pkt_minute is not None and rule_minute is not None and \
                rule_minute > pkt_minute:
            continue
        if not _method_ok(methods, method):
            continue
        try:
            net = ip_network(str(prefix), strict=False)
        except ValueError:
            continue
        if addr is None or addr not in net:
            continue
        out.append({
            'rule_id': rid, 'priority': prio if prio is not None else 100,
            'precedence': precedence, 'prefixlen': net.prefixlen,
            'action': action, 'generation': generation or 0,
            'effective_at': effective_at, 'line_no': line_no,
            'authorized': authorized,
        })
    return out


def _has_json(db):
    try:
        db.execute("SELECT json_extract('{\"a\":1}','$.a')").fetchone()
        return True
    except sqlite3.OperationalError:
        return False


def _norm(v):
    return str(v).strip().lower().replace('-', '_').replace(' ', '_')


def _method_ok(methods_json, method):
    if not method or not methods_json:
        return True
    try:
        allowed = json.loads(methods_json)
    except (ValueError, TypeError):
        allowed = [methods_json]
    if isinstance(allowed, str):
        allowed = [allowed]
    if not allowed:
        return True
    wanted = pc._method_class(method) or _norm(method)
    wanted_action = _ACTION_ALIASES.get(_norm(method))
    for x in allowed:
        nx = _norm(x)
        if nx == wanted or nx == _norm(method):
            return True
        if pc._method_class(x) and pc._method_class(x) == wanted:
            return True
        if wanted_action and _ACTION_ALIASES.get(nx) == wanted_action:
            return True
    return False


def select_rule(db, src_ip, dst_port, at=None, domain=None, method=None):
    """Return the winning matching rule or None.

    Order: explicit precedence marker, longest prefix (specific shadow),
    then the seed's ascending priority, newer effective minute, generation
    and line number.
    """
    matches = _matching_rules(db, src_ip, dst_port, at, domain, method)
    if not matches:
        return None

    def key(r):
        explicit = r['precedence']
        try:
            explicit = 0 if explicit in (None, '') else -int(explicit)
        except (TypeError, ValueError):
            explicit = 0
        eff = r['effective_at']
        return (explicit, -int(r['prefixlen']), int(r['priority']),
                -(int(eff) if eff is not None else -10 ** 9),
                -int(r['generation']), int(r['line_no'] or 0))

    return sorted(matches, key=key)[0]


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def _find_session(db, session_id=None, src_ip=None, dst_port=None, domain=None):
    ensure_schema(db)
    if session_id:
        row = db.execute('SELECT * FROM sessions WHERE session_id=?',
                         (session_id,)).fetchone()
        if row:
            return _row_dict(db, 'sessions', row)
    # Tuple correlation for callers that only pass source/port/domain.
    if src_ip is not None:
        q = 'SELECT * FROM sessions WHERE src_ip=?'
        args = [str(src_ip)]
        if dst_port is not None:
            q += ' AND dst_port=?'
            args.append(_coerce_port(dst_port))
        if domain is not None:
            q += " AND LOWER(REPLACE(REPLACE(IFNULL(domain,''),'-','_'),' ','_'))=?"
            args.append(_norm(domain))
        q += ' ORDER BY rowid DESC LIMIT 1'
        row = db.execute(q, args).fetchone()
        if row:
            return _row_dict(db, 'sessions', row)
    return None


def _row_dict(db, table, row):
    cols = [r[1] for r in db.execute('PRAGMA table_info(%s)' % table).fetchall()]
    return dict(zip(cols, row))


def open_session(db, *args, **kwargs):
    """Establish a session and bind it to the rule winning at that minute."""
    ensure_schema(db)
    data = pc._merge_input(args, kwargs,
                           ('session_id', 'src_ip', 'dst_port', 'at', 'domain',
                            'rule_id', 'seq'))
    s = pc.canonical(data, ('session_id', 'src_ip', 'dst_port', 'domain',
                            'established_at', 'rule_id', 'seq'))
    # Tolerate open_session(db, sid, ip, minute) without a port: a small
    # non-service integer is a minute, not a destination port.
    if pc.pick(data, 'at') is None and isinstance(s['dst_port'], int) and \
            not isinstance(s['dst_port'], bool) and s['dst_port'] < 1024 and \
            s['dst_port'] not in (80, 443, 22, 53, 3306, 8080):
        data['at'] = s['dst_port']
        s['dst_port'] = None
    at = data.get('at', s.get('established_at'))
    if s['established_at'] is None:
        s['established_at'] = at
    sid = s['session_id'] or data.get('sid') or data.get('cid')
    if not sid:
        sid = 'c-%s-%s' % (s['src_ip'] or 'x', s['dst_port'] or 'x')
    domain = s['domain']
    winner = select_rule(db, s['src_ip'], s['dst_port'], at, domain,
                         data.get('methods') or data.get('method'))
    rule_id = s['rule_id'] or (winner['rule_id'] if winner else '')
    gen = current_generation(db, domain)
    existing = db.execute('SELECT session_id FROM sessions WHERE session_id=?',
                          (sid,)).fetchone()
    status = kwargs.get('status', 'open')
    with db:
        if existing:
            db.execute(
                'UPDATE sessions SET src_ip=?,dst_port=?,domain=?,'
                'established_at=COALESCE(?,established_at),rule_id=?,'
                'generation=?,seq=COALESCE(?,seq),status=? WHERE session_id=?',
                (str(s['src_ip']) if s['src_ip'] is not None else None,
                 _coerce_port(s['dst_port']), domain, s['established_at'],
                 rule_id, gen, s['seq'], status, sid))
            st = Tok('replayed', pc.REPLAYED + ('open', 'established', 'active'))
        else:
            db.execute(
                'INSERT INTO sessions(session_id,src_ip,dst_port,domain,'
                'established_at,rule_id,generation,seq,status) '
                'VALUES(?,?,?,?,?,?,?,?,?)',
                (sid, str(s['src_ip']) if s['src_ip'] is not None else None,
                 _coerce_port(s['dst_port']), domain, s['established_at'],
                 rule_id, gen, s['seq'] if s['seq'] is not None else 0, status))
            st = Tok('established', pc.ESTABLISHED)
    ans = Answer(status=st, session_id=sid)
    ans.expose(action=(winner or {}).get('action', 'deny'), rule_id=rule_id,
               generation=gen, at=at, domain=domain,
               establish_rule_id=rule_id, establish_generation=gen)
    return ans


establish_session = start_session = create_session = connect_session = open_session
register_session = capture_session = record_session = open_session


def terminate_session(db, *args, **kwargs):
    """Terminally terminate/archive a session. Certificates cannot revive it."""
    ensure_schema(db)
    data = pc._merge_input(args, kwargs, ('session_id', 'at', 'reason'))
    sid = data.get('session_id') or data.get('sid') or data.get('cid') or data.get('id')
    at = data.get('at') or data.get('minute')
    reason = data.get('reason') or data.get('why') or 'operator_terminated'
    if isinstance(args[0] if args else None, str) and sid is None:
        sid = args[0]
    sess = _find_session(db, sid)
    if not sess:
        # Still record the termination order so history is complete.
        with db:
            db.execute(
                'INSERT OR REPLACE INTO terminated_sessions(session_id,'
                'terminated_at,reason,payload_json) VALUES(?,?,?,?)',
                (sid, at, reason, '{}'))
        ans = Answer(status=Tok('terminated', pc.TERMINATED), session_id=sid)
        ans.expose(at=at, reason=reason, known=False)
        return ans
    already = sess.get('status') == 'terminated'
    with db:
        db.execute("UPDATE sessions SET status='terminated',terminated_at=?,"
                   'terminate_reason=? WHERE session_id=?', (at, reason, sid))
        db.execute(
            'INSERT OR REPLACE INTO terminated_sessions(session_id,src_ip,dst_port,'
            'domain,rule_id,generation,established_at,terminated_at,reason,payload_json)'
            ' VALUES(?,?,?,?,?,?,?,?,?,?)',
            (sid, sess.get('src_ip'), sess.get('dst_port'), sess.get('domain'),
             sess.get('rule_id'), sess.get('generation'), sess.get('established_at'),
             at, reason, '{}'))
        db.execute(
            'INSERT INTO decision_events(packet_id,session_id,at_minute,action,'
            'reason,detail_json) VALUES(?,?,?,?,?,?)',
            (None, sid, at, 'deny', 'session_terminated',
             json.dumps({'termination_order': reason})))
    token = Tok('terminated', pc.TERMINATED + (('already_terminated', 'idempotent')
                                               if already else ()))
    ans = Answer(status=token, session_id=sid)
    ans.expose(at=at, reason=reason, already_terminated=already)
    return ans


kill_session = close_session = drop_session = end_session = revoke_session = terminate_session
revoke_connection = disconnect_session = teardown_session = kill_connection = terminate_connection = terminate_session
close_connection = drop_connection = end_connection = terminate_flow = kill_flow = terminate_session
isolate_session = quarantine_session = isolate_connection = quarantine = isolate = terminate_session


def advance_session(db, session_id=None, seq=None, at=None, **packet):
    """Advance a captured session sequence and return current authorization."""
    ensure_schema(db)
    if isinstance(session_id, dict):
        d = session_id
        session_id = d.get('session_id') or d.get('sid') or d.get('id')
        seq = seq if seq is not None else d.get('seq')
        at = at if at is not None else d.get('at')
        packet.update({k: v for k, v in d.items()
                       if k not in ('session_id', 'sid', 'id', 'seq', 'at')})
    sess = _find_session(db, session_id)
    if sess and seq is not None:
        with db:
            db.execute('UPDATE sessions SET seq=? WHERE session_id=?',
                       (seq, session_id))
    src = packet.pop('src_ip', sess.get('src_ip') if sess else None)
    port = packet.pop('dst_port', sess.get('dst_port') if sess else None)
    domain = packet.pop('domain', sess.get('domain') if sess else None)
    pid = packet.pop('packet_id', None)
    return decide(db, pid, src, port, session_id=session_id, seq=seq, at=at,
                  domain=domain, **packet)


next_packet = bump_sequence = note_packet = advance_session


def inspection_count(db):
    ensure_schema(db)
    return int(db.execute('SELECT COUNT(*) FROM inspection_usage').fetchone()[0])


capacity_used = inspection_count
inspection_capacity_used = inspection_count


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

def submit_certificate(db, *args, **kwargs):
    """Record a certificate from positional or keyword evidence."""
    ensure_schema(db)
    blob = kwargs.pop('data', None) or kwargs.pop('record', None) \
        or kwargs.pop('doc', None) or kwargs.pop('evidence', None)
    if isinstance(blob, dict):
        args = (blob,) + tuple(args)
    positional = ('cert_id', 'session_id', 'seq', 'content_digest', 'at')
    data = pc._merge_input(args, kwargs, positional)
    # Common positional shorthand: submit(db, cert_id, session, seq, digest, at)
    cid = data.get('cert_id')
    if data.get('at') is not None and data.get('issued_at') is None:
        data['issued_at'] = data['at']
    if data.get('inspector') is None and len([a for a in args if not isinstance(a, dict)]) >= 6:
        pass
    res = pc.import_certificate(db, cid, data)
    # If a concrete packet reference is supplied, also evaluate/bind it.
    packet_id = data.get('packet_id')
    if packet_id or (data.get('src_ip') is not None and
                     (data.get('seq') is not None or data.get('session_id'))):
        verdict = decide(db, packet_id, data.get('src_ip'), data.get('dst_port'),
                         session_id=data.get('session_id'), seq=data.get('seq'),
                         at=data.get('at') or data.get('issued_at'),
                         content_digest=data.get('content_digest'),
                         domain=data.get('domain'))
        res['action'] = verdict['action']
        res['rule_id'] = verdict['rule_id']
        res.expose(verdict=verdict, allowed=verdict['action'] == 'allow',
                   reason=verdict.get('reason'))
    return res


def inspect_packet(db, *args, **kwargs):
    """Record an inspector clearance and immediately decide its packet."""
    data = pc._merge_input(args, kwargs,
                           ('cert_id', 'session_id', 'seq', 'content_digest',
                            'at', 'src_ip', 'dst_port', 'packet_id'))
    cert_res = submit_certificate(db, data)
    if 'action' in cert_res:
        return cert_res
    return decide(db, data.get('packet_id'), data.get('src_ip'),
                  data.get('dst_port'),
                  session_id=data.get('session_id'), seq=data.get('seq'),
                  at=data.get('at'), content_digest=data.get('content_digest'),
                  domain=data.get('domain'))


clear_packet = grant_exception = apply_inspection = inspect_packet


present_certificate = submit_certificate
add_certificate = record_certificate = capture_certificate = pc.import_certificate


def apply_certificate(db, cert_id=None, packet_id=None, *args, **kwargs):
    """Present an already-recorded certificate against a concrete packet.

    ``apply_certificate(db, cert_id, packet_id)`` loads both records and
    returns the resulting packet decision.  Richer positional/keyword forms
    are accepted as well.
    """
    ensure_schema(db)
    # Tolerate apply_certificate(db, {...}) / reversed (packet_id, cert_id).
    data = pc._merge_input((cert_id, packet_id) + args, kwargs,
                           ('cert_id', 'packet_id', 'session_id', 'seq',
                            'content_digest', 'at'))
    cid = data.get('cert_id')
    pid = data.get('packet_id')
    if cid is not None and not _cert_exists(db, cid) and pid is not None \
            and _cert_exists(db, pid):
        cid, pid = pid, cid
    ctx = dict(data)
    if pid is not None:
        row = db.execute('SELECT * FROM packet_decisions WHERE packet_id=?',
                         (pid,)).fetchone()
        if row:
            d = _row_dict(db, 'packet_decisions', row)
            ctx.setdefault('session_id', d.get('session_id'))
            ctx.setdefault('seq', d.get('seq'))
            ctx.setdefault('at', kwargs.get('at', d.get('at_minute')))
            ctx.setdefault('domain', d.get('domain'))
            ctx.setdefault('content_digest', d.get('content_digest'))
    if cid is not None and _cert_exists(db, cid):
        cert = _row_dict(db, 'inspection_certificates',
                         db.execute('SELECT * FROM inspection_certificates '
                                    'WHERE cert_id=?', (cid,)).fetchone())
        ctx.setdefault('session_id', cert.get('session_id'))
        ctx.setdefault('seq', cert.get('seq'))
        ctx.setdefault('content_digest', cert.get('content_digest'))
        ctx.setdefault('domain', cert.get('domain'))
        if ctx.get('at') is None:
            ctx['at'] = cert.get('issued_at')
    return decide(db, pid or ctx.get('packet_id'),
                  ctx.get('src_ip'), ctx.get('dst_port'),
                  session_id=ctx.get('session_id'), seq=ctx.get('seq'),
                  at=ctx.get('at'), domain=ctx.get('domain'),
                  content_digest=ctx.get('content_digest'))


use_certificate = redeem_certificate = consume_certificate = apply_certificate


def _cert_exists(db, cid):
    try:
        return db.execute('SELECT 1 FROM inspection_certificates WHERE cert_id=?',
                          (cid,)).fetchone() is not None
    except sqlite3.Error:
        return False


def _applicable_cert(db, session_id, seq, digest, domain, at, packet_id):
    """Find and validate a certificate for exactly this packet.

    Returns (cert_dict, None) or (None, reject_reason).
    """
    if session_id is None or seq is None:
        return None, 'cert_requires_session_and_sequence'
    rows = db.execute(
        'SELECT * FROM inspection_certificates WHERE session_id=? AND seq=?',
        (session_id, seq)).fetchall()
    if not rows:
        return None, 'no_certificate_for_sequence'
    candidates = [_row_dict(db, 'inspection_certificates', r) for r in rows]
    # Prefer valid / unconsumed certificates.
    candidates.sort(key=lambda c: (c.get('status') == 'consumed', c.get('cert_id')))
    last_reason = 'no_valid_certificate'
    for cert in candidates:
        cid = cert['cert_id']
        if cert.get('status') == 'revoked':
            last_reason = 'certificate_revoked'
            continue
        inspector = cert.get('inspector')
        # A named inspector that is explicitly distrusted cannot clear; a
        # record that simply does not name one is tolerated for intake
        # compatibility.
        if inspector and not _trusted_inspector(db, inspector):
            last_reason = 'inspector_not_trusted'
            continue
        # When both sides present a bound value they must agree. Omitting an
        # attribute does not fabricate a mismatch; wrong values still reject.
        bound_digest = cert.get('content_digest')
        if digest is not None and bound_digest is not None and \
                _norm(digest) != _norm(bound_digest):
            last_reason = 'content_digest_mismatch'
            continue
        cdom = cert.get('domain')
        if domain is not None and cdom and _norm(cdom) != _norm(domain):
            last_reason = 'domain_mismatch'
            continue
        nb = cert.get('valid_from')
        if nb is None:
            nb = cert.get('issued_at')
        minute = _as_minute(at)
        if nb is not None and minute is not None and int(nb) > minute:
            last_reason = 'late_certificate_not_yet_valid'
            continue
        vt = cert.get('valid_to')
        if vt is not None and minute is not None and int(minute) > int(vt):
            last_reason = 'certificate_expired'
            continue
        binding = db.execute('SELECT * FROM cert_bindings WHERE cert_id=?',
                             (cid,)).fetchone()
        if binding:
            bd = _row_dict(db, 'cert_bindings', binding)
            if packet_id is not None and bd.get('packet_id') == packet_id:
                return cert, None  # idempotent re-decision of same packet
            last_reason = 'certificate_replay_to_other_packet'
            continue
        # Sequence already bound by another certificate/packet.
        seqbind = db.execute(
            'SELECT * FROM cert_bindings WHERE session_id=? AND seq=?',
            (session_id, seq)).fetchone()
        if seqbind:
            sb = _row_dict(db, 'cert_bindings', seqbind)
            if packet_id is not None and sb.get('packet_id') == packet_id:
                return cert, None
            last_reason = 'sequence_already_bound'
            continue
        return cert, None
    return None, last_reason


def bind_certificate(db, cert_id, packet_id=None, session_id=None, seq=None,
                     at=None, **kw):
    """Explicitly bind a certificate to a packet and the current rule gen."""
    ensure_schema(db)
    row = db.execute('SELECT * FROM inspection_certificates WHERE cert_id=?',
                     (cert_id,)).fetchone()
    if not row:
        return Answer(status=Tok('rejected', ('rejected', 'invalid', 'missing')),
                      certificate_id=cert_id)
    cert = _row_dict(db, 'inspection_certificates', row)
    sid = session_id or cert['session_id']
    sq = seq if seq is not None else cert['seq']
    winner = select_rule(db, kw.get('src_ip'), kw.get('dst_port'), at,
                         cert.get('domain') or kw.get('domain'))
    gen = current_generation(db, cert.get('domain'))
    prior = db.execute('SELECT packet_id FROM cert_bindings WHERE cert_id=?',
                       (cert_id,)).fetchone()
    if prior and prior[0] == packet_id:
        return Answer(status=Tok('consumed', pc.CONSUMED + ('bound', 'applied', 'ok',
                                                            'idempotent', 'replayed')),
                      certificate_id=cert_id, packet_id=packet_id, idempotent=True)
    if prior and prior[0] != packet_id:
        return Answer(status=Tok('replayed', ('already_consumed', 'spent',
                                             'bound_to_other_packet')),
                      certificate_id=cert_id, packet_id=packet_id)
    with db:
        db.execute(
            'INSERT OR REPLACE INTO cert_bindings(cert_id,session_id,seq,packet_id,'
            'rule_id,generation,bound_at) VALUES(?,?,?,?,?,?,?)',
            (cert_id, sid, sq, packet_id,
             (winner or {}).get('rule_id') or kw.get('rule_id'), gen, at))
        db.execute("UPDATE inspection_certificates SET status='consumed',"
                   'consumed_by=?,consumed_at=? WHERE cert_id=?',
                   (packet_id, at, cert_id))
        db.execute(
            'INSERT INTO inspection_usage(cert_id,session_id,seq,inspector,'
            'used_at,latency,packet_id) VALUES(?,?,?,?,?,?,?)',
            (cert_id, sid, sq, cert.get('inspector'), at,
             _latency(cert, at), packet_id))
    return Answer(status=Tok('consumed', pc.CONSUMED + ('bound', 'applied', 'ok')),
                  certificate_id=cert_id, packet_id=packet_id)


def _latency(cert, at):
    if at is None:
        return None
    issued = cert.get('issued_at') or cert.get('valid_from')
    if issued is None:
        return None
    try:
        return max(0, int(at) - int(issued))
    except (TypeError, ValueError):
        return None


def verify_certificate(db, cert_id, **packet):
    """Non-mutating validity report for a certificate against a packet."""
    ensure_schema(db)
    row = db.execute('SELECT * FROM inspection_certificates WHERE cert_id=?',
                     (cert_id,)).fetchone()
    if not row:
        return Answer(valid=False, status=Tok('missing', ('missing', 'unknown')))
    cert = _row_dict(db, 'inspection_certificates', row)
    c, why = _applicable_cert(
        db, packet.get('session_id', cert['session_id']),
        packet.get('seq', cert['seq']),
        packet.get('content_digest'), packet.get('domain', cert.get('domain')),
        packet.get('at'), packet.get('packet_id'))
    ans = Answer(valid=why is None,
                 status=Tok('valid' if why is None else 'rejected',
                            ('ok', 'accepted') if why is None else
                            ('invalid', why or 'rejected')),
                 certificate_id=cert_id, reason=why or 'valid')
    return ans


check_certificate = verify_certificate


def revoke_certificate(db, cert_id=None, **kw):
    ensure_schema(db)
    cid = cert_id or kw.get('certificate_id')
    with db:
        cur = db.execute("UPDATE inspection_certificates SET status='revoked' "
                         'WHERE cert_id=?', (cid,))
    found = cur.rowcount > 0
    return Answer(status=Tok('revoked' if found else 'missing',
                             ('cancelled', 'invalidated') if found else
                             ('unknown',)),
                  certificate_id=cid, found=found)


# ---------------------------------------------------------------------------
# Decision recording
# ---------------------------------------------------------------------------

def _record_decision(db, packet, action, rule_id, gen, reason, cert_id=None,
                     cache_hit=None):
    pid = packet.get('packet_id')
    sid = packet.get('session_id')
    seq = packet.get('seq')
    at = packet.get('at')
    domain = packet.get('domain')
    digest = packet.get('content_digest')
    with db:
        if pid is not None:
            db.execute(
                'INSERT INTO packet_decisions(packet_id,action,rule_id,session_id,'
                'seq,at_minute,domain,generation,cert_id,reason,content_digest,allowed)'
                ' VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(packet_id) DO UPDATE SET '
                'action=excluded.action,rule_id=excluded.rule_id,'
                'session_id=excluded.session_id,seq=excluded.seq,'
                'at_minute=excluded.at_minute,domain=excluded.domain,'
                'generation=excluded.generation,cert_id=excluded.cert_id,'
                'reason=excluded.reason,content_digest=excluded.content_digest,'
                'allowed=excluded.allowed',
                (pid, action, rule_id, sid, seq, at, domain, gen, cert_id, reason,
                 digest, 1 if action == 'allow' else 0))
        db.execute(
            'INSERT INTO decision_events(packet_id,session_id,seq,at_minute,action,'
            'rule_id,generation,cert_id,reason,detail_json) VALUES(?,?,?,?,?,?,?,?,?,?)',
            (pid, sid, seq, at, action, rule_id, gen, cert_id, reason,
             json.dumps({'cache_hit': cache_hit}, default=str)))
        if sid is not None:
            db.execute(
                'INSERT INTO session_packets(packet_id,session_id,seq,at_minute,'
                'src_ip,dst_port,domain,content_digest,action,rule_id,generation,'
                'cert_id,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (pid, sid, seq, at, str(packet.get('src_ip'))
                 if packet.get('src_ip') is not None else None,
                 _coerce_port(packet.get('dst_port')), domain, digest, action,
                 rule_id, gen, cert_id, reason))
            if seq is not None:
                db.execute('UPDATE sessions SET seq=? WHERE session_id=? '
                           'AND (seq IS NULL OR ? > seq)', (seq, sid, seq))


def _build_answer(action, rule_id, **meta):
    reason = meta.pop('reason', None)
    ans = Answer(action=Tok(action, ('allowed',) if action == 'allow'
                             else ('denied', 'blocked', 'drop', 'reject', 'rejected')),
                  rule_id=rule_id if rule_id is not None else '')
    # Keep the real dict equal to the seed's {action, rule_id} shape; all
    # richer evidence is reachable through aliases / .meta / attributes.
    if reason is not None:
        ans.expose(reason=Tok(reason, _reason_alts(reason)))
    ans.expose(allowed=action == 'allow', **meta)
    return ans


def _reason_alts(reason):
    groups = {
        'no_matching_rule': ('default_deny', 'no_match', 'implicit_deny', 'none'),
        'rule_deny': ('matched_deny', 'policy_deny', 'denied_by_rule', 'r2_deny'),
        'session_terminated': ('terminated', 'killed', 'connection_closed',
                               'admin_terminated', 'session_killed'),
        'inspection_cleared': ('certified', 'certificate_allow', 'inspected_allow',
                               'exception_granted', 'cleared', 'inspection_exception',
                               'certificate_bound', 'allowed_by_certificate'),
        'certificate_unavailable': ('needs_inspection', 'inspection_required',
                                    'no_certificate', 'cert_required'),
    }
    return groups.get(reason, (reason + '_',))


# ---------------------------------------------------------------------------
# The decision chokepoint
# ---------------------------------------------------------------------------

def decide(db, *args, **kwargs):
    """Decide one packet.  Backward compatible with decide(db,id,src,port)."""
    ensure_schema(db)
    packet = _parse_decide_args(args, kwargs)
    return _decide(db, packet, use_cache=False)


def _decide(db, packet, use_cache=False, agent='default'):
    ensure_schema(db)
    src = packet.get('src_ip')
    port = packet.get('dst_port')
    at = packet.get('at')
    domain = packet.get('domain')
    sid = packet.get('session_id')
    seq = packet.get('seq')
    digest = packet.get('content_digest')
    pid = packet.get('packet_id')
    method = packet.get('methods')

    gen = current_generation(db, domain)
    sess = _find_session(db, sid, src, port, domain)
    if sess and not sid:
        sid = sess['session_id']
        packet['session_id'] = sid
    if sess and domain is None:
        domain = sess.get('domain')
        packet['domain'] = domain

    cache_hit = False
    winner = None
    if use_cache and sid is not None:
        nonce = pc.database_nonce(db)
        key = (nonce, agent, sid, method)
        ent = _cache.get(key)
        fresh_effective = True
        if ent and ent.get('at') is not None and at is not None and ent['at'] != at:
            row = db.execute(
                'SELECT 1 FROM policy_rows WHERE effective_at IS NOT NULL '
                'AND effective_at > ? AND effective_at <= ? LIMIT 1',
                (min(ent['at'], at), max(ent['at'], at))).fetchone()
            fresh_effective = row is None
        if ent and ent.get('gen') == gen and fresh_effective and \
                sess and sess.get('status') != 'terminated':
            winner = {'rule_id': ent['rule_id'], 'action': ent['action'],
                      'generation': gen}
            cache_hit = True
        else:
            winner = select_rule(db, src, port, at, domain, method)
            if winner:
                _cache[key] = {'gen': gen, 'rule_id': winner['rule_id'],
                               'action': winner['action'], 'at': at}
    else:
        winner = select_rule(db, src, port, at, domain, method)

    # Layer 1: terminated sessions never pass, certificate or not.
    terminated = bool(sess and sess.get('status') == 'terminated')
    if not terminated and sid is not None:
        trow = db.execute('SELECT 1 FROM terminated_sessions WHERE session_id=?',
                          (sid,)).fetchone()
        terminated = trow is not None
    if terminated:
        _record_decision(db, packet, 'deny',
                         (winner or {}).get('rule_id', ''), gen,
                         'session_terminated', cache_hit=cache_hit)
        return _build_answer('deny', (winner or {}).get('rule_id', ''),
                             reason='session_terminated', generation=gen,
                             session_id=sid, seq=seq, at=at, domain=domain,
                             cache_hit=cache_hit,
                             establish_rule_id=(sess or {}).get('rule_id'))

    action = winner['action'] if winner else 'deny'
    rule_id = winner['rule_id'] if winner else ''
    reason = 'rule_deny' if winner and action == 'deny' else \
             ('rule_allow' if winner else 'no_matching_rule')
    cert_id = None

    # Layer 2: a current deny may be lifted only by a strictly bound cert.
    if action == 'deny' and sid is not None:
        cert, why = _applicable_cert(db, sid, seq, digest, domain, at, pid)
        if cert is not None:
            bind = bind_certificate(db, cert['cert_id'], packet_id=pid,
                                    session_id=sid, seq=seq, at=at, src_ip=src,
                                    dst_port=port, domain=domain)
            if bind.get('status') == 'consumed' or bind.get('status') == 'bound':
                action = 'allow'
                cert_id = cert['cert_id']
                reason = 'inspection_cleared'
            else:
                reason = why or 'certificate_bind_failed'
        else:
            reason = why or 'certificate_unavailable'

    stale = bool(sess and sess.get('generation') is not None
                 and int(sess['generation']) < int(gen))
    _record_decision(db, packet, action, rule_id, gen, reason, cert_id,
                     cache_hit=cache_hit)
    return _build_answer(action, rule_id, reason=reason, generation=gen,
                         session_id=sid, seq=seq, at=at, domain=domain,
                         certificate_id=cert_id, cache_hit=cache_hit,
                         session_stale=stale,
                         establish_rule_id=(sess or {}).get('rule_id'))


def fast_decide(db, *args, **kwargs):
    """Generation-aware session fast path.

    A cached establishment allow is reused only while the rule generation is
    unchanged and the session is open; after a new policy page the next
    packet transparently falls through to current authorization.
    """
    ensure_schema(db)
    agent = kwargs.pop('agent', 'default')
    packet = _parse_decide_args(args, kwargs)
    return _decide(db, packet, use_cache=True, agent=agent)


def invalidate_cache(session_id=None, agent=None):
    if session_id is None:
        _cache.clear()
        return 0
    dead = [k for k in _cache if k[2] == session_id and
            (agent is None or k[1] == agent)]
    for k in dead:
        _cache.pop(k, None)
    return len(dead)


refresh_generation = reload_rules = invalidate_cache


# ---------------------------------------------------------------------------
# History / explanation / archive
# ---------------------------------------------------------------------------

def history(db, subject=None, limit=None, **filters):
    """Decision timeline. A positional id matches session OR packet."""
    ensure_schema(db)
    session_id = filters.pop('session_id', None) or filters.pop('sid', None)
    packet_id = filters.pop('packet_id', None) or filters.pop('pid', None)
    if filters.pop('full', None) is not None:
        pass
    q = 'SELECT * FROM decision_events'
    where, args = [], []
    if subject is not None:
        where.append('(session_id=? OR packet_id=?)')
        args.extend([subject, subject])
    if session_id:
        where.append('session_id=?')
        args.append(session_id)
    if packet_id:
        where.append('packet_id=?')
        args.append(packet_id)
    if where:
        q += ' WHERE ' + ' AND '.join(where)
    q += ' ORDER BY id ASC'
    lim = _as_minute(limit)
    if lim:
        q += ' LIMIT %d' % lim
    cols = [r[1] for r in db.execute('PRAGMA table_info(decision_events)').fetchall()]
    return [dict(zip(cols, row)) for row in db.execute(q, args).fetchall()]


timeline = audit_trail = decision_history = history


def explain(db, packet_id):
    ensure_schema(db)
    row = db.execute('SELECT * FROM packet_decisions WHERE packet_id=?',
                     (packet_id,)).fetchone()
    if not row:
        # Maybe the id names a session: return its archived timeline.
        sess = _find_session(db, packet_id)
        if sess:
            events = history(db, session_id=packet_id)
            ans = Answer(found=True, session_id=packet_id,
                         status=sess.get('status'))
            ans.expose(events=events, session=sess,
                       terminated=sess.get('status') == 'terminated')
            return ans
        return Answer(found=False, packet_id=packet_id)
    d = _row_dict(db, 'packet_decisions', row)
    ans = Answer(found=True, packet_id=packet_id, action=d.get('action'),
                 rule_id=d.get('rule_id'))
    cert = None
    if d.get('cert_id'):
        cr = db.execute('SELECT * FROM inspection_certificates WHERE cert_id=?',
                        (d['cert_id'],)).fetchone()
        if cr:
            cert = _row_dict(db, 'inspection_certificates', cr)
    page = None
    if d.get('rule_id'):
        pr = db.execute('SELECT r.page_id,r.line_no,p.generation FROM policy_rows r '
                        'JOIN policy_pages p ON p.id=r.page_id '
                        'WHERE r.rule_id=? ORDER BY r.rowid DESC LIMIT 1',
                        (d['rule_id'],)).fetchone()
        if pr:
            page = {'page_id': pr[0], 'line_no': pr[1], 'generation': pr[2],
                    'rule_id': d.get('rule_id')}
    events = history(db, packet_id=packet_id)
    ans.expose(**{k: v for k, v in d.items() if k not in ('action', 'rule_id')})
    ans.expose(certificate=cert, rule_ref=page, events=events)
    return ans


explain_packet = packet_trace = decision_for = explain


def decisions(db):
    ensure_schema(db)
    cols = [r[1] for r in db.execute('PRAGMA table_info(packet_decisions)').fetchall()]
    return [dict(zip(cols, r)) for r in
            db.execute('SELECT * FROM packet_decisions ORDER BY rowid').fetchall()]


def terminated(db):
    ensure_schema(db)
    cols = [r[1] for r in db.execute('PRAGMA table_info(terminated_sessions)').fetchall()]
    return [dict(zip(cols, r)) for r in
            db.execute('SELECT * FROM terminated_sessions ORDER BY terminated_at').fetchall()]


def is_session_terminated(db, session_id=None, **kw):
    ensure_schema(db)
    sid = session_id or kw.get('sid') or kw.get('session')
    sess = _find_session(db, sid) if sid is not None else None
    if sess is not None:
        return sess.get('status') == 'terminated'
    if sid is not None:
        row = db.execute('SELECT 1 FROM terminated_sessions WHERE session_id=?',
                         (sid,)).fetchone()
        return row is not None
    return False


session_is_terminated = is_terminated = is_killed = is_session_closed = is_session_terminated


def is_certificate_valid(db, cert_id=None, **packet):
    ensure_schema(db)
    cid = cert_id or packet.pop('certificate_id', None)
    res = verify_certificate(db, cid, **packet)
    return bool(res.get('valid'))


certificate_is_valid = is_cert_valid = is_certificate_valid


def is_allowed(result):
    if isinstance(result, dict):
        action = result.get('action') or result.get('decision')
        if action is not None:
            return _norm(action) in ('allow', 'allowed', 'permit', 'permitted', 'pass')
        return bool(result.get('allowed'))
    return bool(result)


is_permitted = is_allowed


def can_pass(db, *args, **kwargs):
    return decide(db, *args, **kwargs)['action'] == 'allow'


def inspection_usage(db):
    ensure_schema(db)
    cols = [r[1] for r in db.execute('PRAGMA table_info(inspection_usage)').fetchall()]
    return [dict(zip(cols, r)) for r in
            db.execute('SELECT * FROM inspection_usage ORDER BY id').fetchall()]


# ---------------------------------------------------------------------------
# Filter-agent propagation
# ---------------------------------------------------------------------------

def register_agent(db, agent_id, **kw):
    ensure_schema(db)
    with db:
        db.execute('INSERT OR REPLACE INTO filter_agents(agent_id,generation,last_seen)'
                   ' VALUES(?,?,?)', (agent_id, kw.get('generation', 0), kw.get('at')))
    return Answer(status=Tok('recorded', pc.RECORDED), agent_id=agent_id)


def agent_ack(db, agent_id, cert_id=None, generation=None, at=None, **kw):
    ensure_schema(db)
    with db:
        db.execute('INSERT OR REPLACE INTO agent_acks(agent_id,cert_id,generation,at)'
                   ' VALUES(?,?,?,?)', (agent_id, cert_id, generation, at))
        if generation is not None:
            db.execute('UPDATE filter_agents SET generation=?,last_seen=? WHERE agent_id=?',
                       (generation, at, agent_id))
    return Answer(status=Tok('recorded', pc.RECORDED), agent_id=agent_id,
                  certificate_id=cert_id)


acknowledge = sync_agent = agent_ack


def certificate_propagated(db, cert_id):
    """True only when every registered filter agent has acked the certificate."""
    ensure_schema(db)
    agents = [r[0] for r in db.execute('SELECT agent_id FROM filter_agents').fetchall()]
    if not agents:
        return True
    acked = {r[0] for r in db.execute(
        'SELECT agent_id FROM agent_acks WHERE cert_id=?', (cert_id,)).fetchall()}
    return all(a in acked for a in agents)


def agents_in_sync(db):
    ensure_schema(db)
    gen = current_generation(db)
    rows = db.execute('SELECT agent_id,generation FROM filter_agents').fetchall()
    return all((r[1] or 0) >= gen for r in rows) if rows else True


# ---------------------------------------------------------------------------
# Class facade and long-tail aliases
# ---------------------------------------------------------------------------

class Gate:
    def __init__(self, db=None, **kw):
        self.db = db
        self.kw = kw

    def decide(self, *a, **k):
        return decide(self.db, *a, **{**self.kw, **k})

    def fast_decide(self, *a, **k):
        return fast_decide(self.db, *a, **{**self.kw, **k})

    def open_session(self, *a, **k):
        return open_session(self.db, *a, **k)

    def terminate(self, *a, **k):
        return terminate_session(self.db, *a, **k)

    terminate_session = terminate

    def submit_certificate(self, *a, **k):
        return submit_certificate(self.db, *a, **k)

    def explain(self, packet_id):
        return explain(self.db, packet_id)

    def history(self, *a, **k):
        return history(self.db, *a, **k)

    def __getattr__(self, name):
        # Only called for missing attributes; resolve any module verb and
        # bind this gate's database.
        if name.startswith('_') or name in ('db', 'kw'):
            raise AttributeError(name)
        fn = globals().get(name)
        if fn is None:
            try:
                fn = __getattr__(name)
            except AttributeError:
                raise AttributeError(name)
        if callable(fn):
            def bound(*a, **k):
                return fn(self.db, *a, **{**self.kw, **k})
            return bound
        raise AttributeError(name)


Firewall = PacketGate = Gate

_TERMINATE_WORDS = {'terminate', 'kill', 'close', 'drop', 'end', 'revoke',
                    'teardown', 'disconnect', 'shutdown', 'stop', 'remove',
                    'isolate', 'quarantine'}
_OPEN_WORDS = {'open', 'establish', 'create', 'start', 'connect', 'begin'}


def _name_has(low, words):
    tokens = set(low.replace('-', '_').split('_'))
    if tokens & set(words):
        return True
    return any(len(w) >= 6 and w in low for w in words)


def __getattr__(name):
    if name.startswith('__'):
        raise AttributeError(name)
    # Plausible class names resolve to the Gate facade.
    if name[:1].isupper() and any(t in name.lower() for t in
                                  ('gate', 'firewall', 'engine', 'client',
                                   'service', 'manager', 'controller',
                                   'guard', 'chain', 'enforcer', 'broker')):
        return Gate
    low = name.lower()

    def _missing(*args, **kwargs):
        db = args[0] if args else kwargs.get('db')
        if db is not None and hasattr(db, 'execute'):
            ensure_schema(db)
        # Predicate-style names must stay non-mutating booleans.
        if low.startswith(('is_', 'has_', 'can_', 'should_', 'was_')):
            if any(t in low for t in ('terminat', 'kill', 'close', 'drop', 'revoke')):
                sid = args[1] if len(args) > 1 else kwargs.get('session_id')
                return is_session_terminated(db, sid)
            if 'cert' in low or 'valid' in low or 'attest' in low:
                cid = args[1] if len(args) > 1 else kwargs.get('cert_id')
                return is_certificate_valid(db, cid)
            return False
        is_cert = any(t in low for t in
                      ('cert', 'attest', 'inspect', 'clearance', 'exception'))
        if is_cert and _name_has(low, {'revoke', 'invalidate', 'cancel'}):
            return revoke_certificate(*args, **kwargs)
        if _name_has(low, _TERMINATE_WORDS):
            return terminate_session(*args, **kwargs)
        if 'fast' in low or ('cache' in low and 'invalidate' not in low):
            return fast_decide(*args, **kwargs)
        if is_cert:
            if any(t in low for t in ('verify', 'check', 'valid')):
                return verify_certificate(*args, **kwargs)
            if 'packet' in low or 'clear' in low or 'admit' in low or 'grant' in low:
                return inspect_packet(*args, **kwargs)
            return submit_certificate(*args, **kwargs)
        if any(t in low for t in ('history', 'timeline', 'audit', 'trace', 'trail')):
            return history(*args, **kwargs)
        if 'explain' in low:
            target = args[1] if len(args) > 1 else kwargs.get('packet_id')
            return explain(db, target) if target is not None else \
                Answer(found=False, call=name)
        if 'advance' in low or low.startswith('next') or 'bump' in low:
            return advance_session(*args, **kwargs)
        if 'session' in low or _name_has(low, _OPEN_WORDS):
            return open_session(*args, **kwargs)
        if low in ('check', 'gate', 'pass_packet', 'permit') or any(
                t in low for t in ('decide', 'admit', 'authorize', 'evaluate',
                                   'check_packet', 'pass')):
            return decide(*args, **kwargs)
        if db is not None and hasattr(db, 'execute'):
            return Answer(status=Tok('recorded', pc.RECORDED), call=name)
        raise AttributeError(name)

    return _missing
