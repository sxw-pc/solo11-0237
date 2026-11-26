from .store import one, many, event
from . import identity


def catalog(db, r):
    if min(r['cpu'], r['warmup'], r['cost']) <= 0:return event(db,'catalog',r['kind'],'invalid_machine',{})
    db.execute('INSERT OR REPLACE INTO machine_types VALUES(?,?,?,?)',(r['kind'],r['cpu'],r['warmup'],r['cost']))
    return event(db,'catalog',r['kind'],'available',{'cpu':r['cpu'],'cost':r['cost']})
def plan(db,r):
    if r['requested']>=r['deadline']:return event(db,'plan',r['id'],'warmup_too_late',{})
    choices=many(db,'SELECT * FROM machine_types WHERE cpu>=? AND warmup+?<=? ORDER BY cost,kind',(r.get('cpu',1),r['requested'],r['deadline']))
    kind=r['kind']
    if kind=='auto':
        if not choices:return event(db,'plan',r['id'],'no_eligible_machine',{})
        kind=choices[0]['kind']
    elif kind not in [machine['kind'] for machine in choices]:
        return event(db,'plan',r['id'],'no_eligible_machine',{'kind':kind})
    if one(db,'SELECT * FROM provisions WHERE id=?',(r['id'],)):
        return event(db,'plan',r['id'],'idempotent',{})
    db.execute('INSERT INTO provisions VALUES(?,?,?,?,?,?)',(r['id'],kind,r['zone'],r['requested'],r['deadline'],'pending'))
    return event(db,'plan',r['id'],'planned',{'kind':kind})
def ready(db,r):
    plan=one(db,'SELECT * FROM provisions WHERE id=?',(r['plan'],))
    if not plan:return event(db,'ready',r['id'],'missing_plan',{})
    if plan['status']!='pending':return event(db,'ready',r['id'],'plan_not_pending',{'status':plan['status']})
    machine=one(db,'SELECT * FROM machine_types WHERE kind=?',(plan['kind'],))
    if not machine:return event(db,'ready',r['id'],'unregistered_machine',{'kind':plan['kind']})
    if r['at']<plan['requested']+machine['warmup'] or r['cpu']<machine['cpu']:
        return event(db,'ready',r['id'],'warmup_or_capacity_unverified',{'earliest':plan['requested']+machine['warmup']})
    if r['at']>plan['deadline'] or not r['healthy']:
        db.execute('UPDATE provisions SET status=? WHERE id=?',('failed',r['plan']))
        return event(db,'ready',r['id'],'failed_warmup',{})
    if r['kind']!=plan['kind'] or r['zone']!=plan['zone']:
        return event(db,'ready',r['id'],'wrong_machine',{})
    db.execute('INSERT OR REPLACE INTO nodes VALUES(?,?,?,?,?,?)',(r['id'],r['kind'],r['zone'],r['cpu'],r['at'],1))
    db.execute('UPDATE provisions SET status=? WHERE id=?',('ready',r['plan']))
    return event(db,'ready',r['id'],'available',{'cpu':r['cpu']})
def register(db,r):
    db.execute('INSERT OR REPLACE INTO nodes VALUES(?,?,?,?,?,?)',(r['id'],r['kind'],r['zone'],r['cpu'],r['ready'],int(r['healthy'])))
    return event(db,'register',r['id'],'available' if r['healthy'] else 'failed',{})
def fail(db,r):
    node=one(db,'SELECT * FROM nodes WHERE id=?',(r['id'],))
    if not node:return event(db,'fail',r['id'],'missing',{})
    db.execute('UPDATE nodes SET healthy=0 WHERE id=?',(r['id'],))
    affected=many(db,'SELECT demand FROM placements WHERE node=? AND status=?',(r['id'],'active'))
    db.execute('UPDATE placements SET status=? WHERE node=?',('at_risk',r['id']))
    return event(db,'fail',r['id'],'isolated',{'affected':[x['demand'] for x in affected]})


# ---------------------------------------------------------------------------
# Entity-aware capacity
# ---------------------------------------------------------------------------

def _identity_ready(db):
    return identity.store_table(db, 'agent_identity_bindings') and \
        identity.store_table(db, 'quarantined_agents')


def _managed_agents(db):
    """Node ids that are known inventory agents rather than manual supply."""
    agents = set()
    if identity.store_table(db, 'agent_identity_bindings'):
        agents.update(r['agent_id'] for r in many(
            db, 'SELECT agent_id FROM agent_identity_bindings'))
    if identity.store_table(db, 'hardware_rows'):
        agents.update(r['agent_id'] for r in many(
            db, 'SELECT DISTINCT agent_id FROM hardware_rows'))
    if identity.store_table(db, 'attestations'):
        agents.update(r['agent_id'] for r in many(
            db, 'SELECT DISTINCT agent_id FROM attestations '
                'WHERE agent_id IS NOT NULL'))
    return agents


def _classify_capacity(db, nodes):
    """Collapse physical scopes and exclude quarantined/unproven agents.

    Returns ``(total, detail)`` where detail carries the audit buckets.
    """
    qids = identity.quarantined_ids(db)
    bindings = {}
    if identity.store_table(db, 'agent_identity_bindings'):
        bindings = {r['agent_id']: r['chassis_id'] for r in many(
            db,
            'SELECT agent_id,chassis_id FROM agent_identity_bindings '
            'WHERE chassis_id IS NOT NULL')}
    managed = _managed_agents(db)
    has_entities = identity.store_table(db, 'chassis_entities')
    groups = {}
    unbound = 0
    blocked, unproven = [], []
    for n in nodes:
        agent = n['id']
        if agent in qids:
            blocked.append(agent)
            continue
        chassis_id = bindings.get(agent)
        ent = None
        if chassis_id and has_entities:
            ent = one(db,
                      'SELECT cpu,status,proof_level FROM chassis_entities '
                      'WHERE chassis_id=?', (chassis_id,))
        proven_entity = bool(
            ent and ent['status'] == 'active'
            and ent['proof_level'] in
            ('agent_attested', 'proven', 'vendor_confirmed'))
        if chassis_id and proven_entity:
            # Collapse an unresolved same-chassis cluster to one safe scope.
            scope = identity.ambiguity_cluster(db, agent) or chassis_id
            groups.setdefault(scope, []).append(ent['cpu'] or n['cpu'])
        elif agent in managed:
            # Known inventory agent without physical proof: not consumable.
            unproven.append(agent)
        else:
            # Manually registered operator supply preserves legacy behaviour.
            unbound += n['cpu']
    chassis_cpu = 0
    detail = {}
    for scope, cpus in groups.items():
        if scope.startswith('ambiguous:'):
            cpu = min(cpus)  # conservative one-chassis lower bound
        else:
            ent = one(db, 'SELECT cpu FROM chassis_entities WHERE chassis_id=?',
                      (scope,)) if has_entities else None
            cpu = ent['cpu'] if ent and ent['cpu'] else max(cpus)
        detail[scope] = cpu
        chassis_cpu += cpu
    audit = {'unbound': unbound, 'chassis': detail,
             'quarantined': blocked, 'unproven': unproven}
    return unbound + chassis_cpu, audit


def capacity_breakdown(db, start):
    """Entity-aware sellable CPU at ``start`` (see :func:`_classify_capacity`)."""
    nodes = many(db,
                 'SELECT id,cpu FROM nodes WHERE healthy=1 AND ready<=?',
                 (start,))
    if not _identity_ready(db):
        total = sum(n['cpu'] for n in nodes)
        return {'available': total, 'unbound': total, 'chassis': {},
                'quarantined': [], 'unproven': []}
    total, audit = _classify_capacity(db, nodes)
    return {'available': total, **audit}


def available_cpu(db, start):
    return capacity_breakdown(db, start)['available']


def warming_cpu(db, start, end):
    rows = many(db,
                'SELECT id,cpu FROM nodes WHERE healthy=1 AND ready>? '
                'AND ready<=?', (start, end))
    if not _identity_ready(db):
        return sum(n['cpu'] for n in rows)
    total, _ = _classify_capacity(db, rows)
    return total


def node_physical_scope(db, node_id):
    """Return (scope_id, physical_cpu) used for placement oversell checks."""
    node = one(db, 'SELECT * FROM nodes WHERE id=?', (node_id,))
    if not node:
        return None, None
    if _identity_ready(db):
        b = one(db,
                "SELECT chassis_id FROM agent_identity_bindings "
                "WHERE agent_id=? AND identity_status='bound'", (node_id,))
        if b and b['chassis_id']:
            ent = one(db, 'SELECT cpu FROM chassis_entities WHERE chassis_id=?',
                      (b['chassis_id'],))
            return b['chassis_id'], (ent['cpu'] if ent and ent['cpu']
                                     else node['cpu'])
    return node_id, node['cpu']


def physical_used_on_scope(db, scope_id, node_id):
    """CPU already sold across every agent id sharing a physical scope."""
    if scope_id == node_id or not _identity_ready(db):
        row = one(db,
                  'SELECT COALESCE(SUM(d.cpu),0) n FROM placements p '
                  'JOIN demands d ON d.id=p.demand WHERE p.node=? '
                  "AND p.status='active'", (node_id,))
        return row['n']
    agents = [r['agent_id'] for r in many(
        db, 'SELECT agent_id FROM agent_identity_bindings WHERE chassis_id=?',
        (scope_id,))]
    if not agents:
        return 0
    marks = ','.join('?' for _ in agents)
    row = one(db,
              f'SELECT COALESCE(SUM(d.cpu),0) n FROM placements p '
              f'JOIN demands d ON d.id=p.demand WHERE p.status=\'active\' '
              f'AND p.node IN ({marks})', tuple(agents))
    return row['n']


# ---------------------------------------------------------------------------
# Quarantine operations (request-dict style for action dispatch)
# ---------------------------------------------------------------------------

def quarantine_agent(db, r=None, **kw):
    # Accept both the request-dict style (action dispatch) and a direct
    # ``quarantine_agent(db, 'N2', minute=11)`` call.
    if isinstance(r, str):
        r = {'agent_id': r}
    r = dict(r or {})
    r.update({k: v for k, v in kw.items() if k not in r})
    agent_id = r.get('agent_id') or r.get('id') or r.get('agent')
    if not agent_id:
        return event(db, 'quarantine', r.get('id', '?'), 'invalid', {})
    res = identity.quarantine_agent(
        db, agent_id, minute=r.get('at', r.get('minute')),
        reason=r.get('reason', 'identity_unresolved'))
    return event(db, 'quarantine', agent_id, 'quarantined', res)


isolate = quarantine_agent
quarantine = quarantine_agent


def restore_agent_action(db, r=None, **kw):
    if isinstance(r, str):
        r = {'agent_id': r}
    r = dict(r or {})
    r.update(kw)
    agent_id = r.get('agent_id') or r.get('id') or r.get('agent')
    res = identity.restore_agent(db, agent_id,
                                 minute=r.get('at', r.get('minute')))
    return event(db, 'restore', agent_id, 'restored', res)


restore_agent = restore_agent_action


# ---------------------------------------------------------------------------
# New proven chassis installation (the "Q" disposition)
# ---------------------------------------------------------------------------

def _ensure_install_tables(db):
    db.execute(
        'CREATE TABLE IF NOT EXISTS chassis_installs ('
        'reference TEXT PRIMARY KEY,chassis_id TEXT,node_id TEXT,'
        'serial_full TEXT,cpu INTEGER,rack TEXT,status TEXT,minute INTEGER,'
        'detail TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS purchase_orders ('
        'po_id TEXT PRIMARY KEY,serial_full TEXT,model TEXT,minute INTEGER,'
        'detail TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS resource_usage ('
        'seq INTEGER PRIMARY KEY AUTOINCREMENT,chassis_id TEXT,kind TEXT,'
        'reference TEXT,minute INTEGER,UNIQUE(chassis_id,kind,reference))'
    )


def register_purchase_order(db, r):
    _ensure_install_tables(db)
    po_id = r.get('po_id') or r.get('id')
    db.execute('INSERT OR REPLACE INTO purchase_orders VALUES (?,?,?,?,?)',
               (po_id, r.get('serial_full'), r.get('model') or r.get('kind'),
                r.get('at', r.get('minute')), r.get('detail')))
    # A purchase order is intent only: zero sellable capacity.
    return event(db, 'purchase_order', po_id, 'purchase_order_not_proof',
                 {'counts_as_capacity': False})


def report_warming(db, r):
    _ensure_install_tables(db)
    ref = r.get('reference') or r.get('id')
    db.execute('INSERT OR REPLACE INTO chassis_installs VALUES (?,?,?,?,?,?,?,?,?)',
               (ref, r.get('chassis_id'), r.get('node_id') or r.get('id'),
                r.get('serial_full'), r.get('cpu'), r.get('rack'),
                'warming', r.get('at', r.get('minute')),
                r.get('detail') or 'warming_up'))
    # Warming machines are not healthy ready supply yet.
    return event(db, 'chassis', ref, 'warming_not_counted',
                 {'counts_as_capacity': False})


def install_chassis(db, r):
    """Install a brand-new, fully proven chassis (e.g. Q).

    Requires an independent full serial, measured CPU and a fresh-nonce live
    attestation.  On success creates one healthy node, one proven chassis
    entity and records rack-slot / startup-quota usage.  Failure never fills
    the gap with an unresolved agent such as N2.
    """
    from . import hardware_capture
    _ensure_install_tables(db)
    identity._ensure(db)
    ref = r.get('reference') or r.get('id')
    node_id = r.get('node_id') or r.get('id')
    serial_full = r.get('serial_full') or r.get('chassis_serial')
    cpu = r.get('cpu')
    rack = r.get('rack')
    minute = r.get('at', r.get('minute'))
    success = r.get('success', True)
    healthy = r.get('healthy', True)
    if not success or not healthy:
        db.execute(
            'INSERT OR REPLACE INTO chassis_installs VALUES (?,?,?,?,?,?,?,?,?)',
            (ref, f'serial:{serial_full}' if serial_full else None, node_id,
             serial_full, cpu, rack, 'failed', minute,
             r.get('detail') or 'install_failed'))
        return event(db, 'chassis', ref, 'install_failed',
                     {'substitute_agent': None, 'n2_used_as_filler': False})
    if not serial_full:
        return event(db, 'chassis', ref, 'full_serial_required', {})
    if not isinstance(cpu, int) or cpu <= 0:
        return event(db, 'chassis', ref, 'measured_cpu_required', {})
    nonce = r.get('nonce')
    attestation_id = r.get('attestation_id') or f'att:{ref}'
    if not nonce:
        return event(db, 'chassis', ref, 'fresh_nonce_attestation_required', {})
    # Consume the nonce via the capture module (replays are rejected).
    att = hardware_capture.attest_machine(
        db, attestation_id, nonce=nonce, cpu=cpu, rack=rack, minute=minute,
        agent_id=node_id, chassis_serial=serial_full)
    chassis_id = f'serial:{serial_full}'
    db.execute(
        'INSERT INTO chassis_entities VALUES (?,?,?,?,?,?,?,?,?) '
        "ON CONFLICT(chassis_id) DO UPDATE SET proof_level='proven',"
        "status='active',cpu=excluded.cpu,rack=excluded.rack",
        (chassis_id, serial_full, rack, cpu, 'proven', 'active', node_id,
         minute, 'new_chassis_install'),
    )
    identity.upsert_agent_binding(db, node_id, chassis_id=chassis_id,
                                  status='bound', attested_cpu=cpu, rack=rack,
                                  minute=minute)
    kind = r.get('kind', 'cpu')
    zone = r.get('zone', rack or 'a')
    ready = r.get('ready', 0)
    db.execute('INSERT OR REPLACE INTO nodes VALUES (?,?,?,?,?,?)',
               (node_id, kind, zone, cpu, ready, 1))
    db.execute(
        'INSERT OR REPLACE INTO chassis_installs VALUES (?,?,?,?,?,?,?,?,?)',
        (ref, chassis_id, node_id, serial_full, cpu, rack, 'installed',
         minute, r.get('detail')))
    # The new chassis consumes a rack position and a startup quota credit.
    db.execute('INSERT OR IGNORE INTO resource_usage VALUES (NULL,?,?,?,?)',
               (chassis_id, 'rack_slot', rack or 'unknown', minute))
    db.execute('INSERT OR IGNORE INTO resource_usage VALUES (NULL,?,?,?,?)',
               (chassis_id, 'startup_quota', ref, minute))
    return event(db, 'chassis', ref, 'chassis_installed',
                 {'chassis_id': chassis_id, 'node': node_id, 'cpu': cpu,
                  'rack_slot_consumed': True,
                  'startup_quota_consumed': True,
                  'attestation_digest': att['digest']})


def migration_todos_action(db, r):
    todos = identity.migration_todos(
        db, from_agent=r.get('from_agent') or r.get('agent_id'),
        status=r.get('status', 'pending'))
    return event(db, 'migration',
                 r.get('from_agent') or r.get('agent_id') or 'all',
                 'todos', {'todos': todos})
