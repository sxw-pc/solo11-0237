"""Physical chassis identity resolution.

Agent ids, management-card certificates and physical chassis are three
different identities.  A scanned row is not itself a machine.  This module
keeps every interpretation compatible with the preserved originals and only
promotes capacity to "proven" when the required physical evidence exists.
"""
import json

from .store import one, many

DEFAULT_SCENE = 'rack-r1-minute10'


def _ensure(db):
    db.execute(
        'CREATE TABLE IF NOT EXISTS chassis_entities ('
        'chassis_id TEXT PRIMARY KEY,serial_full TEXT UNIQUE,rack TEXT,'
        'cpu INTEGER,proof_level TEXT NOT NULL,status TEXT NOT NULL '
        "DEFAULT 'active',primary_agent TEXT,created_minute INTEGER,source TEXT)"
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS agent_identity_bindings ('
        'agent_id TEXT PRIMARY KEY,card_cert TEXT,chassis_id TEXT,'
        'identity_status TEXT NOT NULL,attested_cpu INTEGER,rack TEXT,'
        'updated_minute INTEGER)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS quarantined_agents ('
        'agent_id TEXT PRIMARY KEY,at_minute INTEGER,reason TEXT,'
        'active INTEGER NOT NULL DEFAULT 1,restored_minute INTEGER)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS chassis_interpretations ('
        'interpretation_id TEXT PRIMARY KEY,scene TEXT NOT NULL,kind TEXT '
        'NOT NULL,physical_chassis INTEGER NOT NULL,physical_cpu INTEGER '
        'NOT NULL,provable_cpu INTEGER NOT NULL,status TEXT NOT NULL,'
        'basis TEXT,missing_evidence TEXT)'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS interpretation_members ('
        'interpretation_id TEXT,agent_id TEXT,chassis_id TEXT,'
        'PRIMARY KEY(interpretation_id,agent_id))'
    )
    db.execute(
        'CREATE TABLE IF NOT EXISTS migration_todos ('
        'todo_id TEXT PRIMARY KEY,from_agent TEXT NOT NULL,to_agent TEXT,'
        'chassis_id TEXT,demand TEXT,replica INTEGER,node TEXT,reason TEXT,'
        "status TEXT NOT NULL DEFAULT 'pending',created_minute INTEGER,"
        'UNIQUE(demand,replica))'
    )


# ---------------------------------------------------------------------------
# Agent / chassis attribution
# ---------------------------------------------------------------------------

def upsert_agent_binding(db, agent_id, *, card_cert=None, chassis_id=None,
                         status=None, attested_cpu=None, rack=None,
                         minute=None):
    _ensure(db)
    row = one(db, 'SELECT * FROM agent_identity_bindings WHERE agent_id=?',
              (agent_id,))
    if row:
        db.execute(
            'UPDATE agent_identity_bindings SET card_cert=COALESCE(?,card_cert),'
            'chassis_id=COALESCE(?,chassis_id),'
            'identity_status=COALESCE(?,identity_status),'
            'attested_cpu=COALESCE(?,attested_cpu),rack=COALESCE(?,rack),'
            'updated_minute=? WHERE agent_id=?',
            (card_cert, chassis_id, status, attested_cpu, rack, minute,
             agent_id),
        )
    else:
        db.execute(
            'INSERT INTO agent_identity_bindings VALUES (?,?,?,?,?,?,?)',
            (agent_id, card_cert, chassis_id, status or 'unresolved',
             attested_cpu, rack, minute),
        )
    return one(db, 'SELECT * FROM agent_identity_bindings WHERE agent_id=?',
               (agent_id,))


def attribute_attestation(db, attestation):
    """Turn a fresh attestation into an agent-attested provisional chassis."""
    _ensure(db)
    agent_id = attestation['agent_id']
    serial = attestation['chassis_serial']
    cpu = attestation['cpu']
    rack = attestation['rack']
    minute = attestation['at_minute']
    if agent_id:
        if serial:
            linked = f'serial:{serial}'
            existing = one(db,
                           'SELECT chassis_id FROM chassis_entities WHERE chassis_id=?',
                           (linked,))
            if existing:
                db.execute(
                    'UPDATE chassis_entities SET cpu=?,rack=?,status=\'active\' '
                    'WHERE chassis_id=?', (cpu, rack, linked))
                upsert_agent_binding(
                    db, agent_id, chassis_id=linked, status='bound',
                    attested_cpu=cpu, rack=rack, minute=minute)
                return linked
        provisional = f'prov:{agent_id}'
        db.execute(
            'INSERT OR IGNORE INTO chassis_entities VALUES (?,?,?,?,?,?,?,?,?)',
            (provisional, serial, rack, cpu, 'agent_attested', 'active',
             agent_id, minute, 'live_attestation'),
        )
        db.execute(
            'UPDATE chassis_entities SET cpu=?,rack=? WHERE chassis_id=? '
            "AND proof_level='agent_attested'",
            (cpu, rack, provisional),
        )
        upsert_agent_binding(
            db, agent_id, chassis_id=provisional, status='attested',
            attested_cpu=cpu, rack=rack, minute=minute,
        )
        return provisional
    chassis_id = f'serial:{serial}'
    db.execute(
        'INSERT INTO chassis_entities VALUES (?,?,?,?,?,?,?,?,?)',
        (chassis_id, serial, rack, cpu, 'proven', 'active', None, minute,
         'live_attestation'),
    )
    return chassis_id


def record_attestation(db, attestation_id, **fields):
    """Convenience: capture + attribute a machine attestation in one call."""
    from . import hardware_capture
    rec = hardware_capture.attest_machine(db, attestation_id, **fields)
    row = one(db, 'SELECT * FROM attestations WHERE attestation_id=?',
              (attestation_id,))
    attribute_attestation(db, row)
    return rec


sign_machine = record_attestation


def quarantine_agent(db, agent_id, *, minute=None, reason='identity_unresolved'):
    _ensure(db)
    db.execute(
        'INSERT INTO quarantined_agents(agent_id,at_minute,reason,active) '
        'VALUES (?,?,?,1) ON CONFLICT(agent_id) DO UPDATE SET '
        'at_minute=excluded.at_minute,reason=excluded.reason,active=1,'
        'restored_minute=NULL',
        (agent_id, minute, reason),
    )
    upsert_agent_binding(db, agent_id, status='quarantined', minute=minute)
    return {'agent_id': agent_id, 'quarantined': True, 'reason': reason}


def restore_agent(db, agent_id, *, minute=None):
    _ensure(db)
    db.execute(
        'UPDATE quarantined_agents SET active=0,restored_minute=? '
        'WHERE agent_id=?',
        (minute, agent_id),
    )
    row = one(db, 'SELECT chassis_id FROM agent_identity_bindings '
                  'WHERE agent_id=?', (agent_id,))
    status = 'bound' if row and row['chassis_id'] and \
        not row['chassis_id'].startswith('prov:') else 'attested'
    upsert_agent_binding(db, agent_id, status=status, minute=minute)
    return {'agent_id': agent_id, 'restored': True}


isolate_agent = quarantine_agent
unquarantine_agent = restore_agent


def quarantined_ids(db):
    if not store_table(db, 'quarantined_agents'):
        return set()
    return {r['agent_id'] for r in many(
        db, 'SELECT agent_id FROM quarantined_agents WHERE active=1')}


def store_table(db, name):
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


# ---------------------------------------------------------------------------
# Compatible interpretations (dual world)
# ---------------------------------------------------------------------------

def _scene_rows(db, scene, serial_tail, rack, agent_ids):
    if store_table(db, 'hardware_rows'):
        q = 'SELECT agent_id,card_cert,serial_tail,rack,cpu FROM hardware_rows'
        clauses, params = [], []
        if serial_tail is not None:
            clauses.append('serial_tail=?')
            params.append(serial_tail)
        if rack is not None:
            clauses.append('rack=?')
            params.append(rack)
        if agent_ids:
            clauses.append(f"agent_id IN ({','.join('?' for _ in agent_ids)})")
            params.extend(agent_ids)
        if clauses:
            q += ' WHERE ' + ' AND '.join(clauses)
        rows = many(db, q, tuple(params))
        if rows:
            return rows
    # Fallback: caller supplied agents implicitly via bindings/attestations.
    return []


def open_scene(db, scene=DEFAULT_SCENE, *, serial_tail='44', rack='r1',
               agent_ids=('N1', 'N2'), minute=10):
    """Materialize both interpretations compatible with the captured pages.

    No agent id and no serial tail is treated as physical identity, so both
    ``same_chassis`` (one card-swapped box) and ``distinct_chassis`` (two
    boxes in one rack) stay open.
    """
    _ensure(db)
    rows = _scene_rows(db, scene, serial_tail, rack, tuple(agent_ids)
                       if agent_ids else None)
    if not rows:
        # Caller may be building the scene without importing a page first.
        rows = [{'agent_id': a, 'cpu': 8} for a in (agent_ids or ())]
    # Several pages can repeat the same agent; an agent is one identity.
    by_agent = {}
    for r in rows:
        by_agent.setdefault(r['agent_id'], r)
    rows = list(by_agent.values())
    agents = [r['agent_id'] for r in rows]
    cpus = {r['agent_id']: r['cpu'] for r in rows}
    physical_cpu_same = min(cpus.values()) if cpus else 0
    physical_cpu_distinct = sum(cpus.values())

    proven_by_agent = _attested_cpu_by_agent(db)
    # Conservative provable lower bound: every freshly attested agent proves
    # at least its measured slice once.  Quarantined agents prove nothing for
    # new sales.
    qids = quarantined_ids(db)
    provable = sum(cpu for a, cpu in proven_by_agent.items() if a not in qids)

    same_id = f'{scene}:same_chassis'
    distinct_id = f'{scene}:distinct_chassis'
    # Re-materializing a scene must not erase a terminal proof decision.
    same_status = _existing_status(db, same_id) or 'compatible'
    distinct_status = _existing_status(db, distinct_id) or 'compatible'
    same_missing = [
        'manufacturer_vendor_proof_same_chassis',
        'or_card_replacement_order_linking_cards_plus_full_serial',
    ]
    distinct_missing = [
        'independent_full_chassis_serial_per_agent',
        'fresh_nonce_live_attestation_binding_serial_cpu_rack',
    ]
    db.execute(
        'INSERT OR REPLACE INTO chassis_interpretations VALUES (?,?,?,?,?,?,?,?,?)',
        (same_id, scene, 'same_chassis', 1, physical_cpu_same,
         min(provable, physical_cpu_same) if physical_cpu_same else provable,
         same_status, json.dumps({'agents': agents}),
         json.dumps(same_missing)),
    )
    db.execute(
        'INSERT OR REPLACE INTO chassis_interpretations VALUES (?,?,?,?,?,?,?,?,?)',
        (distinct_id, scene, 'distinct_chassis', len(agents),
         physical_cpu_distinct, provable,
         distinct_status, json.dumps({'agents': agents}),
         json.dumps(distinct_missing)),
    )
    for iid in (same_id, distinct_id):
        db.execute('DELETE FROM interpretation_members WHERE interpretation_id=?',
                   (iid,))
        for a in agents:
            db.execute(
                'INSERT OR IGNORE INTO interpretation_members VALUES (?,?,?)',
                (iid, a, None),
            )
    return interpretations(db, scene)


derive_interpretations = open_scene


def _attested_cpu_by_agent(db):
    if not store_table(db, 'attestations'):
        return {}
    out = {}
    for r in many(db,
                  'SELECT agent_id,cpu FROM attestations '
                  'WHERE agent_id IS NOT NULL ORDER BY at_minute'):
        out[r['agent_id']] = r['cpu']
    return out


def interpretations(db, scene=None):
    _ensure(db)
    if scene:
        rows = many(db,
                    'SELECT * FROM chassis_interpretations WHERE scene=? '
                    'ORDER BY kind DESC', (scene,))
    else:
        rows = many(db, 'SELECT * FROM chassis_interpretations ORDER BY scene,kind')
    qids = quarantined_ids(db)
    attested = _attested_cpu_by_agent(db)
    for r in rows:
        r['basis'] = json.loads(r['basis']) if r['basis'] else {}
        r['missing_evidence'] = (json.loads(r['missing_evidence'])
                                 if r['missing_evidence'] else [])
        members = [m['agent_id'] for m in many(
            db,
            'SELECT agent_id FROM interpretation_members WHERE interpretation_id=?',
            (r['interpretation_id'],))]
        signed_members = [a for a in members
                          if a in attested and a not in qids]
        if r['kind'] == 'same_chassis':
            # One box: a single fresh sign-off proves its measured spec once.
            r['provable_cpu'] = r['physical_cpu'] if signed_members else 0
        else:
            # Two boxes: only independently signed members are provable.
            r['provable_cpu'] = sum(attested[a] for a in signed_members)
        r['signed_agents'] = signed_members
    return rows


def get_interpretation(db, interpretation_id):
    _ensure(db)
    r = one(db, 'SELECT * FROM chassis_interpretations WHERE interpretation_id=?',
            (interpretation_id,))
    if r:
        r['basis'] = json.loads(r['basis']) if r['basis'] else {}
        r['missing_evidence'] = (json.loads(r['missing_evidence'])
                                 if r['missing_evidence'] else [])
        enriched = interpretations(db)
        for full in enriched:
            if full['interpretation_id'] == interpretation_id:
                return full
    return r


# ---------------------------------------------------------------------------
# Proven physical capacity
# ---------------------------------------------------------------------------

def ambiguity_cluster(db, agent_id):
    """Shared safe-capacity key while same-chassis remains possible.

    If the agent belongs to a ``same_chassis`` interpretation that is still
    ``compatible``, all its members may be one physical box reporting under
    old and new ids, so safe capacity collapses them to one lower bound.
    Returns ``None`` once that interpretation is confirmed/ruled out.
    """
    _ensure(db)
    if not store_table(db, 'interpretation_members'):
        return None
    row = one(
        db,
        "SELECT i.interpretation_id FROM interpretation_members m "
        "JOIN chassis_interpretations i "
        "ON i.interpretation_id=m.interpretation_id "
        "WHERE m.agent_id=? AND i.kind='same_chassis' "
        "AND i.status='compatible' LIMIT 1",
        (agent_id,),
    )
    return ('ambiguous:' + row['interpretation_id']) if row else None


def proven_cpu(db):
    """CPU that may actually be signed/sold from physical proof.

    Fully proven/vendor-confirmed chassis count once each (quarantine-aware).
    Agent-only attestations establish a conservative lower bound: members of a
    still-ambiguous same-chassis cluster are collapsed to a single chassis,
    because one swapped-card box can report under two agent ids at once.
    Merged provisional entities are never double counted.
    """
    _ensure(db)
    qids = quarantined_ids(db)

    def quarantined_out(e):
        agents = [r['agent_id'] for r in many(
            db,
            'SELECT agent_id FROM agent_identity_bindings WHERE chassis_id=?',
            (e['chassis_id'],))]
        if not agents and e['primary_agent']:
            agents = [e['primary_agent']]
        return bool(agents) and all(a in qids for a in agents)

    total = 0
    ambiguous = {}
    for e in many(db,
                  "SELECT chassis_id,cpu,primary_agent,proof_level "
                  "FROM chassis_entities WHERE status='active' "
                  "AND proof_level IN "
                  "('agent_attested','proven','vendor_confirmed')"):
        if quarantined_out(e):
            continue
        if e['proof_level'] == 'agent_attested':
            cluster = (ambiguity_cluster(db, e['primary_agent'])
                       if e['primary_agent'] else None) or e['chassis_id']
            ambiguous.setdefault(cluster, []).append(e['cpu'] or 0)
        else:
            total += e['cpu'] or 0
    for cpus in ambiguous.values():
        # Lower bound: one chassis, smallest attested spec is the safe call.
        total += min(cpus) if cpus else 0
    return total


def proven_chassis(db):
    _ensure(db)
    return many(db,
                "SELECT * FROM chassis_entities WHERE status='active' "
                "AND proof_level IN "
                "('agent_attested','proven','vendor_confirmed') ORDER BY chassis_id")


def joint_binding(db, agent_id):
    """Check the *joint* proof for one agent's physical chassis.

    Returns ``complete`` only when an independent full chassis serial and a
    fresh (single-use nonce) live attestation agree on CPU spec and rack
    location.  A serial alone, a certificate copy alone, or a mere serial
    tail is never complete.
    """
    _ensure(db)
    if not store_table(db, 'attestations'):
        return {'agent_id': agent_id, 'complete': False,
                'missing': ['full_serial', 'live_attestation']}
    binding = one(db,
                  'SELECT * FROM agent_identity_bindings WHERE agent_id=?',
                  (agent_id,))
    att = one(db,
              'SELECT * FROM attestations WHERE agent_id=? ORDER BY at_minute DESC '
              'LIMIT 1', (agent_id,))
    missing = []
    full_serial = None
    if binding and binding['chassis_id'] and \
            binding['chassis_id'].startswith('serial:'):
        ent = one(db, 'SELECT serial_full,cpu,rack FROM chassis_entities '
                      'WHERE chassis_id=?', (binding['chassis_id'],))
        if ent and ent['serial_full']:
            full_serial = ent['serial_full']
    if not full_serial:
        # A full serial supplied directly on the attestation also counts.
        if att and att['chassis_serial']:
            full_serial = att['chassis_serial']
        else:
            missing.append('full_chassis_serial')
    if not att:
        missing.append('fresh_nonce_live_attestation')
    else:
        if not att['cpu'] or att['cpu'] <= 0:
            missing.append('bound_cpu_spec')
        if not att['rack']:
            missing.append('bound_rack_location')
        if full_serial and att['chassis_serial'] and \
                att['chassis_serial'] != full_serial:
            missing.append('serial_attestation_mismatch')
        if binding and binding['attested_cpu'] and \
                binding['attested_cpu'] != att['cpu']:
            missing.append('cpu_spec_mismatch')
    quarantined = agent_id in quarantined_ids(db)
    return {'agent_id': agent_id, 'complete': not missing,
            'full_serial': full_serial,
            'cpu': att['cpu'] if att else None,
            'rack': att['rack'] if att else None,
            'quarantined': quarantined,
            'missing': missing}


def two_physical_machines_proven(db, agent_a='N1', agent_b='N2'):
    """True only when both agents have complete, distinct joint bindings."""
    a = joint_binding(db, agent_a)
    b = joint_binding(db, agent_b)
    distinct = bool(a['full_serial'] and b['full_serial']
                     and a['full_serial'] != b['full_serial'])
    return a['complete'] and b['complete'] and distinct and not b['quarantined']



# ---------------------------------------------------------------------------
# Late vendor proof
# ---------------------------------------------------------------------------

def prove_same_chassis(db, proof_id=None, *, agents=('N1', 'N2'),
                       old_agent=None, new_agent=None, chassis_serial=None,
                       cpu=None, rack=None, minute=None, note=None,
                       create_move_todos=True, scene=DEFAULT_SCENE):
    """Manufacturer proof that two agent ids are one physical chassis."""
    _ensure(db)
    agents = tuple(agents or ())
    if old_agent and old_agent not in agents:
        agents = (old_agent,) + agents
    if new_agent and new_agent not in agents:
        agents = agents + (new_agent,)
    _record_proof_artifact(
        db, proof_id, relation='same_chassis', agents=list(agents),
        old_agent=old_agent, new_agent=new_agent,
        chassis_serial=chassis_serial, minute=minute, note=note)
    canonical = (f'serial:{chassis_serial}' if chassis_serial
                 else 'chassis:vendor-same:' + '-'.join(sorted(agents)))
    rows = [r for a in agents for r in many(
        db, 'SELECT cpu,rack FROM chassis_entities WHERE primary_agent=? '
            "AND status='active'", (a,))]
    cpu = cpu or (rows[0]['cpu'] if rows else None) or 8
    rack = rack or (rows[0]['rack'] if rows else None)
    db.execute(
        'INSERT INTO chassis_entities VALUES (?,?,?,?,?,?,?,?,?) '
        'ON CONFLICT(chassis_id) DO UPDATE SET proof_level=\'vendor_confirmed\','
        "status='active',cpu=excluded.cpu,rack=excluded.rack",
        (canonical, chassis_serial, rack, cpu, 'vendor_confirmed', 'active',
         old_agent or agents[0] if agents else None, minute,
         f'vendor_proof:{proof_id}'),
    )
    # Merge provisional entities and rebind every agent to one chassis.
    for a in agents:
        db.execute(
            "UPDATE chassis_entities SET status='merged' "
            "WHERE chassis_id=? AND chassis_id<>?",
            (f'prov:{a}', canonical),
        )
        upsert_agent_binding(db, a, chassis_id=canonical, status='bound',
                            minute=minute)
    _set_interpretation_status(db, f'{scene}:same_chassis', 'confirmed')
    _set_interpretation_status(db, f'{scene}:distinct_chassis', 'ruled_out')
    todos = []
    if create_move_todos and old_agent:
        todos = plan_migration_todos(
            db, from_agent=old_agent, to_agent=new_agent,
            chassis_id=canonical, minute=minute,
            reason=note or 'vendor_confirmed_same_chassis_retire_old_agent')
    return {'relation': 'same_chassis', 'chassis_id': canonical,
            'agents': list(agents), 'migration_todos': todos}


def prove_distinct_chassis(db, proof_id=None, *, agents=None, serials=None,
                           minute=None, cpu=8, rack=None, note=None,
                           scene=DEFAULT_SCENE):
    """Manufacturer proof that agent ids are distinct physical chassis.

    ``serials`` maps agent id -> independent full chassis serial.
    """
    _ensure(db)
    serials = dict(serials or {})
    agents = tuple(agents or tuple(serials.keys()))
    _record_proof_artifact(
        db, proof_id, relation='distinct_chassis', agents=list(agents),
        serials=serials, minute=minute, cpu=cpu, rack=rack, note=note)
    result_entities = []
    for a in agents:
        serial = serials.get(a)
        if not serial:
            raise ValueError('full_serial_required_for_distinct_proof')
        cid = f'serial:{serial}'
        db.execute(
            'INSERT INTO chassis_entities VALUES (?,?,?,?,?,?,?,?,?) '
            "ON CONFLICT(chassis_id) DO UPDATE SET proof_level='vendor_confirmed',"
            "status='active'",
            (cid, serial, rack, cpu, 'vendor_confirmed', 'active', a, minute,
             f'vendor_proof:{proof_id}'),
        )
        db.execute(
            "UPDATE chassis_entities SET status='merged' "
            "WHERE chassis_id=? AND chassis_id<>?",
            (f'prov:{a}', cid),
        )
        upsert_agent_binding(db, a, chassis_id=cid, status='bound',
                             minute=minute)
        result_entities.append(cid)
    _set_interpretation_status(db, f'{scene}:distinct_chassis', 'confirmed')
    _set_interpretation_status(db, f'{scene}:same_chassis', 'ruled_out')
    return {'relation': 'distinct_chassis', 'agents': list(agents),
            'chassis_ids': result_entities}


vendor_prove_same = prove_same_chassis
vendor_prove_distinct = prove_distinct_chassis


def _set_interpretation_status(db, iid, status):
    db.execute('UPDATE chassis_interpretations SET status=? '
               'WHERE interpretation_id=?', (status, iid))


def _existing_status(db, iid):
    if not store_table(db, 'chassis_interpretations'):
        return None
    row = one(db, 'SELECT status FROM chassis_interpretations '
                  'WHERE interpretation_id=?', (iid,))
    return row['status'] if row else None


def _record_proof_artifact(db, proof_id, **payload):
    if not proof_id:
        return
    from . import hardware_capture
    hardware_capture._ensure(db)
    hardware_capture.add_artifact(
        db, proof_id, kind='vendor_proof',
        reference=payload.get('relation'), **payload
    )


# ---------------------------------------------------------------------------
# Migration todos (original placements are never deleted)
# ---------------------------------------------------------------------------

def plan_migration_todos(db, *, from_agent, to_agent=None, chassis_id=None,
                         minute=None, reason='agent_identity_retired'):
    _ensure(db)
    if not store_table(db, 'placements'):
        return []
    placed = many(
        db,
        "SELECT p.demand,p.replica,p.node FROM placements p "
        "WHERE p.node=? AND p.status='active'",
        (from_agent,),
    )
    todos = []
    for p in placed:
        todo_id = f"move:{from_agent}:{p['demand']}:{p['replica']}"
        db.execute(
            'INSERT OR IGNORE INTO migration_todos VALUES (?,?,?,?,?,?,?,?,?,?)',
            (todo_id, from_agent, to_agent, chassis_id, p['demand'],
             p['replica'], p['node'], reason, 'pending', minute),
        )
        todos.append(one(db, 'SELECT * FROM migration_todos WHERE todo_id=?',
                         (todo_id,)))
    return todos


def migration_todos(db, *, from_agent=None, status='pending'):
    _ensure(db)
    q = 'SELECT * FROM migration_todos WHERE 1=1'
    params = []
    if from_agent:
        q += ' AND from_agent=?'
        params.append(from_agent)
    if status:
        q += ' AND status=?'
        params.append(status)
    q += ' ORDER BY todo_id'
    return many(db, q, tuple(params))


def complete_migration_todo(db, todo_id, *, minute=None, destination=None):
    _ensure(db)
    todo = one(db, 'SELECT * FROM migration_todos WHERE todo_id=?', (todo_id,))
    if not todo:
        return {'todo_id': todo_id, 'decision': 'missing'}
    db.execute("UPDATE migration_todos SET status='done' WHERE todo_id=?",
               (todo_id,))
    return {'todo_id': todo_id, 'decision': 'done',
            'destination': destination or todo['to_agent']}


# ---------------------------------------------------------------------------
# Request-dict action wrappers (dispatch / facade)
# ---------------------------------------------------------------------------

def _kwargs(r, skip=('action',)):
    return {k: v for k, v in r.items() if k not in skip}


def open_scene_action(db, r):
    return open_scene(db, **_kwargs(r))


def vendor_same_action(db, r):
    opts = _kwargs(r, ('action', 'relation'))
    proof_id = opts.pop('proof_id', None)
    return prove_same_chassis(db, proof_id, **opts)


def vendor_distinct_action(db, r):
    opts = _kwargs(r, ('action', 'relation'))
    proof_id = opts.pop('proof_id', None)
    return prove_distinct_chassis(db, proof_id, **opts)
