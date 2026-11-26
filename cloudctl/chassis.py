"""Unified physical-chassis decision facade.

This module re-exports the small set of operations used to answer:

    "How much CPU can this physical chassis actually sign out?"

Identity order: agent id != management-card certificate != chassis.  The
facade is a convenience over :mod:`cloudctl.hardware_capture`,
:mod:`cloudctl.identity`, :mod:`cloudctl.capacity_certificate` and
:mod:`cloudctl.supply`; those modules hold the real behaviour.
"""
from . import hardware_capture
from .hardware_capture import (
    import_page, capture_page, add_rack_photo, add_photo,
    add_replacement_order, record_card_swap, attest_machine, attest,
    copy_certificate, add_artifact, sha256_bytes,
    HardwarePageConflict, NonceReplay,
)
from . import identity
from .identity import (
    open_scene, derive_interpretations, interpretations, get_interpretation,
    proven_cpu, proven_chassis, joint_binding, two_physical_machines_proven,
    sign_machine, record_attestation,
    quarantine_agent, restore_agent, quarantined_ids,
    prove_same_chassis, prove_distinct_chassis,
    vendor_prove_same, vendor_prove_distinct,
    migration_todos, plan_migration_todos, complete_migration_todo,
)
from .capacity_certificate import (
    issue, issue_version, issue_safe, issue_replacement,
    replace_certificate, load_certificate, get_certificate,
    obligations, open_obligation_cpu, fulfill_obligation,
    cover_obligations, receive_late_evidence, reassess,
)
from .supply import (
    available_cpu, capacity_breakdown, warming_cpu,
    quarantine_agent as quarantine_supply,
    install_chassis, report_warming, register_purchase_order,
)

# Descriptive aliases (the narrative's vocabulary).
isolate_agent = quarantine_agent
proven_physical_cpu = proven_cpu
physical_lower_bound = proven_cpu
sign_eight_cpu_certificate = issue_safe
new_certificate_version = issue_replacement
late_evidence_reassessment = receive_late_evidence
under_delivery_obligations = obligations
open_shortfall_cpu = open_obligation_cpu
make_good_obligations = cover_obligations
vendor_confirms_same_chassis = prove_same_chassis
vendor_confirms_distinct_chassis = prove_distinct_chassis
move_out_todos = migration_todos

__all__ = [
    'hardware_capture', 'identity',
    'import_page', 'capture_page', 'add_rack_photo', 'add_photo',
    'add_replacement_order', 'record_card_swap', 'attest_machine', 'attest',
    'copy_certificate', 'add_artifact', 'sha256_bytes',
    'HardwarePageConflict', 'NonceReplay',
    'open_scene', 'derive_interpretations', 'interpretations',
    'get_interpretation', 'proven_cpu', 'proven_physical_cpu',
    'physical_lower_bound', 'proven_chassis', 'joint_binding',
    'two_physical_machines_proven', 'sign_machine', 'record_attestation',
    'quarantine_agent', 'isolate_agent', 'restore_agent', 'quarantined_ids',
    'prove_same_chassis', 'prove_distinct_chassis',
    'vendor_prove_same', 'vendor_prove_distinct',
    'vendor_confirms_same_chassis', 'vendor_confirms_distinct_chassis',
    'migration_todos', 'move_out_todos', 'plan_migration_todos',
    'complete_migration_todo',
    'issue', 'issue_version', 'issue_safe', 'issue_replacement',
    'replace_certificate', 'load_certificate', 'get_certificate',
    'obligations', 'under_delivery_obligations', 'open_obligation_cpu',
    'open_shortfall_cpu', 'fulfill_obligation', 'cover_obligations',
    'make_good_obligations', 'receive_late_evidence', 'reassess',
    'late_evidence_reassessment', 'new_certificate_version',
    'available_cpu', 'capacity_breakdown', 'warming_cpu',
    'quarantine_supply', 'install_chassis', 'report_warming',
    'register_purchase_order',
]
