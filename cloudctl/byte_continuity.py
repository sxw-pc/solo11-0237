"""Convenience facade for byte-continuous recovery and fence handoff.

It re-exports the public surface of both causal modules so callers can use
one stable import path; the canonical implementations stay in
:mod:`cloudctl.data_recovery` and :mod:`cloudctl.write_fence`.
"""
from .data_recovery import *  # noqa: F401,F403
from .write_fence import *  # noqa: F401,F403
from . import data_recovery, write_fence  # noqa: F401

# Explicit re-exports / extra name aliases.
from .data_recovery import (  # noqa: F401
    GENESIS_DIGEST,
    PowerLoss,
    Verdict,
    apply_log,
    begin_proof,
    build_ledger,
    canonical_digest,
    chain_digest,
    content_digest,
    continuity_report,
    entry_digest,
    get_conflicts,
    get_material,
    get_proof,
    import_material,
    list_conflicts,
    make_entry,
    make_receipt,
    record_entry,
    record_peer_confirmation,
    recover_bytes,
    verify_chain,
)
from .write_fence import (  # noqa: F401
    active_fence,
    authorize_write,
    can_continue,
    claim,
    get_handoff,
    get_seal,
    install_target,
    invalidate_preparation,
    issue_fence,
    mirror_slot_status,
    old_writer_ack,
    old_writer_append,
    prepare_handoff,
    receive_target_receipt,
    release_mirror_slot,
    resume_handoff,
    run_handoff,
    seal_old_writer,
    verify_handoff,
)

report_continuity = continuity_report
prepare_recovery = prepare_handoff
recover_and_fence = run_handoff
handoff_write_authority = run_handoff
seal_old_epoch = seal_old_writer
continuable = can_continue
executable_fence = active_fence
