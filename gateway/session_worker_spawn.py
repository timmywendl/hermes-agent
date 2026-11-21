"""Cancellation-safe handoff of a managed subprocess acquired off the owner loop."""
import asyncio
import threading


def check_q1_acquisition(handle, diagnostic):
    """Final closed native gate in the original acquisition thread.

    Reopen the Board and hold its real writer boundary through the final
    identity checks and readiness refusal. No VZ or Popen operation is
    reachable until an effective protected authority verifier exists.
    """
    from gateway.session_vz_adapter import (
        NAMESPACE, _board_claim, _check_history, _metadata, require_native_readiness,
    )
    from hermes_cli.kanban_db_connect import connect_closing, write_txn
    from hermes_state_runtime import RuntimeStoreError
    from dataclasses import asdict
    import hashlib
    if (str(diagnostic.board_path.resolve(strict=True)) != handle.record['board_path']
            or asdict(diagnostic.binding) != handle.record['binding']
            or diagnostic.manifest_digest != handle.record['manifest_digest']
            or diagnostic.witness_plan_digest != handle.record['witness_plan_digest']):
        raise RuntimeStoreError('q1_reservation_changed')
    if handle.stop.is_set():
        raise RuntimeStoreError('q1_revoked')
    with connect_closing(diagnostic.board_path) as conn, write_txn(conn):
        task, run = _board_claim(conn, diagnostic, handle.record['session_id'])
        if (_metadata(run['metadata']).get(NAMESPACE) != handle.record
                or hashlib.sha256(task.claim_lock.encode()).hexdigest() != handle.record['claim_digest']):
            raise RuntimeStoreError('q1_reservation_changed')
        _check_history(conn, task, reservation=handle.record)
        with handle.authority.db._read_ctx() as owner_conn:
            handle.verify_acquisition(owner_conn)
            if handle.stop.is_set():
                raise RuntimeStoreError('q1_revoked')
            require_native_readiness()


async def acquire_process(spawn, *args, **kwargs):
    from gateway.session_managed_worker import ManagedWorker
    lock = threading.Lock()
    state = {'cancelled': False, 'process': None}

    def create():
        process = spawn(*args, **kwargs)
        with lock:
            cancelled = state['cancelled']
            if not cancelled:
                state['process'] = process
        if cancelled:
            ManagedWorker(process).close()
        return process

    pending = asyncio.create_task(asyncio.to_thread(create))
    try:
        process = await asyncio.shield(pending)
        with lock:
            state['process'] = None
        return process
    except asyncio.CancelledError:
        with lock:
            state['cancelled'] = True
            process = state['process']
            state['process'] = None
        if process is not None:
            await asyncio.to_thread(ManagedWorker(process).close)
        # If creation still runs, its thread owns cleanup; consume an eventual spawn exception.
        pending.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
        raise
