"""Guest projections for the existing same-session Worker persistence methods."""
import json

from hermes_state_runtime import RuntimeStoreError

_SESSION_FIELDS = frozenset({
    'id', 'source', 'model', 'title', 'title_source', 'created_at', 'started_at', 'ended_at', 'end_reason',
    'system_prompt', 'tool_names', 'user_id', 'session_key', 'chat_id', 'chat_type', 'thread_id',
    'parent_session_id', 'display_name', 'runtime_generation', 'runtime_revision',
    'input_tokens', 'output_tokens', 'cache_read_tokens', 'cache_write_tokens', 'total_tokens',
    'estimated_cost_usd', 'cost_status', 'cost_source', 'billing_mode',
    'compression_fallback_streak', 'compression_ineffective_count', 'compression_recovery_deadline',
    'compression_failure_cooldown_until', 'compression_failure_error',
})
_MODEL_FIELDS = frozenset({
    'max_iterations', 'max_tokens', 'reasoning_config', 'yolo_mode', 'codex_thread_id',
    '_usage_anchor', '_proactive_prune_rearm_tokens', '_anthropic_rejected_thinking',
})


def guest_context(db, conn, session_id, payload):
    from hermes_state_worker_context import worker_context
    if payload != {'target': session_id}:
        raise RuntimeStoreError('permission_denied')
    original = worker_context(db, conn, session_id, {})['session']
    projected = {key: value for key, value in original.items() if key in _SESSION_FIELDS}
    model = original.get('model_config') or '{}'
    model = json.loads(model) if isinstance(model, str) else model
    if not isinstance(model, dict):
        raise RuntimeStoreError('storage_unavailable')
    projected.update(cwd='/task', git_repo_root='/task',
                     model_config=json.dumps({key: value for key, value in model.items() if key in _MODEL_FIELDS}))
    return {'session': projected}


def guest_lineage(db, conn, session_id, payload):
    from hermes_state_worker_compression import worker_lineage
    if payload != {'target': session_id}:
        raise RuntimeStoreError('permission_denied')
    result = worker_lineage(db, conn, session_id, payload)
    # Assignment rotation needs native Owner/channel rebinding, not a copied
    # Host adoption scope. First admission supports one exact physical session.
    if set(result['readable_ids']) != {session_id}:
        raise RuntimeStoreError('unsupported_guest_lineage')
    return result


def guest_history(db, conn, session_id, payload):
    from hermes_state_worker_compression import worker_history
    if not isinstance(payload, dict) or payload.get('target') != session_id:
        raise RuntimeStoreError('permission_denied')
    guest_lineage(db, conn, session_id, {'target': session_id})
    return worker_history(db, conn, session_id, payload)


def guest_create(db, conn, session_id, payload, *, scope):
    from hermes_state_worker_lifecycle import worker_create
    identity = {'cwd': '/task', 'git_repo_root': '/task', 'user_id': '', 'chat_id': '',
                'session_key': 'guest:' + scope['execution_id'], 'profile_name': 'default'}
    if (not isinstance(payload, dict)
            or any(payload.get(key) not in (None, value) for key, value in identity.items())):
        raise RuntimeStoreError('permission_denied')
    mapped = dict(payload)
    if mapped.get('origin_json') is not None:
        expected = {'platform': 'kanban', 'chat_id': '', 'chat_name': None, 'chat_type': 'dm',
                    'user_id': '', 'user_name': None, 'thread_id': None}
        try:
            origin = json.loads(mapped['origin_json'])
        except (TypeError, ValueError):
            raise RuntimeStoreError('permission_denied') from None
        if origin != expected:
            raise RuntimeStoreError('permission_denied')
    row = conn.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
    if row is None:
        raise RuntimeStoreError('not_found')
    # Guest-local placeholders never rewrite the Owner's canonical routing or
    # profile identity. The original constructor still validates every other key.
    for key in (*identity, 'origin_json'):
        if mapped.get(key) is not None:
            mapped[key] = row[key]
    return worker_create(db, conn, session_id, mapped)


def guest_turn_cleanup(db, conn, session_id, payload):
    from hermes_state_worker_compression import worker_turn_cleanup
    if not isinstance(payload, dict) or payload.get('target') != session_id:
        raise RuntimeStoreError('permission_denied')
    return worker_turn_cleanup(db, conn, session_id, payload)


def guest_context_handlers(scope):
    from functools import partial
    from hermes_state_worker_context import (
        worker_prompt, worker_row_role, worker_sidecars, worker_tail_role, worker_tool_names,
    )
    from hermes_state_worker_lifecycle import WORKER_LIFECYCLE_HANDLERS
    lifecycle = {key: WORKER_LIFECYCLE_HANDLERS[key] for key in (
        'session.title', 'session.title_source', 'session.activity', 'session.activity_clear',
        'session.api_content', 'session.message_api_content', 'session.user_content', 'session.end',
        'session.lifecycle',
    )}
    return lifecycle | {
        'compression.context': guest_context, 'compression.lineage': guest_lineage,
        'compression.history': guest_history, 'session.create': partial(guest_create, scope=scope),
        'turn.cleanup': guest_turn_cleanup,
        'session.prompt': worker_prompt, 'session.tools': worker_tool_names, 'session.sidecars': worker_sidecars,
        'session.tail_role': worker_tail_role, 'session.row_role': worker_row_role,
    }


def guest_compression_cleanup(db, conn, session_id, payload):
    from hermes_state_worker_compression import worker_compression_cleanup
    if not isinstance(payload, dict) or payload.get('target') != session_id:
        raise RuntimeStoreError('permission_denied')
    return worker_compression_cleanup(db, conn, session_id, payload)


def guest_compression_handlers():
    from functools import partial
    from hermes_state_worker_compression import WORKER_COMPRESSION_HANDLERS, worker_compression_lock
    # Reuse the original in-place compression transaction. Session rotation needs
    # a new physical assignment and remains unsupported on this exact channel.
    handlers = {key: WORKER_COMPRESSION_HANDLERS[key] for key in (
        'compression.append', 'compression.watermark', 'compression.archive', 'compression.boundary',
        'compression.cooldown.record', 'compression.cooldown.restore', 'compression.cooldown.clear',
        'compression.fallback', 'compression.ineffective', 'compression.recovery',
    )}
    return handlers | {'compression.cleanup': guest_compression_cleanup} | {
        'compression.lock.' + action: partial(worker_compression_lock, action=action,
                                             holder_is_dead=lambda _holder: False)
        for action in ('acquire', 'renew', 'release', 'holder')
    }
