"""Constructor context is assignment-scoped and shares durable mutation receipts."""
import pytest

from agent.runtime_session_store import RuntimeSessionStore, WorkerPersistenceError
from hermes_state import SessionDB
from hermes_state_runtime import begin_runtime_epoch, mutate_worker_execution, register_worker_execution


def test_worker_context_preserves_authority_identity_and_prompt_receipts(tmp_path):
    db = SessionDB(tmp_path / 'state.db')
    try:
        db.create_session('owned', 'subagent', parent_session_id=None, model='requested',
                          model_config={'_delegate_from': 'parent'}, system_prompt='prefix', profile_name='fixture')
        db.create_session('foreign', 'cli', system_prompt='private')
        epoch = begin_runtime_epoch(db, instance_id='fixture')
        scope = dict(epoch=epoch, execution_id='worker', session_id='owned', generation=0)
        register_worker_execution(db, **scope, kind='child', adoption_secret='test-secret')
        store = RuntimeSessionStore(lambda method, **p: mutate_worker_execution(db, **p), scope, tmp_path / 'outbox')
        try:
            assert store.get_session('owned')['system_prompt'] == 'prefix'
            with pytest.raises(WorkerPersistenceError, match='permission_denied'):
                store.get_session('foreign')
            store.update_system_prompt('owned', 'stable-prefix')
            store.patch_session_model_config('owned', {'_usage_anchor': {'tokens': 23}})
            assert store.get_session_model_config_value('owned', '_usage_anchor') == {'tokens': 23}
            assert db.get_session_model_config_value('owned', '_delegate_from') == 'parent'
            assert db.get_session('foreign')['system_prompt'] == 'private'
            original = store.rpc
            def lost_ack(method, **params):
                original(method, **params)
                raise TimeoutError('lost-ack')
            store.rpc = lost_ack
            with pytest.raises(TimeoutError, match='lost-ack'):
                store.update_system_prompt('owned', 'durable-prefix')
            store.rpc = original
            assert len(store.retry_pending()) == 1
            assert db.get_session('owned')['system_prompt'] == 'durable-prefix'
            with pytest.raises(Exception, match='invalid_params'):
                mutate_worker_execution(db, **scope, sequence=store.journal['next_sequence'],
                                        operation='session.sidecars', payload={'patch': {'_delegate_from': 'foreign'}})
        finally:
            store.close()
    finally:
        db.close()


def test_worker_constructor_restores_persisted_compressor_guards(tmp_path):
    import time
    from agent.context_compressor import ContextCompressor
    db = SessionDB(tmp_path / 'state.db')
    try:
        db.create_session('owned', 'cli', model_config={'_proactive_prune_rearm_tokens': 1234})
        db.set_compression_fallback_streak('owned', 4)
        db.set_compression_ineffective_count('owned', 3)
        deadline = time.time() + 3600
        db.set_compression_recovery_deadline('owned', deadline)
        db.record_compression_failure_cooldown('owned', deadline, 'fixture-cooldown')
        epoch = begin_runtime_epoch(db, instance_id='fixture')
        scope = dict(epoch=epoch, execution_id='worker', session_id='owned', generation=0)
        register_worker_execution(db, **scope, kind='compute', adoption_secret='test-secret')
        store = RuntimeSessionStore(lambda method, **p: mutate_worker_execution(db, **p), scope, tmp_path / 'outbox')
        try:
            compressor = ContextCompressor(model='fixture', config_context_length=100000, quiet_mode=True)
            compressor.bind_session_state(store, 'owned')
            assert compressor._fallback_compression_streak == 4
            assert compressor._ineffective_compression_count == 3
            assert compressor._anti_thrash_recovery_deadline == deadline
            assert compressor._proactive_prune_rearm_tokens == 1234
            assert store.get_compression_failure_cooldown_row('owned') == db.get_compression_failure_cooldown_row('owned')
            assert store.get_compression_failure_cooldown('owned')['cooldown_until'] == deadline
            db.set_session_title('owned', 'retained-title')
            assert store.get_session_title('owned') == db.get_session_title('owned')
        finally:
            store.close()
    finally:
        db.close()


def test_codex_binding_receipt_allows_cleanup_and_exact_lost_ack_retry(tmp_path):
    from types import SimpleNamespace

    from agent.codex_runtime import _store_codex_thread_id, _stored_codex_thread_id

    db = SessionDB(tmp_path / 'state.db')
    try:
        db.create_session('owned', 'kanban', model_config={'_usage_anchor': {'tokens': 23}})
        db.create_session('foreign', 'cli', model_config={'codex_thread_id': 'foreign-thread'})
        epoch = begin_runtime_epoch(db, instance_id='fixture')
        scope = dict(epoch=epoch, execution_id='worker', session_id='owned', generation=0)
        register_worker_execution(db, **scope, kind='compute', adoption_secret='fixture-secret')
        sent = []

        def rpc(method, **params):
            sent.append(params)
            return mutate_worker_execution(db, **params)

        store = RuntimeSessionStore(rpc, scope, tmp_path / 'outbox')
        try:
            assert store.try_acquire_session_turn_lease('owned', 'old-holder')
            agent = SimpleNamespace(_session_db=store, session_id='owned')
            _store_codex_thread_id(agent, 'codex-thread')
            assert store.failure is None
            assert _stored_codex_thread_id(agent) == 'codex-thread'
            assert db.get_session_model_config_value('owned', '_usage_anchor') == {'tokens': 23}
            committed = sent[-2]  # _stored_codex_thread_id reads session.context after the sidecar.
            assert committed['operation'] == 'session.sidecars'
            assert rpc('worker.persist', **committed) == {'value': None}
            store.release_session_turn_lease('owned', 'old-holder')
            cleanup = sent[-1]
            assert cleanup['operation'] == 'turn.cleanup'
            assert rpc('worker.persist', **cleanup) == {'released': True}
            assert store.try_acquire_session_turn_lease('owned', 'new-holder')
            store.release_session_turn_lease('owned', 'old-holder')
            assert not store.try_acquire_session_turn_lease('owned', 'other-holder')
            assert store.refresh_session_turn_lease('owned', 'new-holder')

            def lost_ack(method, **params):
                rpc(method, **params)
                raise TimeoutError('lost-ack')

            store.rpc = lost_ack
            with pytest.raises(TimeoutError, match='lost-ack'):
                store.patch_session_model_config('owned', {'codex_thread_id': None})
            store.rpc = rpc
            pending = store.journal['pending'][0]
            assert pending['operation'] == 'session.sidecars'
            assert store.retry_pending() == [{'value': None}]
            assert store.journal['pending'] == [] and store.failure is None
            assert _stored_codex_thread_id(agent) is None
            assert db.get_session_model_config_value('foreign', 'codex_thread_id') == 'foreign-thread'
            for wrong_scope, reason in (({'generation': 99}, 'stale_generation'),
                                         ({'session_id': 'foreign'}, 'permission_denied')):
                with pytest.raises(Exception, match=reason):
                    mutate_worker_execution(db, **(scope | wrong_scope), **pending)
            store.release_session_turn_lease('owned', 'new-holder')
            assert store.finish()['status'] == 'terminal'
        finally:
            store.close()
    finally:
        db.close()


@pytest.mark.parametrize('patch', [
    {'codex_thread_id': True}, {'codex_thread_id': 1}, {'codex_thread_id': []},
    {'codex_thread_id': {}}, {'codex_thread_id': ''}, {'codex_thread_id': 'x' * 1025},
    {'codex_thread_id': 'valid', '_delegate_from': 'foreign'},
])
def test_codex_sidecar_refuses_invalid_or_authority_fields_atomically(tmp_path, patch):
    db = SessionDB(tmp_path / 'state.db')
    try:
        db.create_session('owned', 'kanban', model_config={'codex_thread_id': 'retained'})
        epoch = begin_runtime_epoch(db, instance_id='fixture')
        scope = dict(epoch=epoch, execution_id='worker', session_id='owned', generation=0)
        register_worker_execution(db, **scope, kind='compute', adoption_secret='fixture-secret')
        with pytest.raises(Exception, match='invalid_params'):
            mutate_worker_execution(db, **scope, sequence=1, operation='session.sidecars',
                                    payload={'patch': patch})
        assert db.get_session_model_config_value('owned', 'codex_thread_id') == 'retained'
        assert db._read_one('SELECT last_sequence FROM worker_executions WHERE execution_id=?',
                            ('worker',))[0] == 0
    finally:
        db.close()


@pytest.mark.parametrize('thread_id', ['valid-thread', True, None])
def test_codex_binding_is_not_an_archive_patch_permission(tmp_path, thread_id):
    db = SessionDB(tmp_path / 'state.db')
    try:
        db.create_session('owned', 'kanban', model_config={'codex_thread_id': 'retained'})
        epoch = begin_runtime_epoch(db, instance_id='fixture')
        scope = dict(epoch=epoch, execution_id='worker', session_id='owned', generation=0)
        register_worker_execution(db, **scope, kind='compute', adoption_secret='fixture-secret')
        with pytest.raises(Exception, match='invalid_params'):
            mutate_worker_execution(db, **scope, sequence=1, operation='compression.archive', payload={
                'messages': [{'role': 'assistant', 'content': 'summary'}],
                'model_config_patch': {'codex_thread_id': thread_id},
                'watermark': None, 'lock_holder': None, 'tail_count': 0})
        assert db.get_session_model_config_value('owned', 'codex_thread_id') == 'retained'
        assert db.get_messages('owned') == []
        assert db._read_one('SELECT last_sequence FROM worker_executions WHERE execution_id=?',
                            ('worker',))[0] == 0
    finally:
        db.close()
