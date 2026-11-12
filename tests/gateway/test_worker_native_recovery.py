"""Native selector writes follow the authenticated existing SessionDB owner."""
import asyncio
import json
import subprocess
import sys
import time
from types import SimpleNamespace

import psutil
import pytest

from agent.runtime_session_store import RuntimeSessionStore
from gateway.config import Platform
from gateway.session_authority import LiveSession, SessionAuthority
from gateway.session_contract import Principal, SessionRef
from gateway.session_worker import worker_request
from hermes_state import SessionDB
from hermes_state_runtime import RuntimeStoreError, begin_runtime_epoch
from tests.hermes_state.test_native_recovery import hint


def test_owner_proxy_uses_no_selector_journal_and_fences_restart(tmp_path):
    process = subprocess.Popen([sys.executable, '-c', 'import sys;sys.stdin.read()'], stdin=subprocess.PIPE)
    db = SessionDB(tmp_path / 'state.db')
    db.create_session('owned', 'cli')
    epoch = begin_runtime_epoch(db, instance_id='owner')
    runner = SimpleNamespace(_draining=False, config=SimpleNamespace(multiplex_profiles=False),
                             _adapter_for_source=lambda source: None)
    authority = SessionAuthority(runner, db=db, epoch=epoch, profile_id=str(tmp_path), instance_id='owner')
    authority.sessions['owned'] = LiveSession(SimpleNamespace(platform=Platform.TELEGRAM, user_id='human'), 'route')
    actor = Principal('human', str(tmp_path), frozenset({'worker:adopt'}), 'ticket')
    ref = SessionRef(str(tmp_path), 'owned')
    connection = SimpleNamespace(authority=authority, actor=actor)
    scope = {'profile_id': str(tmp_path), 'session_id': 'owned', 'execution_id': 'worker',
        'generation': 0, 'pid': process.pid, 'birth': psutil.Process(process.pid).create_time(), 'secret': 's' * 32}
    store = None
    try:
        asyncio.run(worker_request(connection, ref, scope | {'kind': 'compute'}, operation='register'))
        adopted = asyncio.run(worker_request(connection, ref, scope, operation='adopt'))
        def rpc(method, *, _deadline=None, **params):
            assert method == 'worker.persist'
            return asyncio.run(worker_request(connection, ref, params, operation='persist'))
        store = RuntimeSessionStore(rpc, scope | {'epoch': adopted['owner_epoch']}, tmp_path / 'existing-outbox')
        value = hint(original_session_id='owned')
        assert store.native_response_use(str(tmp_path), 'persist', value,
                                         deadline=time.monotonic() + 1) == {'state': 'PERSISTED'}
        assert store.native_response_use(str(tmp_path), 'read', {'project_id': 'cloud'},
                                         deadline=time.monotonic() + 1)['selector']['request_id'] == 'request'
        journal = json.loads(store.path.read_text())
        assert journal['pending'] == [] and journal['next_sequence'] == 1
        assert 'projection_digest' not in store.path.read_text()
        assert db._read_one('SELECT count(*) FROM worker_receipts')[0] == 0
        # Profile, current assignment and credential checks precede the sidecar.
        with pytest.raises(RuntimeStoreError):
            store.native_response_use(str(tmp_path / 'other'), 'read', {'project_id': 'cloud'},
                                      deadline=time.monotonic() + 1)
        with pytest.raises(RuntimeStoreError):
            store.native_response_use(str(tmp_path), 'persist', hint(original_session_id='foreign'),
                                      deadline=time.monotonic() + 1)
        begin_runtime_epoch(db, instance_id='restarted-owner')
        with pytest.raises(RuntimeStoreError):
            store.native_response_use(str(tmp_path), 'clear', {'project_id': 'cloud', 'request_id': 'request'},
                                      deadline=time.monotonic() + 1)
        assert db._read_one('SELECT count(*) FROM native_response_use_hints')[0] == 1
    finally:
        if store is not None:
            store.close()
        db.close()
        process.stdin.close()
        process.wait(timeout=5)


def test_bounded_rpc_does_not_discover_or_reconnect_owner(tmp_path, monkeypatch):
    from agent.runtime_session_store import WorkerPersistenceError, WorkerRPC
    rpc = WorkerRPC(tmp_path)
    def forbidden():
        raise AssertionError('native recovery must not discover/reconnect')
    monkeypatch.setattr(rpc, '_connection', forbidden)
    with pytest.raises(WorkerPersistenceError, match='owner_unavailable'):
        rpc('worker.persist', _deadline=time.monotonic() + 0.1)
    assert rpc.link is None
