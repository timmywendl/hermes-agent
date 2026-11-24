"""Real messaging ingress and authenticated WS must share one warm agent."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest


def test_messaging_then_authenticated_ws_reuses_live_agent(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    home = tmp_path / "home"
    home.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    # A fresh interpreter keeps import-time profile caches and background workers
    # away from both the user's state and pytest's process-global fixtures.
    env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "LANG", "TZ") if key in os.environ}
    env.update(HOME=str(home), USERPROFILE=str(home), HERMES_HOME=str(state),
               PYTHONPATH=str(repo), PYTHONUNBUFFERED="1")
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "fixtures" / "shared_authority_peer.py")],
        cwd=repo, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=100, check=False
    )
    assert result.returncode == 0, result.stdout + "\n" + result.stderr
    receipt = json.loads((state / "receipt.json").read_text())
    print(json.dumps(receipt, indent=2))
    assert receipt["messaging_completed"], receipt
    assert receipt["unauthenticated_rejected"], receipt
    assert receipt["ws_completed"], receipt
    assert receipt["same_agent"], receipt


@pytest.mark.platforms("linux")
def test_native_queue_survives_owner_kill_without_replaying_unknown(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    home, state = tmp_path / 'home', tmp_path / 'state'
    home.mkdir()
    state.mkdir()
    env = {key: os.environ[key] for key in ('PATH', 'LANG', 'TZ') if key in os.environ}
    env.update(HOME=str(home), USERPROFILE=str(home), HERMES_HOME=str(state),
               PYTHONPATH=str(repo), PYTHONUNBUFFERED='1', AUTHORITY_PROBE_MODE='crash')
    command = [sys.executable, str(Path(__file__).parent / 'fixtures' / 'shared_authority_peer.py')]
    with (state / 'owner.log').open('w+') as log:
        child = subprocess.Popen(command, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 90
            while not (state / 'crash-ready.json').exists():
                if child.poll() is not None or time.monotonic() > deadline:
                    log.seek(0)
                    pytest.fail(log.read())
                time.sleep(0.05)
            child.kill()
            assert child.wait(timeout=10) < 0
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
    env['AUTHORITY_PROBE_MODE'] = 'recover'
    for expected_calls in (1, 0):
        result = subprocess.run(command, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=70, check=False)
        assert result.returncode == 0, result.stdout + '\n' + result.stderr
        receipt = json.loads((state / 'recovery-receipt.json').read_text())
        assert receipt['model_calls'] == expected_calls, receipt
        print(json.dumps(receipt, indent=2))


@pytest.mark.asyncio
@pytest.mark.parametrize('restart', [False, True])
async def test_board_pause_keeps_persisted_queue_and_unknown(owner, paused_session, restart, monkeypatch):
    from types import SimpleNamespace
    from gateway.session_authority import initialize_session_authority
    from gateway.session_contract import Submission
    from hermes_state_runtime import RuntimeStoreError, admit_session_input, list_session_admissions
    actor, ref, _policy = paused_session()
    for request in ('first', 'follower'):
        admit_session_input(owner.db, epoch=owner.epoch, principal_id=actor.subject,
                            session_id=ref.session_id, request_id=request, payload={'text': request})
    before = list_session_admissions(owner.db, session_id=ref.session_id)
    if restart:
        runner = SimpleNamespace(_draining=False, session_store=owner.runner.session_store, adapters={})
        runner._adapter_for_source = lambda source: runner.adapters[source.platform]
        owner = await initialize_session_authority(runner, profile_id=owner.profile_id,
                                                   instance_id='cold', db=owner.db)
    def forbidden_restore(*args, **kwargs):
        raise AssertionError('paused claim restored/prepared an execution')
    monkeypatch.setattr('gateway.session_local_recovery.restore_local_session', forbidden_restore)
    with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
        await owner._claim_next(ref, owner.sessions[ref.session_id])
    with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
        await owner.submit(actor, Submission('new', ref, {'text': 'do not admit'}, 'queue'))
    assert list_session_admissions(owner.db, session_id=ref.session_id) == before
    assert owner.db.get_session(ref.session_id)['runtime_generation'] == 0
    assert not owner.executing


@pytest.mark.asyncio
async def test_board_pause_non_board_local_still_admits_and_claims(owner, paused_session):
    from gateway.session_contract import Submission
    actor, ref, _policy = paused_session(board=False)
    receipt = await owner.submit(actor, Submission('normal', ref, {'text': 'ordinary turn'}, 'queue'))
    row, first = await owner._claim_next(ref, owner.sessions[ref.session_id])
    assert row['admission_id'] == receipt.admission_id == first['admission_id']
    assert row['status'] == 'started'


@pytest.mark.asyncio
@pytest.mark.parametrize('marker', ['created_source', 'compression_ancestor'])
async def test_board_pause_preserves_board_provenance_through_surface_changes(owner, paused_session, marker):
    from gateway.session_contract import Submission
    from hermes_state_runtime import RuntimeStoreError, list_session_admissions

    actor, ref, _policy = paused_session(board=False)
    if marker == 'compression_ancestor':
        owner.db.create_session('board-ancestor', 'kanban')
    def change(conn):
        if marker == 'created_source':
            conn.execute("UPDATE sessions SET source='cli',created_source='kanban' WHERE id=?", (ref.session_id,))
        else:
            conn.execute("UPDATE sessions SET end_reason='compression' WHERE id='board-ancestor'")
            conn.execute("UPDATE sessions SET parent_session_id='board-ancestor' WHERE id=?", (ref.session_id,))
    owner.db._execute_write(change)
    before = list_session_admissions(owner.db, session_id=ref.session_id)
    with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
        await owner.submit(actor, Submission('no-board', ref, {'text': 'held'}, 'queue'))
    assert list_session_admissions(owner.db, session_id=ref.session_id) == before


@pytest.mark.parametrize('marker', ['row', 'context', 'policy_source', 'request_source', 'request_board',
                                    'request_id', 'missing_receipt', 'malformed_receipt', 'missing_context', 'bad_request'])
@pytest.mark.asyncio
async def test_board_pause_provenance_cannot_downgrade_to_local(owner, paused_session, marker):
    from hermes_state_local import POLICY_PREFIX
    from gateway.session_kanban import check_board_execution
    from hermes_state_runtime import RuntimeStoreError, admit_session_input, list_session_admissions
    actor, ref, _policy = paused_session(board=False)
    admit_session_input(owner.db, epoch=owner.epoch, principal_id=actor.subject,
                        session_id=ref.session_id, request_id='held', payload={'text': 'held'})
    key = POLICY_PREFIX + ref.session_id
    def mutate(conn):
        saved = json.loads(conn.execute('SELECT value FROM state_meta WHERE key=?', (key,)).fetchone()[0])
        policy_updates = {
            'context': {'kanban_json': '{}'}, 'policy_source': {'source': 'kanban'},
            'request_source': {'request_json': '{"source":"kanban"}'},
            'request_board': {'request_json': '{"board":"held"}'}, 'bad_request': {'request_json': '['},
        }
        saved['policy'].update(policy_updates.get(marker, {}))
        if marker == 'row':
            conn.execute("UPDATE sessions SET source='kanban' WHERE id=?", (ref.session_id,))
        if marker == 'request_id':
            saved['request_id'] = 'kanban:held'
        if marker == 'missing_context':
            del saved['policy']['kanban_json']
        if marker == 'missing_receipt':
            conn.execute('DELETE FROM state_meta WHERE key=?', (key,))
        else:
            value = '{' if marker == 'malformed_receipt' else json.dumps(saved)
            conn.execute('UPDATE state_meta SET value=? WHERE key=?', (value, key))
    owner.db._execute_write(mutate)
    before = list_session_admissions(owner.db, session_id=ref.session_id)
    with pytest.raises(RuntimeStoreError):
        check_board_execution(owner, ref)
    assert list_session_admissions(owner.db, session_id=ref.session_id) == before

    with pytest.raises(RuntimeStoreError):
        await owner._claim_next(ref, owner.sessions[ref.session_id])
    assert list_session_admissions(owner.db, session_id=ref.session_id) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("existing", [False, True])
async def test_board_pause_internal_completion_cannot_admit_board_turn(owner, paused_session, monkeypatch, existing):
    """Real trusted automation ingress must not add input to a paused Board FIFO."""
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from hermes_state_runtime import RuntimeStoreError, list_session_admissions
    _actor, ref, _policy = paused_session()
    live = owner.sessions[ref.session_id]
    adapter = owner.runner.adapters[Platform.LOCAL]
    event = MessageEvent(text='background result', source=live.source, internal=True,
                         metadata={'gateway_session_key': live.route, 'gateway_session_id': ref.session_id})
    if existing:
        from gateway.session_automation import snapshot_automation
        from hermes_state_runtime import admit_session_input
        payload, entry = snapshot_automation(owner, adapter, event, 'completion:paused-board')
        admit_session_input(owner.db, epoch=owner.epoch, principal_id='automation:' + entry.session_key,
                            session_id=ref.session_id, request_id='completion:paused-board', payload=payload)
    scheduled = []
    monkeypatch.setattr(owner, '_schedule', lambda target: scheduled.append(target))
    before = list_session_admissions(owner.db, session_id=ref.session_id)
    try:
        await owner.admit_automation(adapter, event, 'completion:paused-board')
    except RuntimeStoreError as exc:
        assert exc.reason == 'board_execution_paused'
    after = list_session_admissions(owner.db, session_id=ref.session_id)
    assert after == before, 'Board automation bypass added a new queued admission while execution is paused'
    assert scheduled == []


@pytest.mark.asyncio
@pytest.mark.parametrize('becomes_board', [False, True])
async def test_board_pause_automation_checks_real_writer(owner, paused_session, monkeypatch, becomes_board):
    import sqlite3
    from gateway.config import Platform
    from gateway.platforms.event import MessageEvent
    from hermes_state_runtime import RuntimeStoreError, list_session_admissions
    _actor, ref, _policy = paused_session(board=False)
    live = owner.sessions[ref.session_id]
    event = MessageEvent(text='completion', source=live.source, internal=True,
                         metadata={'gateway_session_key': live.route, 'gateway_session_id': ref.session_id})
    scheduled, checked = [], []
    monkeypatch.setattr(owner, '_schedule', lambda target: scheduled.append(target))
    original_gate = owner._board_admission_gate
    def gate(target, authorize=None):
        guarded = original_gate(target, authorize)
        def guard(conn):
            checked.append((target, conn.in_transaction))
            guarded(conn)
        return guard
    monkeypatch.setattr(owner, '_board_admission_gate', gate)
    original_write = owner.db._execute_write
    def write(operation):
        if becomes_board:
            # Snapshot was ordinary; an independent writer commits Board provenance
            # before the admission obtains its writer transaction.
            with sqlite3.connect(owner.db.db_path) as other:
                other.execute("UPDATE sessions SET source='kanban' WHERE id=?", (ref.session_id,))
        return original_write(operation)
    monkeypatch.setattr(owner.db, '_execute_write', write)
    before = list_session_admissions(owner.db, session_id=ref.session_id)
    adapter = owner.runner.adapters[Platform.LOCAL]
    if becomes_board:
        with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
            await owner.admit_automation(adapter, event, 'completion:writer')
        assert list_session_admissions(owner.db, session_id=ref.session_id) == before
        assert scheduled == []
    else:
        await owner.admit_automation(adapter, event, 'completion:writer')
        rows = list_session_admissions(owner.db, session_id=ref.session_id)
        assert len(rows) == 1 and rows[0]['status'] == 'queued'
        assert rows[0]['request_id'] == 'completion:writer' and scheduled == [ref]
    assert checked == [(ref, True)]


@pytest.mark.asyncio
@pytest.mark.parametrize('blocked', ['old', 'new', 'malformed', 'none'])
async def test_board_pause_route_wakes_preserve_queue_before_cancel(owner, tmp_path, monkeypatch, blocked):
    from dataclasses import asdict, replace
    from gateway.config import Platform
    from gateway.session import SessionSource
    from gateway.session_authority import LiveSession
    from gateway.session_automation import move_route_wakes
    from gateway.session_contract import SessionRef
    from gateway.session_policy import build_policy
    from hermes_state_local import POLICY_PREFIX
    from hermes_state_runtime import RuntimeStoreError, admit_session_input, list_session_admissions
    source = SessionSource(platform=Platform.TELEGRAM, chat_id='route', user_id='human')
    old = owner.register(source)
    route = owner.sessions[old.session_id].route
    new = SessionRef(owner.profile_id, 'rotated')
    owner.db.create_session(new.session_id, 'telegram')
    owner.sessions[new.session_id] = LiveSession(source, route)
    owner.runner.session_store.lookup_by_session_key(route).session_id = new.session_id
    scheduled, writer_checks = [], []
    original_gate = owner._board_admission_gate
    def gate(target, authorize=None):
        guarded = original_gate(target, authorize)
        def guard(conn):
            writer_checks.append((target, conn.in_transaction))
            guarded(conn)
        return guard
    monkeypatch.setattr(owner, '_board_admission_gate', gate)
    monkeypatch.setattr(owner, '_schedule', lambda ref: scheduled.append(ref))
    request = json.dumps(['kanban-wake', 'held-route'])
    payload = {'text': 'wake', 'native_text_v1': {'automation': {'owner': old.session_id}}}
    admit_session_input(owner.db, epoch=owner.epoch, principal_id='automation:' + route,
                        session_id=old.session_id, request_id=request, payload=payload)
    if blocked != 'none':
        policy = build_policy({'source': 'cli', 'cwd': str(tmp_path), 'model': 'fixture'}, {})
        policy = replace(policy, source='kanban', kanban_json='{"task_id":"held"}')
        target = new if blocked == 'new' else old
        receipt = {'session_id': target.session_id, 'profile_id': owner.profile_id,
                   'request_id': 'kanban:held', 'policy': asdict(policy)}
        raw = '{' if blocked == 'malformed' else json.dumps(receipt)
        owner.db._execute_write(lambda conn: conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)',
                                                          (POLICY_PREFIX + target.session_id, raw)))
    with owner.db._read_ctx() as conn:
        before = list(conn.iterdump())
    if blocked == 'none':
        await move_route_wakes(owner.runner, route, old.session_id)
        prior = list_session_admissions(owner.db, session_id=old.session_id, pending_only=False)
        current = list_session_admissions(owner.db, session_id=new.session_id)
        assert prior[0]['status'] == 'terminal' and prior[0]['outcome'] == 'cancelled'
        assert len(current) == 1 and current[0]['status'] == 'queued'
        assert current[0]['request_id'] == request and scheduled == [old, new]
        assert writer_checks == [(new, True)]
    else:
        with pytest.raises(RuntimeStoreError):
            await move_route_wakes(owner.runner, route, old.session_id)
        with owner.db._read_ctx() as conn:
            assert list(conn.iterdump()) == before
        assert not owner.cancel_obligations and scheduled == []


@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['submit', 'claim'])
async def test_board_pause_owner_rechecks_provenance_in_writer(owner, paused_session, monkeypatch, operation):
    import sqlite3
    from gateway.session_contract import Submission
    from hermes_state_runtime import RuntimeStoreError, admit_session_input, list_session_admissions
    actor, ref, _policy = paused_session(board=False)
    if operation == 'claim':
        admit_session_input(owner.db, epoch=owner.epoch, principal_id=actor.subject,
                            session_id=ref.session_id, request_id='held', payload={'text': 'held'})
    before = list_session_admissions(owner.db, session_id=ref.session_id)
    original_write = owner.db._execute_write
    def write(action):
        with sqlite3.connect(owner.db.db_path) as other:
            other.execute("UPDATE sessions SET source='kanban' WHERE id=?", (ref.session_id,))
        return original_write(action)
    monkeypatch.setattr(owner.db, '_execute_write', write)
    with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
        if operation == 'submit':
            await owner.submit(actor, Submission('new', ref, {'text': 'no start'}, 'queue'))
        else:
            await owner._claim_next(ref, owner.sessions[ref.session_id])
    assert list_session_admissions(owner.db, session_id=ref.session_id) == before
    assert not owner.executing
