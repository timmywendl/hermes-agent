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


@pytest.mark.asyncio
@pytest.mark.parametrize('receipt_kind', ['valid', 'missing', 'broken_lineage'])
async def test_board_pause_orphan_requires_independent_non_board_receipt(owner, paused_session, receipt_kind):
    import json
    import sqlite3
    from gateway.session_contract import Submission
    from hermes_state_local import POLICY_PREFIX
    from hermes_state_runtime import RuntimeStoreError
    actor, ref, _policy = paused_session(board=False)
    # Older databases could have been written without foreign-key enforcement.
    with sqlite3.connect(owner.db.db_path) as legacy:
        legacy.execute('UPDATE sessions SET parent_session_id=? WHERE id=?', ('missing-parent', ref.session_id))
    def prepare(conn):
        key = POLICY_PREFIX + ref.session_id
        if receipt_kind == 'missing':
            conn.execute('DELETE FROM state_meta WHERE key=?', (key,))
        elif receipt_kind == 'broken_lineage':
            receipt = json.loads(conn.execute('SELECT value FROM state_meta WHERE key=?', (key,)).fetchone()[0])
            receipt['lineage'] = ['missing-parent', ref.session_id]
            conn.execute('UPDATE state_meta SET value=? WHERE key=?', (json.dumps(receipt), key))
    owner.db._execute_write(prepare)
    request = Submission('orphan-check', ref, {'text': 'fixture'}, 'queue')
    # A singleton receipt cannot establish why the parent edge is missing.
    with pytest.raises(RuntimeStoreError, match='storage_unavailable'):
        await owner.submit(actor, request)


@pytest.mark.asyncio
@pytest.mark.parametrize('edge', ['_reset_from', '_branched_from', '_delegate_from'])
async def test_board_pause_separate_fork_does_not_inherit_board_parent(owner, paused_session, edge):
    import json
    from gateway.session_contract import Submission
    actor, ref, _policy = paused_session(board=False)
    owner.db.create_session('board-parent', 'kanban')
    def prepare(conn):
        conn.execute("UPDATE sessions SET end_reason='compression' WHERE id='board-parent'")
        conn.execute('UPDATE sessions SET parent_session_id=?,model_config=? WHERE id=?',
                     ('board-parent', json.dumps({edge: 'board-parent'}), ref.session_id))
    owner.db._execute_write(prepare)
    assert (await owner.submit(actor, Submission('fork-check', ref, {'text': 'fixture'}, 'queue'))).status == 'queued'


@pytest.mark.asyncio
async def test_board_pause_orphan_explicit_fork_with_receipt_is_non_board(owner, paused_session):
    import json
    import sqlite3
    from gateway.session_contract import Submission
    actor, ref, _policy = paused_session(board=False)
    with sqlite3.connect(owner.db.db_path) as legacy:
        legacy.execute('UPDATE sessions SET parent_session_id=?,model_config=? WHERE id=?',
                       ('missing-parent', json.dumps({'_branched_from': 'missing-parent'}), ref.session_id))
    assert (await owner.submit(actor, Submission('orphan-fork', ref, {'text': 'fixture'}, 'queue'))).status == 'queued'


@pytest.mark.asyncio
async def test_board_pause_non_board_history_after_real_parent_delete(owner, paused_session):
    import json
    from gateway.session_contract import Submission
    actor, ref, _policy = paused_session(board=False)
    owner.db.create_session('deleted-parent', 'cli')
    def link(conn):
        conn.execute('UPDATE sessions SET parent_session_id=?,model_config=? WHERE id=?',
                     ('deleted-parent', json.dumps({'_branched_from': 'deleted-parent'}), ref.session_id))
    owner.db._execute_write(link)
    assert owner.db.delete_sessions(['deleted-parent']) == 1
    assert owner.db.get_session(ref.session_id)['parent_session_id'] is None
    assert (await owner.submit(actor, Submission('after-delete', ref, {'text': 'fixture'}, 'queue'))).status == 'queued'


@pytest.mark.asyncio
async def test_board_pause_non_board_compression_uses_original_owner(owner, paused_session):
    from gateway.session_contract import Submission
    actor, ref, _policy = paused_session(board=False)
    owner.db.end_session(ref.session_id, 'compression')
    owner.db.create_session('compression-child', 'cli', parent_session_id=ref.session_id)
    assert owner.logical_owner('compression-child') == ref.session_id
    assert (await owner.submit(actor, Submission('after-compression', ref, {'text': 'fixture'}, 'queue'))).status == 'queued'


@pytest.mark.asyncio
async def test_board_pause_non_board_real_reset_keeps_original_owner(owner, paused_session):
    from gateway.session_contract import Submission
    from tests.hermes_state.test_reset_owner_housekeeping import _store_reset
    actor, ref, _policy = paused_session(board=False)
    child = _store_reset(owner.db, owner.epoch, ref.session_id)
    assert owner.db.get_session(child)['parent_session_id'] == ref.session_id
    assert (await owner.submit(actor, Submission('after-reset', ref, {'text': 'fixture'}, 'queue'))).status == 'queued'


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
@pytest.mark.parametrize('blocked', ['old', 'new', 'malformed', 'none', 'race-old', 'race-new', 'mid-write',
                                      'mid-deny', 'settle-fail', 'publish-fail', 'commit-ack-loss', 'retry-after-commit',
                                      'cancel-window', 'media-fail', 'media-runtime-fail', 'retry-retag',
                                      'publish-after-event', 'fanout-fail'])
async def test_board_pause_route_wakes_preserve_queue_before_cancel(owner, tmp_path, monkeypatch, blocked):
    import asyncio
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
            if blocked == 'mid-write' and len(writer_checks) == 3:
                # The old row was cancelled in this transaction. A competing
                # writer cannot commit provenance until the move completes.
                import sqlite3
                with sqlite3.connect(owner.db.db_path, timeout=0) as rival:
                    with pytest.raises(sqlite3.OperationalError, match='locked'):
                        rival.execute("UPDATE sessions SET source='kanban' WHERE id=?", (old.session_id,))
            if blocked == 'mid-deny' and len(writer_checks) == 3:
                conn.execute("UPDATE sessions SET source='kanban' WHERE id=?", (old.session_id,))
            guarded(conn)
        return guard
    monkeypatch.setattr(owner, '_board_admission_gate', gate)
    monkeypatch.setattr(owner, '_schedule', lambda ref: scheduled.append(ref))
    request = json.dumps(['kanban-wake', 'held-route'])
    payload = {'text': 'wake', 'native_text_v1': {'automation': {'owner': old.session_id}}}
    wake = admit_session_input(owner.db, epoch=owner.epoch, principal_id='automation:' + route,
                               session_id=old.session_id, request_id=request, payload=payload)
    waiter = asyncio.get_running_loop().create_future()
    owner.waiters[wake['admission_id']] = waiter
    if blocked in {'old', 'new', 'malformed'}:
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
    if blocked.startswith('race-'):
        import sqlite3
        target = old if blocked == 'race-old' else new
        original_write = owner.db._execute_write
        def race(operation):
            with sqlite3.connect(owner.db.db_path) as rival:
                rival.execute("UPDATE sessions SET source='kanban' WHERE id=?", (target.session_id,))
            return original_write(operation)
        monkeypatch.setattr(owner.db, '_execute_write', race)
    if blocked in {'commit-ack-loss', 'retry-after-commit', 'retry-retag'}:
        original_write = owner.db._execute_write
        once = []
        def commit_then_retry(operation, **kwargs):
            result = original_write(operation, **kwargs)
            if not once:
                once.append(True)
                if blocked == 'commit-ack-loss':
                    raise OSError('fixture lost commit acknowledgement')
                if blocked == 'retry-retag':
                    import sqlite3
                    with sqlite3.connect(owner.db.db_path) as rival:
                        rival.execute("UPDATE sessions SET source='kanban' WHERE id=?", (new.session_id,))
                return original_write(operation, **kwargs)
            return result
        monkeypatch.setattr(owner.db, '_execute_write', commit_then_retry)
    if blocked == 'cancel-window':
        import threading
        import hermes_state_runtime as runtime
        entered, release = threading.Event(), threading.Event()
        original_move = runtime.move_queued_route_input
        def delayed(*args, **kwargs):
            entered.set()
            assert release.wait(5)
            return original_move(*args, **kwargs)
        monkeypatch.setattr(runtime, 'move_queued_route_input', delayed)
    if blocked in {'settle-fail', 'publish-fail'}:
        target_method = '_settle_cancelled' if blocked == 'settle-fail' else '_admitted'
        original_method = getattr(owner, target_method)
        def fail(*_args):
            raise ValueError('fixture publication failure')
        monkeypatch.setattr(owner, target_method, fail)
    if blocked in {'publish-after-event', 'fanout-fail'}:
        stream = owner.sessions[old.session_id].event_stream
        original_publish = stream.publish
        cancellation_events = []
        stream.observers.add(lambda event: cancellation_events.append(event)
                             if event['params']['payload'].get('outcome') == 'cancelled' else None)
        def publish_then_fail(sid, payload, **kwargs):
            result = original_publish(sid, payload, **kwargs)
            if payload.get('outcome') == 'cancelled':
                raise OSError('fixture fanout lost acknowledgement')
            return result
        if blocked == 'publish-after-event':
            monkeypatch.setattr(stream, 'publish', publish_then_fail)
        else:
            original_fanout = stream.fanout.write
            def fail_fanout(frame, **kwargs):
                if frame['params']['payload'].get('outcome') == 'cancelled':
                    raise OSError('fixture fanout failure')
                return original_fanout(frame, **kwargs)
            monkeypatch.setattr(stream.fanout, 'write', fail_fanout)
    if blocked in {'media-fail', 'media-runtime-fail'}:
        from gateway import session_ingress_media
        media_calls = []
        def release_media(*_args):
            media_calls.append('release')
            if len(media_calls) == 1:
                if blocked == 'media-runtime-fail':
                    raise RuntimeStoreError('storage_unavailable')
                raise OSError('fixture media release failed')
        monkeypatch.setattr(session_ingress_media, 'release_admission_media', release_media)
    if blocked == 'cancel-window':  # health: allow HX011 -- each injected failure has distinct assertions
        task = asyncio.create_task(move_route_wakes(owner.runner, route, old.session_id))
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        waiters = list(owner._mutation_tasks)
        release.set()
        await asyncio.gather(*waiters)
        prior = list_session_admissions(owner.db, session_id=old.session_id, pending_only=False)
        assert prior[0]['status'] == 'terminal'
        assert len(list_session_admissions(owner.db, session_id=new.session_id)) == 1
        assert not owner.cancel_obligations and new in scheduled
        assert waiter.done() and waiter.result() is None
    elif blocked in {'none', 'mid-write', 'retry-after-commit', 'publish-after-event', 'fanout-fail'}:
        await move_route_wakes(owner.runner, route, old.session_id)
        prior = list_session_admissions(owner.db, session_id=old.session_id, pending_only=False)
        current = list_session_admissions(owner.db, session_id=new.session_id)
        assert prior[0]['status'] == 'terminal' and prior[0]['outcome'] == 'cancelled'
        assert len(current) == 1 and current[0]['status'] == 'queued'
        assert current[0]['request_id'] == request and scheduled == [old, new]
        assert waiter.done() and waiter.result() is None
        expected_checks = [(old, True), (new, True), (old, True), (new, True)]
        if blocked == 'retry-after-commit':
            expected_checks.extend([(old, True), (new, True)])
        assert writer_checks == expected_checks
        if blocked in {'publish-after-event', 'fanout-fail'}:
            assert len(cancellation_events) == 1
    elif blocked in {'settle-fail', 'publish-fail', 'commit-ack-loss', 'media-fail', 'media-runtime-fail'}:
        expected = (RuntimeStoreError if blocked == 'media-runtime-fail'
                    else OSError if blocked in {'commit-ack-loss', 'media-fail'} else ValueError)
        with pytest.raises(expected):
            await move_route_wakes(owner.runner, route, old.session_id)
        prior = list_session_admissions(owner.db, session_id=old.session_id, pending_only=False)
        current = list_session_admissions(owner.db, session_id=new.session_id)
        assert prior[0]['status'] == 'terminal' and len(current) == 1 and current[0]['status'] == 'queued'
        assert new in scheduled
        if blocked in {'settle-fail', 'publish-fail'}:
            monkeypatch.setattr(owner, target_method, original_method)
        if blocked == 'media-fail':
            assert media_calls == ['release', 'release']
        await move_route_wakes(owner.runner, route, old.session_id)
        if blocked == 'media-runtime-fail':
            assert media_calls == ['release', 'release']
        assert not owner.cancel_obligations
        assert len(list_session_admissions(owner.db, session_id=new.session_id)) == 1
        assert waiter.done() and waiter.result() is None
    elif blocked == 'retry-retag':
        with pytest.raises(RuntimeStoreError, match='board_execution_paused'):
            await move_route_wakes(owner.runner, route, old.session_id)
        prior = list_session_admissions(owner.db, session_id=old.session_id, pending_only=False)
        current = list_session_admissions(owner.db, session_id=new.session_id)
        assert prior[0]['status'] == 'terminal' and len(current) == 1 and current[0]['status'] == 'queued'
        assert not owner.cancel_obligations
        assert scheduled == [old]
        assert waiter.done() and waiter.result() is None
    else:
        with pytest.raises(RuntimeStoreError):
            await move_route_wakes(owner.runner, route, old.session_id)
        if blocked.startswith('race-'):
            assert len(list_session_admissions(owner.db, session_id=old.session_id)) == 1
            assert not list_session_admissions(owner.db, session_id=new.session_id)
        else:
            with owner.db._read_ctx() as conn:
                assert list(conn.iterdump()) == before
        assert not owner.cancel_obligations and scheduled == []
        assert not waiter.done()


@pytest.mark.asyncio
@pytest.mark.parametrize('crash_point', ['before-notice', 'after-notice'])
@pytest.mark.parametrize('destination_terminal', [False, True])
async def test_board_pause_route_move_restart_recovers_one_pending_input(owner, monkeypatch, crash_point, destination_terminal):
    """Restart the in-process Owner after a post-commit publication failure; no Worker is run."""
    from gateway.config import Platform
    from gateway.session import SessionSource
    from gateway.session_authority import LiveSession, SessionAuthority
    from gateway.session_automation import move_route_wakes
    from gateway.session_contract import SessionRef
    from hermes_state_runtime import (admit_session_input, begin_runtime_epoch, claim_session_input,
                                      list_session_admissions, recover_session_inputs, settle_session_input)
    source = SessionSource(platform=Platform.TELEGRAM, chat_id='restart-route', user_id='human')
    old = owner.register(source)
    route = owner.sessions[old.session_id].route
    new = SessionRef(owner.profile_id, 'restart-target')
    owner.db.create_session(new.session_id, 'telegram')
    owner.sessions[new.session_id] = LiveSession(source, route)
    owner.runner.session_store.lookup_by_session_key(route).session_id = new.session_id
    request = json.dumps(['kanban-wake', 'restart'])
    payload = {'text': 'fixture', 'native_text_v1': {'automation': {'owner': old.session_id}}}
    admit_session_input(owner.db, epoch=owner.epoch, principal_id='automation:' + route,
                        session_id=old.session_id, request_id=request, payload=payload)
    monkeypatch.setattr(owner, '_schedule', lambda _ref: None)
    from gateway import session_ingress_media
    original_release = session_ingress_media.release_admission_media
    def fail_publish(*_args):
        raise ValueError('fixture interrupted publication')
    if crash_point == 'before-notice':
        monkeypatch.setattr(owner, '_settle_cancelled', fail_publish)
    else:
        monkeypatch.setattr(session_ingress_media, 'release_admission_media', fail_publish)
    with pytest.raises(ValueError, match='fixture interrupted publication'):
        await move_route_wakes(owner.runner, route, old.session_id)
    monkeypatch.setattr(session_ingress_media, 'release_admission_media', original_release)
    if destination_terminal:
        # Simulate a previously settled row; no Worker or model is run.
        started = claim_session_input(owner.db, epoch=owner.epoch, session_id=new.session_id)
        settle_session_input(owner.db, epoch=owner.epoch, admission_id=started['admission_id'],
                             generation=started['generation'], outcome='completed')
    epoch = begin_runtime_epoch(owner.db, instance_id='restart-fixture')
    recover_session_inputs(owner.db, epoch=epoch)
    restarted = SessionAuthority(owner.runner, profile_id=owner.profile_id, instance_id='restart-fixture',
                                 db=owner.db, epoch=epoch)
    scheduled = []
    monkeypatch.setattr(restarted, '_schedule', lambda ref: scheduled.append(ref))
    events = []
    from gateway.session_events import SessionEvents
    original_publish = SessionEvents.publish
    def record_publish(stream, sid, payload, **kwargs):
        result = original_publish(stream, sid, payload, **kwargs)
        if sid == old.session_id and payload.get('outcome') == 'cancelled':
            events.append(payload)
        return result
    monkeypatch.setattr(SessionEvents, 'publish', record_publish)
    async def check_route(*_args):
        return source, route
    # Transport bindings are synthetic; the original recovery and SQLite rows are real.
    monkeypatch.setattr('gateway.session_envelope.check_native_route', check_route)
    async def no_service(*_args, **_kwargs):
        return None
    monkeypatch.setattr('gateway.session_hosted_service.ensure_hosted_service', no_service)
    monkeypatch.setattr('gateway.platforms.webhook_ingress.recover_webhook_finalizations', no_service)
    monkeypatch.setattr('gateway.session_local_recovery.recover_local_sessions', lambda *_a, **_k: None)
    owner.runner.session_authority = restarted
    owner.runner._adapter_for_source = lambda _source: object()
    from gateway.run_runtime import recover_gateway_native_sessions
    assert await recover_gateway_native_sessions(owner.runner) == {new.session_id: 'ready'}
    assert old.session_id in restarted.sessions and len(events) == 1
    queued = list_session_admissions(owner.db, session_id=new.session_id)
    assert new in scheduled
    if destination_terminal:
        assert queued == [] and claim_session_input(owner.db, epoch=epoch, session_id=new.session_id) is None
    else:
        assert len(queued) == 1
        first = claim_session_input(owner.db, epoch=epoch, session_id=new.session_id)
        assert first['request_id'] == request and first['status'] == 'started'
        assert claim_session_input(owner.db, epoch=epoch, session_id=new.session_id) is None


@pytest.mark.asyncio
@pytest.mark.parametrize('second_succeeds', [False, True])
async def test_board_pause_route_move_chain_recovers_all_notices(owner, monkeypatch, second_succeeds):
    from gateway.config import Platform
    from gateway.session import SessionSource
    from gateway.session_authority import LiveSession, SessionAuthority
    from gateway.session_automation import move_route_wakes
    from gateway.session_contract import SessionRef
    from gateway.session_events import SessionEvents
    from hermes_state_runtime import (admit_session_input, begin_runtime_epoch, claim_session_input,
                                      recover_session_inputs, route_move_receipts)
    source = SessionSource(platform=Platform.TELEGRAM, chat_id='chain-route', user_id='human')
    first = owner.register(source)
    route = owner.sessions[first.session_id].route
    entry = owner.runner.session_store.lookup_by_session_key(route)
    owner.db.create_session('chain-b', 'telegram')
    owner.db.create_session('chain-c', 'telegram')
    owner.sessions['chain-b'] = LiveSession(source, route)
    owner.sessions['chain-c'] = LiveSession(source, route)
    request = json.dumps(['kanban-wake', 'chain'])
    admit_session_input(owner.db, epoch=owner.epoch, principal_id='automation:' + route,
                        session_id=first.session_id, request_id=request,
                        payload={'text': 'fixture', 'native_text_v1': {'automation': {'owner': first.session_id}}})
    monkeypatch.setattr(owner, '_schedule', lambda _ref: None)
    original_settle = owner._settle_cancelled
    def fail_notice(ref, admission_id):
        if second_succeeds and ref.session_id == 'chain-b':
            return original_settle(ref, admission_id)
        raise ValueError('fixture cancellation notice failure')
    monkeypatch.setattr(owner, '_settle_cancelled', fail_notice)
    for previous, target in ((first.session_id, 'chain-b'), ('chain-b', 'chain-c')):
        entry.session_id = target
        if second_succeeds and previous == 'chain-b':
            await move_route_wakes(owner.runner, route, previous)
        else:
            with pytest.raises(ValueError, match='fixture cancellation notice failure'):
                await move_route_wakes(owner.runner, route, previous)
    assert len(route_move_receipts(owner.db)) == 2
    epoch = begin_runtime_epoch(owner.db, instance_id='chain-restart')
    recover_session_inputs(owner.db, epoch=epoch)
    restarted = SessionAuthority(owner.runner, profile_id=owner.profile_id, instance_id='chain-restart',
                                 db=owner.db, epoch=epoch)
    owner.runner.session_authority = restarted
    owner.runner._adapter_for_source = lambda _source: object()
    monkeypatch.setattr(restarted, '_schedule', lambda _ref: None)
    notices = []
    original_publish = SessionEvents.publish
    def capture(stream, sid, payload, **kwargs):
        result = original_publish(stream, sid, payload, **kwargs)
        if payload.get('outcome') == 'cancelled':
            notices.append(sid)
        return result
    monkeypatch.setattr(SessionEvents, 'publish', capture)
    async def check_route(*_args):
        return source, route
    async def no_service(*_args, **_kwargs):
        return None
    monkeypatch.setattr('gateway.session_envelope.check_native_route', check_route)
    monkeypatch.setattr('gateway.session_hosted_service.ensure_hosted_service', no_service)
    monkeypatch.setattr('gateway.platforms.webhook_ingress.recover_webhook_finalizations', no_service)
    monkeypatch.setattr('gateway.session_local_recovery.recover_local_sessions', lambda *_a, **_k: None)
    from gateway.run_runtime import recover_gateway_native_sessions
    assert await recover_gateway_native_sessions(owner.runner) == {'chain-c': 'ready'}
    expected = [first.session_id] if second_succeeds else [first.session_id, 'chain-b']
    assert notices == expected and route_move_receipts(owner.db) == []
    claimed = claim_session_input(owner.db, epoch=epoch, session_id='chain-c')
    assert claimed['request_id'] == request and claim_session_input(owner.db, epoch=epoch, session_id='chain-c') is None


def test_board_pause_route_move_survives_disposable_process_restart(tmp_path):
    """Two independent fixture interpreters exercise the actual durable transaction; no Worker runs."""
    import subprocess
    import sys
    from pathlib import Path
    repo = str(Path(__file__).resolve().parents[2])
    db_path = str(tmp_path / 'route-restart.db')
    script = r'''
import asyncio, copy, json, os, sys
from pathlib import Path
from types import SimpleNamespace
from hermes_state import SessionDB
from hermes_state_runtime import (admit_session_input, begin_runtime_epoch, claim_session_input,
                                  find_session_admission, list_session_admissions, move_queued_route_input,
                                  recover_session_inputs, route_move_receipts)
from gateway.config import Platform
from gateway.session import SessionSource
from gateway.session_authority import LiveSession, SessionAuthority
from gateway.session_automation import recover_route_move_settlements
from gateway.session_contract import SessionRef
from gateway.session_ingress_media import capture_native_media
db = SessionDB(Path(sys.argv[1]))
mode = sys.argv[2]
payload = {'text': 'fixture', 'native_text_v1': {'automation': {'owner': 'old'}}}
epoch = begin_runtime_epoch(db, instance_id=mode)
if mode == 'first':
    staged = Path(sys.argv[1]).with_name('fixture-media.bin')
    staged.write_bytes(b'disposable fixture media')
    payload['native_text_v1']['media'] = capture_native_media([str(staged)])
    destination = copy.deepcopy(payload)
    destination['native_text_v1']['automation']['owner'] = 'new'
    db.create_session('old', 'telegram')
    db.create_session('new', 'telegram')
    old = admit_session_input(db, epoch=epoch, principal_id='automation:fixture', session_id='old',
                              request_id='fixture-request', payload=payload)
    move_queued_route_input(db, epoch=epoch, admission_id=old['admission_id'], old_session_id='old',
                            new_session_id='new', principal_id='automation:fixture', request_id='fixture-request',
                            payload=destination, guard=lambda conn: None)
    os._exit(0)  # after commit, before any Owner notification or cleanup
recover_session_inputs(db, epoch=epoch)
old = find_session_admission(db, principal_id='automation:fixture', session_id='old', request_id='fixture-request')
destination = copy.deepcopy(old['payload'])
destination['native_text_v1']['automation']['owner'] = 'new'
media_path = Path(destination['native_text_v1']['media'][0]['path'])
assert media_path.exists() and len(route_move_receipts(db)) == 1
runner = SimpleNamespace(_draining=False)
authority = SessionAuthority(runner, profile_id='fixture', instance_id=mode, db=db, epoch=epoch)
authority.sessions['old'] = LiveSession(SessionSource(platform=Platform.TELEGRAM, chat_id='old', user_id='u'), 'route')
authority._publish_pending = lambda _ref: None  # no transport in this offline fixture
authority._schedule = lambda _ref: None          # no Worker in this offline fixture
events = []
authority.sessions['old'].event_stream.observers.add(events.append)
asyncio.run(recover_route_move_settlements(authority, SessionRef('fixture', 'old')))
assert len([e for e in events if e['params']['payload'].get('outcome') == 'cancelled']) == 1
assert media_path.exists() and route_move_receipts(db) == []  # new queued input still owns the media
first = list_session_admissions(db, session_id='new')
replay = move_queued_route_input(db, epoch=epoch, admission_id=old['admission_id'], old_session_id='old',
                                 new_session_id='new', principal_id='automation:fixture', request_id='fixture-request',
                                 payload=destination, guard=lambda conn: None)
claim = claim_session_input(db, epoch=epoch, session_id='new')
second = claim_session_input(db, epoch=epoch, session_id='new')
assert old['status'] == 'terminal' and old['outcome'] == 'cancelled'
assert len(first) == 1 and replay['admission_id'] == first[0]['admission_id'] == claim['admission_id']
assert second is None
print('recovered one admission')
db.close()
'''
    env = {'PATH': os.environ.get('PATH', ''), 'HOME': str(tmp_path), 'HERMES_HOME': str(tmp_path),
           'PYTHONPATH': repo}
    for phase in ('first', 'restart'):
        result = subprocess.run([sys.executable, '-c', script, db_path, phase], cwd=repo, env=env,
                                capture_output=True, text=True, timeout=30, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
        if phase == 'restart':
            assert 'recovered one admission' in result.stdout


@pytest.mark.asyncio
async def test_board_pause_route_media_recovery_rejects_corrupt_receipt(owner, monkeypatch):
    from gateway.config import Platform
    from gateway.session import SessionSource
    from gateway.session_authority import LiveSession
    from gateway.session_automation import recover_route_move_settlements
    from gateway.session_contract import SessionRef
    from hermes_state_runtime import (ROUTE_MOVE_PREFIX, admit_session_input, mark_route_move_notified,
                                      move_queued_route_input)
    owner.db.create_session('old-receipt', 'telegram')
    owner.db.create_session('new-receipt', 'telegram')
    old = admit_session_input(owner.db, epoch=owner.epoch, principal_id='automation:fixture',
                              session_id='old-receipt', request_id='fixture', payload={'text': 'old'})
    move_queued_route_input(owner.db, epoch=owner.epoch, admission_id=old['admission_id'],
                            old_session_id='old-receipt', new_session_id='new-receipt',
                            principal_id='automation:fixture', request_id='fixture', payload={'text': 'new'},
                            guard=lambda _conn: None)
    key = ROUTE_MOVE_PREFIX + old['admission_id']
    def corrupt(conn):
        receipt = json.loads(conn.execute('SELECT value FROM state_meta WHERE key=?', (key,)).fetchone()[0])
        receipt['digest'] = 'corrupt'
        conn.execute('UPDATE state_meta SET value=? WHERE key=?', (json.dumps(receipt), key))
    owner.db._execute_write(corrupt)
    owner.db.create_session('valid-old', 'telegram')
    owner.db.create_session('valid-new', 'telegram')
    valid = admit_session_input(owner.db, epoch=owner.epoch, principal_id='automation:fixture',
                                session_id='valid-old', request_id='valid', payload={'text': 'old'})
    move_queued_route_input(owner.db, epoch=owner.epoch, admission_id=valid['admission_id'],
                            old_session_id='valid-old', new_session_id='valid-new',
                            principal_id='automation:fixture', request_id='valid', payload={'text': 'new'},
                            guard=lambda _conn: None)
    mark_route_move_notified(owner.db, epoch=owner.epoch, admission_id=valid['admission_id'])
    released = []
    monkeypatch.setattr('gateway.session_ingress_media.release_admission_media', lambda _db, aid: released.append(aid))
    source = SessionSource(platform=Platform.TELEGRAM, chat_id='valid-old', user_id='human')
    owner.sessions['valid-old'] = LiveSession(source, 'valid-route')
    monkeypatch.setattr(owner, '_schedule', lambda _ref: None)
    await recover_route_move_settlements(owner, SessionRef(owner.profile_id, 'valid-old'))
    assert released == [valid['admission_id']]
    with owner.db._read_ctx() as conn:
        assert conn.execute('SELECT 1 FROM state_meta WHERE key=?', (key,)).fetchone() is not None
        assert conn.execute('SELECT 1 FROM state_meta WHERE key=?', (ROUTE_MOVE_PREFIX + valid['admission_id'],)).fetchone() is None


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
