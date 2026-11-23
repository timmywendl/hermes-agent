"""The canonical dispatcher speaks only the declared wire contract (``tui_gateway/contracts``)."""
from types import SimpleNamespace

import pytest

from gateway.session_authority import LiveSession, SessionAuthority
from gateway.session_controls import AuthorityConnection
from gateway.session_group_controls import GROUP_METHODS
from hermes_state import SessionDB
from hermes_state_runtime import begin_runtime_epoch
from tui_gateway.contracts.registry import CANONICAL_METHODS, METHODS


@pytest.fixture
def owner(tmp_path):
    with SessionDB(db_path=tmp_path / 'state.db') as db:
        db.create_session('s', source='test')
        epoch = begin_runtime_epoch(db, instance_id='current')
        authority = SessionAuthority(SimpleNamespace(_draining=False), profile_id='owned',
                                     instance_id='current', db=db, epoch=epoch)
        authority.sessions['s'] = LiveSession(None, 'route')
        yield AuthorityConnection(authority, object(), {'user_id': 'owner'}), db


def test_every_canonical_verb_has_a_declared_contract(owner):
    """Each name the authority answers is a ``METHODS`` (shared with the sidecar) or
    ``CANONICAL_METHODS`` declaration, so it is rendered into the generated TypeScript and
    OpenRPC; and no canonical declaration outlives its handler."""
    connection, _ = owner
    served = set(connection.handlers()) | set(GROUP_METHODS) | {'profiles.list'}
    assert sorted(served - set(METHODS) - set(CANONICAL_METHODS)) == []
    assert sorted(set(CANONICAL_METHODS) - served) == []


@pytest.mark.asyncio
async def test_declared_params_gate_canonical_verbs_before_their_handlers(owner):
    """An unknown or missing key is ``4001 invalid_params`` naming the field, including verbs
    whose handlers only ``.get`` their keys; a well-formed call is unaffected."""
    connection, db = owner
    revision = db.get_session('s')['runtime_revision']
    mutate = {'session_id': 's', 'request_id': 'r1', 'expected_revision': revision,
              'operation': 'rename', 'payload': {'title': 'Declared'}}
    try:
        for method, params, field in (
                ('prompt.receipt', {'session_id': 's', 'admission_id': 'a', 'bogus': 1}, 'bogus'),
                ('prompt.cancel', {'session_id': 's'}, 'admission_id'),
                ('session.mutate', {**mutate, 'expected_revison': revision}, 'expected_revison')):
            response = await connection.dispatch({'id': 1, 'method': method, 'params': params})
            assert response['error']['code'] == 4001, (method, response)
            assert response['error']['data']['reason'] == 'invalid_params'
            assert field in response['error']['data']['fields'], (method, response)
        applied = await connection.dispatch({'id': 2, 'method': 'session.mutate', 'params': mutate})
        CANONICAL_METHODS['session.mutate'].result.model_validate(applied['result'])
        assert db.get_session('s')['title'] == 'Declared'
    finally:
        await connection.close()


@pytest.mark.asyncio
async def test_finish_projection_is_authorized_and_requires_explicit_receipt(owner, monkeypatch):
    from hermes_state_runtime import admit_session_input, claim_session_input, mutate_worker_execution, register_worker_execution

    connection, db = owner
    authority = connection.authority
    import json
    context = dict(board='owned', task_id='t_abc', run_id=1, claim_lock='private-claim')
    request = 'kanban:' + json.dumps(['owned', 't_abc', 1], separators=(',', ':'))
    monkeypatch.setattr('hermes_state_local.local_receipt', lambda *_: {'policy': {}})
    monkeypatch.setattr('gateway.session_policy.restore_policy', lambda _: SimpleNamespace(source='kanban', kanban_json=json.dumps(context)))
    admitted = admit_session_input(db, epoch=authority.epoch, principal_id=connection.actor.subject,
        session_id='s', request_id=request, payload={'text': 'work'})
    claimed = claim_session_input(db, epoch=authority.epoch, session_id='s')
    scope = dict(epoch=authority.epoch, execution_id='admission-worker:' + admitted['admission_id'],
                 session_id='s', generation=claimed['generation'])
    register_worker_execution(db, **scope, kind='compute', adoption_secret='private-proof')
    params = dict(session_id='s', admission_id=admitted['admission_id'], include_worker_finish=True)
    async def query(client):
        return await client.dispatch({'id': 2, 'method': 'prompt.receipt', 'params': params})
    before = await query(connection)
    assert before['result']['worker_finish'] == dict(receipt='UNKNOWN', ack='UNKNOWN', physical_retirement='UNKNOWN')
    mutate_worker_execution(db, **scope, sequence=1, operation='execution.finish', payload={})
    after = await query(connection)
    assert after['result']['worker_finish'] == dict(receipt='RECORDED', ack='UNKNOWN', physical_retirement='UNKNOWN')
    assert 'private-proof' not in str(after)
    context['run_id'] = 2
    assert (await query(connection))['result']['worker_finish']['receipt'] == 'UNKNOWN'
    context['run_id'] = 1
    monkeypatch.setattr('gateway.session_policy.restore_policy', lambda _: SimpleNamespace(source='cli', kanban_json=json.dumps(context)))
    assert (await query(connection))['result']['worker_finish']['receipt'] == 'UNKNOWN'
    foreign = AuthorityConnection(authority, object(), {'user_id': 'foreign', 'capabilities': ['session:submit']})
    try:
        denied = await query(foreign)
        assert denied['error']['data']['reason'] == 'permission_denied'
    finally:
        await foreign.close()
