"""Authenticated private sidecar operations on the existing profile writer.

The reserved zero sequence is not a transcript receipt stream. Operations are
idempotent and their selectors never enter receipts or worker JSON journals.
"""
import asyncio

from hermes_state_runtime import RuntimeStoreError, _epoch


async def native_recovery_request(connection, ref, params):
    from gateway.session_authorities import require_serving
    from gateway.session_worker import _SCOPE, _claim, _verify
    authority = connection.authority
    require_serving(authority)
    if (set(params) != _SCOPE | {'epoch', 'sequence', 'operation', 'payload'}
            or type(params['sequence']) is not int or params['sequence'] != 0
            or 'worker:adopt' not in connection.actor.capabilities):
        raise RuntimeStoreError('invalid_params')
    claim = _claim(connection, ref, params)
    _verify(connection, ref, params, claim)
    payload = params['payload']
    if (type(payload) is not dict or set(payload) != {'profile', 'action', 'value', 'deadline'}
            or payload['profile'] != authority.profile_id):
        raise RuntimeStoreError('invalid_params')

    def guard(conn):
        _epoch(conn, params['epoch'])
        row = conn.execute('SELECT * FROM worker_executions WHERE execution_id=?',
                           (params['execution_id'],)).fetchone()
        if (row is None or row['owner_epoch'] != params['epoch']
                or row['session_id'] != params['session_id']
                or row['generation'] != params['generation']
                or row['status'] not in ('registered', 'running')):
            raise RuntimeStoreError('stale_generation')
        if (payload['action'] == 'persist'
                and payload['value'].get('original_session_id') != params['session_id']):
            raise RuntimeStoreError('permission_denied')

    return await asyncio.to_thread(authority.db.native_response_use, payload['profile'],
                                   payload['action'], payload['value'],
                                   deadline=payload['deadline'], _guard=guard)
