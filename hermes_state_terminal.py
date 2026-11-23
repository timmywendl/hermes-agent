"""Private terminal-only tombstone queries; never reconstruct executable history.

The authenticated edge supplies the original principal/target/request and frozen
payload. A retired target permits only that exact digest, never fresh admission.
Worker receipt reads additionally require the original private adoption proof.
"""
import hmac
import json

from hermes_state_runtime import RuntimeStoreError, _epoch, _json, _row, _secret_digest, _text, admission_fingerprint

RESULT_PREFIX = 'gateway.admission.result.v1.'
ADMISSION_PREFIX = 'gateway.terminal_admission.v1.'
IDENTITY_PREFIX = 'gateway.terminal_identity.v1.'
WORKER_PREFIX = 'gateway.terminal_worker.v1.'


def compact_result(result, *, user_message=None):
    """Retain replay/accounting and current-turn API output, never cumulative history."""
    result = dict(result)
    value = result.get('result')
    if not isinstance(value, dict):
        return result
    value = dict(value)
    # The tool schema list rides every turn result for in-process transcript logging; it is the
    # same session-wide copy each turn (tens of KB, more with MCP) and no stored-result reader uses it.
    value.pop('tools', None)
    messages = value.get('messages')
    if isinstance(messages, list):
        # Agent results include all previous turns. APIs only project this turn's
        # assistant/tool suffix; previous_response_id stores its own history. Compression
        # is the exception: its replacement snapshot is the only immutable record of the
        # rewritten prefix for this turn. A later live transcript may include a successor.
        if not value.get('_compressed') and not value.get('_messages_are_turn_suffix'):
            from agent.turn_context import reanchor_current_turn_user_idx
            anchor = value.get('current_turn_user_idx')
            if not (type(anchor) is int and 0 <= anchor < len(messages)
                    and isinstance(messages[anchor], dict) and messages[anchor].get('role') == 'user'):
                anchor = reanchor_current_turn_user_idx(messages, user_message)
            value['messages'] = messages[anchor + 1:]
            if anchor >= 0 and isinstance(messages[anchor], dict) and messages[anchor].get('api_content'):
                # The user row as the model saw it (memory prefetch, plugin context): a chained
                # Responses turn replays it instead of a row rebuilt from the raw request text.
                value['_turn_user_row'] = {k: messages[anchor][k] for k in ('role', 'content', 'api_content')}
            # Recovery/verification nudges are later user-role rows within this same turn.
            # Consumers must not infer a new boundary from them after the real anchor is gone.
            value['_messages_are_turn_suffix'] = True
            value.pop('current_turn_user_idx', None)
    result['result'] = value
    return result


def identity_key(principal_id, session_id, request_id):
    return IDENTITY_PREFIX + admission_fingerprint(canonical_target=session_id,
        payload={'principal': principal_id, 'request': request_id})


def terminal_admission(conn, admission_id):
    saved = conn.execute('SELECT value FROM state_meta WHERE key=?',
                         (ADMISSION_PREFIX + admission_id,)).fetchone()
    return json.loads(saved[0]) if saved else None


def retry_terminal_admission(db, *, epoch, principal_id, session_id, request_id, payload, intent='queue'):
    """None means a live target; a retired miss/conflict is a definitive refusal.

    This is a read-only identity lookup, not authorization to attach, restore a
    route, or write. HTTP authentication/grant checks must precede this query.
    """
    for value in (principal_id, session_id, request_id):
        _text(value)
    digest = admission_fingerprint(canonical_target=session_id,
        payload={'input': json.loads(_json(payload)), 'intent': intent})
    with db._read_ctx() as conn:
        _epoch(conn, epoch)
        from hermes_state_mutation_retirement import RETIRED_PREFIX
        if not conn.execute('SELECT 1 FROM state_meta WHERE key=?', (RETIRED_PREFIX + session_id,)).fetchone():
            return None
        saved = conn.execute('SELECT value FROM state_meta WHERE key=?',
                             (identity_key(principal_id, session_id, request_id),)).fetchone()
        if saved is None:
            raise RuntimeStoreError('not_found')
        row = terminal_admission(conn, json.loads(saved[0]))
        if row['payload_digest'] != digest:
            raise RuntimeStoreError('admission_conflict')
        return _row(row)


def terminal_worker_receipt(db, *, execution_id, session_id, generation, sequence,
                            adoption_secret, payload_digest):
    """Exact retired producer evidence; possession never reactivates the worker."""
    proof = _secret_digest(adoption_secret)
    with db._read_ctx() as conn:
        saved = conn.execute('SELECT value FROM state_meta WHERE key=?',
                             (WORKER_PREFIX + execution_id,)).fetchone()
        if saved is None:
            raise RuntimeStoreError('not_found')
        worker = json.loads(saved[0])
        if worker['session_id'] != session_id or not hmac.compare_digest(worker['adoption_digest'], proof):
            raise RuntimeStoreError('permission_denied')
        if type(generation) is not int or generation != worker['generation']:
            raise RuntimeStoreError('stale_generation')
        receipt = next((r for r in worker['receipts'] if r['sequence'] == sequence), None)
        if receipt is None:
            raise RuntimeStoreError('stale_generation')
        if receipt['payload_digest'] != payload_digest:
            raise RuntimeStoreError('admission_conflict')
        if receipt['result_json'] is None:
            raise RuntimeStoreError('stale_generation')
        return json.loads(receipt['result_json'])


def _verified_finish_ack(profile_home, admission, worker, sequence):
    """Verify the private durable outbox without returning its adoption secret."""
    import os
    import re
    import stat

    if not all(hasattr(os, key) for key in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK')):
        return False
    execution_id = worker['execution_id']
    name = execution_id.replace(':', '-')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,200}', name):
        return False
    opened = []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        home = os.open(profile_home, flags)
        opened.append(home)
        parent = os.open('worker-outboxes', flags, dir_fd=home)
        opened.append(parent)
        directory = os.open(name, flags, dir_fd=parent)
        opened.append(directory)
        for fd in (parent, directory):
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                return False
        fd = os.open('pending.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        opened.append(fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_mode & 0o077
                or before.st_nlink != 1 or before.st_size > 4 * 1024 * 1024):
            return False
        data = bytearray()
        while len(data) <= 4 * 1024 * 1024:
            chunk = os.read(fd, min(65536, 4 * 1024 * 1024 + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after, current = os.fstat(fd), os.stat('pending.json', dir_fd=directory, follow_symlinks=False)
        stamp = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        inode = lambda info: (info.st_dev, info.st_ino)
        if (len(data) > 4 * 1024 * 1024 or stamp(before) != stamp(after) or stamp(after) != stamp(current)
                or inode(os.fstat(directory)) != inode(os.stat(name, dir_fd=parent, follow_symlinks=False))
                or inode(os.fstat(parent)) != inode(os.stat('worker-outboxes', dir_fd=home, follow_symlinks=False))
                or inode(os.fstat(home)) != inode(os.stat(profile_home, follow_symlinks=False))):
            return False
        journal = json.loads(data)
        scope = journal['scope']
        fields = {'profile_id', 'session_id', 'execution_id', 'generation', 'pid', 'birth', 'secret', 'epoch'}
        if (not isinstance(scope, dict) or set(scope) != fields or scope['profile_id'] != str(profile_home)
                or scope['session_id'] != worker['session_id'] or scope['execution_id'] != execution_id
                or type(scope['generation']) is not int or scope['generation'] != worker['generation']
                or type(scope['epoch']) is not int or scope['epoch'] != worker['owner_epoch']
                or type(scope['pid']) is not int or scope['pid'] <= 0 or type(scope['birth']) not in (int, float)
                or not isinstance(scope['secret'], str) or not 16 <= len(scope['secret']) <= 256
                or type(journal['next_sequence']) is not int or journal['next_sequence'] != sequence + 1
                or journal['pending'] != []):
            return False
        # A rotated physical session needs the original claim lineage; do not guess it.
        if worker['session_id'] != admission['target_session_id']:
            return False
        claim_scope = {key: value for key, value in scope.items() if key != 'epoch'}
        claim = admission_fingerprint(canonical_target=worker['session_id'],
                                      payload={**claim_scope, 'principal': admission['principal_id']})
        return hmac.compare_digest(worker['adoption_digest'], _secret_digest(claim))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return False
    finally:
        for fd in reversed(opened):
            os.close(fd)


def owner_finish_projection(db, *, admission_id, session_id, expected_request_id, profile_home):
    """Project only an explicit finish receipt after the Owner authenticated the caller.

    The public RPC authorizes admission/session first. This internal read cannot adopt a
    worker and never returns the replay proof, stored result, or physical identity.
    """
    unknown = {'receipt': 'UNKNOWN', 'ack': 'UNKNOWN', 'physical_retirement': 'UNKNOWN'}
    try:
        with db._read_ctx() as conn:
            if conn.in_transaction:
                return unknown
            conn.execute('BEGIN')
            try:
                admission = conn.execute('SELECT * FROM session_admissions WHERE admission_id=?', (admission_id,)).fetchone()
                admission = dict(admission) if admission is not None else terminal_admission(conn, admission_id)
                if (not isinstance(admission, dict) or admission['target_session_id'] != session_id
                        or admission['request_id'] != expected_request_id):
                    return unknown
                execution_id = 'admission-worker:' + admission_id
                worker = conn.execute('SELECT * FROM worker_executions WHERE execution_id=?', (execution_id,)).fetchone()
                if worker is None:
                    saved = conn.execute('SELECT value FROM state_meta WHERE key=?', (WORKER_PREFIX + execution_id,)).fetchone()
                    worker = json.loads(saved[0]) if saved else None
                    receipts = worker.get('receipts', []) if isinstance(worker, dict) else []
                else:
                    worker = dict(worker)
                    receipts = [dict(r) for r in conn.execute('SELECT sequence,payload_digest,result_json FROM worker_receipts WHERE execution_id=?', (execution_id,))]
                if not isinstance(worker, dict):
                    return unknown
                lineage = json.loads(admission['lineage_json'])
                physical = worker['session_id']
                # Retirement strips lineage: only the exact logical session remains provable.
                if (not isinstance(lineage, list) or any(not isinstance(x, str) or not x for x in lineage)
                        or worker['execution_id'] != execution_id or worker['status'] != 'terminal'
                        or not isinstance(physical, str) or not physical
                        or type(worker['generation']) is not int or type(admission['generation']) is not int
                        or worker['generation'] < 0 or worker['generation'] != admission['generation']
                        or type(worker['owner_epoch']) is not int or type(admission['owner_epoch']) is not int
                        or worker['owner_epoch'] < 1 or worker['owner_epoch'] != admission['owner_epoch']
                        or (physical != session_id and physical not in lineage)):
                    return unknown
                digest = admission_fingerprint(canonical_target=physical, payload={'operation': 'execution.finish', 'payload': {}})
                matches = [r for r in receipts if r.get('payload_digest') == digest and r.get('result_json') is not None]
                if (len(matches) == 1 and type(matches[0].get('sequence')) is int and matches[0]['sequence'] > 0
                        and type(worker['last_sequence']) is int and worker['last_sequence'] == matches[0]['sequence']
                        and json.loads(matches[0]['result_json']) == {'status': 'terminal'}):
                    ack = 'RECORDED' if _verified_finish_ack(profile_home, admission, worker, matches[0]['sequence']) else 'UNKNOWN'
                    return {**unknown, 'receipt': 'RECORDED', 'ack': ack}
            finally:
                conn.rollback()
    except (ValueError, TypeError, KeyError, AttributeError):
        return unknown
    return unknown
