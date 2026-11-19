"""Private response-use sidecar survives Session deletion and owner replacement."""
import json
import sqlite3
import threading
import time

import pytest

from hermes_state import SessionDB
from hermes_state_native_recovery import FIELDS, RETENTION


def hint(**changes):
    value = dict(dict.fromkeys(FIELDS, 'provenance'), project_id='cloud', request_id='request',
                 result_ref='result', projection_digest='a' * 64)
    return value | changes


def operate(db, action, payload):
    return db.native_response_use(str(db.db_path.parent.resolve()), action, payload,
                                  deadline=time.monotonic() + 1)


def test_upgrade_private_sidecar_preserves_transcript_and_export(tmp_path):
    path = tmp_path / 'state.db'
    db = SessionDB(path)
    db.create_session('s', 'cli')
    db.append_message('s', 'user', 'original prompt')
    before = db.export_session('s')
    db._execute_write(lambda c: c.execute('DROP TABLE native_response_use_hints'))
    db._execute_write(lambda c: c.execute('UPDATE schema_version SET version=32'))
    db.close()
    with SessionDB(path) as db:
        assert db.export_session('s') == before
        assert operate(db, 'persist', hint()) == {'state': 'PERSISTED'}
        assert db.export_session('s') == before
        assert 'projection_digest' not in json.dumps(db.export_all())
        assert db.get_messages_as_conversation('s')[0]['content'] == 'original prompt'
        assert set(db._read_one('SELECT * FROM native_response_use_hints').keys()) == set(FIELDS) | {
            'created_at', 'recovery_expires_at', 'retained_until', 'state'}
        assert 'original prompt' not in str(dict(db._read_one('SELECT * FROM native_response_use_hints')))
        db.delete_session('s')
        assert operate(db, 'read', {'project_id': 'cloud'}) == {
            'state': 'ONE', 'selector': {'request_id': 'request', 'result_ref': 'result', 'projection_digest': 'a' * 64}}


def test_retention_redacts_to_durable_block_not_new_intake(tmp_path, monkeypatch):
    path = tmp_path / 'state.db'
    with SessionDB(path) as db:
        operate(db, 'persist', hint())
        created = db._read_one('SELECT created_at FROM native_response_use_hints')[0]
    monkeypatch.setattr('hermes_state_native_recovery.time.time', lambda: created + 601)
    with SessionDB(path) as db:
        assert operate(db, 'read', {'project_id': 'cloud'}) == {'state': 'EXPIRED'}
    monkeypatch.setattr('hermes_state_native_recovery.time.time', lambda: created + RETENTION + 1)
    with SessionDB(path) as db:
        assert operate(db, 'read', {'project_id': 'cloud'}) == {'state': 'EXPIRED'}
        row = dict(db._read_one('SELECT * FROM native_response_use_hints'))
        assert row['state'] == 'BLOCKED'
        assert all(row[k] == '' for k in FIELDS[1:])
        with pytest.raises(ValueError, match='blocked'):
            operate(db, 'persist', hint(request_id='fresh'))
    with SessionDB(path) as db:
        assert operate(db, 'read', {'project_id': 'cloud'}) == {'state': 'EXPIRED'}


def test_exact_clear_capacity_and_profile_isolation(tmp_path):
    first = tmp_path / 'one'
    first.mkdir()
    second = tmp_path / 'two'
    second.mkdir()
    with SessionDB(first / 'state.db') as db, SessionDB(second / 'state.db') as other:
        for index in range(16):
            operate(db, 'persist', hint(request_id='r' + str(index)))
        with pytest.raises(ValueError, match='capacity'):
            operate(db, 'persist', hint(request_id='extra'))
        assert operate(db, 'read', {'project_id': 'cloud'}) == {'state': 'AMBIGUOUS'}
        assert operate(other, 'read', {'project_id': 'cloud'}) == {'state': 'NONE'}
        with pytest.raises(PermissionError):
            db.native_response_use(str(second), 'read', {'project_id': 'cloud'}, deadline=time.monotonic() + 1)
        operate(db, 'clear', {'project_id': 'load', 'request_id': 'r0'})
        assert db._read_one('SELECT count(*) FROM native_response_use_hints')[0] == 16
        operate(db, 'clear', {'project_id': 'cloud', 'request_id': 'r0'})
        assert db._read_one('SELECT count(*) FROM native_response_use_hints')[0] == 15


def test_multiple_results_clear_together_without_clearing_other_requests(tmp_path):
    with SessionDB(tmp_path / 'state.db') as db:
        operate(db, 'persist', hint())
        operate(db, 'persist', hint())  # duplicate callback preserves the original expiry
        operate(db, 'persist', hint(result_ref='refreshed'))
        operate(db, 'persist', hint(request_id='other'))
        assert operate(db, 'read', {'project_id': 'cloud'}) == {'state': 'AMBIGUOUS'}
        operate(db, 'clear', {'project_id': 'cloud', 'request_id': 'request'})
        assert operate(db, 'read', {'project_id': 'cloud'})['selector']['request_id'] == 'other'


def test_readonly_busy_and_unknown_commit_are_not_success(tmp_path, monkeypatch):
    path = tmp_path / 'state.db'
    db = SessionDB(path)
    db.close()
    with SessionDB(path, read_only=True) as readonly:
        with pytest.raises(PermissionError):
            operate(readonly, 'persist', hint())
    with SessionDB(path) as db:
        with sqlite3.connect(path) as competing:
            competing.execute('BEGIN IMMEDIATE')
            with pytest.raises(sqlite3.OperationalError):
                operate(db, 'persist', hint())
            competing.rollback()
        original = db._execute_write
        def uncertain(fn, **kw):
            original(fn, **kw)
            raise sqlite3.OperationalError('unknown commit')
        monkeypatch.setattr(db, '_execute_write', uncertain)
        with pytest.raises(sqlite3.OperationalError):
            operate(db, 'persist', hint())
        assert db._read_one('SELECT count(*) FROM native_response_use_hints')[0] == 1


def test_real_sqlite_full_propagates_without_partial_selector(tmp_path):
    with SessionDB(tmp_path / 'state.db') as db:
        pages = db._conn.execute('PRAGMA page_count').fetchone()[0]
        db._conn.execute(f'PRAGMA max_page_count={pages}')
        for index in range(16):
            value = {k: 'x' * 256 for k in FIELDS}
            value.update(project_id='cloud', request_id=str(index), projection_digest='a' * 64)
            try:
                operate(db, 'persist', value)
            except sqlite3.OperationalError as error:
                assert error.sqlite_errorcode == sqlite3.SQLITE_FULL
                assert db._read_one('SELECT count(*) FROM native_response_use_hints')[0] == index
                break
        else:
            pytest.fail('fixture did not reach real SQLite page exhaustion')


def test_native_selector_owner_lock_respects_deadline(tmp_path):
    db = SessionDB(tmp_path / 'state.db')
    entered, done = threading.Event(), threading.Event()
    outcomes = []
    db._lock.acquire()
    def read():
        entered.set()
        try:
            db.native_response_use(str(tmp_path), 'read', {'project_id': 'cloud'},
                                   deadline=time.monotonic() + .05)
        except Exception as error:
            outcomes.append(type(error).__name__)
        finally:
            done.set()
    worker = threading.Thread(target=read)
    worker.start()
    try:
        assert entered.wait(1)
        # Keep the ordinary owner's lock held until the bounded operation has
        # failed. It must not wait for unrelated maintenance to release it.
        bounded = done.wait(1)
    finally:
        db._lock.release()
        worker.join(5)
        db.close()
    assert not worker.is_alive()
    assert bounded, {'completed_before_owner_lock_release': bounded, 'outcomes_after_release': outcomes}
