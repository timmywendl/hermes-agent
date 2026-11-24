"""Task claims, not caller-supplied launch policy, authorize Kanban execution."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize('command', [
    'pytest --help',
    'pytest tests/test_candidate.py -h',
    'pytest tests/test_candidate.py --setup-only',
    'pytest tests/test_candidate.py --collect-only=yes',
    'pytest tests/other_project.py || true',
    'pytest --collect-only',
    'echo ignored; pytest tests/test_candidate.py',
])
def test_review_validation_rejects_non_execution_or_masked_status(command):
    from gateway.session_kanban import _is_review_validation_command

    assert not _is_review_validation_command(command)


@pytest.mark.parametrize('exception', [
    {'sandbox': {'excludedCommands': ['python3 *']}},
    {'sandbox': {'network': {'allowedDomains': ['example.invalid']}}},
    {'sandbox': {'network': {'socksProxyPort': 12345}}},
    {'sandbox': {'network': {'allowLocalBinding': True}}},
    {'sandbox': {'network': {'allowUnixSockets': ['/tmp/fixture.sock']}}},
    {'sandbox': {'filesystem': {'disabled': True}}},
    {'sandbox': {'filesystem': {'allowWrite': ['/tmp']}}},
    {'sandbox': {'allowAppleEvents': True}},
    {'sandbox': {'enableWeakerNetworkIsolation': True}},
    {'sandbox': {'enableWeakerNestedSandbox': True}},
    {'sandbox': {'allowNestedUserNamespaces': True}},
    {'sandbox': {'network': {'allowMachLookup': ['example.invalid']}}},
    {'permissions': {'allow': ['Edit(./*)']}},
    {'permissions': {'allow': ['WebFetch']}},
    {'permissions': {'additionalDirectories': ['/tmp']}},
    {'permissions': {'allow': ['WebFetch(domain:example.invalid)']}},
])
def test_review_refuses_user_sandbox_exceptions(tmp_path, exception):
    import subprocess
    from gateway.session_kanban import _review_sandbox_policy
    from hermes_state_runtime import RuntimeStoreError

    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    assert _review_sandbox_policy(str(tmp_path), str(tmp_path))['sandbox']['enabled'] is True
    (tmp_path / 'settings.json').write_text(json.dumps(exception))
    with pytest.raises(RuntimeStoreError, match='sandbox_unavailable'):
        _review_sandbox_policy(str(tmp_path), str(tmp_path))


def test_review_sandbox_covers_linked_git_common_directory(tmp_path):
    import subprocess
    from gateway.session_kanban import _review_sandbox_policy

    source = tmp_path / 'source'
    source.mkdir()
    subprocess.run(['git', 'init', '-q', str(source)], check=True)
    subprocess.run(['git', '-C', str(source), '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                    'commit', '--allow-empty', '-qm', 'base'], check=True)
    linked = tmp_path / 'review'
    subprocess.run(['git', '-C', str(source), 'worktree', 'add', '--detach', str(linked)],
                   check=True, capture_output=True)
    policy = _review_sandbox_policy(str(tmp_path), str(linked))
    assert policy['sandbox']['filesystem']['denyWrite'] == [str(linked.resolve()), str((source / '.git').resolve())]


def test_review_validation_binds_task_test_file():
    from gateway.session_kanban import _review_command_matches_task

    criteria = 'Run tests/test_candidate.py offline.'
    assert _review_command_matches_task('python3 -m pytest -q -o addopts= tests/test_candidate.py', criteria)
    assert _review_command_matches_task('.venv/bin/python -m pytest -q -o addopts= tests/test_candidate.py', criteria)
    assert _review_command_matches_task('uv run pytest -q -o addopts= tests/test_candidate.py', criteria)
    assert _review_command_matches_task('uv run --extra test python -m pytest -q -o addopts= tests/test_candidate.py', criteria)
    assert not _review_command_matches_task('python3 -m pytest -q tests/test_candidate.py', criteria)
    assert not _review_command_matches_task('python3 -m pytest -q -o addopts= tests/test_other.py', criteria)
    assert not _review_command_matches_task('pytest -o addopts= tests/test_candidate.py -k unrelated', criteria)
    assert not _review_command_matches_task('pytest -o addopts= tests/test_candidate.py -kunrelated', criteria)
    assert not _review_command_matches_task('pytest -o addopts= tests/test_candidate.py --setup-plan', criteria)
    assert not _review_command_matches_task('pytest -o addopts=-qq tests/test_candidate.py', criteria)
    assert not _review_command_matches_task('pytest -o addopts= tests/test_candidate.py --password synthetic-secret', criteria)


def test_review_validation_reads_native_intake_serialized_criteria():
    from gateway.session_kanban import _review_command_matches_task

    body = json.dumps({'task_spec': {'title': 'Fix fixture',
                                    'acceptance_criteria': 'Run tests/test_candidate.py offline'}})
    assert _review_command_matches_task('python3 -m pytest -q -o addopts= tests/test_candidate.py', body)
    assert not _review_command_matches_task('python3 -m pytest -q -o addopts= tests/test_other.py', body)
    prohibited = json.dumps({'task_spec': {'instructions': 'Run tests/test_live.py',
                             'acceptance_criteria': 'Run tests/test_candidate.py offline.\n'
                                                    'Never run tests/test_live.py because it reaches TEST.'}})
    assert not _review_command_matches_task('python3 -m pytest -q -o addopts= tests/test_live.py', prohibited)


def test_review_requires_a_real_test_summary():
    from gateway.session_kanban import _review_tests_passed

    command = 'pytest tests/test_candidate.py'
    assert _review_tests_passed('..\n2 passed, 1 skipped in 0.2s\n', command)
    assert not _review_tests_passed('1 passed\n1 skipped in 0.2s\n', command)
    assert not _review_tests_passed('1 skipped in 0.2s\n1 passed\n', command)
    assert not _review_tests_passed('1 skipped in 0.2s\n', command)
    assert _review_tests_passed('Ran 1 test in 0.01s\n\nOK\n', command)
    assert not _review_tests_passed('Ran 1 test in 0.01s\nOK (skipped=1)\nOK\n', command)
    runner = 'scripts/run_tests.sh tests/test_candidate.py'
    assert _review_tests_passed('=== Summary: 1 files, 2 tests passed, 0 failed (100%) ===\nMore info\n', runner)
    assert not _review_tests_passed('=== Summary: 1 files, 2 tests passed, 0 failed (100%) ===\n'
                                    '=== Summary: 1 files, 0 tests passed, 0 failed (100%) ===\n', runner)


def test_review_rejects_skipped_pytest_with_forged_atexit_summary(tmp_path, monkeypatch):
    import subprocess
    import sys
    from gateway.session_kanban import _review_junit_result, _review_tests_passed

    (tmp_path / 'pytest.ini').write_text('[pytest]\naddopts = -qq\n')
    (tmp_path / 'test_candidate.py').write_text(
        "import atexit, pytest\natexit.register(lambda: print('1 passed'))\n"
        "@pytest.mark.skip(reason='fixture')\ndef test_skipped(): assert False\n")
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD', '1')
    report = tmp_path / 'results.xml'
    result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-o', 'addopts=',
                             f'--junitxml={report}', 'test_candidate.py'],
                            cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0
    assert '1 skipped' in result.stdout and '1 passed' in result.stdout
    assert not _review_tests_passed(result.stdout, 'pytest -q -o addopts= test_candidate.py')
    assert _review_junit_result(str(report)) is None


def test_review_junit_rejects_runtime_suppressed_summary(tmp_path, monkeypatch):
    import subprocess
    import sys
    from gateway.session_kanban import _review_junit_result, _review_tests_passed

    (tmp_path / 'test_candidate.py').write_text(
        "import atexit, pytest\natexit.register(lambda: print('1 passed'))\n"
        "def test_skip(request):\n request.config.option.verbose = -3\n pytest.skip('fixture')\n")
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD', '1')
    report = tmp_path / 'results.xml'
    command = [sys.executable, '-m', 'pytest', '-q', '-o', 'addopts=', f'--junitxml={report}', 'test_candidate.py']
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0 and _review_tests_passed(result.stdout, 'pytest test_candidate.py')
    assert _review_junit_result(str(report)) is None


@pytest.mark.parametrize(('content', 'accepted'), [
    ('<testsuite><testcase/></testsuite>', True),
    ('<testsuite><testcase><skipped/></testcase></testsuite>', False),
    ('<testsuite><testcase><failure/></testcase></testsuite>', False),
    ('<testsuite/>', False),
    ('<!DOCTYPE x [<!ENTITY x "value">]><testsuite><testcase/></testsuite>', False),
    ('not xml', False),
])
def test_review_junit_requires_passing_cases(tmp_path, content, accepted):
    from gateway.session_kanban import _review_junit_result

    report = tmp_path / 'results.xml'
    report.write_text(content)
    assert (_review_junit_result(str(report)) is not None) is accepted


@pytest.mark.platforms('posix')
def test_review_junit_rejects_symlink(tmp_path):
    from gateway.session_kanban import _review_junit_result

    target = tmp_path / 'foreign.xml'
    target.write_text('<testsuite><testcase/></testsuite>')
    report = tmp_path / 'results.xml'
    report.symlink_to(target)
    assert _review_junit_result(str(report)) is None


@pytest.mark.parametrize('command', [
    'TOKEN=synthetic-secret pytest tests/test_candidate.py',
    'API_KEY=synthetic-secret pytest tests/test_candidate.py',
    'pytest tests/test_candidate.py --password synthetic-secret',
    'pytest tests/test_candidate.py --api-key=synthetic-secret',
])
def test_review_command_redacts_sensitive_values(command):
    from gateway.session_kanban import _redact_review_command

    redacted = _redact_review_command(command)
    assert 'synthetic-secret' not in redacted
    assert '<redacted>' in redacted


@pytest.mark.parametrize('runtime', [
    {'stdout': 'ok', 'stderr': '', 'interrupted': False},
    {'stdout': '', 'stderr': '', 'interrupted': False, 'returnCodeInterpretation': 'No matches found'},
    {'stdout': '', 'stderr': '', 'interrupted': True, 'exitCode': 0},
    {'stdout': '', 'stderr': '', 'interrupted': False, 'exitCode': 0, 'backgroundTaskId': 'pending'},
])
def test_review_tool_result_does_not_invent_exit_status(runtime):
    from gateway.session_kanban import _review_tool_result

    block = {'type': 'tool_result', 'tool_use_id': 't', 'content': runtime['stdout']}
    receipt = _review_tool_result({'command': 'pytest tests/test_candidate.py'}, block, runtime)
    assert receipt['exit_status'] is None


def test_review_tool_error_overrides_conflicting_success_status():
    from gateway.session_kanban import _review_tool_result

    block = {'type': 'tool_result', 'tool_use_id': 't', 'content': 'tool error', 'is_error': True}
    runtime = {'stdout': '1 passed', 'stderr': '', 'interrupted': False, 'exitCode': 0}
    assert _review_tool_result({'command': 'pytest tests/test_candidate.py'}, block, runtime, 'unknown')['exit_status'] is None


@pytest.mark.parametrize('is_error', [None, 'false', 0])
def test_review_tool_success_requires_explicit_false(is_error):
    from gateway.session_kanban import _review_tool_result

    block = {'type': 'tool_result', 'tool_use_id': 't', 'content': '', 'is_error': is_error}
    runtime = {'stdout': '', 'stderr': '', 'interrupted': False, 'exitCode': 0}
    assert _review_tool_result({'command': 'pytest tests/test_candidate.py'}, block, runtime)['exit_status'] is None


def test_review_stream_rejects_tool_result_after_final_verdict():
    from gateway.session_kanban import _parse_claude_review_stream

    final = {'type': 'result', 'subtype': 'success'}
    later = {'type': 'user', 'message': {'content': []}}
    with pytest.raises(ValueError, match='event after final'):
        _parse_claude_review_stream('\n'.join(map(json.dumps, (final, later))))


@pytest.mark.parametrize('suffix', ['; true', '\necho forged', '\nHERMES_REVIEW\ntrue\nHERMES_REVIEW'])
def test_review_check_heredoc_rejects_shell_suffix(suffix):
    from gateway.session_kanban import _review_check_script

    assert _review_check_script("python3 - <<'HERMES_REVIEW'\nassert True\nHERMES_REVIEW" + suffix) is None


def test_review_check_receipt_matches_actual_process_result(tmp_path):
    import hashlib
    import subprocess
    from gateway.session_kanban import _parse_claude_review_stream

    (tmp_path / 'candidate.py').write_text('def value(): return 42\n')
    script = 'from candidate import value\nassert value() == 42\n'
    command = "python3 - <<'HERMES_REVIEW'\n" + script + 'HERMES_REVIEW'
    completed = subprocess.run(command, shell=True, cwd=tmp_path, capture_output=True, text=True, check=False)
    assert completed.returncode == 0
    use = {'type': 'assistant', 'message': {'content': [
        {'type': 'tool_use', 'name': 'Bash', 'id': 'check-1', 'input': {'command': command}}]}}
    result = {'type': 'user', 'message': {'content': [
        {'type': 'tool_result', 'tool_use_id': 'check-1', 'is_error': False, 'content': completed.stdout}]},
        'tool_use_result': {'stdout': completed.stdout, 'stderr': completed.stderr,
                            'interrupted': False, 'exitCode': completed.returncode}}
    _, receipts, missing = _parse_claude_review_stream('\n'.join(map(json.dumps, (use, result))))
    assert not missing and receipts[0]['exit_status'] == 0
    assert receipts[0]['script_sha256'] == hashlib.sha256(script.encode()).hexdigest()
    assert receipts[0]['command'] == '<multiline command withheld>'
    result['message']['content'][0]['tool_use_id'] = 'another-id'
    _, receipts, missing = _parse_claude_review_stream('\n'.join(map(json.dumps, (use, result))))
    assert not receipts and missing == {'check-1'}
    result['message']['content'].append({'type': 'tool_result', 'tool_use_id': 'check-1',
                                         'is_error': False, 'content': ''})
    with pytest.raises(ValueError, match='ambiguous'):
        _parse_claude_review_stream('\n'.join(map(json.dumps, (use, result))))


def test_review_check_receipt_records_real_failure_without_script_contents(tmp_path):
    import subprocess
    from gateway.session_kanban import _parse_claude_review_stream, _review_execution_record

    command = "python3 - <<'HERMES_REVIEW'\nassert False\nHERMES_REVIEW"
    completed = subprocess.run(command, shell=True, cwd=tmp_path, capture_output=True, text=True, check=False)
    assert completed.returncode != 0
    use = {'type': 'assistant', 'message': {'content': [
        {'type': 'tool_use', 'name': 'Bash', 'id': 'failed-1', 'input': {'command': command}}]}}
    result = {'type': 'user', 'message': {'content': [
        {'type': 'tool_result', 'tool_use_id': 'failed-1', 'is_error': True,
         'content': f'Exit code {completed.returncode}\nfailed'}]},
        'tool_use_result': {'stdout': completed.stdout, 'stderr': completed.stderr, 'interrupted': False}}
    _, receipts, missing = _parse_claude_review_stream('\n'.join(map(json.dumps, (use, result))),
                                                       '2.1.323 (Claude Code)')
    assert not missing and receipts[0]['exit_status'] == completed.returncode
    assert receipts[0]['tool_use_id'] == 'failed-1'
    record = _review_execution_record({'task_id': 't', 'run_id': 1, 'claim_lock': 'secret'},
                                      {'url': 'fixture', 'head': 'head'}, receipts)
    assert 'assert False' not in json.dumps(record)


def _pilot_check_fixture():
    body = {'repo': 'DesignLibro/petlibro-cloud-test-platform',
            'work_key': 'cloud-confirm-feeding-plan-absent-bool-id/v1',
            'task_spec': {'title': 'Repair confirm_feeding_plan_absent',
                          'instructions': 'Fixture acceptance criterion: reject bool IDs',
                          'acceptance_criteria': 'Preserve valid and error behavior.\nRun tests/test_candidate.py offline'}}
    handoff = {'url': 'https://github.com/DesignLibro/petlibro-cloud-test-platform/pull/1'}
    script = """import sys
from pathlib import Path
from types import SimpleNamespace
if not __debug__:
    raise SystemExit(1)
sys.path.insert(0, 'src')
from cloud_test.domains.feeding_plan_resources import confirm_feeding_plan_absent
assert Path(confirm_feeding_plan_absent.__code__.co_filename).resolve() == Path('src/cloud_test/domains/feeding_plan_resources.py').resolve()
"""
    cases = [
        (200, {'code': 0, 'data': [{'id': True}]}, False),
        (200, {'code': 0, 'data': [{'id': False}]}, False),
        (200, {'code': 0, 'data': [{'id': 8}]}, True),
        (200, {'code': 0, 'data': [{'id': 7}]}, False),
        (200, {'code': 0, 'data': []}, True),
        (500, {'code': 0, 'data': []}, False),
        (200, {'code': 1, 'data': []}, False),
        (200, {'code': False, 'data': []}, False),
        (200, {'code': 0, 'data': {}}, False),
        (200, {'code': 0, 'data': [{'id': 'bad'}]}, False),
        (200, {'code': 0, 'data': [{}]}, False),
    ]
    for status, data, expected in cases:
        script += ('assert confirm_feeding_plan_absent(SimpleNamespace(status_code='
                   f'{status!r}, json=lambda: {data!r}), 7) is {expected!r}\n')
    return script, 'Pilot\n\n' + json.dumps(body), handoff


def test_pilot_check_executes_candidate_and_rejects_unrelated_or_unsafe_programs(tmp_path):
    import ast
    import os
    import subprocess
    import sys
    from gateway.session_kanban import _pilot_review_script

    script, goal, handoff = _pilot_check_fixture()
    canonical = _pilot_review_script(script, goal, handoff)
    assert canonical is not None and ast.dump(ast.parse(canonical)) == ast.dump(ast.parse(script))
    assert _pilot_review_script(script, goal.replace('bool-id/v1', 'other/v1'), handoff) is None
    assert _pilot_review_script(script + '# secret\n', goal, handoff) is None
    assert _pilot_review_script(script.replace(' is False', ' == False', 1), goal, handoff) is None
    assert _pilot_review_script(script.replace("{'id': True}", "{'id': 1}", 1), goal, handoff) is None
    assert _pilot_review_script(script.replace("{'id': True}",
                                                "{'id': 'SECRET_VALUE', 'id': True}", 1), goal, handoff) is None
    tuples = script.replace("[{'id': True}]", "({'id': True},)").replace(
        "[{'id': False}]", "({'id': False},)")
    assert _pilot_review_script(tuples, goal, handoff) is None
    source = tmp_path / 'src' / 'cloud_test' / 'domains'
    source.mkdir(parents=True)
    (source / 'feeding_plan_resources.py').write_text(
        "def confirm_feeding_plan_absent(response, plan_id):\n"
        "    body = response.json()\n"
        "    rows = body.get('data')\n"
        "    return (response.status_code == 200 and type(body.get('code')) is int\n"
        "            and body['code'] == 0 and isinstance(rows, list)\n"
        "            and all(type(row.get('id')) is int for row in rows)\n"
        "            and all(row['id'] != plan_id for row in rows))\n")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    run = subprocess.run([sys.executable, '-'], input=script, cwd=tmp_path,
                         text=True, capture_output=True, env=env, check=False)
    assert run.returncode == 0, run.stderr
    optimized = subprocess.run([sys.executable, '-O', '-'], input=script, cwd=tmp_path,
                               text=True, capture_output=True, env=env, check=False)
    assert optimized.returncode != 0
    (source / 'feeding_plan_resources.py').write_text(
        (source / 'feeding_plan_resources.py').read_text().replace(
            "type(row.get('id')) is int", "isinstance(row.get('id'), int)"))
    broken = subprocess.run([sys.executable, '-'], input=script, cwd=tmp_path,
                            text=True, capture_output=True, env=env, check=False)
    assert broken.returncode != 0
    misleading = subprocess.run([sys.executable, '-'], input=tuples, cwd=tmp_path,
                                text=True, capture_output=True, env=env, check=False)
    assert misleading.returncode == 0


def test_review_completion_guard_checks_task_in_final_write_transaction(tmp_path):
    import sqlite3
    from gateway.session_kanban import _review_completion_guard

    path = tmp_path / 'guard.db'
    with sqlite3.connect(path) as setup:
        setup.execute('CREATE TABLE tasks (id TEXT, title TEXT, body TEXT, status TEXT, '
                      'current_run_id INTEGER, claim_lock TEXT, created_by TEXT, idempotency_key TEXT)')
        setup.execute('CREATE TABLE task_events (id INTEGER, task_id TEXT, kind TEXT, payload TEXT)')
        setup.execute("INSERT INTO tasks VALUES ('task', 'title', 'body', 'running', 7, 'claim', 'creator', 'key')")
        setup.execute("INSERT INTO task_events VALUES (1, 'task', 'created', 'origin')")
    context = {'task_id': 'task', 'review_task_title': 'title', 'review_task_body': 'body',
               'run_id': 7, 'claim_lock': 'claim'}
    owner = sqlite3.connect(path)
    writer = sqlite3.connect(path)
    origin = ('creator', 'key', 1, 'origin')
    try:
        with _review_completion_guard(owner, context, origin):
            writer.execute("UPDATE tasks SET body='changed' WHERE id='task'")
            writer.commit()
            with pytest.raises(sqlite3.IntegrityError, match='review task changed'):
                with owner:
                    owner.execute("UPDATE tasks SET status='done' WHERE id='task'")
        assert owner.execute("SELECT status FROM tasks WHERE id='task'").fetchone() == ('running',)
        assert owner.execute("SELECT count(*) FROM sqlite_temp_master WHERE type='trigger'").fetchone() == (0,)
        writer.execute("UPDATE tasks SET body='body' WHERE id='task'")
        writer.commit()
        with _review_completion_guard(owner, context, origin), owner:
            owner.execute("UPDATE tasks SET status='done' WHERE id='task'")
        assert owner.execute("SELECT status FROM tasks WHERE id='task'").fetchone() == ('done',)
        assert owner.execute("SELECT count(*) FROM sqlite_temp_master WHERE type='trigger'").fetchone() == (0,)
    finally:
        writer.close()
        owner.close()


@pytest.mark.parametrize('mode', ['success', 'missing', 'mismatched', 'nonzero', 'wrong_task'])
def test_pilot_review_receipt_uses_real_check_and_matching_events(tmp_path, monkeypatch, mode):
    import hashlib
    import subprocess
    import sys
    from gateway import session_kanban as sk

    workspace = tmp_path / 'candidate'
    source = workspace / 'src' / 'cloud_test' / 'domains'
    source.mkdir(parents=True)
    def git(*args):
        return subprocess.check_output(['git', '-C', str(workspace), *args], text=True).strip()
    git('init')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        'commit', '--allow-empty', '-m', 'base')
    base = git('rev-parse', 'HEAD')
    (source / 'feeding_plan_resources.py').write_text(
        "def confirm_feeding_plan_absent(response, plan_id):\n"
        "    body = response.json()\n"
        "    rows = body.get('data')\n"
        "    return (response.status_code == 200 and type(body.get('code')) is int\n"
        "            and body['code'] == 0 and isinstance(rows, list)\n"
        "            and all(type(row.get('id')) is int for row in rows)\n"
        "            and all(row['id'] != plan_id for row in rows))\n")
    if mode == 'nonzero':
        target = source / 'feeding_plan_resources.py'
        target.write_text(target.read_text().replace("type(row.get('id')) is int", 'True'))
    git('add', 'src/cloud_test/domains/feeding_plan_resources.py')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'candidate')
    head = git('rev-parse', 'HEAD')
    script, goal, handoff = _pilot_check_fixture()
    handoff.update(head=head, base='main')
    command = "python3 - <<'HERMES_REVIEW'\n" + script + 'HERMES_REVIEW'
    cli = tmp_path / 'fake-claude'
    cli.write_text(f'#!{sys.executable}\n'
                   'import json, subprocess, sys\n'
                   'if "--version" in sys.argv:\n'
                   '    print("2.1.323 (Claude Code)"); sys.exit(0)\n'
                   'sys.stdin.read()\n'
                   f'command = {command!r}\n'
                   'run = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)\n'
                   f'assert (run.returncode != 0) == {mode == "nonzero"!r}\n'
                   'use = {"type":"tool_use", "name":"Bash", "id":"tool-1", '
                   '"input":{"command":command}}\n'
                   'print(json.dumps({"type":"assistant", "message":{"content":[use]}}))\n'
                   f'mode = {mode!r}\n'
                   'if mode != "missing":\n'
                   '    failed = mode == "nonzero"\n'
                   '    result = {"type":"tool_result", "tool_use_id":'
                   '"different" if mode == "mismatched" else "tool-1", '
                   '"is_error":failed, "content":("Exit code " + str(run.returncode) + "\\nfailed") '
                   'if failed else run.stdout}\n'
                   '    runtime = {"stdout":run.stdout, "stderr":run.stderr, "interrupted":False, '
                   '"exitCode":run.returncode}\n'
                   '    print(json.dumps({"type":"user", "message":{"content":[result]}, '
                   '"tool_use_result":runtime}))\n'
                   'print(json.dumps({"type":"result", "subtype":"success", "is_error":False, '
                   '"structured_output":{"verdict":"approved", "reason":"fixture"}}))\n')
    cli.chmod(0o700)
    monkeypatch.setattr('agent.skill_commands.build_preloaded_skills_prompt',
                        lambda *_: ('skill', ['sdlc-review'], []))
    context = {'claude_review': {'executable': str(cli), 'config_dir': str(tmp_path)},
               'workspace': str(workspace), 'task_id': 'task', 'run_id': 7, 'claim_lock': 'private-claim',
               'goal_text': goal.replace('bool-id/v1', 'other/v1') if mode == 'wrong_task' else goal,
               'context': 'fixture', 'review_findings': []}
    verdict, receipt, accepted = sk._claude_verdict(context, handoff, base)
    assert verdict['verdict'] == 'approved'
    assert accepted is (mode == 'success')
    assert receipt['task_id'] == 'task' and receipt['run_id'] == 7
    assert receipt['claim_digest'] == hashlib.sha256(b'private-claim').hexdigest()
    assert receipt['published_pr'] == handoff['url'] and receipt['head_sha'] == head
    if mode == 'success':
        check = receipt['commands'][0]
        assert check['tool_use_id'] == 'tool-1' and check['exit_status'] == 0
        assert check['script'] == sk._pilot_review_script(script, goal, handoff)
        assert check['script_sha256'] == hashlib.sha256(script.encode()).hexdigest()


@pytest.mark.parametrize('mode', ['success', 'root_success', 'failed', 'interrupted', 'missing', 'unrelated_task', 'wrong_path'])
def test_generic_python_review_requires_real_bound_behavior_check(tmp_path, monkeypatch, mode):
    import subprocess
    import sys
    from gateway import session_kanban as sk

    workspace = tmp_path / 'candidate'
    (workspace / 'src').mkdir(parents=True)
    def git(*args):
        return subprocess.check_output(['git', '-C', str(workspace), *args], text=True).strip()
    git('init')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        'commit', '--allow-empty', '-m', 'base')
    base = git('rev-parse', 'HEAD')
    source = 'calc.py' if mode == 'root_success' else 'src/calc.py'
    (workspace / source).write_text('def increment(value):\n    return value + 1\n')
    git('add', source)
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'candidate')
    head = git('rev-parse', 'HEAD')
    target = 'src/other.py' if mode == 'wrong_path' else source
    expected = 9 if mode in {'failed', 'interrupted'} else 3
    import_root = '.' if mode == 'root_success' else 'src'
    script = (f"import sys\nfrom pathlib import Path\nsys.path.insert(0, {import_root!r})\n"
              "from calc import increment\n"
              f"assert Path(increment.__code__.co_filename).resolve() == Path({target!r}).resolve()\n"
              "assert increment(1) == 2\n"
              f"assert increment(2) == {expected}\n")
    command = "python3 - <<'HERMES_REVIEW'\n" + script + 'HERMES_REVIEW'
    cli = tmp_path / 'fake-claude'
    cli.write_text(f'#!{sys.executable}\n'
                   'import json, subprocess, sys\n'
                   'if "--version" in sys.argv:\n'
                   '    print("2.1.323 (Claude Code)"); sys.exit(0)\n'
                   'sys.stdin.read()\n'
                   f'command = {command!r}\n'
                   'run = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)\n'
                   'use = {"type":"tool_use", "name":"Bash", "id":"tool-1", "input":{"command":command}}\n'
                   'print(json.dumps({"type":"assistant", "message":{"content":[use]}}))\n'
                   f'if {mode != "missing"!r}:\n'
                   '    result = {"type":"tool_result", "tool_use_id":"tool-1", "is_error":bool(run.returncode), '
                   '"content":("Exit code " + str(run.returncode) + "\\nfailed") if run.returncode else run.stdout}\n'
                   f'    runtime = {{"stdout":run.stdout, "stderr":run.stderr, "interrupted":{mode == "interrupted"!r}, '
                   '"exitCode":run.returncode}\n'
                   '    print(json.dumps({"type":"user", "message":{"content":[result]}, "tool_use_result":runtime}))\n'
                   'print(json.dumps({"type":"result", "subtype":"success", "is_error":False, '
                   '"structured_output":{"verdict":"approved", "reason":"fixture"}}))\n')
    cli.chmod(0o700)
    monkeypatch.setattr('agent.skill_commands.build_preloaded_skills_prompt',
                        lambda *_: ('skill', ['sdlc-review'], []))
    spec = {'title': 'Fix increment', 'instructions': f'Update {source}',
            'acceptance_criteria': f'increment returns the next integer\nVerify {source}::increment'}
    if mode == 'unrelated_task':
        spec['acceptance_criteria'] = 'Do not verify src/calc.py::increment'
    body = {'repo': 'example/project', 'work_key': 'generic/v1', 'task_spec': spec}
    context = {'claude_review': {'executable': str(cli), 'config_dir': str(tmp_path)},
               'workspace': str(workspace), 'task_id': 'task', 'run_id': 7, 'claim_lock': 'private-claim',
               'review_task_body': json.dumps(body), 'goal_text': 'Generic\n\n' + json.dumps(body),
               'context': 'fixture', 'review_findings': []}
    handoff = {'url': 'https://github.com/example/project/pull/1', 'head': head, 'base': 'main'}
    verdict, receipt, accepted = sk._claude_verdict(context, handoff, base)
    assert verdict['verdict'] == 'approved'
    assert accepted is (mode in {'success', 'root_success'})
    if accepted:
        check = receipt['commands'][0]
        assert check['python_check'] == {'source': source, 'symbol': 'increment', 'cases': 2,
                                         'assertion_failed': False}
        assert check['exit_status'] == 0 and 'increment(1)' not in json.dumps(receipt)
    elif mode == 'failed':
        assert receipt['commands'][0]['python_check']['assertion_failed'] is True
    elif mode == 'interrupted':
        assert receipt['commands'][0]['python_check']['assertion_failed'] is False


def test_generic_python_review_rejects_unrelated_or_unexecuted_checks():
    from gateway.session_kanban import _generic_python_review_script

    body = {'task_spec': {'title': 'Fix increment', 'instructions': 'Update src/calc.py',
                          'acceptance_criteria': 'Verify src/calc.py::increment'}}
    goal = 'Task\n\n' + json.dumps(body)
    script = ("import sys\nfrom pathlib import Path\nsys.path.insert(0, 'src')\n"
              "from calc import increment\n"
              "assert Path(increment.__code__.co_filename).resolve() == Path('src/calc.py').resolve()\n"
              "assert increment(1) == 2\nassert increment(2) == 3\n")
    def validate(value, paths=None):
        return _generic_python_review_script(value, goal, ['src/calc.py'] if paths is None else paths)
    assert validate(script) == {'source': 'src/calc.py', 'symbol': 'increment', 'cases': 2,
                                '_assert_lines': [6, 7]}
    assert validate(script, []) is None
    assert validate(script.replace('assert increment(2) == 3\n', '')) is None
    assert validate(script.replace('increment(2)', 'increment(1)')) is None
    assert validate(script.replace('increment(2)', 'increment(value=1)')) is None
    assert validate(script.replace('assert increment(2) == 3', 'assert True')) is None
    assert validate(script + "print('1 passed')\n") is None
    assert validate(script.replace('increment(2)', 'increment(open("secret"))')) is None
    assert validate(script.replace("Path('src/calc.py')", "Path('src/other.py')")) is None


def test_native_ci_review_history_survives_gc(tmp_path, monkeypatch):
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_pr_acceptance_store import event_gc_sql

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    kb.init_db()
    with closing(connect()) as conn:
        selected = kb.create_task(conn, title='selected', created_by='ai-colleague-stage3')
        ordinary = kb.create_task(conn, title='ordinary', created_by='fixture')
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET status='done' WHERE id IN (?,?)", (selected, ordinary))
            for task_id in (selected, ordinary):
                for kind in ('review_execution', 'review_ci_failure', 'changes_requested'):
                    kb._append_event(conn, task_id, kind, {'fixture': True})
            conn.execute("UPDATE task_events SET created_at=1 WHERE kind IN "
                         "('review_execution','review_ci_failure','changes_requested')")
            conn.execute(event_gc_sql(), (2,))
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind IN "
                            "('review_execution','review_ci_failure','changes_requested')", (selected,)).fetchone()[0] == 3
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind IN "
                            "('review_execution','review_ci_failure','changes_requested')", (ordinary,)).fetchone()[0] == 0


@pytest.mark.parametrize(('budget', 'frozen', 'count', 'expected'), [
    (1, 1, 0, None),
    (1, 1, 1, 'review repair limit reached; preserve evidence and request a decision'),
    (0, 0, 0, 'review repair limit reached; preserve evidence and request a decision'),
    (2, 1, 0, 'review Task repair budget is inconsistent'),
    (9, 9, 3, 'review repair limit reached; preserve evidence and request a decision'),
])
def test_review_repair_budget_never_exceeds_frozen_task_grant(monkeypatch, budget, frozen, count, expected):
    import sqlite3
    from hermes_cli import kanban_pr_acceptance_store as store

    conn = sqlite3.connect(':memory:')
    conn.execute('CREATE TABLE tasks(id TEXT, body TEXT, max_retries INTEGER)')
    conn.execute('CREATE TABLE task_events(task_id TEXT, kind TEXT)')
    conn.execute('INSERT INTO tasks VALUES (?,?,?)', ('task', json.dumps({'task_spec': {'max_retries': frozen}}), budget))
    conn.executemany("INSERT INTO task_events VALUES ('task','changes_requested')", [()] * count)
    monkeypatch.setattr(store, 'wave2_enabled', lambda *_: True)
    monkeypatch.setattr(store, 'wave2_review_claim', lambda *_: object())
    try:
        assert store.wave2_review_refusal(conn, 'task', 7, 'claim') == expected
    finally:
        conn.close()


@pytest.mark.parametrize('mode', [
    'approved', 'changes_requested', 'escalate', 'round2', 'failure', 'timeout', 'invalid',
    'head_drift', 'remote_drift', 'no_execution', 'test_failure', 'missing_result',
    'workspace_dirty',
    'task_mismatch', 'run_mismatch', 'claim_mismatch', 'approved_real_format', 'unknown_cli_version',
    'unrelated_execution', 'all_skipped', 'missing_junit', 'report_overwritten', 'forged_junit',
    'body_drift',
    'changes_unknown_result', 'escalate_unknown_result', 'changes_failed_result', 'timeout_after_result',
    'malformed_after_result', 'ci_failure', 'ci_pending', 'ci_stale', 'ci_failure_prior',
    'changes_limit', 'changes_limit_drift', 'changes_limit_count_drift', 'generic_changes', 'generic_limit',
    'generic_approved', 'generic_root_approved', 'generic_ci_failure', 'generic_ci_drift', 'generic_ci_unknown', 'generic_ci_limit',
    'generic_ci_event_drift', 'generic_ci_body_drift', 'generic_ci_handoff_drift', 'generic_ci_pending_failure', 'generic_budget',
    'generic_ci_late_pending_success', 'generic_ci_late_failure', 'generic_ci_late_pending_timeout',
    'changes_transition_body_drift', 'changes_transition_handoff_drift',
    'escalate_transition_body_drift', 'escalate_transition_handoff_drift', 'escalate_triage_handoff_drift',
])
def test_claude_native_review_turn(tmp_path, monkeypatch, mode):
    import hashlib
    import os
    import subprocess
    import sys
    from contextlib import closing

    from gateway import session_kanban as sk
    from hermes_cli import kanban_db as kb, kanban_pr_acceptance as acceptance
    from hermes_cli.kanban_db_connect import connect
    from hermes_state_runtime import RuntimeStoreError

    variant = mode
    if mode in {'generic_ci_late_pending_success', 'generic_ci_late_failure', 'generic_ci_late_pending_timeout'}:
        mode = 'generic_approved'

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    from tools import skills_tool
    monkeypatch.setattr(skills_tool, '_skills_dir', lambda: Path(__file__).resolve().parents[2] / 'skills')
    workspace = tmp_path / 'candidate'
    workspace.mkdir()

    def git(*args):
        return subprocess.check_output(['git', '-C', str(workspace), *args], text=True).strip()

    git('init')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        'commit', '--allow-empty', '-m', 'base')
    base = git('rev-parse', 'HEAD')
    (workspace / 'candidate.txt').write_text('fixture change\n')
    git('add', 'candidate.txt')
    script, goal, pilot_handoff = _pilot_check_fixture()
    if mode in {'approved', 'approved_real_format', 'round2', 'body_drift',
                'ci_failure', 'ci_pending', 'ci_stale', 'ci_failure_prior'}:
        source = workspace / 'src' / 'cloud_test' / 'domains'
        source.mkdir(parents=True)
        (source / 'feeding_plan_resources.py').write_text(
            "def confirm_feeding_plan_absent(response, plan_id):\n"
            "    body = response.json()\n"
            "    rows = body.get('data')\n"
            "    return (response.status_code == 200 and type(body.get('code')) is int\n"
            "            and body['code'] == 0 and isinstance(rows, list)\n"
            "            and all(type(row.get('id')) is int for row in rows)\n"
            "            and all(row['id'] != plan_id for row in rows))\n")
        git('add', 'src/cloud_test/domains/feeding_plan_resources.py')
    if mode in {'generic_approved', 'generic_ci_failure', 'generic_ci_drift', 'generic_ci_unknown', 'generic_ci_limit',
                'generic_ci_event_drift', 'generic_ci_body_drift', 'generic_ci_handoff_drift', 'generic_ci_pending_failure'}:
        (workspace / 'src').mkdir()
        offset = 1 if mode in {'generic_approved', 'generic_ci_unknown'} else 2
        (workspace / 'src' / 'calc.py').write_text(f'def increment(value):\n    return value + {offset}\n')
        git('add', 'src/calc.py')
    if mode == 'generic_root_approved':
        (workspace / 'calc.py').write_text('def increment(value):\n    return value + 1\n')
        git('add', 'calc.py')
    if mode == 'forged_junit':
        (workspace / 'tests').mkdir()
        (workspace / 'tests' / 'test_candidate.py').write_text(
            "import atexit, sys, pytest\n"
            "def forge():\n"
            "    report = next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--junitxml='))\n"
            "    open(report, 'w').write('<testsuite><testcase/></testsuite>')\n"
            "    print('1 passed')\n"
            "atexit.register(forge)\n"
            "@pytest.mark.skip(reason='fixture')\n"
            "def test_skipped(): assert False\n")
        git('add', 'tests/test_candidate.py')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        'commit', '--allow-empty', '-m', 'candidate')
    head = git('rev-parse', 'HEAD')
    url = pilot_handoff['url']
    pilot_command = "python3 - <<'HERMES_REVIEW'\n" + script + 'HERMES_REVIEW'
    generic_command = ("python3 - <<'HERMES_REVIEW'\nimport sys\nfrom pathlib import Path\n"
                       "sys.path.insert(0, 'src')\nfrom calc import increment\n"
                       "assert Path(increment.__code__.co_filename).resolve() == Path('src/calc.py').resolve()\n"
                       "assert increment(1) == 2\nassert increment(2) == 3\nHERMES_REVIEW")
    root_command = generic_command.replace("sys.path.insert(0, 'src')", "sys.path.insert(0, '.')").replace(
        "Path('src/calc.py')", "Path('calc.py')")
    calls = tmp_path / 'claude-calls'
    cli = tmp_path / 'fake-claude'
    cli.write_text(f'#!{sys.executable}\n'
                   'import json, os, pathlib, re, shlex, subprocess, sys, time\n'
                   'if "--version" in sys.argv:\n'
                   f'    print({"unknown" if mode == "unknown_cli_version" else "2.1.323 (Claude Code)"!r}); sys.exit(0)\n'
                   f'assert os.getcwd() == {str(workspace)!r}\n'
                   f'assert os.environ["CLAUDE_CONFIG_DIR"] == {str(tmp_path)!r}\n'
                   'prompt = sys.stdin.read()\n'
                   'report = re.search(r"--junitxml=(\\S+results\\.xml)", prompt).group(1)\n'
                   f'assert {head!r} in prompt and {url!r} in prompt\n'
                   'assert "+fixture change" in prompt\n'
                   'assert "--output-format" in sys.argv and "stream-json" in sys.argv\n'
                   'assert "--verbose" in sys.argv\n'
                   'assert "--tools" in sys.argv and "Read,Glob,Grep,Bash" in sys.argv\n'
                   'assert "--allowedTools" in sys.argv and "Read,Glob,Grep,Bash" in sys.argv\n'
                   'policy = json.loads(sys.argv[sys.argv.index("--settings") + 1])["sandbox"]\n'
                   'assert policy["enabled"] and policy["failIfUnavailable"]\n'
                   'assert not policy["allowUnsandboxedCommands"]\n'
                   f'assert policy["filesystem"]["denyWrite"] == [{str(workspace.resolve())!r}, '
                   f'{str((workspace / ".git").resolve())!r}]\n'
                   'assert policy["network"]["strictAllowlist"] and policy["network"]["deniedDomains"] == ["*"]\n'
                   f'with open({str(calls)!r}, "a") as f: f.write("call\\n")\n'
                   f'mode = {mode!r}\n'
                   'if mode == "failure": sys.exit(2)\n'
                   'if mode == "timeout": time.sleep(10)\n'
                   'if mode == "head_drift":\n'
                   '    subprocess.run(["git","-c","user.name=Fake","-c","user.email=f@example.invalid",'
                   '"commit","--allow-empty","-m","drift"], stdout=subprocess.DEVNULL, check=True)\n'
                   'if mode == "workspace_dirty": pathlib.Path("candidate.txt").write_text("modified by review\\n")\n'
                   'assert "Review Lenses" in prompt and "Fixture acceptance criterion" in prompt\n'
                   'if mode in {"generic_changes", "generic_limit", "generic_budget", "generic_approved", "generic_root_approved", '
                   '"generic_ci_failure", "generic_ci_drift", "generic_ci_unknown", "generic_ci_limit", '
                   '"generic_ci_event_drift", "generic_ci_body_drift", "generic_ci_handoff_drift", "generic_ci_pending_failure"}:\n'
                   '    assert "Execute the Task\'s relevant verification commands" in prompt\n'
                   '    assert "For the authorized feeding-plan Pilot" not in prompt\n'
                   'if mode in {"round2", "ci_failure_prior", "changes_limit", "changes_limit_drift", "changes_limit_count_drift"}:\n'
                   '    assert "Prior attempts on this task" in prompt and "Round 2 handoff" in prompt\n'
                   '    assert prompt.count("Round 1: preserve the exact ID type") >= 2\n'
                   'if mode in {"approved", "approved_real_format", "round2", "body_drift", "generic_approved", "generic_root_approved", '
                   '"generic_ci_failure", "generic_ci_drift", "generic_ci_unknown", "generic_ci_limit", '
                   '"generic_ci_event_drift", "generic_ci_body_drift", "generic_ci_handoff_drift", "generic_ci_pending_failure", '
                   '"ci_failure", "ci_pending", "ci_stale", "ci_failure_prior"}:\n'
                   f'    command = {root_command!r} if mode == "generic_root_approved" else '
                   f'{generic_command!r} if mode.startswith("generic_") else {pilot_command!r}\n'
                   '    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")\n'
                   '    run = subprocess.run(command, shell=True, capture_output=True, text=True, env=env, check=False)\n'
                   '    assert (run.returncode != 0) == (mode in {"generic_ci_failure", "generic_ci_drift", "generic_ci_limit", '
                   '"generic_ci_event_drift", "generic_ci_body_drift", "generic_ci_handoff_drift", "generic_ci_pending_failure"}), run.stderr\n'
                   '    use = {"type":"tool_use", "name":"Bash", "id":"tool-1", '
                   '"input":{"command":command}}\n'
                   '    print(json.dumps({"type":"assistant", "message":{"content":[use]}}))\n'
                   '    result = {"type":"tool_result", "tool_use_id":"tool-1", '
                   '"is_error":bool(run.returncode), "content": '
                   '("Exit code " + str(run.returncode) + "\\nfailed") if run.returncode else run.stdout}\n'
                   '    runtime = {"stdout":run.stdout, "stderr":run.stderr, "interrupted":False}\n'
                   '    if mode != "approved_real_format": runtime["exitCode"] = run.returncode\n'
                   '    print(json.dumps({"type":"user", "message":{"content":[result]}, '
                   '"tool_use_result":runtime}))\n'
                   'if mode == "forged_junit":\n'
                   '    args = [sys.executable, "-m", "pytest", "-q", "-o", "addopts=", '
                   '"--junitxml=" + report, "tests/test_candidate.py"]\n'
                   '    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")\n'
                   '    result = subprocess.run(args, capture_output=True, text=True, env=env, check=False)\n'
                   '    assert result.returncode == 0 and "1 skipped" in result.stdout and "1 passed" in result.stdout\n'
                   '    assert "<testcase/>" in pathlib.Path(report).read_text()\n'
                   '    call = {"type": "tool_use", "id": "tool-1", "name": "Bash", '
                   '"input": {"command": shlex.join(args)}}\n'
                   '    print(json.dumps({"type": "assistant", "message": {"content": [call]}}))\n'
                   '    block = {"type": "tool_result", "tool_use_id": "tool-1", "is_error": False, '
                   '"content": result.stdout}\n'
                   '    print(json.dumps({"type": "user", "message": {"content": [block]}, '
                   '"tool_use_result": {"stdout": result.stdout, "stderr": result.stderr, '
                   '"interrupted": False, "exitCode": result.returncode}}))\n'
                   'if mode not in {"no_execution", "changes_requested", "changes_limit", "changes_limit_drift", "changes_limit_count_drift", "generic_changes", "generic_limit", "generic_budget", "escalate", "forged_junit", '
                   '"approved", "approved_real_format", "round2", "body_drift", '
                   '"ci_failure", "ci_pending", "ci_stale", "ci_failure_prior", "generic_approved", "generic_root_approved", '
                   '"generic_ci_failure", "generic_ci_drift", "generic_ci_unknown", "generic_ci_limit", '
                   '"generic_ci_event_drift", "generic_ci_body_drift", "generic_ci_handoff_drift", "generic_ci_pending_failure"} and not mode.startswith('
                   '("changes_transition_", "escalate_transition_", "escalate_triage_")):\n'
                   '    target = "tests/test_other.py" if mode == "unrelated_execution" else "tests/test_candidate.py"\n'
                   '    call = {"type": "assistant", "message": {"content": [{"type": "tool_use", '
                   '"id": "tool-1", "name": "Bash", "input": {"command": '
                   '"scripts/run_tests.sh -o addopts= " + target + " --junitxml=" + report}}]}}\n'
                   '    print(json.dumps(call))\n'
                   'if mode not in {"no_execution", "changes_requested", "changes_limit", "changes_limit_drift", "changes_limit_count_drift", "generic_changes", "generic_limit", "generic_budget", "escalate", "missing_result", '
                   '"forged_junit", "approved", "approved_real_format", "round2", "body_drift", '
                   '"ci_failure", "ci_pending", "ci_stale", "ci_failure_prior", "generic_approved", "generic_root_approved", '
                   '"generic_ci_failure", "generic_ci_drift", "generic_ci_unknown", "generic_ci_limit", '
                   '"generic_ci_event_drift", "generic_ci_body_drift", "generic_ci_handoff_drift", "generic_ci_pending_failure"} and not mode.startswith('
                   '("changes_transition_", "escalate_transition_", "escalate_triage_")):\n'
                   '    failed = mode in {"test_failure", "changes_failed_result"}\n'
                   '    block = {"type": "tool_result", "tool_use_id": "tool-1", '
                   '"content": "Exit code 7\\nfailed" if failed else "1 passed", "is_error": failed}\n'
                   '    runtime = {"stdout": "1 skipped" if mode == "all_skipped" else "1 passed", '
                   '"stderr": "", "interrupted": False}\n'
                   '    if mode not in {"approved_real_format", "unknown_cli_version", "changes_unknown_result", '
                   '"escalate_unknown_result"}: runtime["exitCode"] = 7 if failed else 0\n'
                   '    event = {"type": "user", "message": {"content": [block]}, '
                   '"tool_use_result": runtime}\n'
                   '    if mode == "changes_failed_result": event.pop("tool_use_result")\n'
                   '    print(json.dumps(event))\n'
                   '    child = "<skipped/>" if mode in {"all_skipped", "report_overwritten"} else "<failure/>" if failed else ""\n'
                   '    if mode != "missing_junit":\n'
                   '        pathlib.Path(report).write_text("<testsuite><testcase>" + child + "</testcase></testsuite>")\n'
                   'if mode == "report_overwritten":\n'
                   '    other = {"type": "tool_use", "id": "tool-2", "name": "Bash", '
                   '"input": {"command": "scripts/run_tests.sh -o addopts= tests/test_other.py --junitxml=" + report}}\n'
                   '    print(json.dumps({"type": "assistant", "message": {"content": [other]}}))\n'
                   '    result = {"type": "tool_result", "tool_use_id": "tool-2", "content": "1 passed", "is_error": False}\n'
                   '    print(json.dumps({"type": "user", "message": {"content": [result]}, '
                   '"tool_use_result": {"stdout": "1 passed", "stderr": "", "interrupted": False, "exitCode": 0}}))\n'
                   '    pathlib.Path(report).write_text("<testsuite><testcase/></testsuite>")\n'
                   'if mode == "malformed_after_result": print("{malformed"); sys.exit(0)\n'
                   'if mode == "timeout_after_result":\n'
                   '    print("{\\\"type\\\":", end="", flush=True); time.sleep(10)\n'
                   'verdict_mode = {"generic_changes": "changes_requested", "generic_limit": "changes_requested", '
                   '"generic_budget": "changes_requested", '
                   '"generic_ci_failure": "changes_requested", "generic_ci_drift": "changes_requested", '
                   '"generic_ci_unknown": "changes_requested", "generic_ci_limit": "changes_requested", '
                   '"generic_ci_event_drift": "changes_requested", "generic_ci_body_drift": "changes_requested", "generic_ci_handoff_drift": "changes_requested", "generic_ci_pending_failure": "changes_requested", '
                   '"changes_limit": "changes_requested", "changes_limit_drift": "changes_requested", '
                   '"changes_limit_count_drift": "changes_requested", '
                   '"changes_unknown_result": "changes_requested", '
                   '"changes_failed_result": "changes_requested", '
                   '"escalate_unknown_result": "escalate"}.get(mode, mode)\n'
                   'if mode.startswith("changes_transition_"): verdict_mode = "changes_requested"\n'
                   'if mode.startswith(("escalate_transition_", "escalate_triage_")): verdict_mode = "escalate"\n'
                   'verdict = {"verdict": verdict_mode if verdict_mode in {"changes_requested", "escalate"} else '
                   '"unexpected" if mode == "invalid" else "approved", "reason": "review evidence"}\n'
                   'print(json.dumps(dict(type="result", subtype="success", is_error=False, '
                   'structured_output=verdict)))\n')
    cli.chmod(0o700)
    kb.init_db()
    with closing(connect()) as conn:
        root = kb.create_task(conn, title='Root', assignee='dev')
        body = json.loads(goal.split('\n\n', 1)[1])
        if mode in {'generic_changes', 'generic_limit', 'generic_budget', 'generic_approved', 'generic_root_approved', 'generic_ci_failure',
                    'generic_ci_drift', 'generic_ci_unknown', 'generic_ci_limit', 'generic_ci_event_drift', 'generic_ci_body_drift', 'generic_ci_handoff_drift', 'generic_ci_pending_failure'}:
            body['work_key'] = 'independent-generic-task/v1'
        if mode == 'generic_budget':
            body['task_spec']['max_retries'] = 1
        if mode in {'generic_approved', 'generic_ci_failure', 'generic_ci_drift', 'generic_ci_unknown', 'generic_ci_limit',
                    'generic_ci_event_drift', 'generic_ci_body_drift', 'generic_ci_handoff_drift', 'generic_ci_pending_failure'}:
            body['task_spec']['instructions'] = 'Fixture acceptance criterion: update src/calc.py'
            body['task_spec']['acceptance_criteria'] = 'increment returns the next integer\nVerify src/calc.py::increment'
        if mode == 'generic_root_approved':
            body['task_spec']['instructions'] = 'Fixture acceptance criterion: update calc.py'
            body['task_spec']['acceptance_criteria'] = 'increment returns the next integer\nVerify calc.py::increment'
        body['root_id'] = root
        body['objective_id'] = 'cloud-test-status-next-legal-step/v1'
        body['publication_protocol'] = 'wave2_v1'
        body['publication_target'] = {'repo': body['repo'], 'base': 'main', 'branch': 'candidate'}
        body['task_spec']['publication_target'] = body['publication_target']
        body['task_spec_digest'] = hashlib.sha256(json.dumps(
            body['task_spec'], sort_keys=True, ensure_ascii=False, separators=(',', ':'),
            allow_nan=False).encode()).hexdigest()
        key = 'colleague-stage3:' + hashlib.sha256(json.dumps(
            [body['repo'], body['objective_id'], body['work_key']], separators=(',', ':')).encode()).hexdigest()
        task = kb.create_task(conn, title='Pilot', body=json.dumps(body), assignee='dev',
                              created_by='fixture', creator_task_id=root,
                              completion_contract=body['repo'], idempotency_key=key,
                              workspace_kind='dir', workspace_path=str(workspace),
                              max_retries=1 if mode == 'generic_budget' else None)
        sibling = kb.create_task(conn, title='sibling', assignee='dev')
        sibling_run = kb.claim_task(conn, sibling)
        dev = kb.claim_task(conn, task)
        for _ in range(3 if mode in {'ci_failure_prior', 'changes_limit', 'changes_limit_drift',
                                     'changes_limit_count_drift', 'generic_limit', 'generic_ci_limit'} else 1 if mode in {'round2', 'generic_budget'} else 0):
            assert kb.request_review(conn, task, reviewer='reviewer', summary='Round 1 handoff',
                                     expected_run_id=dev.current_run_id)
            prior_review = kb.claim_review_task(conn, task)
            assert kb.request_changes(conn, task, reason='Round 1: preserve the exact ID type',
                                      expected_run_id=prior_review.current_run_id)[0]
            dev = kb.claim_task(conn, task)
        assert kb.request_review(conn, task, reviewer='reviewer', summary='Round 2 handoff',
                                 expected_run_id=dev.current_run_id)
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET created_by='ai-colleague-stage3' WHERE id=?", (task,))
            row = conn.execute("SELECT id,payload FROM task_events WHERE task_id=? AND kind='created'", (task,)).fetchone()
            created = json.loads(row['payload'])
            created.update(publication_protocol='wave2_v1', publication_target=body['publication_target'])
            conn.execute('UPDATE task_events SET payload=? WHERE id=?', (json.dumps(created), row['id']))
        claimed = kb.claim_review_task(conn, task)
        run_id, lock = claimed.current_run_id, claimed.claim_lock
        request_id = 'kanban:' + json.dumps(['default', task, run_id], separators=(',', ':'))
        with kb.write_txn(conn):
            kb._append_event(conn, task, 'owner_admitted', {
                'db': str(tmp_path / 'session.db'), 'pid': os.getpid(), 'birth': 1,
                'request_id': request_id, 'session_id': 'native-review',
            }, run_id=run_id)
            kb._append_event(conn, task, 'worker_bound', {
                'pid': os.getpid(), 'claim_lock': lock,
            }, run_id=run_id)
            kb._append_event(conn, task, 'wave2_handoff', {
                'url': url, 'head': head, 'base': 'main', 'branch': 'candidate',
                'reviewer': 'reviewer', 'implementer': 'dev',
            }, run_id=dev.current_run_id)
        sk._bind_owner_admission(conn, {'task_id': task, 'run_id': run_id, 'claim_lock': lock},
                                 'native-review', request_id, 'admission')
        monkeypatch.setattr(acceptance, '_assignee_profile_home', lambda _: None)
        check_reads = []
        def fake_api(endpoint, **kwargs):
            if endpoint == 'graphql':
                if mode == 'body_drift':
                    with closing(connect()) as other:
                        with kb.write_txn(other):
                            other.execute('UPDATE tasks SET body=? WHERE id=?', ('changed after review', task))
                protection = {'requiredStatusChecks': [{'context': 'foundation', 'app': {'databaseId': 7}}]}
                pr = {'headRefOid': head, 'baseRefName': 'main', 'state': 'OPEN',
                      'baseRef': {'branchProtectionRule': protection}}
                return {'data': {'repository': {'pullRequest': pr}}}
            if '/rules/branches/' in endpoint or '/statuses' in endpoint:
                return [[]]
            if '/check-runs' in endpoint:
                check_reads.append(1)
                pending = (mode == 'ci_pending' or (mode == 'generic_ci_drift' and len(check_reads) > 1)
                           or (variant == 'generic_ci_late_pending_success' and len(check_reads) == 2)
                           or (variant == 'generic_ci_late_pending_timeout' and len(check_reads) > 1)
                           or (mode == 'generic_ci_pending_failure' and len(check_reads) == 1))
                late_failure = variant == 'generic_ci_late_failure' and len(check_reads) > 1
                return [{'total_count': 1, 'check_runs': [{'id': 4, 'name': 'foundation',
                         'head_sha': base if mode == 'ci_stale' else head, 'app': {'id': 7},
                         'status': 'in_progress' if pending else 'completed',
                         'conclusion': (None if pending else 'failure' if late_failure or mode in {
                             'ci_failure', 'ci_failure_prior', 'generic_ci_failure', 'generic_ci_drift',
                             'generic_ci_unknown', 'generic_ci_limit', 'generic_ci_event_drift',
                             'generic_ci_body_drift', 'generic_ci_handoff_drift', 'generic_ci_pending_failure'} else 'success')}]}]
            assert endpoint == 'repos/DesignLibro/petlibro-cloud-test-platform/pulls/1'
            return {
                'state': 'open', 'draft': True,
                'head': {'sha': base if mode == 'remote_drift' and calls.exists() else head,
                         'ref': 'candidate', 'repo': {'full_name': 'DesignLibro/petlibro-cloud-test-platform'}},
                'base': {'sha': base, 'ref': 'main',
                         'repo': {'full_name': 'DesignLibro/petlibro-cloud-test-platform'}},
            }
        if mode == 'generic_ci_pending_failure' or variant == 'generic_ci_late_pending_success':
            monkeypatch.setattr('time.sleep', lambda _seconds: None)
        monkeypatch.setattr(acceptance, '_api', fake_api)
        monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda name: str(tmp_path / name))
        params = dict(task_id=task, run_id=run_id, claim_lock=lock, board='default')
        actor = SimpleNamespace(profile_id=str(tmp_path / 'reviewer'), capabilities={'session:create'})
        connection = SimpleNamespace(actor=actor, authority=actor, native_owner=True)
        config = {'model': {'default': 'fake', 'provider': 'custom'},
                  'kanban': {'claude_review': {'executable': str(cli), 'config_dir': str(tmp_path)}}}
        policy, _ = sk.build_kanban_policy(connection, params, config)
        context = json.loads(policy.kanban_json)
        context['max_runtime_seconds'] = 1 if mode in {'timeout', 'timeout_after_result'} else 15
        if variant == 'generic_ci_late_pending_timeout':
            context['max_runtime_seconds'] = 4
        if mode == 'task_mismatch':
            context['task_id'] = sibling
        elif mode == 'run_mismatch':
            context['run_id'] = sibling_run.current_run_id
        elif mode == 'claim_mismatch':
            context['claim_lock'] = 'wrong-claim'
        if mode in {'changes_limit_drift', 'changes_limit_count_drift'}:
            request_changes = kb.request_changes
            def drift_after_refusal(*args, **kwargs):
                result = request_changes(*args, **kwargs)
                with closing(connect()) as other, kb.write_txn(other):
                    if mode == 'changes_limit_drift':
                        other.execute('UPDATE tasks SET body=? WHERE id=?', ('changed after refusal', task))
                    else:
                        other.execute("DELETE FROM task_events WHERE id=(SELECT id FROM task_events "
                                      "WHERE task_id=? AND kind='changes_requested' LIMIT 1)", (task,))
                return result
            monkeypatch.setattr(kb, 'request_changes', drift_after_refusal)
        if mode in {'generic_ci_event_drift', 'generic_ci_body_drift', 'generic_ci_handoff_drift'}:
            request_changes = kb.request_changes
            def drift_before_handoff(*args, **kwargs):
                with closing(connect()) as other, kb.write_txn(other):
                    if mode == 'generic_ci_body_drift':
                        other.execute('UPDATE tasks SET body=? WHERE id=?', ('changed before handoff', task))
                    elif mode == 'generic_ci_handoff_drift':
                        row = other.execute("SELECT id,payload FROM task_events WHERE task_id=? "
                                            "AND kind='wave2_handoff' ORDER BY id DESC LIMIT 1", (task,)).fetchone()
                        payload = json.loads(row['payload'])
                        payload['branch'] = 'changed-branch'
                        other.execute('UPDATE task_events SET payload=? WHERE id=?', (json.dumps(payload), row['id']))
                    else:
                        other.execute("UPDATE task_events SET payload='{}' WHERE task_id=? AND run_id=? "
                                      "AND kind='review_ci_failure'", (task, run_id))
                return request_changes(*args, **kwargs)
            monkeypatch.setattr(kb, 'request_changes', drift_before_handoff)
        if mode.startswith(('changes_transition_', 'escalate_transition_', 'escalate_triage_')):
            if mode.startswith('escalate_triage_'):
                with kb.write_txn(conn):
                    conn.execute("UPDATE tasks SET block_kind='needs_input', block_recurrences=1 WHERE id=?", (task,))
            method = 'request_changes' if mode.startswith('changes_') else 'block_task'
            original = getattr(kb, method)
            def drift_before_transition(*args, **kwargs):
                with closing(connect()) as other, kb.write_txn(other):
                    if mode.endswith('body_drift'):
                        other.execute('UPDATE tasks SET body=? WHERE id=?', ('changed before transition', task))
                    else:
                        row = other.execute("SELECT id,payload FROM task_events WHERE task_id=? "
                                            "AND kind='wave2_handoff' ORDER BY id DESC LIMIT 1", (task,)).fetchone()
                        payload = json.loads(row['payload'])
                        payload['branch'] = 'changed-branch'
                        other.execute('UPDATE task_events SET payload=? WHERE id=?', (json.dumps(payload), row['id']))
                return original(*args, **kwargs)
            monkeypatch.setattr(kb, method, drift_before_transition)
        prior_runs = [r for r in kb.list_runs(conn, task) if r.id != run_id]
        if variant not in {'generic_ci_late_failure', 'generic_ci_late_pending_timeout'} and mode in {'approved', 'approved_real_format', 'changes_requested', 'escalate', 'round2',
                    'changes_limit', 'generic_changes', 'generic_limit', 'generic_budget', 'generic_approved', 'generic_root_approved',
                    'generic_ci_failure', 'generic_ci_limit', 'generic_ci_pending_failure',
                    'changes_unknown_result', 'escalate_unknown_result', 'changes_failed_result'}:
            result = sk._run_task_turns(None, {}, [], context)
            if mode in {'generic_ci_failure', 'generic_ci_limit', 'generic_ci_pending_failure'}:
                assert 'review evidence' in result['final_response']
            else:
                assert result['final_response'] == 'review evidence'
            task_state = kb.get_task(conn, task)
            assert task_state.status == {'changes_requested': 'ready', 'changes_unknown_result': 'ready',
                                         'changes_failed_result': 'ready',
                                         'changes_limit': 'blocked', 'generic_changes': 'ready', 'generic_limit': 'blocked',
                                         'generic_budget': 'blocked',
                                         'generic_ci_failure': 'ready', 'generic_ci_pending_failure': 'ready', 'generic_ci_limit': 'blocked',
                                         'escalate': 'blocked', 'escalate_unknown_result': 'blocked'}.get(mode, 'done')
            if mode in {'changes_requested', 'changes_unknown_result', 'changes_failed_result', 'generic_changes'}:
                assert task_state.assignee == 'dev'
            if mode in {'generic_ci_failure', 'generic_ci_limit', 'generic_ci_pending_failure'}:
                event = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND run_id=? "
                                     "AND kind='review_ci_failure'", (task, run_id)).fetchone()
                payload = json.loads(event['payload'])
                assert payload['ci']['head'] == head and payload['ci']['pr_url'] == url
                assert payload['verification']['python_check']['assertion_failed'] is True
                if mode in {'generic_ci_failure', 'generic_ci_pending_failure'}:
                    assert task_state.assignee == 'dev' and kb.get_run(conn, run_id).outcome == 'changes_requested'
                    developer_context = kb.build_worker_context(conn, task)
                    assert url in developer_context and head in developer_context
                    assert 'foundation' in developer_context and 'src/calc.py::increment' in developer_context
                else:
                    assert task_state.block_kind == 'needs_input' and kb.get_run(conn, run_id).outcome == 'blocked'
            if mode in {'changes_limit', 'generic_limit', 'generic_budget'}:
                assert task_state.block_kind == 'needs_input'
            if mode in {'changes_limit', 'generic_limit', 'generic_budget'}:
                assert task_state.current_run_id is None
                assert kb.get_run(conn, run_id).outcome == 'blocked'
                assert 'review repair limit reached' in kb.get_run(conn, run_id).summary
                assert kb.get_task(conn, sibling).current_run_id == sibling_run.current_run_id
            if mode == 'changes_failed_result':
                row = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND run_id=? "
                                   "AND kind='review_execution'", (task, run_id)).fetchone()
                assert json.loads(row['payload'])['commands'][0]['exit_status'] == 7
            if mode in {'escalate', 'escalate_unknown_result'}:
                assert task_state.assignee == 'reviewer' and task_state.block_kind == 'needs_input'
                assert task_state.current_run_id is None and kb.get_run(conn, run_id).outcome == 'blocked'
                assert kb.get_run(conn, run_id).summary == 'review evidence'
                assert [r for r in kb.list_runs(conn, task) if r.id != run_id] == prior_runs
                assert kb.get_task(conn, sibling).current_run_id == sibling_run.current_run_id
            if mode in {'approved', 'approved_real_format', 'round2'}:
                evidence = kb.get_run(conn, run_id).metadata['review_execution']
                assert evidence['task_id'] == task and evidence['run_id'] == run_id
                assert evidence['published_pr'] == url and evidence['head_sha'] == head
                assert len(evidence['claim_digest']) == 64
                assert evidence['commands'][0]['command'] == '<multiline command withheld>'
                assert evidence['commands'][0]['script'] == sk._pilot_review_script(script, goal, {'url': url})
                assert evidence['commands'][0]['exit_status'] == 0
                assert len(evidence['commands'][0]['output_sha256']) == 64
            if mode in {'generic_approved', 'generic_root_approved'}:
                evidence = kb.get_run(conn, run_id).metadata['review_execution']
                assert evidence['task_id'] == task and evidence['run_id'] == run_id
                assert evidence['published_pr'] == url and evidence['head_sha'] == head
                assert evidence['commands'][0]['python_check'] == {
                    'source': 'calc.py' if mode == 'generic_root_approved' else 'src/calc.py',
                    'symbol': 'increment', 'cases': 2, 'assertion_failed': False}
        else:
            race = (mode.startswith(('changes_transition_', 'escalate_transition_', 'escalate_triage_'))
                    or mode == 'generic_ci_handoff_drift')
            error = ('review_ci_uncertain' if variant in {'generic_ci_late_failure', 'generic_ci_late_pending_timeout'} else
                     'review_(stale_claim|acceptance_refused)' if mode == 'changes_transition_body_drift' else
                     'review_stale_claim' if race else
                     'review_(failed|candidate_changed|stale_claim|sandbox_unavailable|acceptance_refused|ci_uncertain)')
            with pytest.raises(RuntimeStoreError, match=error):
                sk._run_task_turns(None, {}, [], context)
            assert kb.get_task(conn, task).status == 'running'
            if variant == 'generic_ci_late_failure':
                assert len(check_reads) == 2
                assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='review_execution'",
                                    (task,)).fetchone()[0] == 1
                assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='changes_requested'",
                                    (task,)).fetchone()[0] == 0
                assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='pr_acceptance'",
                                    (task,)).fetchone()[0] == 0
            if variant == 'generic_ci_late_pending_timeout':
                row = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND run_id=? "
                                   "AND kind='review_execution'", (task, run_id)).fetchone()
                evidence = json.loads(row['payload'])
                assert evidence['task_id'] == task and evidence['run_id'] == run_id
                assert evidence['published_pr'] == url and evidence['head_sha'] == head
                assert evidence['claim_digest'] == hashlib.sha256(lock.encode()).hexdigest()
                assert evidence['provisional_verdict'] == {'verdict': 'approved', 'reason': 'review evidence'}
                assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? "
                                    "AND kind IN ('wave2_verdict', 'completed', 'changes_requested')",
                                    (task,)).fetchone()[0] == 0
            if mode.startswith(('changes_transition_', 'escalate_transition_', 'escalate_triage_')):
                assert kb.get_task(conn, task).current_run_id == run_id
                assert kb.get_task(conn, sibling).current_run_id == sibling_run.current_run_id
            if mode in {'generic_ci_drift', 'generic_ci_unknown'}:
                assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='review_ci_failure'",
                                    (task,)).fetchone()[0] == 0
            if mode in {'changes_limit_drift', 'changes_limit_count_drift'}:
                if mode == 'changes_limit_drift':
                    assert kb.get_task(conn, task).body == 'changed after refusal'
                assert kb.get_task(conn, sibling).current_run_id == sibling_run.current_run_id
            if mode in {'ci_pending', 'ci_stale', 'ci_failure', 'ci_failure_prior'}:
                row = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND run_id=? "
                                   "AND kind='pr_acceptance' ORDER BY id DESC LIMIT 1",
                                   (task, run_id)).fetchone()
                receipt = json.loads(row['payload'])
                assert receipt['classification'] == ('failure' if mode == 'ci_failure_prior'
                                                      else mode.removeprefix('ci_'))
                assert receipt['head_sha'] == head and receipt['pr_url'] == url
            if mode == 'body_drift':
                assert kb.get_task(conn, task).body == 'changed after review'
                assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='pr_acceptance'",
                                    (task,)).fetchone()[0] == 0
            if mode in {'test_failure', 'invalid', 'timeout_after_result', 'malformed_after_result'}:
                row = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND run_id=? "
                                   "AND kind='review_execution'", (task, run_id)).fetchone()
                evidence = json.loads(row['payload'])
                assert evidence['task_id'] == task and evidence['run_id'] == run_id
                assert evidence['published_pr'] == url and evidence['head_sha'] == head
                assert evidence['commands'][0]['exit_status'] == (7 if mode == 'test_failure' else 0)
        if mode in {'task_mismatch', 'run_mismatch', 'claim_mismatch', 'unknown_cli_version'}:
            assert not calls.exists()
        else:
            assert calls.read_text() == 'call\n'
        if variant == 'generic_ci_late_pending_success':
            assert len(check_reads) >= 4


@pytest.mark.parametrize('outcome', ['failure', 'success', 'timeout', 'head_drift', 'claim_drift', 'handoff_drift'])
def test_review_waits_for_pending_ci_before_one_review(monkeypatch, outcome):
    import time
    from gateway import session_kanban as sk
    from hermes_cli import kanban_pr_acceptance as acceptance
    from hermes_state_runtime import RuntimeStoreError

    handoff = {'url': 'https://github.com/owner/repo/pull/1', 'head': 'a' * 40, 'base': 'main'}
    context = {'profile': 'reviewer', 'max_runtime_seconds': 8}
    calls = []
    now = [0.0]
    monkeypatch.setattr(time, 'monotonic', lambda: now[0])
    monkeypatch.setattr(time, 'sleep', lambda seconds: now.__setitem__(0, now[0] + seconds))
    monkeypatch.setattr(sk, '_bound_claim_is_live', lambda _: outcome != 'claim_drift' or not calls)
    monkeypatch.setattr(sk, '_review_handoff', lambda *_: (5, {**handoff, 'base': 'other'})
                        if outcome == 'handoff_drift' and calls else (5, handoff))
    def collect(*_args, **_kwargs):
        calls.append(1)
        final = len(calls) > 1 and outcome != 'timeout'
        state = outcome if final and outcome in {'failure', 'success'} else 'pending'
        return {'ok': state == 'success', 'classification': state, 'pr_url': handoff['url'],
                'head_sha': 'b' * 40 if final and outcome == 'head_drift' else handoff['head'],
                'base_ref': 'main', 'checks': [{'id': 1, 'name': 'unit', 'head_sha': handoff['head'],
                                               'classification': state, 'conclusion': state}]}
    monkeypatch.setattr(acceptance, 'collect_acceptance', collect)
    if outcome in {'timeout', 'head_drift', 'claim_drift', 'handoff_drift'}:
        with pytest.raises(RuntimeStoreError, match='review_(ci_uncertain|stale_claim)'):
            sk._wait_review_ci(None, context, 5, handoff)
    else:
        result = sk._wait_review_ci(None, context, 5, handoff)
        assert (result is not None) == (outcome == 'failure')
        if result:
            assert result['checks'][0]['classification'] == 'failure'
    assert len(calls) == (1 if outcome in {'claim_drift', 'handoff_drift'} else 2)


def test_claim_freezes_task_policy_and_rejects_forgery(tmp_path, monkeypatch):
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from gateway.session_contract import Principal
    from hermes_state_runtime import RuntimeStoreError
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda name: str(tmp_path) if name == 'default' else str(tmp_path / name))
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    (workspace / 'pyproject.toml').write_text('[project]\nname = "task"\n')  # a code worktree
    from contextlib import closing
    kb.create_board('owned')  # explicit creation; connect() never creates a board (#43243)
    with closing(connect(board='owned')) as conn:
        task_id = kb.create_task(conn, title='Owned acceptance', body='Goal criteria', assignee='default',
            workspace_kind='dir', workspace_path=str(workspace), skills=['owned-skill'], goal_mode=True,
            goal_max_turns=3, model_override='loop-model', provider_override='custom')
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
    actor = Principal('owner', str(tmp_path), frozenset({'session:create'}), 'transport')
    connection = SimpleNamespace(authority=SimpleNamespace(profile_id=str(tmp_path)), actor=actor, native_owner=True)
    params = dict(board='owned', task_id=task.id, run_id=task.current_run_id, claim_lock=task.claim_lock)
    from gateway.session_kanban import build_kanban_policy
    config = {'model': {'default': 'loop-model', 'provider': 'custom'}, 'platform_toolsets': {'cli': ['terminal', 'file']},
              'agent': {'coding_context': 'focus'}}  # the worktree must not collapse a worker into the coding posture
    policy, _secrets = build_kanban_policy(connection, params, config)
    context = json.loads(policy.kanban_json)
    assert policy.source == 'kanban' and policy.cwd == str(workspace)
    assert policy.model == task.model_override and policy.provider == task.provider_override
    assert {'kanban', 'terminal', 'file'} <= set(policy.toolsets)
    assert context['task_id'] == task.id and context['run_id'] == task.current_run_id
    assert context['board'] == 'owned' and context['claim_lock'] == task.claim_lock
    assert context['skills'] == ['owned-skill'] and context['goal_mode'] and context['goal_max_turns'] == 3
    assert context['accept_hooks'] is True and 'Goal criteria' in context['goal_text']
    for changed in ({'run_id': task.current_run_id + 1}, {'board': 'foreign'}, {'claim_lock': 'forged'}, {'cwd': '/tmp'}):
        with pytest.raises(RuntimeStoreError):
            build_kanban_policy(connection, params | changed, config)
    connection.native_owner = False
    with pytest.raises(RuntimeStoreError, match='permission_denied'):
        build_kanban_policy(connection, params, config)
    from gateway.session_policy import build_policy
    with pytest.raises(RuntimeStoreError, match='invalid_params'):
        build_policy({'source': 'kanban', 'cwd': str(workspace)}, config)


@pytest.mark.parametrize('mode', ['complete', 'timeout', 'rate_limit', 'billing', 'crash'])
def test_real_dispatcher_lifecycle(tmp_path, mode):
    import os
    import subprocess
    import sys
    repo = Path(__file__).resolve().parents[2]
    from tests.gateway.fixtures.local_recovery_probe import child_env
    env = child_env()
    env.update(HOME=str(tmp_path / 'home'), USERPROFILE=str(tmp_path / 'home'), HERMES_HOME=str(tmp_path / 'state'), PYTHONPATH=str(repo), KANBAN_PROBE_MODE=mode)
    result = subprocess.run([sys.executable, str(Path(__file__).parent / 'fixtures' / 'kanban_owner_probe.py')],
        env=env, cwd=repo, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=150, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads((tmp_path / 'state' / 'receipt.json').read_text())
    print(json.dumps(receipt))
    if mode != 'complete':
        assert receipt['task_status'] == 'ready'
        return
    assert receipt['task_status'] == 'done' and receipt['source'] == 'kanban'
    assert receipt['tools'] and receipt['task_context'] and receipt['skill_context'] and receipt['hook_effect']
    assert receipt['admissions'] == 1 and receipt['retry_same_session']
    assert receipt['goal_continuation'] and receipt['stable_prefix']
    print(json.dumps(receipt))


def test_late_launcher_cannot_stamp_replacement_claim(tmp_path, monkeypatch):
    from contextlib import closing
    from hermes_cli import kanban_db as kb, kanban_db_dispatch as dispatch
    from hermes_cli.kanban_db_connect import connect
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    kb.create_board('owned')  # explicit creation; connect() never creates a board (#43243)
    with closing(connect(board='owned')) as conn:
        tid = kb.create_task(conn, title='Owned race', assignee='default')
        old = kb.claim_task(conn, tid)
        kb.block_task(conn, tid, reason='replace claim', expected_run_id=old.current_run_id)
        kb.unblock_task(conn, tid)
        new = kb.claim_task(conn, tid)
        dispatch._set_worker_pid(conn, tid, 424242, run_id=old.current_run_id, claim_lock=old.claim_lock)
        assert kb.get_task(conn, tid).worker_pid is None
        assert conn.execute('SELECT worker_pid FROM task_runs WHERE id=?', (new.current_run_id,)).fetchone()[0] is None


def test_claim_reclaimed_before_admission_marker_is_refused(tmp_path, monkeypatch):
    """A claim that stops being current between policy/session creation and the marker
    transaction is refused: no owner_admitted row, no resume, no submit."""
    import asyncio
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from gateway.session_contract import Principal
    from hermes_state_runtime import RuntimeStoreError
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda name: str(tmp_path) if name == 'default' else str(tmp_path / name))
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    kb.create_board('owned')  # explicit creation; connect() never creates a board (#43243)
    with closing(connect(board='owned')) as conn:
        task_id = kb.create_task(conn, title='Owned race', assignee='default', workspace_kind='dir', workspace_path=str(workspace))
        kb.recompute_ready(conn)
        old = kb.claim_task(conn, task_id)
    config = {'model': {'default': 'loop-model', 'provider': 'custom'}, 'platform_toolsets': {'cli': ['terminal']}}
    monkeypatch.setattr('gateway.run._load_gateway_config', lambda: config)
    calls = []
    def create_local_session(authority, actor, params, *, trusted_policy=None, trusted_secrets=None):
        # Another process reclaims the task while the owner session is being created.
        with closing(connect(board='owned')) as conn:
            kb.block_task(conn, task_id, reason='replace claim', expected_run_id=old.current_run_id)
            kb.unblock_task(conn, task_id)
            kb.claim_task(conn, task_id)
        return SimpleNamespace(session_id='owner-session', profile_id=str(tmp_path))
    monkeypatch.setattr('gateway.session_local.create_local_session', create_local_session)
    async def submit(actor, submission):
        calls.append(('submit', submission))
    async def resume(ref, params):
        calls.append(('resume', ref))
    db = SimpleNamespace(get_session=lambda sid: None, db_path=str(tmp_path / 'state.db'))
    authority = SimpleNamespace(profile_id=str(tmp_path), instance_id='owner', epoch=1, db=db, submit=submit)
    actor = Principal('owner', str(tmp_path), frozenset({'session:create'}), 'transport')
    connection = SimpleNamespace(authority=authority, actor=actor, native_owner=True, resume=resume)
    params = dict(board='owned', task_id=task_id, run_id=old.current_run_id, claim_lock=old.claim_lock)
    from gateway.session_kanban import run_task
    with pytest.raises(RuntimeStoreError, match='stale_kanban_claim'):
        asyncio.run(run_task(connection, params))
    assert calls == []
    with closing(connect(board='owned')) as conn:
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admitted'", (task_id,)).fetchone()[0] == 0


def test_admission_binding_fences_stale_claim_and_preserves_no_secret(tmp_path, monkeypatch):
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from gateway.session_kanban import _bind_owner_admission
    from hermes_state_runtime import RuntimeStoreError

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    kb.create_board('owned')
    with closing(connect(board='owned')) as conn:
        task_id = kb.create_task(conn, title='test', assignee='default')
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
        params = dict(task_id=task_id, run_id=task.current_run_id, claim_lock=task.claim_lock)
        request = 'kanban:' + json.dumps(['owned', task_id, task.current_run_id], separators=(',', ':'))
        with kb.write_txn(conn):
            kb._append_event(conn, task_id, 'owner_admitted', {'session_id': 's', 'request_id': request}, run_id=task.current_run_id)
        _bind_owner_admission(conn, params, 's', request, 'admission')
        _bind_owner_admission(conn, params, 's', request, 'admission')
        rows = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='owner_admission_bound'", (task_id,)).fetchall()
        assert len(rows) == 1 and json.loads(rows[0][0]) == {'session_id': 's', 'request_id': request, 'admission_id': 'admission'}
        assert task.claim_lock not in rows[0][0]
        with pytest.raises(RuntimeStoreError, match='unknown_execution'):
            _bind_owner_admission(conn, params | {'claim_lock': 'stale'}, 's', request, 'other')
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admission_bound'", (task_id,)).fetchone()[0] == 1
        with kb.write_txn(conn):
            kb._end_run(conn, task_id, outcome='crashed', status='ready')
            conn.execute("UPDATE tasks SET status='ready', claim_lock=NULL, claim_expires=NULL WHERE id=?", (task_id,))
        successor = kb.claim_task(conn, task_id)
        assert successor.current_run_id != task.current_run_id
        before = tuple(conn.execute('SELECT status,current_run_id,claim_lock FROM tasks WHERE id=?', (task_id,)).fetchone())
        # A fully matching old receipt can be read again, but cannot overwrite the new run.
        _bind_owner_admission(conn, params, 's', request, 'admission')
        with pytest.raises(RuntimeStoreError, match='unknown_execution'):
            _bind_owner_admission(conn, params, 's', request, 'different-admission')
        assert tuple(conn.execute('SELECT status,current_run_id,claim_lock FROM tasks WHERE id=?', (task_id,)).fetchone()) == before
        assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admission_bound'", (task_id,)).fetchone()[0] == 1


@pytest.mark.asyncio
async def test_finish_readback_never_starts_missing_gateway(tmp_path, monkeypatch):
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_owner_recovery import read_owner_finish
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda _: str(tmp_path))
    monkeypatch.setattr('hermes_cli.gateway_runtime.discover_gateway_endpoint', lambda _: SimpleNamespace(state='absent', endpoint=None))
    def forbidden(*args, **kwargs):
        raise AssertionError('missing owner must not be started or contacted')
    monkeypatch.setattr('hermes_cli.gateway_client.connect_gateway', forbidden)
    kb.create_board('owned')
    with closing(connect(board='owned')) as conn:
        task_id = kb.create_task(conn, title='test', assignee='default')
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
        request = 'kanban:' + json.dumps(['owned', task_id, task.current_run_id], separators=(',', ':'))
        with kb.write_txn(conn):
            kb._append_event(conn, task_id, 'owner_admitted', {'session_id': 's', 'request_id': request}, run_id=task.current_run_id)
            kb._append_event(conn, task_id, 'owner_admission_bound', {'session_id': 's', 'request_id': request, 'admission_id': 'a'}, run_id=task.current_run_id)
        result = await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path)
        assert result == dict(board_terminal='UNKNOWN', receipt='UNKNOWN', ack='UNKNOWN', physical_retirement='UNKNOWN')


@pytest.mark.asyncio
async def test_finish_readback_uses_bound_owner_receipt_without_gateway(tmp_path, monkeypatch):
    import os
    import psutil
    from contextlib import asynccontextmanager, closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_owner_recovery import read_owner_finish
    from gateway.session_kanban import _bind_owner_admission
    from gateway.session_authority import LiveSession, SessionAuthority
    from gateway.session_controls import AuthorityConnection
    from hermes_state import SessionDB
    from hermes_state_runtime import (admit_session_input, begin_runtime_epoch, claim_session_input,
                                      mutate_worker_execution, register_worker_execution)

    reviewer_home = tmp_path / 'profiles' / 'reviewer'
    reviewer_home.mkdir(parents=True)
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda profile: str(reviewer_home if profile == 'reviewer' else tmp_path))
    endpoint = SimpleNamespace(profile_id=str(reviewer_home), instance_id='owner', api_origin='http://127.0.0.1:12345')
    monkeypatch.setattr('hermes_cli.gateway_runtime.discover_gateway_endpoint', lambda _: SimpleNamespace(state='ready', endpoint=endpoint))
    kb.create_board('owned')
    with closing(connect(board='owned')) as conn, SessionDB(reviewer_home / 'state.db') as db:
        task_id = kb.create_task(conn, title='test', assignee='default')
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
        conn.execute("UPDATE task_runs SET profile='reviewer' WHERE id=?", (task.current_run_id,))
        params = dict(task_id=task_id, run_id=task.current_run_id, claim_lock=task.claim_lock)
        request = 'kanban:' + json.dumps(['owned', task_id, task.current_run_id], separators=(',', ':'))
        db.create_session('s', source='test')
        epoch = begin_runtime_epoch(db, instance_id='owner')
        authority = SessionAuthority(SimpleNamespace(_draining=False), profile_id=str(reviewer_home), instance_id='owner', db=db, epoch=epoch)
        authority.sessions['s'] = LiveSession(None, 'route')
        connection = AuthorityConnection(authority, object(), {'user_id': 'owner'})
        monkeypatch.setattr('hermes_state_local.local_receipt', lambda *_: {'policy': {}})
        monkeypatch.setattr('gateway.session_policy.restore_policy', lambda _: SimpleNamespace(source='kanban', kanban_json=json.dumps(dict(board='owned', task_id=task_id, run_id=task.current_run_id, claim_lock=task.claim_lock))))
        admitted = admit_session_input(db, epoch=epoch, principal_id=connection.actor.subject, session_id='s', request_id=request, payload={})
        claim = claim_session_input(db, epoch=epoch, session_id='s')
        scope = dict(epoch=epoch, execution_id='admission-worker:' + admitted['admission_id'], session_id='s', generation=claim['generation'])
        register_worker_execution(db, **scope, kind='compute', adoption_secret='private-proof')
        mutate_worker_execution(db, **scope, sequence=1, operation='execution.finish', payload={})
        marker = {'session_id': 's', 'request_id': request, 'db': str(reviewer_home / 'state.db'),
                  'pid': os.getpid(), 'birth': psutil.Process().create_time(),
                  'instance_id': 'owner', 'authority_epoch': epoch}
        with kb.write_txn(conn):
            kb._append_event(conn, task_id, 'owner_admitted', marker, run_id=task.current_run_id)
        _bind_owner_admission(conn, params, 's', request, admitted['admission_id'])
        foreign_connection = AuthorityConnection(authority, object(), {'user_id': 'foreign', 'capabilities': ['session:submit']})
        client_connection = connection
        class Client:
            async def rpc(self, method, **kwargs):
                response = await client_connection.dispatch({'id': 1, 'method': method, 'params': kwargs})
                return response['result']
        @asynccontextmanager
        async def fake_connect(*, endpoint):
            from hermes_constants import get_hermes_home
            assert get_hermes_home().resolve() == reviewer_home
            assert endpoint.api_origin == 'http://127.0.0.1:12345'
            yield Client()
        monkeypatch.setattr('hermes_cli.gateway_client.connect_gateway', fake_connect)
        try:
            result = await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path)
            assert result == dict(board_terminal='UNKNOWN', receipt='RECORDED', ack='UNKNOWN', physical_retirement='UNKNOWN')
            assert 'private-proof' not in str(result)
            # The original Owner identity must still be provable on the exact bound DB.
            for changes in ({'pid': 0}, {'birth': marker['birth'] + 1}, {'db': str(tmp_path / 'foreign.db')},
                            {'instance_id': ''}, {'authority_epoch': epoch + 1}, {'authority_epoch': True}):
                with kb.write_txn(conn):
                    conn.execute("UPDATE task_events SET payload=? WHERE task_id=? AND kind='owner_admitted'",
                                 (json.dumps(marker | changes), task_id))
                assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            with kb.write_txn(conn):
                conn.execute("UPDATE task_events SET payload=? WHERE task_id=? AND kind='owner_admitted'",
                             (json.dumps({k: v for k, v in marker.items() if k != 'instance_id'}), task_id))
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            with kb.write_txn(conn):
                conn.execute("UPDATE task_events SET payload=? WHERE task_id=? AND kind='owner_admitted'", (json.dumps(marker), task_id))
            endpoint.instance_id = 'replacement-owner'
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            endpoint.instance_id = 'owner'
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'RECORDED'
            from hermes_constants import get_hermes_home
            assert get_hermes_home().resolve() == tmp_path
            endpoint.profile_id = str(tmp_path)
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            endpoint.profile_id = str(reviewer_home)
            client_connection = foreign_connection
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            client_connection = connection
            endpoint.api_origin = 'https://example.com:443'
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
            endpoint.api_origin = 'http://127.0.0.1:12345'
            from websockets.exceptions import WebSocketException
            @asynccontextmanager
            async def closed_connect(*, endpoint):
                raise WebSocketException('closed')
                yield  # pragma: no cover
            monkeypatch.setattr('hermes_cli.gateway_client.connect_gateway', closed_connect)
            assert (await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path))['receipt'] == 'UNKNOWN'
        finally:
            await foreign_connection.close()
            await connection.close()


@pytest.mark.parametrize('case', ['ordinary', 'bad_contract', 'bad_marker', 'valid_wave2'])
def test_non_wave2_fast_completion_does_not_bind_but_bad_stage3_fails_closed(tmp_path, monkeypatch, case):
    import asyncio
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from gateway.session_contract import Principal
    from hermes_state_runtime import RuntimeStoreError
    from gateway.session_kanban import run_task

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.setenv('HOME', str(tmp_path / 'home'))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.delenv('HERMES_DELEGATED_CHILD', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda _: str(tmp_path))
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    kb.create_board('owned')
    with closing(connect(board='owned')) as conn:
        kwargs = {} if case == 'ordinary' else {'created_by': 'ai-colleague-stage3'}
        if case in {'bad_marker', 'valid_wave2'}:
            kwargs['completion_contract'] = 'owner/repo'
        if case == 'valid_wave2':
            kwargs['body'] = json.dumps({'publication_protocol': 'wave2_v1'})
        task_id = kb.create_task(conn, title='Fast task', assignee='default', workspace_kind='dir',
                                 workspace_path=str(workspace), **kwargs)
        kb.recompute_ready(conn)
        task = kb.claim_task(conn, task_id)
    config = {'model': {'default': 'loop-model', 'provider': 'custom'}, 'platform_toolsets': {'cli': ['terminal']}}
    monkeypatch.setattr('gateway.run._load_gateway_config', lambda: config)
    monkeypatch.setattr('gateway.session_local.create_local_session', lambda *a, **k: SimpleNamespace(
        session_id='owner-session', profile_id=str(tmp_path)))
    monkeypatch.setattr('gateway.session_kanban.asdict', lambda _: {'admission_id': 'admission'})
    def forbidden_bind(*args, **kwargs):
        raise AssertionError('ordinary task must not use Wave 2 binding')
    if case == 'ordinary':
        monkeypatch.setattr('gateway.session_kanban._bind_owner_admission', forbidden_bind)
    calls = []
    async def submit(actor, submission):
        calls.append('submit')
        # The Worker can finish before submit returns; this is a real Board transition.
        if case == 'ordinary':
            with closing(connect(board='owned')) as conn:
                assert kb.block_task(conn, task_id, reason='fast completion', expected_run_id=task.current_run_id)
        return SimpleNamespace(admission_id='admission')
    async def resume(ref, params):
        calls.append('resume')
    db = SimpleNamespace(get_session=lambda _: None, db_path=str(tmp_path / 'state.db'))
    authority = SimpleNamespace(profile_id=str(tmp_path), instance_id='owner', epoch=1, db=db, submit=submit)
    actor = Principal('owner', str(tmp_path), frozenset({'session:create'}), 'transport')
    connection = SimpleNamespace(authority=authority, actor=actor, native_owner=True, resume=resume)
    params = dict(board='owned', task_id=task_id, run_id=task.current_run_id, claim_lock=task.claim_lock)
    if case in {'bad_contract', 'bad_marker'}:
        with pytest.raises(RuntimeStoreError, match='unknown_execution'):
            asyncio.run(run_task(connection, params))
        assert calls == []
        with closing(connect(board='owned')) as conn:
            assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admitted'", (task_id,)).fetchone()[0] == 0
    else:
        result = asyncio.run(run_task(connection, params))
        assert result['receipt']['admission_id'] == 'admission'
        assert calls == ['resume', 'submit']
        if case == 'valid_wave2':
            with closing(connect(board='owned')) as conn:
                assert conn.execute("SELECT count(*) FROM task_events WHERE task_id=? AND kind='owner_admission_bound'", (task_id,)).fetchone()[0] == 1
                marker = json.loads(conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='owner_admitted'", (task_id,)).fetchone()[0])
                assert marker['instance_id'] == 'owner' and marker['authority_epoch'] == 1


@pytest.mark.asyncio
async def test_finish_readback_rejects_same_task_and_run_ids_on_foreign_board(tmp_path, monkeypatch):
    import os
    import psutil
    from contextlib import asynccontextmanager, closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_owner_recovery import read_owner_finish

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    monkeypatch.setattr('hermes_cli.profiles.resolve_profile_env', lambda _: str(tmp_path))
    monkeypatch.setattr(kb, '_new_task_id', lambda: 't_deadbeef')
    (tmp_path / 'state.db').touch()
    endpoint = SimpleNamespace(profile_id=str(tmp_path), instance_id='owner', api_origin='http://127.0.0.1:12345')
    monkeypatch.setattr('hermes_cli.gateway_runtime.discover_gateway_endpoint', lambda _: SimpleNamespace(state='ready', endpoint=endpoint))
    calls = []
    class Client:
        async def rpc(self, method, **kwargs):
            calls.append((method, kwargs))
            return {'authority_epoch': 1, 'worker_finish': {'receipt': 'RECORDED', 'ack': 'UNKNOWN', 'physical_retirement': 'UNKNOWN'}}
    @asynccontextmanager
    async def fake_connect(*, endpoint):
        yield Client()
    monkeypatch.setattr('hermes_cli.gateway_client.connect_gateway', fake_connect)
    for board in ('owned', 'foreign'):
        kb.create_board(board)
        with closing(connect(board=board)) as conn:
            task_id = kb.create_task(conn, title='test', assignee='default')
            kb.recompute_ready(conn)
            task = kb.claim_task(conn, task_id)
            assert task_id == 't_deadbeef' and task.current_run_id == 1
            # A copied foreign marker refers to the other Board despite identical IDs.
            request = 'kanban:' + json.dumps(['owned', task_id, task.current_run_id], separators=(',', ':'))
            with kb.write_txn(conn):
                kb._append_event(conn, task_id, 'owner_admitted', {'session_id': 's', 'request_id': request, 'db': str(tmp_path / 'state.db'), 'pid': os.getpid(), 'birth': psutil.Process().create_time(), 'instance_id': 'owner', 'authority_epoch': 1}, run_id=task.current_run_id)
                kb._append_event(conn, task_id, 'owner_admission_bound', {'session_id': 's', 'request_id': request, 'admission_id': 'a'}, run_id=task.current_run_id)
            result = await read_owner_finish(conn, task_id, task.current_run_id, profile_home=tmp_path)
            assert result['receipt'] == ('RECORDED' if board == 'owned' else 'UNKNOWN')
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['early_return', 'exception'])
async def test_finish_readback_discards_stale_terminal_on_early_exit(tmp_path, monkeypatch, failure):
    import asyncio
    import threading
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_owner_recovery import read_owner_finish

    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(tmp_path))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    entered, proceed = threading.Event(), threading.Event()
    def delayed(*_):
        entered.set()
        assert proceed.wait(5)
        if failure == 'exception':
            raise ValueError('unavailable profile')
    monkeypatch.setattr('hermes_cli.kanban_owner_recovery._matching_profile_home', delayed)
    kb.create_board('owned')
    with closing(connect(board='owned')) as reader, closing(connect(board='owned')) as writer:
        task_id = kb.create_task(reader, title='test', assignee='default')
        kb.recompute_ready(reader)
        task = kb.claim_task(reader, task_id)
        with kb.write_txn(reader):
            reader.execute("UPDATE tasks SET status='done' WHERE id=?", (task_id,))
            reader.execute("UPDATE task_runs SET outcome='completed' WHERE id=?", (task.current_run_id,))
        pending = asyncio.create_task(read_owner_finish(reader, task_id, task.current_run_id, profile_home=tmp_path))
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            with kb.write_txn(writer):
                writer.execute("UPDATE tasks SET status='doing' WHERE id=?", (task_id,))
        finally:
            proceed.set()
        assert await pending == dict(board_terminal='UNKNOWN', receipt='UNKNOWN', ack='UNKNOWN', physical_retirement='UNKNOWN')


@pytest.mark.asyncio
async def test_finish_readback_rejects_same_named_profile_from_foreign_root(tmp_path, monkeypatch):
    from contextlib import closing
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from hermes_cli.kanban_owner_recovery import read_owner_finish
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    authorized = tmp_path / 'authorized'
    foreign = tmp_path / 'foreign'
    for root in (authorized, foreign):
        reviewer = root / 'profiles' / 'reviewer'
        reviewer.mkdir(parents=True)
        (reviewer / '.env').touch()  # profile identity only; no credentials
    monkeypatch.setenv('HERMES_HOME', str(foreign))
    monkeypatch.setenv('HERMES_KANBAN_HOME', str(authorized))
    monkeypatch.delenv('HERMES_KANBAN_DB', raising=False)
    def forbidden(*_args, **_kwargs):
        raise AssertionError('must not discover a foreign Owner')
    monkeypatch.setattr('hermes_cli.gateway_runtime.discover_gateway_endpoint', forbidden)
    monkeypatch.setattr('hermes_cli.gateway_client.connect_gateway', forbidden)
    token = set_hermes_home_override(authorized)
    try:
        kb.create_board('owned')
        with closing(connect(board='owned')) as conn:
            task_id = kb.create_task(conn, title='test', assignee='default')
            kb.recompute_ready(conn)
            task = kb.claim_task(conn, task_id)
            conn.execute("UPDATE task_runs SET profile='reviewer' WHERE id=?", (task.current_run_id,))
            request = 'kanban:' + json.dumps(['owned', task_id, task.current_run_id], separators=(',', ':'))
            with kb.write_txn(conn):
                kb._append_event(conn, task_id, 'owner_admitted', {'session_id': 's', 'request_id': request}, run_id=task.current_run_id)
                kb._append_event(conn, task_id, 'owner_admission_bound', {'session_id': 's', 'request_id': request, 'admission_id': 'a'}, run_id=task.current_run_id)
            assert await read_owner_finish(conn, task_id, task.current_run_id, profile_home=authorized) == dict(
                board_terminal='UNKNOWN', receipt='UNKNOWN', ack='UNKNOWN', physical_retirement='UNKNOWN')
    finally:
        reset_hermes_home_override(token)
