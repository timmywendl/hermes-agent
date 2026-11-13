"""Tests for the hermes-tools-as-MCP server module surface.

We don't run a live MCP session in unit tests — that requires the codex
subprocess + client + an event loop. These tests pin the static
contract: the module imports, the EXPOSED_TOOLS list is sane, and the
build helper assembles a server when the SDK is present.
"""

from __future__ import annotations

import inspect

from agent.transports.hermes_tools_mcp_server import (
    _signature_from_schema,
)


class TestSignatureFromSchema:
    """Test the JSON Schema -> Python signature conversion."""

    def test_simple_required_string_param(self):
        """A required string param becomes str with no default."""
        schema = {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        }
        sig, annots = _signature_from_schema(schema)

        assert len(sig.parameters) == 1
        param = sig.parameters["query"]
        assert param.name == "query"
        assert param.kind == inspect.Parameter.KEYWORD_ONLY
        assert annots["query"] == str
        assert param.default is inspect.Parameter.empty


    def test_skip_private_params(self):
        """Params starting with '_' are excluded from the signature."""
        schema = {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "_internal": {"type": "string"},
            },
            "required": ["query", "_internal"],
        }
        sig, annots = _signature_from_schema(schema)

        assert "_internal" not in sig.parameters
        assert "_internal" not in annots
        assert "query" in sig.parameters

    def test_all_json_types(self):
        """All JSON schema types map to correct Python types."""
        schema = {
            "type": "object",
            "properties": {
                "s": {"type": "string"},
                "i": {"type": "integer"},
                "n": {"type": "number"},
                "b": {"type": "boolean"},
                "a": {"type": "array"},
                "o": {"type": "object"},
            },
            "required": ["s", "i", "n", "b", "a", "o"],
        }
        _sig, annots = _signature_from_schema(schema)

        assert annots["s"] == str
        assert annots["i"] == int
        assert annots["n"] == float
        assert annots["b"] == bool
        assert annots["a"] == list
        assert annots["o"] == dict


class TestModuleSurface:

    def test_exposed_tools_are_safe_subset(self):
        """We MUST NOT expose tools codex already has, because codex'
        own builtins are better-integrated with its sandbox + approvals.
        Specifically: no terminal/shell, no read_file/write_file, no
        patch — those are codex's built-in tools."""
        from agent.transports.hermes_tools_mcp_server import EXPOSED_TOOLS
        forbidden = {
            "terminal", "shell", "read_file", "write_file", "patch",
            "search_files", "process",
        }
        leaked = forbidden & set(EXPOSED_TOOLS)
        assert not leaked, (
            f"these tools must NOT be exposed via the codex callback "
            f"because codex has built-in equivalents: {leaked}"
        )


class TestMain:
    def test_main_returns_2_when_mcp_unavailable(self, monkeypatch):
        """When the mcp package isn't installed, main() should exit
        cleanly with code 2 and an install hint, not crash."""
        import agent.transports.hermes_tools_mcp_server as m

        def boom_build(*a, **kw):
            raise ImportError("mcp not installed")

        monkeypatch.setattr(m, "_build_server", boom_build)
        rc = m.main(["--verbose"])
        assert rc == 2

    def test_main_handles_keyboard_interrupt(self, monkeypatch):
        import agent.transports.hermes_tools_mcp_server as m

        class FakeServer:
            def run(self):
                raise KeyboardInterrupt()

        monkeypatch.setattr(m, "_build_server", lambda: FakeServer())
        rc = m.main([])
        assert rc == 0

    def test_main_returns_1_on_runtime_error(self, monkeypatch):
        import agent.transports.hermes_tools_mcp_server as m

        class CrashingServer:
            def run(self):
                raise RuntimeError("boom")

        monkeypatch.setattr(m, "_build_server", lambda: CrashingServer())
        rc = m.main([])
        assert rc == 1


import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from tests.tools.test_kanban_tools import reviewer_env as _reviewer_fixture
reviewer_env = _reviewer_fixture


@pytest.fixture
def reviewer_server(reviewer_env, monkeypatch):
    from agent.transports import hermes_tools_mcp_server as endpoint
    from tools import kanban_tools as kt
    from tools.registry import registry
    import model_tools

    schemas = [{'type': 'function', 'function': registry.get_schema(name)} for name in kt.REVIEWER_TOOLS]
    monkeypatch.setattr(model_tools, 'get_tool_definitions', lambda **kw: schemas)
    return endpoint._build_server()


@pytest.mark.parametrize('method', ['prompts/list', 'prompts/get', 'resources/list', 'resources/templates/list',
                                   'resources/read', 'subscriptions/listen', 'resources/subscribe', 'resources/unsubscribe'])
@pytest.mark.parametrize('params', [{}, {'uri': 'fixture://known'}, {'uri': 'fixture://guessed'},
                                    {'filters': {'resource_subscriptions': ['fixture://known']}}, {'filters': []}])
def test_reviewer_protocol_denies_before_sdk_lookup(reviewer_server, method, params):
    from mcp.shared.exceptions import MCPError
    downstream = AsyncMock(side_effect=AssertionError('must not reach handlers/managers/listeners'))
    with pytest.raises(MCPError):
        asyncio.run(reviewer_server.middleware[-1](SimpleNamespace(method=method, params=params), downstream))
    downstream.assert_not_called()
    handlers = reviewer_server._lowlevel_server._request_handlers
    assert 'resources/subscribe' not in handlers and 'resources/unsubscribe' not in handlers
    assert all(name in handlers for name in ['prompts/list', 'prompts/get', 'resources/list', 'resources/templates/list', 'resources/read', 'subscriptions/listen'])


def test_reviewer_capabilities_remain_truthful(reviewer_server):
    caps = reviewer_server._lowlevel_server.get_capabilities()
    assert caps.prompts is not None and caps.resources is not None


def test_reviewer_mcp_rejects_created_cards_before_dispatch(reviewer_server, monkeypatch):
    from tools import kanban_tools as kt
    from mcp.shared.exceptions import MCPError
    from unittest.mock import Mock
    validation = Mock(side_effect=AssertionError('must not read Store'))
    monkeypatch.setattr(kt, 'validate_reviewer_binding', validation)
    downstream = AsyncMock()
    ctx = SimpleNamespace(method='tools/call', params={'name': 'kanban_complete', 'arguments': {'summary': 'Review passed', 'created_cards': ['foreign']}})
    with pytest.raises(MCPError):
        asyncio.run(reviewer_server.middleware[-1](ctx, downstream))
    validation.assert_not_called()
    downstream.assert_not_called()


def test_reviewer_real_stdio_identity_and_resource_refusal(reviewer_env, tmp_path):
    """Actual SDK/stdio/server; synthetic credential-free profile, no Codex/model."""
    import os
    import selectors
    import subprocess
    import sys
    from pathlib import Path
    from dataclasses import asdict
    from tools.environments.local import hermes_subprocess_env
    from tools.kanban_tools import REVIEWER_TOOLS

    marker = tmp_path / 'provider-called'
    # This adds a provider only inside the disposable test child. Reaching it
    # would leave a deterministic receipt, so denial isn't an unknown-URI error.
    script = """from pathlib import Path
from agent.transports.hermes_tools_mcp_server import _build_server
server = _build_server()
@server.resource('fixture://known')
def private_resource():
    Path(__import__('sys').argv[1]).write_text('provider was called')
    return 'PRIVATE_SYNTHETIC_CONTENT'
server.run()
"""
    env = hermes_subprocess_env(inherit_credentials=False)
    for key in ('HERMES_HOME', 'HERMES_PROFILE', 'HERMES_SESSION_ID', 'HERMES_KANBAN_HOME',
                'HERMES_KANBAN_DB', 'HERMES_KANBAN_BOARD', 'HERMES_KANBAN_TASK',
                'HERMES_KANBAN_RUN_ID', 'HERMES_KANBAN_CLAIM_LOCK'):
        env[key] = os.environ[key]
    env['HERMES_QUIET'] = '1'
    from agent.delegation_context import DELEGATED_CHILD_ENV_MARKER
    env[DELEGATED_CHILD_ENV_MARKER] = ''
    stderr = tmp_path / 'mcp-stderr.log'
    with stderr.open('w') as errors:
        proc = subprocess.Popen([sys.executable, '-c', script, str(marker)],
            cwd=Path(__file__).resolve().parents[3], env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=errors, text=True, bufsize=1)
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        serial = 0
        def rpc(method, params):
            nonlocal serial
            serial += 1
            proc.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': serial, 'method': method, 'params': params}) + '\n')
            proc.stdin.flush()
            while True:
                assert selector.select(timeout=15), stderr.read_text()
                line = proc.stdout.readline()
                assert line, stderr.read_text()
                message = json.loads(line)
                if message.get('id') == serial:
                    return message
        try:
            init = rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                                     'clientInfo': {'name': 'disposable-review-test', 'version': '1'}})
            assert 'result' in init, init
            proc.stdin.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) + '\n')
            proc.stdin.flush()
            catalog = rpc('tools/list', {})
            assert {tool['name'] for tool in catalog['result']['tools']} == set(REVIEWER_TOOLS)
            heartbeat = rpc('tools/call', {'name': 'kanban_heartbeat', 'arguments': {'note': 'Reviewer host preflight'},
                                         '_meta': {'hermes/reviewerPreflight': True}})
            payload = json.loads(heartbeat['result']['content'][0]['text'])
            assert payload.get('ok') is True, payload
            assert payload['reviewer_identity'] == asdict(reviewer_env)
            normal = rpc('tools/call', {'name': 'kanban_heartbeat', 'arguments': {}})
            assert 'reviewer_identity' not in json.loads(normal['result']['content'][0]['text'])
            for method, params in [('resources/list', {}), ('resources/templates/list', {}),
                ('resources/read', {'uri': 'fixture://known'}), ('resources/read', {'uri': 'fixture://guessed'}),
                ('prompts/list', {}), ('prompts/get', {'name': 'known'}),
                ('subscriptions/listen', {'filters': {'resource_subscriptions': ['fixture://known']}}),
                ('resources/subscribe', {'uri': 'fixture://known'}), ('resources/unsubscribe', {'uri': 'fixture://known'})]:
                reply = rpc(method, params)
                assert reply.get('error', {}).get('code') == -32600, reply
                assert 'PRIVATE_SYNTHETIC_CONTENT' not in json.dumps(reply)
            assert not marker.exists()
        finally:
            proc.stdin.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=5)
            selector.close()
            proc.stdout.close()
        assert proc.poll() is not None


@pytest.mark.platforms('macos', 'linux')
def test_actual_codex_core_resource_tools_refuse_registered_and_guessed_uris(reviewer_env, tmp_path):
    """Actual Core ToolRouter, synthetic loopback Responses API, real SDK denial.

    This isolates the Core boundary; it does not qualify the Session gate or a
    real model. No production credentials or Provider endpoint are used.
    """
    import os
    import shutil
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path
    from agent.transports.codex_app_server import CodexAppServerClient

    binary = shutil.which('codex')
    if binary is None:
        pytest.skip('actual Core qualification requires Codex')
    calls = [('list_mcp_resources', {}), ('list_mcp_resource_templates', {}),
             ('read_mcp_resource', {'server': 'hermes-tools', 'uri': 'fixture://known'}),
             ('read_mcp_resource', {'server': 'hermes-tools', 'uri': 'fixture://guessed'})]
    requests = []
    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            data = json.dumps({'data': []}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append(request)
            step = len(requests) - 1
            rid = 'fixture-response-' + str(step)
            if step < len(calls):
                name, args = calls[step]
                item = {'id': 'fc-' + str(step), 'type': 'function_call', 'name': name,
                        'call_id': 'call-' + str(step), 'arguments': json.dumps(args), 'status': 'completed'}
            else:
                item = {'id': 'message-final', 'type': 'message', 'role': 'assistant', 'status': 'completed',
                        'content': [{'type': 'output_text', 'text': 'Offline boundary verification complete', 'annotations': []}]}
            events = [
                {'type': 'response.created', 'response': {'id': rid, 'object': 'response', 'status': 'in_progress', 'output': []}},
                {'type': 'response.output_item.added', 'output_index': 0, 'item': item},
                {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
                {'type': 'response.completed', 'response': {'id': rid, 'object': 'response', 'status': 'completed',
                    'output': [item], 'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}},
            ]
            body = ''.join('data: ' + json.dumps(event) + '\n\n' for event in events).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
    worker = threading.Thread(target=httpd.serve_forever, daemon=True)
    worker.start()
    audit = tmp_path / 'rpc-audit.jsonl'
    provider_marker = tmp_path / 'resource-provider-called'
    code = """import json, sys
from pathlib import Path
from agent.transports.hermes_tools_mcp_server import _build_server
server = _build_server()
async def audit(ctx, call_next):
    with Path(sys.argv[1]).open('a') as output:
        output.write(json.dumps({'method':ctx.method,'params':dict(ctx.params or {})})+'\\n')
    return await call_next(ctx)
server.middleware.insert(2, audit)
@server.resource('fixture://known')
def known_resource():
    Path(sys.argv[2]).write_text('provider called')
    return 'PRIVATE_SYNTHETIC_CONTENT'
server.run()
"""
    codex_home = tmp_path / 'core-codex-home'
    codex_home.mkdir()
    env = {key: os.environ[key] for key in ('HERMES_HOME', 'HERMES_PROFILE', 'HERMES_SESSION_ID',
        'HERMES_KANBAN_HOME', 'HERMES_KANBAN_DB', 'HERMES_KANBAN_BOARD', 'HERMES_KANBAN_TASK',
        'HERMES_KANBAN_RUN_ID', 'HERMES_KANBAN_CLAIM_LOCK')}
    from agent.delegation_context import DELEGATED_CHILD_ENV_MARKER
    env[DELEGATED_CHILD_ENV_MARKER] = ''
    lines = ['model = "offline-model"', 'model_provider = "offline"', '[features]', 'apps = false',
        '[analytics]', 'enabled = false', '[model_providers.offline]', 'name = "Synthetic fixture"',
        'base_url = ' + json.dumps(f'http://127.0.0.1:{httpd.server_port}/v1'),
        'wire_api = "responses"', 'requires_openai_auth = false', '[mcp_servers.hermes-tools]',
        'command = ' + json.dumps(sys.executable),
        'args = ' + json.dumps(['-c', code, str(audit), str(provider_marker)]),
        'cwd = ' + json.dumps(str(Path(__file__).resolve().parents[3])), '[mcp_servers.hermes-tools.env]']
    lines.extend(key + ' = ' + json.dumps(value) for key, value in env.items())
    (codex_home / 'config.toml').write_text('\n'.join(lines))
    client = None
    try:
        client = CodexAppServerClient(codex_bin=binary, codex_home=str(codex_home))
        client.initialize(capabilities={'experimentalApi': True})
        started = client.request('thread/start', {'cwd': str(tmp_path), 'sandbox': 'read-only',
            'model': 'offline-model', 'modelProvider': 'offline', 'config': {'features.apps': False}})
        tid = started['thread']['id']
        turn = client.request('turn/start', {'threadId': tid, 'input': [{'type': 'text', 'text': 'Run the offline boundary fixture'}],
                                           'sandboxPolicy': {'type': 'readOnly', 'networkAccess': False}})
        import time
        deadline = time.monotonic() + 45
        completed = None
        while time.monotonic() < deadline:
            note = client.take_notification(timeout=1)
            if note and note.get('method') == 'turn/completed':
                completed = note
                break
        assert completed is not None, client.stderr_tail(20)
        assert completed['params']['turn']['id'] == turn['turn']['id']
        assert len(requests) == 5, (requests, completed)
        names = {tool.get('name') or tool.get('function', {}).get('name') for tool in requests[0].get('tools', [])}
        assert {name for name, _ in calls} <= names
        records = [json.loads(line) for line in audit.read_text().splitlines()]
        assert any(r['method'] == 'resources/list' for r in records)
        assert any(r['method'] == 'resources/templates/list' for r in records)
        reads = {r['params'].get('uri') for r in records if r['method'] == 'resources/read'}
        assert {'fixture://known', 'fixture://guessed'} <= reads
        assert not provider_marker.exists()
        assert 'PRIVATE_SYNTHETIC_CONTENT' not in json.dumps(requests)
    finally:
        if client is not None:
            client.close()
        httpd.shutdown()
        worker.join(timeout=5)
        httpd.server_close()
    assert not worker.is_alive()
