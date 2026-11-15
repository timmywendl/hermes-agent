"""A managed worker (every Kanban run, opt-in CLI sessions) builds its agent with the session's
provider routing and service tier, as ``hermes chat`` did on main (``HermesCLI._init_agent``):
``provider_routing.ignore``/``data_collection`` and a static ``agent.service_tier`` reach AIAgent."""
import json
import os
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from tests.gateway.test_managed_turn_contract import assignment

ROUTING = {'only': ['Anthropic'], 'ignore': ['DeepInfra'], 'order': ['Anthropic'], 'sort': 'price',
           'require_parameters': True, 'data_collection': 'deny'}


@pytest.mark.parametrize('tier, overrides', [('priority', {'service_tier': 'priority'}), ('', None)])
def test_managed_worker_agent_gets_the_session_provider_routing(tmp_path, monkeypatch, tier, overrides):
    from agent import managed_worker as worker
    frame, _ = assignment(tmp_path, monkeypatch)
    config = json.loads(frame['policy']['config_json'])
    config.update(provider_routing=ROUTING, openrouter={'min_coding_score': 0.8})
    config.setdefault('agent', {})['service_tier'] = tier
    config['model'] = {**config.get('model', {}), 'default': 'gpt-5.5', 'provider': 'openai',
                       'base_url': 'https://api.openai.com/v1'}
    frame = {**frame, 'policy': {**frame['policy'], 'model': 'gpt-5.5', 'config_json': json.dumps(config)}}
    built = {}

    class Agent:
        def __init__(self, **kwargs):
            built.update(kwargs)
            self.session_prompt_tokens = self.session_completion_tokens = 0
        def run_conversation(self, text, **kwargs):
            return {'final_response': 'ok', 'completed': True}

    class Store:
        def __init__(self, *args): pass
        def get_messages_as_conversation(self, sid): return []
        def flush_token_counts(self): pass
        def finish(self): pass
        def close(self): pass

    class Controls:
        def __init__(self, *args):
            self.stopped, self.finish = threading.Event(), threading.Event()
            self.finish.set()
        def approval(self, data): pass
        def clarify(self, questions): pass

    monkeypatch.setattr(worker, 'bind_worker_policy', lambda frame: None)
    monkeypatch.setattr(worker, 'discover_profile_mcp', lambda policy: None)
    monkeypatch.setattr(worker, 'retire_agent', lambda agent: None)
    monkeypatch.setattr(worker, 'WorkerControls', Controls)
    monkeypatch.setattr('agent.runtime_session_store.WorkerRPC', lambda home: lambda *a, **k: {'owner_epoch': 1})
    monkeypatch.setattr('agent.runtime_session_store.RuntimeSessionStore', Store)
    monkeypatch.setattr('tools.process_registry.process_registry.recover_from_checkpoint', lambda: None)
    monkeypatch.setattr('run_agent.AIAgent', Agent)
    monkeypatch.setattr('agent.title_generator.wait_for_title_upgrades', lambda: None)
    worker.execute(frame, SimpleNamespace(send=lambda kind, **payload: None))
    assert {k: built.get(k) for k in ('providers_allowed', 'providers_ignored', 'providers_order', 'provider_sort',
                                      'provider_require_parameters', 'provider_data_collection')} == {
        'providers_allowed': ['Anthropic'], 'providers_ignored': ['DeepInfra'], 'providers_order': ['Anthropic'],
        'provider_sort': 'price', 'provider_require_parameters': True, 'provider_data_collection': 'deny'}
    assert built.get('openrouter_min_coding_score') == 0.8
    assert built.get('service_tier') == (tier or None)
    assert built.get('request_overrides') == overrides


# Bind before importing runtime modules, exactly as the real child does. RPC,
# process bookkeeping and the final Agent are local doubles; route resolution
# and the frozen config readers are real and no model can be contacted.
FROZEN_EXECUTE = '''
import json, socket, sys, threading
from types import SimpleNamespace
from agent import managed_worker as worker
data = json.load(sys.stdin)
frame = data['frame']
worker.bind_worker_policy(frame)
from agent.safe_worker_policy import worker_config_snapshot
from unittest.mock import patch
from pathlib import Path
Path(frame['home'], 'config.yaml').write_text('model: {provider: foreign, base_url: https://foreign.invalid}')
captured = {}
class Agent:
    def __init__(self, **kwargs):
        captured.update({k: kwargs.get(k) for k in ('model', 'provider', 'requested_provider', 'api_mode', 'base_url', 'api_key')})
        self.session_prompt_tokens = self.session_completion_tokens = 0
    def run_conversation(self, *args, **kwargs):
        return {'final_response': 'offline construction only', 'completed': True}
class Store:
    def __init__(self, *args): pass
    def get_messages_as_conversation(self, sid): return []
    def flush_token_counts(self): pass
    def finish(self): pass
    def close(self): pass
class Controls:
    def __init__(self, *args):
        self.stopped, self.finish = threading.Event(), threading.Event()
        self.finish.set()
    def approval(self, data): raise AssertionError('approval is forbidden')
    def clarify(self, questions): raise AssertionError('clarify is forbidden')
def already_bound(value):
    assert worker_config_snapshot() == json.loads(value['policy']['config_json'])
def no_network(*args, **kwargs):
    raise AssertionError('provider/network request is forbidden')
from hermes_cli import runtime_provider
resolve = runtime_provider.resolve_runtime_provider
def corrupted(**kwargs):
    route = resolve(**kwargs)
    key, value = data['corrupt']
    if value is None: route.pop(key, None)
    else: route[key] = value
    return route
from contextlib import ExitStack
with ExitStack() as stack:
    for target, value in (
        ('agent.managed_worker.bind_worker_policy', already_bound),
        ('agent.managed_worker.discover_profile_mcp', lambda p: None),
        ('agent.managed_worker.retire_agent', lambda a: None),
        ('agent.managed_worker.WorkerControls', Controls),
        ('agent.runtime_session_store.WorkerRPC', lambda home: lambda *a, **k: {'owner_epoch': 1}),
        ('agent.runtime_session_store.RuntimeSessionStore', Store),
        ('tools.process_registry.process_registry.recover_from_checkpoint', lambda: None),
        ('run_agent.AIAgent', Agent),
        ('agent.title_generator.wait_for_title_upgrades', lambda: None),
        ('socket.socket.connect', no_network),
    ): stack.enter_context(patch(target, value))
    if data.get('corrupt'):
        stack.enter_context(patch.object(runtime_provider, 'resolve_runtime_provider', corrupted))
    try:
        worker.execute(frame, SimpleNamespace(send=lambda *a, **k: None))
        error = None
    except ValueError as exc:
        error = str(exc)
print(json.dumps({'built': captured, 'error': error}))
'''


def frozen_constructor(tmp_path, monkeypatch, *, codex=True, corrupt=None, missing=False):
    frame, _ = assignment(tmp_path, monkeypatch)
    endpoint = 'http://127.0.0.1:9/v1' if codex else 'https://api.openai.com/v1'
    provider = 'codex_local_access' if codex else 'openai'
    config = json.loads(frame['policy']['config_json'])
    config['model'] = {'default': 'gpt-6-luna', 'provider': provider, 'base_url': endpoint,
                       'api_mode': 'codex_responses' if codex else 'chat_completions'}
    if codex:
        config['model']['openai_runtime'] = 'codex_app_server'
        config['providers'] = {'codex_local_access': {'base_url': endpoint, 'api_mode': 'codex_responses'}}
    if missing:
        config['model'].pop('provider')
    frame = {**frame, 'api_key': 'frozen-fixture-key', 'ignore_user_config': False,
             'policy': {**frame['policy'], 'model': 'gpt-6-luna', 'ignore_user_config': False,
                        'config_json': json.dumps(config)}}
    result = subprocess.run([sys.executable, '-c', FROZEN_EXECUTE],
                            input=json.dumps({'frame': frame, 'corrupt': corrupt}),
                            text=True, capture_output=True, timeout=30, env=dict(os.environ), check=False)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize('codex', [True, False])
def test_execute_uses_frozen_resolved_dialect_without_replacing_authority(tmp_path, monkeypatch, codex):
    result = frozen_constructor(tmp_path, monkeypatch, codex=codex)
    assert result['error'] is None
    assert result['built'] == {
        'model': 'gpt-6-luna', 'provider': 'custom' if codex else 'openai',
        'requested_provider': 'codex_local_access' if codex else None,
        'api_mode': 'codex_app_server' if codex else None,
        'base_url': 'http://127.0.0.1:9/v1' if codex else 'https://api.openai.com/v1',
        'api_key': 'frozen-fixture-key',
    }


@pytest.mark.parametrize('corrupt', [
    ('base_url', 'https://foreign.invalid/v1'), ('provider', 'openrouter'),
    ('requested_provider', 'foreign'), ('requested_provider', None),
    ('source', None), ('source', 'fallback'), ('source', 'custom_provider:foreign'),
    ('api_mode', None), ('api_mode', 'chat_completions'), ('model', 'foreign-model'),
])
def test_execute_rejects_inconsistent_resolver_identity_before_agent(tmp_path, monkeypatch, corrupt):
    result = frozen_constructor(tmp_path, monkeypatch, corrupt=corrupt)
    assert result == {'built': {}, 'error': 'managed_worker_route_mismatch'}


def test_execute_rejects_missing_frozen_route_before_agent(tmp_path, monkeypatch):
    result = frozen_constructor(tmp_path, monkeypatch, missing=True)
    assert result == {'built': {}, 'error': 'managed_worker_route_mismatch'}


def test_execute_never_adopts_a_new_resolver_credential(tmp_path, monkeypatch):
    result = frozen_constructor(tmp_path, monkeypatch, corrupt=('api_key', 'new-unapproved-fixture-key'))
    assert result['error'] is None
    assert result['built']['api_key'] == 'frozen-fixture-key'
