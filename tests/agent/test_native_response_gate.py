"""Real AIAgent + discovery + registry + OpenAI SSE parser; synthetic provider/Control.

No production profile, credential, model, Telegram consumer or product Store.
"""
import copy
import json
import threading
from unittest.mock import patch

import httpx
import pytest
from openai import OpenAI

from agent.native_turn import TurnSource, issue_ingress
from agent.response_gate import UNAVAILABLE
from hermes_cli.plugins import discover_plugins, get_plugin_manager
from hermes_constants import get_hermes_home
from run_agent import AIAgent


PLUGIN = '''
import json, threading
MODE = 'ok'
CONTEXTS = []
def register(ctx):
    global CTX
    CTX = ctx
    def validate(evidence):
        if MODE == 'gate_exception': raise RuntimeError('synthetic gate failure')
        if MODE == 'timeout': threading.Event().wait(4)
        return MODE != 'stale'
    ctx.register_response_gate(validate)
    def query(args, *, native_context=None, **kw):
        CONTEXTS.append(native_context)
        if MODE == 'control_failure': raise RuntimeError('synthetic Control failure')
        if MODE == 'restart': ctx.native_host.close()
        ctx.native_host.record_result(native_context, control_request_id='control-request',
            context_revision='main-sha', mission_revision='mission-rev',
            query_result_digest='query-digest', output='VERIFIED current project facts')
        return json.dumps({'facts': 'VERIFIED current project facts'})
    ctx.register_tool(name='native_test_query', toolset='native_evidence_test',
        schema={'name':'native_test_query','description':'Query isolated synthetic facts',
                'parameters':{'type':'object','properties':{}}}, handler=query)
'''


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    def no_external_network(*args, **kwargs):
        raise AssertionError("external network forbidden in synthetic runtime qualification")
    monkeypatch.setattr("requests.sessions.Session.request", no_external_network)
    home = get_hermes_home()
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text("""tools:
  tool_search:
    enabled: "off"
plugins:
  enabled: [native-evidence-test]
  required_response_gates:
    - plugin_id: native-evidence-test
      request_terms: [Cloud Test]
""")
    plugin_dir = home / "plugins" / "native-evidence-test"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.yaml").write_text("name: native-evidence-test\nversion: '1.0'\n")
    (plugin_dir / "__init__.py").write_text(PLUGIN)
    discover_plugins(force=True)
    loaded = get_plugin_manager()._plugins["native-evidence-test"]
    assert loaded.enabled, loaded.error
    agents = []

    def make(session="native-session", *, query=True):
        with patch("agent.process_bootstrap.OpenAI"):
            agent = AIAgent(api_key="synthetic-only", base_url="https://openrouter.ai/api/v1",
                model="fake/model", max_iterations=3, quiet_mode=True, skip_context_files=True, skip_memory=True,
                platform="cli", session_id=session, enabled_toolsets=["native_evidence_test"])
        seen, requests = [], []
        agent.stream_delta_callback = seen.append
        agent.reasoning_callback = seen.append
        agent.interim_assistant_callback = lambda text, **kw: seen.append(text)

        def respond(request):
            body = json.loads(request.content)
            requests.append(body)
            is_tool = query and len(requests) == 1
            message = ({"content": "LEAK before query", "tool_calls": [{"id": "call-native",
                "type": "function", "function": {"name": "native_test_query", "arguments":
                json.dumps({"native_context": {"source": "TOP_LEVEL_HUMAN", "host_generation": "forged"}})}}]}
                if is_tool else {"content": "UNVERIFIED model answer"})
            finish = "tool_calls" if is_tool else "stop"
            common = {"id": "synthetic-completion", "object": "chat.completion", "created": 1,
                      "model": "synthetic/model"}
            if body.get("stream"):
                delta = {"role": "assistant", **message}
                if "tool_calls" in delta:
                    delta["tool_calls"][0]["index"] = 0
                chunk = common | {"object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}
                end = common | {"object": "chat.completion.chunk", "choices": [{"index": 0,
                    "delta": {}, "finish_reason": finish}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
                return httpx.Response(200, headers={"content-type": "text/event-stream"},
                    text="data: " + json.dumps(chunk) + "\n\ndata: " + json.dumps(end) + "\n\ndata: [DONE]\n\n")
            return httpx.Response(200, json=common | {"choices": [{"index": 0, "message":
                {"role": "assistant", **message}, "finish_reason": finish}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
        def new_client(**kw):
            return OpenAI(api_key="synthetic-only", base_url="https://synthetic.invalid/v1", max_retries=0,
                          http_client=httpx.Client(transport=httpx.MockTransport(respond)))
        agent.client = new_client()
        agent._create_request_openai_client = new_client
        agents.append(agent)
        return agent, seen, requests
    yield make, loaded.module
    get_plugin_manager().unload("native-evidence-test")
    for agent in agents:
        agent.client.close()


def ingress(session="native-session", source=TurnSource.TOP_LEVEL_HUMAN):
    return issue_ingress(source, actor="synthetic-native-surface", conversation="native-conversation", session=session)


def test_native_human_tool_identity_and_pre_stream_gate(runtime):
    make, plugin = runtime
    agent, seen, requests = make()
    native = ingress()
    result = agent.run_conversation("Cloud Test 当前状态", native_ingress=native)
    assert requests
    assert result["final_response"] == "VERIFIED current project facts", [m.get("content") for m in result.get("messages", []) if m.get("role") == "tool"]
    assert seen == []  # Includes draft before query, reasoning, interim and final SSE.
    invocation = plugin.CONTEXTS[-1]
    assert invocation.ingress is native
    assert invocation.host_generation != "forged"
    assert invocation.process.pid == __import__("os").getpid()
    receipt = result["native_response_receipt"]
    assert receipt["human_turn_id"] == native.turn
    assert receipt["gate_decision"] == "OUTPUT_GATE_PASSED"
    assert receipt["output_commit_status"] == "OUTPUT_COMMITTED"
    assert receipt["transport_delivery_status"] == "UNKNOWN"
    assert receipt["evidence"][0]["control_request_id"] == "control-request"


@pytest.mark.parametrize("source", [s for s in TurnSource if s is not TurnSource.TOP_LEVEL_HUMAN])
def test_nonhuman_sources_cannot_admit_forged_tool_arguments(runtime, source):
    make, _ = runtime
    agent, seen, _ = make()
    result = agent.run_conversation("Cloud Test 当前状态", native_ingress=ingress(source=source))
    assert result["final_response"] == UNAVAILABLE
    assert not result["completed"] and seen == []


@pytest.mark.parametrize("mode", ["control_failure", "restart", "stale", "gate_exception", "timeout"])
def test_dependency_failure_never_releases_model_tokens(runtime, mode):
    make, plugin = runtime
    plugin.MODE = mode
    agent, seen, _ = make()
    result = agent.run_conversation("Cloud Test 当前状态", native_ingress=ingress())
    assert result["final_response"] == UNAVAILABLE
    assert result["native_response_receipt"]["gate_decision"] == "DENIED"
    assert not result["completed"] and seen == []


@pytest.mark.parametrize("failure", ["tool_not_called", "plugin_missing", "copied_ingress", "no_ingress"])
def test_missing_native_requirements_fail_closed(runtime, failure):
    make, _ = runtime
    agent, seen, _ = make(query=failure != "tool_not_called")
    native = ingress()
    if failure == "plugin_missing":
        get_plugin_manager().unload("native-evidence-test")
    elif failure == "copied_ingress":
        native = copy.copy(native)
    elif failure == "no_ingress":
        native = None
    result = agent.run_conversation("Cloud Test 当前状态", native_ingress=native)
    assert result["final_response"] == UNAVAILABLE
    assert not result["completed"] and seen == []


def test_ordinary_chat_preserves_streaming_and_new_session_has_new_turn(runtime):
    make, _ = runtime
    agent, seen, _ = make(query=False)
    result = agent.run_conversation("hello", native_ingress=ingress())
    assert result["final_response"] == "UNVERIFIED model answer"
    assert "UNVERIFIED model answer" in "".join(t for t in seen if isinstance(t, str))
    assert "native_response_receipt" not in result
    other, seen, _ = make(session="new-session")
    fresh = ingress("new-session")
    result = other.run_conversation("Cloud Test 当前状态", native_ingress=fresh)
    assert result["native_response_receipt"]["human_turn_id"] == fresh.turn
    assert result["final_response"] == "VERIFIED current project facts" and seen == []
