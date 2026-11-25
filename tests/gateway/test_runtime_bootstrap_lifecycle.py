"""Live runtime HTTP lifecycle boundaries, with no provider inference."""
import asyncio
import json

import pytest
from websockets.asyncio.client import connect


@pytest.mark.asyncio
async def test_no_cron_never_hot_serves_another_profile(tmp_path):
    from types import SimpleNamespace
    from gateway.run_runtime import serve_profile_runtime

    with pytest.raises(RuntimeError, match="cannot hot-serve"):
        await serve_profile_runtime(SimpleNamespace(_no_cron=True), "other", tmp_path / "other")


@pytest.mark.asyncio
async def test_no_cron_bootstrap_creates_only_noncron_housekeeping(monkeypatch):
    from types import SimpleNamespace
    from gateway import run_bootstrap
    from gateway.runtime_ownership import process_ownership

    created = []
    monkeypatch.setattr(process_ownership, "start_writer", lambda thread: created.append(thread))
    runner = SimpleNamespace(_no_cron=True, adapters={})
    stop, provider, ticker, housekeeping = run_bootstrap._start_gateway_start_cron_and_housekeeping(runner)
    assert not stop.is_set()
    assert provider is None and ticker is None and created == [housekeeping]
    assert housekeeping.name == "gateway-housekeeping"
    assert housekeeping._kwargs["cron_enabled"] is False


def test_no_cron_cannot_publish_ready_without_idle_exit(monkeypatch):
    from types import SimpleNamespace
    from gateway import run_bootstrap, run_idle_exit, run_runtime

    monkeypatch.setattr(run_idle_exit, "arm_unmanaged_idle_exit", lambda runner: False)
    monkeypatch.setattr(run_runtime, "publish_gateway_runtime_ready", lambda runner: pytest.fail("published"))
    with pytest.raises(RuntimeError, match="idle-exit watcher"):
        run_bootstrap._start_gateway_publish_ready(SimpleNamespace(), idle_exit=True, no_cron=True)


def test_no_cron_profile_reservation_must_match_served_identity(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from gateway import run_bootstrap, run_runtime
    import hermes_constants

    home = tmp_path.resolve()
    monkeypatch.setattr(hermes_constants, "get_hermes_home", lambda: home)
    monkeypatch.setattr(run_runtime, "reserved_profile_homes", lambda runner: [("default", home)])
    runner = SimpleNamespace(session_runtime_descriptor={"served_profiles": [{"home": str(home), "profile_id": str(home)}]})
    assert run_bootstrap._no_cron_profiles_match(runner)
    runner.session_runtime_descriptor["served_profiles"] = [{"home": str(home)}, {"home": str(home / "other")}]
    assert not run_bootstrap._no_cron_profiles_match(runner)
    runner.session_runtime_descriptor["served_profiles"] = [{"home": str(home / "other")}]
    assert not run_bootstrap._no_cron_profiles_match(runner)


def test_no_cron_host_lock_failure_cannot_fall_through(monkeypatch):
    from gateway import run, host_attach, host_rendezvous

    monkeypatch.setattr(host_attach, "standalone_attach_decision", lambda *args: None)
    for outcome in (host_rendezvous.HostLockOutcome.COULD_NOT_OPEN, host_rendezvous.HostLockOutcome.HELD_BY_OTHER):
        monkeypatch.setattr(host_rendezvous, "claim_host_lock", lambda role, value=outcome: (value, None))
        with pytest.raises(SystemExit, match="exclusive host lock"):
            run._claim_host_gateway_role(strict_no_cron=True)


def test_no_cron_refuses_existing_host_and_ambiguous_config(monkeypatch):
    from types import SimpleNamespace
    from gateway import host_attach, run_bootstrap

    monkeypatch.setattr(host_attach, "host_gateway", lambda **kwargs: None)
    assert run_bootstrap._no_cron_can_start(SimpleNamespace(multiplex_profiles=False))
    assert not run_bootstrap._no_cron_can_start(SimpleNamespace(multiplex_profiles=None))
    assert not run_bootstrap._no_cron_can_start(SimpleNamespace(multiplex_profiles=True))
    monkeypatch.setattr(host_attach, "host_gateway", lambda **kwargs: object())
    assert not run_bootstrap._no_cron_can_start(SimpleNamespace(multiplex_profiles=False))


@pytest.mark.asyncio
async def test_no_cron_bootstrap_refuses_supervision_and_multiplex_before_adapters(monkeypatch):
    from types import SimpleNamespace
    from gateway import run, run_bootstrap
    from gateway import control_socket, restart

    monkeypatch.setattr(control_socket, "_detect_supervisor", lambda: "manual")
    monkeypatch.setattr(restart, "is_gateway_supervisor_process", lambda: False)
    monkeypatch.setattr(run_bootstrap, "_start_gateway_resolve_terminal_cwd", lambda: None)
    monkeypatch.setattr("hermes_cli.resource_limits.apply_nofile_soft_limit", lambda: None)
    monkeypatch.setattr("gateway.code_skew.record_boot_fingerprint", lambda: None)
    monkeypatch.setattr(run_bootstrap, "_start_gateway_early_environment_probe",
                        lambda: pytest.fail("startup continued"))
    monkeypatch.setattr(run, "GatewayRunner", lambda *a: pytest.fail("adapters may start"))
    launch = "a" * 32
    assert not await run_bootstrap.start_gateway(SimpleNamespace(multiplex_profiles=True),
                                                 idle_exit=True, no_cron_launch_id=launch)
    monkeypatch.setattr(restart, "is_gateway_supervisor_process", lambda: True)
    assert not await run_bootstrap.start_gateway(SimpleNamespace(multiplex_profiles=False),
                                                 idle_exit=True, no_cron_launch_id=launch)


@pytest.mark.asyncio
async def test_no_cron_shutdown_awaits_housekeeping_without_cron_provider(monkeypatch):
    import threading
    from types import SimpleNamespace
    from gateway import run, run_bootstrap

    housekeeping = object()
    awaited = []
    async def await_thread(thread, *, timeout):
        awaited.append(thread)
        return True
    async def close_mcp(**kwargs):
        return None
    monkeypatch.setattr(run, "_await_thread_exit", await_thread)
    monkeypatch.setattr(run, "_shutdown_mcp_servers_nonblocking", close_mcp)
    monkeypatch.setattr(run, "_stop_cron_provider", lambda provider: pytest.fail("cron stopped"))
    monkeypatch.setattr(run, "_best_effort", lambda fn: None)
    monkeypatch.setattr(run, "_resolve_gateway_exit_verdict", lambda runner, signal: True)
    stop, watcher_stop = threading.Event(), threading.Event()
    watcher = SimpleNamespace(join=lambda timeout: None)
    assert await run_bootstrap._start_gateway_shutdown_tail(
        SimpleNamespace(), None, stop, None, None, housekeeping, watcher_stop, watcher, [False])
    assert stop.is_set() and watcher_stop.is_set() and awaited == [housekeeping]

    async def stuck_thread(thread, *, timeout):
        return False
    monkeypatch.setattr(run, "_await_thread_exit", stuck_thread)
    assert not await run_bootstrap._start_gateway_shutdown_tail(
        SimpleNamespace(_no_cron=True), None, threading.Event(), None, None, housekeeping,
        threading.Event(), watcher, [False])


def test_no_cron_shutdown_omits_cron_interrupt_and_keeps_other_cleanup(monkeypatch):
    from gateway.run_shutdown import GatewayShutdownMixin

    labels = []
    monkeypatch.setattr(GatewayShutdownMixin, "_quiet_step", lambda label, fn: labels.append(label))
    assert GatewayShutdownMixin._stop_kill_tool_subprocesses("fixture", no_cron=True) == []
    assert any("process_registry.kill_all" in label for label in labels)
    assert any("async interrupt_all" in label for label in labels)
    assert any("cleanup_all_environments" in label for label in labels)
    assert not any("mark_running_jobs_interrupted" in label for label in labels)


@pytest.mark.asyncio
async def test_runtime_preserves_browser_ticket_gate(tmp_path):
    from gateway.config import GatewayConfig
    from gateway.run import GatewayRunner
    from gateway.run_runtime import (initialize_gateway_runtime, start_gateway_runtime_api,
                                     publish_gateway_runtime_ready)
    from gateway.runtime_ownership import process_ownership
    from hermes_constants import get_hermes_home
    from hermes_cli.dashboard_auth import register_provider, clear_providers
    from hermes_cli.dashboard_auth.ws_tickets import mint_ticket
    from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider

    home = get_hermes_home()
    (home / 'config.yaml').write_text('dashboard:\n  public_url: https://gateway.example.test\n')
    register_provider(StubAuthProvider())
    process_ownership.reserve([home])
    runner = GatewayRunner(GatewayConfig())
    try:
        await initialize_gateway_runtime(runner)
        from gateway.control_socket import GatewayControlServer
        runner.session_control_server = GatewayControlServer()
        assert await runner.session_control_server.start()
        await start_gateway_runtime_api(runner)
        assert await runner.start()
        publish_gateway_runtime_ready(runner)
        ticket = mint_ticket(user_id='browser-owner', provider='stub')
        url = runner.session_api.api_origin.replace('http:', 'ws:') + '/api/ws'
        async with connect(url, origin='https://gateway.example.test', subprotocols=[
                'hermes-gateway-v1', 'hermes-gateway-ticket.' + ticket]) as ws:
            await ws.send(json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'gateway.ping'}))
            while True:
                reply = json.loads(await asyncio.wait_for(ws.recv(), 10))
                if reply.get('id') == 1:
                    break
            assert reply['result']['ok'] is True
    finally:
        await runner.stop()
        await runner.session_control_server.stop()
        process_ownership.close()
        clear_providers()


@pytest.mark.asyncio
async def test_drain_withdraws_native_admission_before_listener_close(tmp_path):
    from gateway.config import GatewayConfig, Platform, PlatformConfig
    from gateway.platforms.base import BasePlatformAdapter, SendResult
    from gateway.platforms.event import MessageEvent
    from gateway.run import GatewayRunner
    from gateway.run_runtime import initialize_gateway_runtime, drain_gateway_runtime
    from gateway.runtime_ownership import process_ownership
    from gateway.session import SessionSource
    from hermes_constants import get_hermes_home

    class LocalAdapter(BasePlatformAdapter):
        async def connect(self, *, is_reconnect=False):
            return True

        async def disconnect(self):
            pass

        async def get_chat_info(self, chat_id):
            return {'id': chat_id}

        async def send(self, *args, **kwargs):
            return SendResult(success=True)

    home = get_hermes_home()
    process_ownership.reserve([home])
    runner = GatewayRunner(GatewayConfig())
    adapter = LocalAdapter(PlatformConfig(enabled=True), Platform.TELEGRAM)
    handled = asyncio.Event()

    async def handler(event):
        handled.set()
        return 'local control'

    adapter.set_message_handler(handler)
    runner.adapters[Platform.TELEGRAM] = adapter
    source = SessionSource(platform=Platform.TELEGRAM, chat_id='owned', user_id='owned')
    try:
        await initialize_gateway_runtime(runner)
        first = MessageEvent(text='/status', source=source)
        await adapter.handle_message(first)
        await asyncio.wait_for(handled.wait(), 5)
        assert first._gateway_accepted
        await drain_gateway_runtime(runner)
        assert runner.session_runtime_descriptor['state'] == 'draining'
        later = MessageEvent(text='/status', source=SessionSource(
            platform=Platform.TELEGRAM, chat_id='another-owned-route', user_id='owned'))
        await adapter.handle_message(later)
        assert not later._gateway_accepted
    finally:
        await runner.stop()
        process_ownership.close()
