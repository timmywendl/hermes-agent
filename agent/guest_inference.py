"""SDK adapter for a single Owner-selected Responses operation over serial.

The placeholder HTTP request is intercepted inside the Guest process. No socket,
HTTP headers, credentials or destination cross the VM boundary.
"""
import json
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from inspect import signature
from typing import Any, Callable, ParamSpec, TypeVar

import httpx

from agent.guest_serial import MAX_FRAME, SerialError

REQUEST_FIELDS = frozenset({'input', 'instructions', 'tools', 'tool_choice', 'parallel_tool_calls',
                            'reasoning', 'max_output_tokens', 'text'})


def _prompt_only(value, depth=0):
    if depth > 32:
        raise SerialError('inference_input_too_deep')
    if isinstance(value, list):
        if len(value) > 1024:
            raise SerialError('inference_input_too_long')
        for child in value:
            _prompt_only(child, depth + 1)
    elif isinstance(value, dict):
        allowed = {'message', 'input_text', 'output_text', 'summary_text', 'refusal',
                   'function_call', 'function_call_output', 'reasoning', 'compaction'}
        if (set(value) & {'image_url', 'file_id', 'file_url'}
                or value.get('type', 'message') not in allowed):
            raise SerialError('remote_input_forbidden')
        for child in value.values():
            _prompt_only(child, depth + 1)


def validate_request(payload):
    if not isinstance(payload, dict) or set(payload) - REQUEST_FIELDS or 'input' not in payload:
        raise SerialError('unsupported_inference_field')
    if len(json.dumps(payload, allow_nan=False).encode()) > MAX_FRAME // 2:
        raise SerialError('inference_request_too_large')
    tools = payload.get('tools', [])
    if not isinstance(tools, list) or len(tools) > 128 or any(
            not isinstance(tool, dict) or tool.get('type') != 'function' for tool in tools):
        raise SerialError('remote_tools_forbidden')
    choice = payload.get('tool_choice', 'auto')
    if choice not in ('auto', 'none', 'required'):
        names = {tool.get('name') for tool in tools}
        if (not isinstance(choice, dict) or set(choice) != {'type', 'name'}
                or choice['type'] != 'function' or choice['name'] not in names):
            raise SerialError('remote_tools_forbidden')
    _prompt_only(payload['input'])
    return payload


class SerialHTTPTransport(httpx.BaseTransport):
    def __init__(self, channel):
        self.channel = channel

    def handle_request(self, request):
        if (request.method != 'POST' or str(request.url) != 'http://guest.invalid/v1/responses'):
            raise SerialError('guest_http_route_forbidden')
        body = json.loads(request.read())
        # Route/model/cache/session are Owner-selected. They never cross as authority.
        payload = {key: value for key, value in body.items() if key in REQUEST_FIELDS}
        validate_request(payload)
        result = self.channel.call('inference', payload)
        if not isinstance(result, dict) or set(result) != {'events'} or not isinstance(result['events'], list):
            raise SerialError('invalid_inference_reply')
        raw = b''.join(b'data: ' + json.dumps(event, allow_nan=False).encode() + b'\n\n'
                       for event in result['events'])
        if len(raw) > MAX_FRAME:
            raise SerialError('inference_response_too_large')
        return httpx.Response(200, headers={'content-type': 'text/event-stream'}, content=raw)


_SERIAL_INFERENCE: ContextVar[tuple[Any, str, list[Any]] | None] = ContextVar('guest_serial_inference', default=None)


@contextmanager
def bind_serial_inference(channel, model):
    """Bind all existing main/aux SDK clients to this Guest's one channel."""
    state = (channel, model, [])
    token = _SERIAL_INFERENCE.set(state)
    try:
        yield
    finally:
        _SERIAL_INFERENCE.reset(token)
        for client in state[2]:
            client.close()


def serial_openai_client(channel):
    from openai import OpenAI
    client = OpenAI(api_key='guest-transport', base_url='http://guest.invalid/v1', max_retries=0,
                    http_client=httpx.Client(transport=SerialHTTPTransport(channel), trust_env=False))
    state = _SERIAL_INFERENCE.get()
    if state is not None:
        state[2].append(client)
    return client


def serial_auxiliary_client(*, async_mode=False, raw_codex=False):
    """Use mature Responses/compression adapters, bypassing Host client caches."""
    state = _SERIAL_INFERENCE.get()
    if state is None:
        return None
    from agent.auxiliary_client import CodexAuxiliaryClient, AsyncCodexAuxiliaryClient
    if async_mode and raw_codex:
        raise SerialError('guest_async_raw_inference_unsupported')
    client = serial_openai_client(state[0])
    if not raw_codex:
        client = CodexAuxiliaryClient(client, state[1])
        if async_mode:
            client = AsyncCodexAuxiliaryClient(client)
    return client, state[1]


_P = ParamSpec('_P')
_R = TypeVar('_R')


def serial_auxiliary_route(callback: Callable[_P, _R]) -> Callable[_P, _R]:
    """Keep the existing auxiliary API, with a Guest-only fixed transport binding."""
    parameters = signature(callback)
    @wraps(callback)
    def routed(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        if _SERIAL_INFERENCE.get() is None:
            return callback(*args, **kwargs)
        values = parameters.bind(*args, **kwargs).arguments
        return serial_auxiliary_client(async_mode=values.get('async_mode', False),
                                       raw_codex=values.get('raw_codex', False))
    return routed
