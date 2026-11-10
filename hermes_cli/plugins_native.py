"""Additive native turn/required response surface for trusted Python plugins."""
from functools import cached_property, wraps
import inspect

from agent.native_turn import PluginHost, current_invocation
from hermes_cli.plugins_loader import _serialized_replacement


class NativePluginContextMixin:
    def _abandon_load(self) -> None:
        """Mark this load as timed out; every later ``register_*``/``subscribe``/``on_unload`` is ignored."""
        self._load_abandoned = True

    @cached_property
    def native_host(self):
        host = PluginHost(self.plugin_id, self._manager.scope_key)
        self._track("native_host", host.instance, host.close)
        return host

    @_serialized_replacement
    def register_response_gate(self, validate, *, on_commit=None):
        """Require current Control evidence when the operator's profile scope matches.

        ``validate(evidence) -> True`` rechecks freshness/revision with Control.
        Exceptions, a non-True result or the native two-second deadline deny.
        Scope is declared in ``plugins.required_response_gates`` so missing
        plugins cannot silently remove the requirement.
        """
        from agent.response_gate import register_gate
        release = register_gate(self.native_host, validate, on_commit=on_commit)
        return self._track("response_gate", self.plugin_id, release)

    def native_turn_attestation(self):
        """Attest the active native turn for a trusted hook's Control intake.

        Not a model tool. The verifier separately checks source and kernel peer.
        """
        host = self.native_host
        invocation = host.invocation("__native_turn__")
        if invocation is None:
            raise PermissionError("no native turn")
        token = current_invocation.set(invocation)
        try:
            return host.attest(invocation)
        finally:
            current_invocation.reset(token)

    def _bind_native_handler(self, name, handler, *, is_async=False):
        # Only opted-in handlers get native_context; existing narrow signatures
        # stay compatible. Model args remain a separate untrusted dictionary.
        try:
            accepts = "native_context" in inspect.signature(handler).parameters
        except (TypeError, ValueError):
            # Opaque legacy callables remain usable, but never receive a
            # capability without an explicit introspectable opt-in.
            return handler
        if not accepts:
            return handler
        host = self.native_host

        @wraps(handler)
        def wrapped(args, **kwargs):
            invocation = host.invocation(name)
            token = current_invocation.set(invocation)
            try:
                kwargs["native_context"] = invocation
                return handler(args, **kwargs)
            finally:
                current_invocation.reset(token)

        @wraps(handler)
        async def async_wrapped(args, **kwargs):
            invocation = host.invocation(name)
            token = current_invocation.set(invocation)
            try:
                kwargs["native_context"] = invocation
                return await handler(args, **kwargs)
            finally:
                current_invocation.reset(token)
        return async_wrapped if is_async else wrapped
