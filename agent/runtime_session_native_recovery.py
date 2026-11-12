"""Private idempotent sidecar operations through the existing SessionDB owner.

Unlike transcript mutations these never enter the worker's JSON retry journal
or receipt projections. A lost reply is UNKNOWN; Core then withholds use RPC.
"""


class RuntimeNativeRecoveryMixin:
    def native_response_use(self, profile, action, payload, *, deadline):
        import time

        from agent.runtime_session_store import WorkerPersistenceError
        remaining = min(0.5, deadline - time.monotonic())
        if remaining <= 0 or not self.lock.acquire(timeout=remaining):
            raise TimeoutError('native recovery owner deadline')
        try:
            if self.failure or self.journal['pending']:
                raise WorkerPersistenceError('native recovery owner unavailable')
            return self.rpc('worker.persist', **self.scope, sequence=0,
                            operation='native.recovery', _deadline=deadline,
                            payload={'profile': profile, 'action': action,
                                     'value': payload, 'deadline': deadline})
        finally:
            self.lock.release()
