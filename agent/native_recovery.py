"""Core-only durable selector lifecycle. Selectors grant no authority."""
import time

UNKNOWN = {'state': 'UNKNOWN'}


def recovery_operation(state, profile, action, payload, deadline):
    store = state.recovery_store
    if store is None or not callable(getattr(store, 'native_response_use', None)):
        raise PermissionError('native recovery owner unavailable')
    result = store.native_response_use(profile, action, payload, deadline=deadline)
    if time.monotonic() >= deadline or not isinstance(result, dict):
        raise TimeoutError('native recovery outcome unknown')
    return result


def settle(state, profile, project_id, request_id, receipt, deadline):
    if not isinstance(receipt, dict):
        return
    # NativeControlChannel envelopes retain their existing wire shape.
    if receipt.get('status') == 'OK':
        receipt = receipt.get('result')
    if (isinstance(receipt, dict) and receipt.get('request_id') == request_id
            and receipt.get('request_state') == 'COMPLETED_READ_ONLY'):
        result = recovery_operation(state, profile, 'clear',
                                    {'project_id': project_id, 'request_id': request_id}, deadline)
        if result != {'state': 'CLEARED'}:
            raise PermissionError('native recovery cleanup unknown')


def persist(state, evidence, deadline):
    invocation = evidence.invocation
    return recovery_operation(state, invocation.ingress.profile, 'persist', {
        'project_id': evidence.project_id,
        'request_id': evidence.control_request_id,
        'result_ref': evidence.result_ref,
        'projection_digest': evidence.projection_digest,
        'original_session_id': invocation.ingress.session,
        'original_turn_id': invocation.ingress.turn,
        'original_control_epoch': evidence.control_epoch,
        'original_channel_ref': evidence.channel_ref,
        'original_host_generation': invocation.host_generation,
    }, deadline)
