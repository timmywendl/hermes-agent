"""Separate-process Control test peer; imports no product runtime or Host object."""
import json
import socket
import sys

from agent.native_control_verifier import NativeControlVerifier
from agent.native_wire import receive, send
from hermes_platform.native_peer import process_snapshot


def serve(path, approved, profile):
    from agent.native_bootstrap import PinnedBootstrapProvider
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(path)
        listener.listen()
        print(json.dumps(process_snapshot(__import__('os').getpid())), flush=True)
        while True:
            connection, _ = listener.accept()
            try:
                approval = PinnedBootstrapProvider(approved).verify(approved)
                verifier = NativeControlVerifier(connection, approval=approval,
                                                 plugin_id='fixture', profile=profile)
                while True:
                    body, payload = verifier.receive_call()
                    if payload.get('payload', {}).get('fixture_bad_result'):
                        send(connection, {'call_nonce': body['nonce'], 'payload_digest': body['payload_digest'],
                                          'control_epoch':approval.control_epoch,
                                          'result': {'output': 'different'}, 'result_digest': 'wrong'})
                    else:
                        # Synthetic peer only; product responses require Control-owned permit.
                        result={'turn':body['invocation']['ingress']['turn'],'pid':__import__('os').getpid(),'value':payload}
                        from agent.native_wire import canonical
                        import hashlib
                        send(connection,{'call_nonce':body['nonce'],'payload_digest':body['payload_digest'],
                            'control_epoch':approval.control_epoch,'result':result,
                            'result_digest':hashlib.sha256(canonical(result)).hexdigest()})
            except (PermissionError, OSError, EOFError, ValueError, KeyError, TypeError):
                connection.close()


if __name__ == '__main__':
    serve(sys.argv[1], json.loads(sys.argv[2]), sys.argv[3])
