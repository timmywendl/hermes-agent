"""Separate-process Control test peer; imports no product runtime or Host object."""
import json
import socket
import sys

from agent.native_control_verifier import NativeControlVerifier
from agent.native_wire import receive, send
from hermes_platform.native_peer import process_snapshot


def serve(path, approved, profile):
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(path)
        listener.listen()
        print(json.dumps(process_snapshot(__import__('os').getpid())), flush=True)
        while True:
            connection, _ = listener.accept()
            try:
                verifier = NativeControlVerifier(connection, approved_process=approved,
                                                 plugin_id='fixture', profile=profile)
                while True:
                    body, payload = verifier.receive_call()
                    if payload.get('operation') == 'bad-result':
                        send(connection, {'call_nonce': body['nonce'], 'payload_digest': body['payload_digest'],
                                          'result': {'output': 'different'}, 'result_digest': 'wrong'})
                    else:
                        verifier.reply(body, {'turn': body['invocation']['ingress']['turn'],
                                              'pid': __import__('os').getpid(), 'value': payload})
            except (PermissionError, OSError, EOFError, ValueError, KeyError, TypeError):
                connection.close()


if __name__ == '__main__':
    serve(sys.argv[1], json.loads(sys.argv[2]), sys.argv[3])
