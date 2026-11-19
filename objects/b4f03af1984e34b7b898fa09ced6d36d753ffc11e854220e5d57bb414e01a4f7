"""Disposable crash-boundary producer; no model, credentials or production paths."""
import json
import os
import sys
import time
from pathlib import Path


def pause(name):
    print(json.dumps({'boundary': name}), flush=True)
    assert sys.stdin.readline().strip() == 'continue'


def main():
    from agent.native_capabilities import commit_capability
    from agent.native_selector import install_selector, select
    from agent.native_turn import (
        PluginHost,
        TurnSource,
        consume_ingress,
        current_invocation,
        current_turn,
        digest,
        issue_ingress,
    )
    from agent.response_gate import TurnGate, register_gate
    from hermes_state import SessionDB
    from tests.agent.test_native_isolated_capabilities import _Channel, bundle

    profile = str(Path(sys.argv[1]).resolve())
    os.environ['HERMES_HOME'] = profile
    mode = sys.argv[2]
    with SessionDB(Path(profile) / 'state.db') as db:
        if mode == 'read':
            print(json.dumps(db.native_response_use(profile, 'read', {'project_id': 'cloud'},
                             deadline=time.monotonic() + 1)), flush=True)
            return
        install_selector(profile, bundle(profile))
        host = PluginHost('fixture', profile)
        ingress = issue_ingress(TurnSource.TOP_LEVEL_HUMAN, actor='fixture', conversation='c', session='old')
        state = TurnGate(consume_ingress(ingress, 'old'), ('fixture',),
                         selection=select(profile, 'Check Cloud Test status'), recovery_store=db)
        token = current_turn.set(state)
        release = register_gate(host, lambda evidence: True)
        try:
            channel = _Channel(host)
            host._channels.append(channel)
            invocation = host.invocation('query')
            call = current_invocation.set(invocation)
            try:
                evidence = host.record_result(invocation, control_request_id='request', context_revision='c',
                    mission_revision='m', query_result_digest='q', output='verified', result_ref='result',
                    control_epoch='control1', channel_ref='channel1', project_id='cloud')
            finally:
                current_invocation.reset(call)
            state.closed = True
            cap = commit_capability(host, evidence, state, {'output_commit_status': 'OUTPUT_COMMITTED',
                'gate_decision': 'OUTPUT_GATE_PASSED', 'final_output_digest': digest(evidence.output)})
            write = db._execute_write
            def boundary_write(fn, **kw):
                if mode == 'before_commit':
                    def before(conn):
                        result = fn(conn)
                        pause('before_commit')
                        return result
                    return write(before, **kw)
                result = write(fn, **kw)
                pause('after_commit')
                return result
            db._execute_write = boundary_write
            def remote(*args, **kw):
                print(json.dumps({'unexpected_rpc': True}), flush=True)
                return {'state': 'UNKNOWN'}
            channel._call = remote
            print(json.dumps({'generation': host.generation, 'pid': os.getpid()}), flush=True)
            cap.response_used()
        finally:
            release()
            current_turn.reset(token)
            host.close()


if __name__ == '__main__':
    main()
