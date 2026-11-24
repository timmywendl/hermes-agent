"""A failed same-thread projection cannot abort canonical event publication."""
import pytest

from gateway.session_events import SessionEvents


@pytest.mark.parametrize('healthy', [False, True])
def test_failed_observer_isolated_and_not_counted_as_delivery(healthy, caplog):
    stream = SessionEvents()
    received = []
    def broken(frame):
        raise RuntimeError('viewer detached')
    stream.observers.add(broken)
    if healthy:
        stream.observers.add(lambda frame: received.append(frame))
    assert stream.publish('session', {'text': 'committed'}) is healthy
    assert bool(received) is healthy
    replay = stream.since(stream.epoch, 0)
    assert replay['count'] == 1
    assert replay['events'][0]['payload']['text'] == 'committed'
    assert 'observer' in caplog.text.lower()


def test_fanout_failure_after_replay_still_notifies_observer(monkeypatch):
    stream = SessionEvents()
    received = []
    stream.observers.add(received.append)
    def fail(*_args, **_kwargs):
        raise OSError('fixture fanout failure')
    monkeypatch.setattr(stream.fanout, 'write', fail)
    with pytest.raises(OSError, match='fixture fanout failure'):
        stream.publish('session', {'text': 'committed'})
    assert len(received) == 1 and received[0]['params']['payload']['text'] == 'committed'
    assert stream.since(stream.epoch, 0)['count'] == 1
