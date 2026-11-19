"""Optional response-critical deadline on the existing SessionDB writer."""
import time
from contextlib import contextmanager


@contextmanager
def owner_write_lock(lock, deadline):
    if deadline is None:
        with lock:
            yield
        return
    if not lock.acquire(timeout=max(0, deadline - time.monotonic())):
        raise TimeoutError('SessionDB owner deadline')
    try:
        if time.monotonic() >= deadline:
            raise TimeoutError('SessionDB owner deadline')
        yield
    finally:
        lock.release()


def begin_owner_write(conn, deadline):
    if deadline is None:
        conn.execute('BEGIN IMMEDIATE')
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('SessionDB owner deadline')
    previous = conn.execute('PRAGMA busy_timeout').fetchone()[0]
    conn.execute(f'PRAGMA busy_timeout={min(previous, int(remaining * 1000))}')
    try:
        conn.execute('BEGIN IMMEDIATE')
    finally:
        conn.execute(f'PRAGMA busy_timeout={previous}')
