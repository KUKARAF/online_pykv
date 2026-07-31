"""Cross-process serialization test for KVClient._renew_session.

Uses real separate processes (not threads) because flock semantics need
genuinely distinct file descriptors to prove anything: threads within one
process share the fd table and wouldn't exercise the cross-process lock at
all.
"""

import multiprocessing
import os
import tempfile
import time

from online_pykv.client import KVClient, _save_session_token


def _worker(config_home, call_counter, barrier, result_queue):
    os.environ["XDG_CONFIG_HOME"] = config_home

    def fake_on_auth_error():
        with call_counter.get_lock():
            call_counter.value += 1
        time.sleep(1.0)  # simulate a human clicking "approve"
        _save_session_token("tok-shared")
        return "tok-shared"

    barrier.wait()  # start both processes as close together as possible
    client = KVClient(on_auth_error=fake_on_auth_error, request_label="test")
    client._renew_session()
    result_queue.put(client._session_token)


def test_renew_session_serializes_across_processes():
    ctx = multiprocessing.get_context("fork")
    with tempfile.TemporaryDirectory() as tmp:
        call_counter = ctx.Value("i", 0)
        barrier = ctx.Barrier(2)
        result_queue = ctx.Queue()

        procs = [
            ctx.Process(target=_worker, args=(tmp, call_counter, barrier, result_queue))
            for _ in range(2)
        ]

        start = time.monotonic()
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=15)
        elapsed = time.monotonic() - start

        assert all(p.exitcode == 0 for p in procs), [p.exitcode for p in procs]

        # The whole point of the lock: only ONE process should ever have
        # actually driven an approval, even though both discovered a
        # missing token at (near) the same instant.
        assert call_counter.value == 1, (
            f"expected exactly one on_auth_error call across both processes, "
            f"got {call_counter.value} (lock failed to serialize them)"
        )

        tokens = {result_queue.get(timeout=5) for _ in range(2)}
        assert tokens == {"tok-shared"}, tokens

        # One ~1s auth call plus lock overhead — not two processes each
        # independently blocking for their own ~1s (which would still pass
        # the call_counter assertion above but points at a different,
        # worse bug: both would still request a session, just sequentially).
        assert elapsed < 5, f"took {elapsed:.2f}s — lock may be serializing without adoption"
