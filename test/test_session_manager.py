"""SessionManager robustness tests (FAKE_IDA workers with fault injection).

These cover what real idalib cannot produce on demand: hung/ignored-signal
closes (ladder escalation), oversized responses (protocol errors), stderr
floods, controlled slow ops (timeout semantics), injected crashes and spawn
failures. Happy-path behavior is covered by the real-IDA suites.

Configuration knobs are monkeypatched on the session module (they are read at
call time), fault injection flows through the FAKE_IDA_* environment into the
worker processes.
"""
import asyncio
import json
import os
import signal
import time

import pytest

from headless_ida_mcp_server import session as session_mod
from headless_ida_mcp_server.session import SessionManager

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = os.path.join(REPO_ROOT, "test", "samples", "tiny", "libz.so")
BINARY2 = os.path.join(REPO_ROOT, "test", "samples", "tiny", "libbz2.so")

assert os.path.exists(BINARY) and os.path.exists(BINARY2), "sample binaries missing"


@pytest.fixture
async def manager():
    """Fresh manager per test; guaranteed teardown so no test can leak a live
    worker process into the next one (shutdown_all is idempotent)."""
    m = SessionManager()
    yield m
    try:
        await asyncio.wait_for(m.shutdown_all(), timeout=60)
    except asyncio.TimeoutError:
        pytest.fail("shutdown_all timed out during fixture teardown")


@pytest.fixture(autouse=True)
def fake_ida(monkeypatch):
    monkeypatch.setenv("FAKE_IDA", "1")


def rec_path(tmp_path, name="rec.jsonl"):
    return str(tmp_path / name)


def read_records(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def records_of(path, **fields):
    out = []
    for r in read_records(path):
        if all(r.get(k) == v for k, v in fields.items()):
            out.append(r)
    return out


async def until(pred, timeout=10.0, interval=0.05):
    """Poll pred() until true or timeout; returns the last value."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        await asyncio.sleep(interval)
    return pred()


# ── open / basic call flow ──────────────────────────────────────────────────



async def test_open_rejects_missing_path(manager):
    with pytest.raises(ValueError, match="does not exist"):
        await manager.open_session(os.path.join(REPO_ROOT, "no", "such", "file"))




async def test_open_dispatch_failure_marks_crashed(manager, monkeypatch, tmp_path):
    monkeypatch.setenv("FAKE_IDA_FAIL_OPEN", "1")
    with pytest.raises(RuntimeError, match="open failed"):
        await manager.open_session(BINARY)
    session = next(iter(manager.sessions.values()))
    await until(lambda: session.state == "DEAD")
    assert session.close_reason == "crashed"
    # process reaped: no zombie
    await until(lambda: session.proc.returncode is not None)
    await manager.shutdown_all()


async def test_open_timeout_kills_worker(manager, monkeypatch):
    monkeypatch.setenv("FAKE_IDA_SLOW_OPEN_SECONDS", "3")
    monkeypatch.setattr(session_mod, "OPEN_TIMEOUT_BASE", 0.3)
    with pytest.raises(TimeoutError, match="timed out"):
        await manager.open_session(BINARY)
    session = next(iter(manager.sessions.values()))
    await until(lambda: session.state == "DEAD")
    assert session.close_reason == "crashed"
    await until(lambda: session.proc.returncode is not None)
    await manager.shutdown_all()


# ── concurrency semantics ───────────────────────────────────────────────────

async def test_dual_sessions_run_in_parallel(manager, monkeypatch):
    monkeypatch.setenv("FAKE_IDA_SLOW_OP_SECONDS", "1.0")
    sid1 = await manager.open_session(BINARY)
    sid2 = await manager.open_session(BINARY2)
    t0 = time.monotonic()
    r = await asyncio.gather(manager.call(sid1, "get_image_size", {}),
                             manager.call(sid2, "get_image_size", {}))
    elapsed = time.monotonic() - t0
    assert r == [0x200000, 0x200000]
    # two worker processes: cross-session calls must not serialize
    assert elapsed < 1.9, f"cross-session calls serialized: {elapsed:.2f}s"
    await manager.shutdown_all()


async def test_single_session_calls_serialized(manager, monkeypatch):
    monkeypatch.setenv("FAKE_IDA_SLOW_OP_SECONDS", "0.4")
    sid = await manager.open_session(BINARY)
    t0 = time.monotonic()
    await asyncio.gather(manager.call(sid, "get_image_size", {}),
                         manager.call(sid, "get_image_size", {}))
    elapsed = time.monotonic() - t0
    # call_lock serializes both inside one session (ping would bypass it: the
    # worker itself would still serialize, but call_lock must be exercised)
    assert elapsed >= 0.75, f"calls inside one session were not serialized: {elapsed:.2f}s"
    await manager.shutdown_all()



async def test_max_sessions_limit_counts_only_live(manager, monkeypatch):
    monkeypatch.setattr(session_mod, "MAX_SESSIONS", 2)
    sid1 = await manager.open_session(BINARY)
    sid2 = await manager.open_session(BINARY2)
    with pytest.raises(ValueError, match="MAX_SESSIONS"):
        await manager.open_session(REPO_ROOT + "/pyproject.toml")
    # closing one frees a slot (DEAD sessions do not count)
    await manager.close_session(sid1)
    sid3 = await manager.open_session(BINARY)
    assert sid3 != sid2
    await manager.shutdown_all()


# ── open timeout: size-aware formula (design v1.3) ─────────────────────────

async def test_open_timeout_formula(tmp_path, monkeypatch):
    """Unit test of _open_timeout_for: floor, super-linear growth, .i64 linear
    mode, sanity cap. (The flat OPEN_TIMEOUT override is gone: only
    OPEN_TIMEOUT_BASE is configurable; PER_MB/POWER/MAX are fixed constants.)"""
    from headless_ida_mcp_server.session import _open_timeout_for

    def sized(name, mib):
        p = tmp_path / name
        with open(p, "wb") as fh:            # sparse file: instant
            fh.truncate(int(mib * 1024 * 1024))
        return str(p)

    tiny = sized("tiny.bin", 0.01)
    m1 = sized("a.bin", 1)
    m10 = sized("b.bin", 10)
    m100 = sized("c.bin", 100)
    i64_10 = sized("d.i64", 10)

    t_tiny = _open_timeout_for(tiny)
    t_1, t_10, t_100 = _open_timeout_for(m1), _open_timeout_for(m10), _open_timeout_for(m100)
    t_i64 = _open_timeout_for(i64_10)

    assert session_mod.OPEN_TIMEOUT_BASE <= t_tiny < session_mod.OPEN_TIMEOUT_BASE + 1
    assert t_tiny < t_1 < t_10 < t_100                       # monotonic in size
    # super-linear for raw binaries: 10× size ⇒ way more than 10× the scaled part
    assert t_10 - session_mod.OPEN_TIMEOUT_BASE > 10 * (t_1 - session_mod.OPEN_TIMEOUT_BASE)
    assert t_100 - session_mod.OPEN_TIMEOUT_BASE > 10 * (t_10 - session_mod.OPEN_TIMEOUT_BASE)
    # .i64: loading only → linear (no POWER), and smaller than the raw form
    assert t_i64 == pytest.approx(session_mod.OPEN_TIMEOUT_BASE + session_mod._OPEN_TIMEOUT_PER_MB * 10)
    assert t_i64 < t_10
    # sanity cap for absurd sizes (patching the fixed constant for the test)
    monkeypatch.setattr(session_mod, "_OPEN_TIMEOUT_MAX", 5000.0)
    assert _open_timeout_for(sized("huge.bin", 100000)) == 5000.0


async def test_open_timeout_scales_with_file_size(manager, monkeypatch, tmp_path):
    """The formula actually feeds the open wait: a 2 MB sample with a tuned
    formula times out, a fast open under a generous formula passes."""
    sample = tmp_path / "sample.bin"
    with open(sample, "wb") as fh:
        fh.truncate(int(2 * 1024 * 1024))
    # tuned formula ≈ 1.03s: comfortably above worker boot time, comfortably
    # below the 3s injected slow open — no boot/timeout race either way
    monkeypatch.setattr(session_mod, "OPEN_TIMEOUT_BASE", 1.0)
    monkeypatch.setattr(session_mod, "_OPEN_TIMEOUT_PER_MB", 0.01)
    monkeypatch.setenv("FAKE_IDA_SLOW_OPEN_SECONDS", "3")
    with pytest.raises(TimeoutError, match="timed out"):
        await manager.open_session(str(sample))
    session = next(iter(manager.sessions.values()))
    await until(lambda: session.state == "DEAD")
    assert session.close_reason == "crashed"
    await until(lambda: session.proc.returncode is not None)
    # generous formula, normal open speed → no false timeout
    monkeypatch.setenv("FAKE_IDA_SLOW_OPEN_SECONDS", "")
    monkeypatch.setattr(session_mod, "OPEN_TIMEOUT_BASE", 60.0)
    sid = await manager.open_session(BINARY)
    assert manager.sessions[sid].state == "READY"
    await manager.shutdown_all()


# ── call semantics without a forced timeout (design v1.3) ───────────────────

async def test_call_waits_for_slow_op_without_false_timeout(manager, monkeypatch):
    """No CALL_TIMEOUT by default: a slow op simply takes its time."""
    monkeypatch.setenv("FAKE_IDA_SLOW_OP_SECONDS", "1.5")
    sid = await manager.open_session(BINARY)
    t0 = time.monotonic()
    result = await manager.call(sid, "get_image_size", {})
    elapsed = time.monotonic() - t0
    assert result == 0x200000
    assert elapsed >= 1.4, f"op finished too early: {elapsed:.2f}s"
    await manager.shutdown_all()


async def test_call_with_explicit_timeout_covers_whole_span(manager, monkeypatch, tmp_path):
    """Opt-in per-call timeout (design v1.2 D1 coverage): queueing + write +
    drain + response wait all count; locks are released so the close ladder
    stays reachable; timeout ≠ not-executed."""
    rec = rec_path(tmp_path)
    monkeypatch.setenv("FAKE_IDA_SLOW_OP_SECONDS", "2.0")
    monkeypatch.setenv("FAKE_IDA_RECORD_FILE", rec)
    sid = await manager.open_session(BINARY)

    t0 = time.monotonic()
    with pytest.raises(TimeoutError, match="may still have been executed"):
        await manager.call(sid, "list_functions", {}, timeout=0.3)
    elapsed = time.monotonic() - t0
    assert elapsed < 1.5, f"timeout did not cover the whole span: {elapsed:.2f}s"

    # timeout ≠ not-executed: the op does run to completion in the worker
    await until(lambda: records_of(rec, op="list_functions"))
    # close ladder must still work (locks were released by the timeout)
    result = await manager.close_session(sid, save=True)
    assert "closed" in result
    session = manager.sessions[sid]
    assert session.state == "DEAD" and session.close_reason == "closed"
    assert {"op": "clean_up", "save": True} in read_records(rec)


async def test_queued_call_timeout_counts_queueing(manager, monkeypatch):
    """Second call queued behind a slow op must time out within the given
    timeout, not after (queue wait + op duration)."""
    monkeypatch.setenv("FAKE_IDA_SLOW_OP_SECONDS", "2.0")
    sid = await manager.open_session(BINARY)
    t0 = time.monotonic()
    results = await asyncio.gather(
        manager.call(sid, "get_image_size", {}, timeout=0.5),
        manager.call(sid, "get_image_size", {}, timeout=0.5),
        return_exceptions=True,
    )
    elapsed = time.monotonic() - t0
    assert all(isinstance(r, TimeoutError) for r in results), results
    assert elapsed < 1.8, f"queueing was not counted into the timeout: {elapsed:.2f}s"
    await manager.shutdown_all()


async def test_cancelled_call_late_reply_does_not_crosstalk(manager, monkeypatch):
    """A cancelled caller (e.g. client disconnect) drops its late reply without
    resolving a different request."""
    monkeypatch.setenv("FAKE_IDA_SLOW_OP_SECONDS", "1.2")
    sid = await manager.open_session(BINARY)
    task = asyncio.create_task(manager.call(sid, "decompile_function", {"address": 0x401000}))
    await asyncio.sleep(0.2)                    # the request is in flight
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # while the slow op is still running, a ping must come back with ITS result
    assert await manager.ping_session(sid) == "pong"
    await manager.shutdown_all()


async def test_ping_queues_behind_long_op(manager, monkeypatch):
    """ping is a responsiveness check: a long op in the worker queues it."""
    monkeypatch.setenv("FAKE_IDA_SLOW_OP_SECONDS", "1.0")
    sid = await manager.open_session(BINARY)
    slow = asyncio.create_task(manager.call(sid, "get_image_size", {}))
    await asyncio.sleep(0.05)
    t0 = time.monotonic()
    assert await manager.ping_session(sid) == "pong"
    assert time.monotonic() - t0 >= 0.8
    await slow
    await manager.shutdown_all()


# ── giant responses / protocol errors ───────────────────────────────────────

async def test_giant_response_closes_session_as_protocol_error(manager, monkeypatch, tmp_path):
    rec = rec_path(tmp_path)
    monkeypatch.setenv("FAKE_IDA_HUGE_RESPONSE_BYTES", "5000")
    monkeypatch.setenv("FAKE_IDA_RECORD_FILE", rec)
    monkeypatch.setattr(session_mod, "MAX_RESPONSE_BYTES", 1024)
    sid = await manager.open_session(BINARY)
    session = manager.sessions[sid]
    with pytest.raises(RuntimeError, match="protocol error"):
        await manager.call(sid, "list_functions", {})
    # reader died → ladder skips the close-response wait → SIGTERM directly;
    # the worker's SIGTERM handler still saves
    await until(lambda: session.state == "DEAD")
    assert session.close_reason == "protocol-error"
    await until(lambda: session.proc.returncode is not None)
    assert {"op": "clean_up", "save": True} in read_records(rec)


async def test_near_limit_response_passes(manager, monkeypatch):
    monkeypatch.setenv("FAKE_IDA_HUGE_RESPONSE_BYTES", "8000")
    monkeypatch.setattr(session_mod, "MAX_RESPONSE_BYTES", 16384)
    sid = await manager.open_session(BINARY)
    result = await manager.call(sid, "list_functions", {})
    assert isinstance(result, str) and len(result) == 8000
    await manager.shutdown_all()


# ── stderr drain must never die (I1) ────────────────────────────────────────

async def test_stderr_drain_survives_oversized_lines(manager, monkeypatch, caplog):
    import logging
    caplog.set_level(logging.INFO, logger="headless_ida_mcp_server")
    monkeypatch.setenv("FAKE_IDA_STDERR_LINE_BYTES", "5000")
    monkeypatch.setattr(session_mod, "MAX_RESPONSE_BYTES", 1024)
    sid = await manager.open_session(BINARY)
    # worker not frozen and stderr keeps flowing after the oversized line
    for _ in range(3):
        assert await manager.call(sid, "ping", {}) == "pong"
    await until(lambda: any("fake-op ping" in r.message for r in caplog.records))
    assert any("fake-op" in r.message for r in caplog.records)
    await manager.shutdown_all()


# ── close ladder (§5.4) ─────────────────────────────────────────────────────

async def test_normal_close_saves_and_unindexes(manager, monkeypatch, tmp_path):
    rec = rec_path(tmp_path)
    monkeypatch.setenv("FAKE_IDA_RECORD_FILE", rec)
    sid = await manager.open_session(BINARY)
    result = await manager.close_session(sid, save=True)
    assert "closed" in result
    session = manager.sessions[sid]
    assert session.state == "DEAD" and session.close_reason == "closed"
    assert await until(lambda: session.proc.returncode is not None)
    assert {"op": "clean_up", "save": True} in read_records(rec)
    # unindexed: the same path now opens as a brand-new session
    sid2 = await manager.open_session(BINARY)
    assert sid2 != sid
    await manager.close_session(sid2)



async def test_close_without_save_records_false(manager, monkeypatch, tmp_path):
    rec = rec_path(tmp_path)
    monkeypatch.setenv("FAKE_IDA_RECORD_FILE", rec)
    sid = await manager.open_session(BINARY)
    await manager.close_session(sid, save=False)
    assert {"op": "clean_up", "save": False} in read_records(rec)


async def test_close_waits_for_slow_save_to_finish(manager, monkeypatch, tmp_path):
    """No SAVE_TIMEOUT by default: a slow but finite save completes cleanly
    instead of being SIGKILLed half-written."""
    rec = rec_path(tmp_path)
    monkeypatch.setenv("FAKE_IDA_SLOW_CLOSE_SECONDS", "2")       # slow, finite
    monkeypatch.setenv("FAKE_IDA_RECORD_FILE", rec)
    sid = await manager.open_session(BINARY)
    session = manager.sessions[sid]
    t0 = time.monotonic()
    result = await manager.close_session(sid, save=True)
    elapsed = time.monotonic() - t0
    assert "closed" in result
    assert session.close_reason == "closed"
    assert elapsed >= 1.8, f"close did not wait for the slow save: {elapsed:.2f}s"
    assert {"op": "clean_up", "save": True} in read_records(rec)


async def test_close_hang_with_explicit_timeout_escalates_to_sigterm(manager, monkeypatch, tmp_path):
    """Opt-in close timeout: no reply in time → SIGTERM → worker exits mid-save."""
    rec = rec_path(tmp_path)
    monkeypatch.setenv("FAKE_IDA_SLOW_CLOSE_SECONDS", "3")     # interruptible hang
    monkeypatch.setenv("FAKE_IDA_RECORD_FILE", rec)
    monkeypatch.setattr(session_mod, "_TERM_EXIT_WAIT", 1.0)
    sid = await manager.open_session(BINARY)
    session = manager.sessions[sid]
    t0 = time.monotonic()
    await manager.close_session(sid, save=True, timeout=0.4)
    # no reply within the requested timeout → SIGTERM → worker handler exits mid-save
    assert session.close_reason == "term-killed"
    assert time.monotonic() - t0 < 3.0
    assert await until(lambda: session.proc.returncode is not None)
    assert records_of(rec, op="clean_up")          # save attempt happened


async def test_close_hang_with_explicit_timeout_escalates_to_sigkill(manager, monkeypatch):
    monkeypatch.setenv("FAKE_IDA_HANG_CLOSE", "1")             # SIGTERM ignored
    monkeypatch.setattr(session_mod, "_TERM_EXIT_WAIT", 0.6)
    sid = await manager.open_session(BINARY)
    session = manager.sessions[sid]
    await manager.close_session(sid, save=True, timeout=0.4)
    assert session.close_reason == "timeout-killed"
    assert await until(lambda: session.proc.returncode is not None)
    assert session.proc.returncode == -signal.SIGKILL


async def test_close_recovers_after_external_worker_kill(manager, monkeypatch):
    """Escape hatch for a worker stuck in a never-returning op: the pid from
    list_sessions can be killed externally; the pending close then finishes and
    the ladder reaps the process (no hang, no orphan)."""
    # per-op form: hang only decompile_function, keep the open ack fast
    monkeypatch.setenv("FAKE_IDA_SLOW_OP_SECONDS", "decompile_function:3600")
    sid = await manager.open_session(BINARY)
    session = manager.sessions[sid]
    hung_call = asyncio.create_task(
        manager.call(sid, "decompile_function", {"address": 0x401000}))
    await asyncio.sleep(0.3)                    # request is in flight inside the worker
    close_task = asyncio.create_task(manager.close_session(sid, save=True))
    await asyncio.sleep(0.3)                    # close op queued behind the hung op
    os.kill(session.proc.pid, signal.SIGKILL)   # external kill (documented escape)
    result = await asyncio.wait_for(close_task, 10)
    assert "closed" in result
    assert await until(lambda: session.state == "DEAD")
    assert await until(lambda: session.proc.returncode is not None)
    # the in-flight call is failed by the reader EOF path, not left hanging
    with pytest.raises(RuntimeError, match="worker exited"):
        await asyncio.wait_for(hung_call, 10)


async def test_close_starting_waits_for_open_first(manager, monkeypatch, tmp_path):
    """L4: close during STARTING waits for open to finish (open_database runs in
    C and cannot be interrupted); no SIGKILL against a mid-open worker."""
    rec = rec_path(tmp_path)
    monkeypatch.setenv("FAKE_IDA_SLOW_OPEN_SECONDS", "1.5")
    monkeypatch.setenv("FAKE_IDA_RECORD_FILE", rec)
    sid_task = asyncio.create_task(manager.open_session(BINARY))
    await asyncio.sleep(0.2)                     # ensure the session is STARTING
    session = manager.sessions[1]
    assert session.state == "STARTING"
    t0 = time.monotonic()
    await manager.close_session(session.id, save=True)
    assert session.state == "DEAD" and session.close_reason == "closed"
    assert time.monotonic() - t0 >= 1.2          # actually waited for the open
    assert {"op": "clean_up", "save": True} in read_records(rec)
    await asyncio.gather(sid_task, return_exceptions=True)


# ── crash recovery / restart ────────────────────────────────────────────────


async def test_restart_ready_requires_force(manager, monkeypatch, tmp_path):
    rec = rec_path(tmp_path)
    monkeypatch.setenv("FAKE_IDA_RECORD_FILE", rec)
    sid = await manager.open_session(BINARY)
    session = manager.sessions[sid]
    with pytest.raises(ValueError, match="force=True"):
        await manager.restart_session(sid)
    old_pid = session.proc.pid
    await manager.restart_session(sid, force=True)
    assert session.state == "READY"
    assert session.proc.pid != old_pid
    assert await manager.ping_session(sid) == "pong"
    # force restart saved the database on the way down
    assert {"op": "clean_up", "save": True} in read_records(rec)


async def test_restart_rejects_when_another_session_holds_path(manager):
    sid1 = await manager.open_session(BINARY)
    session1 = manager.sessions[sid1]
    os.kill(session1.proc.pid, signal.SIGKILL)
    await until(lambda: session1.state == "DEAD")
    # the freed path is picked up by a NEW session…
    sid2 = await manager.open_session(BINARY)
    # …so reviving the old one must be rejected (two workers → .i64 lock clash)
    with pytest.raises(ValueError, match=f"already open in session {sid2}"):
        await manager.restart_session(sid1)
    await manager.shutdown_all()


# ── shutting_down guard (L5) ────────────────────────────────────────────────

async def test_dead_tombstones_are_bounded_and_restartable(manager, monkeypatch, tmp_path):
    """DEAD records are kept for close_reason/restart_session, but pruned
    beyond DEAD_SESSION_RETENTION (bounds list_sessions growth on a
    long-lived server); retained tombstones still restart under their id."""
    import shutil as _shutil
    monkeypatch.setattr(session_mod, "DEAD_SESSION_RETENTION", 3)
    for i in range(5):
        work = tmp_path / f"bound_{i}.so"
        _shutil.copy(BINARY, work)
        sid = await manager.open_session(str(work))
        await manager.close_session(sid, save=False)

    dead = sorted(s.id for s in manager.sessions.values() if s.state == "DEAD")
    assert dead == [3, 4, 5], dead                       # oldest two pruned

    # a retained tombstone still revives under the same id
    result = await manager.restart_session(5)
    assert "restarted" in result
    assert manager.sessions[5].state == "READY"
    await manager.close_session(5, save=False)

    # -1 disables pruning entirely
    monkeypatch.setattr(session_mod, "DEAD_SESSION_RETENTION", -1)
    for i in range(5, 8):
        work = tmp_path / f"bound_{i}.so"
        _shutil.copy(BINARY, work)
        sid = await manager.open_session(str(work))
        await manager.close_session(sid, save=False)
    assert len([s for s in manager.sessions.values() if s.state == "DEAD"]) >= 6


async def test_concurrent_restart_same_id_spawns_one_worker(manager, tmp_path):
    """Two concurrent force-restarts of the SAME id: exactly one may win —
    the loser must be rejected inside the lock, never allowed to a second
    _start (it would overwrite session.proc and orphan the first worker,
    which still holds the path's unpacked .id0)."""
    import shutil as _shutil
    work = str(tmp_path / "double_restart.so")
    _shutil.copy(BINARY, work)
    sid = await manager.open_session(work)

    results = await asyncio.gather(
        manager.restart_session(sid, force=True),
        manager.restart_session(sid, force=True),
        return_exceptions=True)
    winners = [r for r in results if not isinstance(r, Exception)]
    rejected = [r for r in results if isinstance(r, Exception)]
    assert len(winners) == 1 and "restarted" in winners[0]
    assert len(rejected) == 1 and isinstance(rejected[0], RuntimeError)
    assert "concurrent restart" in str(rejected[0])

    session = manager.sessions[sid]
    assert session.state == "READY"
    assert len([s for s in manager.sessions.values() if s.state != "DEAD"]) == 1
    assert await manager.ping_session(sid) == "pong"
    await manager.close_session(sid, save=False)


async def test_spawn_failure_leaves_no_zombie_session(manager, tmp_path):
    """A failed create_subprocess_exec must propagate cleanly: no STARTING
    record with proc=None left behind (it would permanently occupy a
    MAX_SESSIONS slot and break close_session's STARTING path)."""
    import shutil as _shutil
    work = str(tmp_path / "spawnfail.so")
    _shutil.copy(BINARY, work)

    real_spawn = asyncio.create_subprocess_exec

    async def broken_spawn(*a, **kw):
        raise OSError("simulated fork failure")

    asyncio.create_subprocess_exec = broken_spawn
    try:
        with pytest.raises(OSError, match="simulated fork failure"):
            await manager.open_session(work)
    finally:
        asyncio.create_subprocess_exec = real_spawn

    assert manager.sessions == {}, manager.sessions        # no zombie record
    assert manager._path_index == {}                       # path unindexed
    # the manager still works afterwards
    sid = await manager.open_session(work)
    assert manager.sessions[sid].state == "READY"
    await manager.close_session(sid, save=False)


async def test_shutdown_in_progress_rejects_open_and_restart(manager, monkeypatch):
    monkeypatch.setenv("FAKE_IDA_SLOW_CLOSE_SECONDS", "3")     # slow save = window
    sid = await manager.open_session(BINARY)
    shutdown = asyncio.create_task(manager.shutdown_all())
    await asyncio.sleep(0.3)                    # shutdown ladder is now waiting
    with pytest.raises(RuntimeError, match="shutting down"):
        await manager.open_session(BINARY2)
    with pytest.raises(RuntimeError, match="shutting down"):
        await manager.restart_session(sid, force=True)
    await shutdown
    assert manager.sessions[sid].state == "DEAD"
    assert manager._shutting_down is True



async def test_shutdown_kills_starting_session_without_leaking(manager, monkeypatch):
    monkeypatch.setenv("FAKE_IDA_SLOW_OPEN_SECONDS", "5")
    open_task = asyncio.create_task(manager.open_session(BINARY))
    await asyncio.sleep(0.2)                      # session is STARTING
    session = manager.sessions[1]
    t0 = time.monotonic()
    await manager.shutdown_all()
    # not SIGKILLed mid-open after a long wait: SIGTERM ends the Python-level
    # sleep immediately; no orphan worker remains
    assert session.state == "DEAD"
    assert await until(lambda: session.proc.returncode is not None)
    assert time.monotonic() - t0 < 4.0
    await asyncio.gather(open_task, return_exceptions=True)


async def test_open_during_shutdown_is_blocked_afterwards(manager):
    await manager.shutdown_all()
    with pytest.raises(RuntimeError, match="shutting down"):
        await manager.open_session(BINARY)
