"""Real-IDA integration tests (auto-skip when idalib is unavailable).

Runs against a real idalib installation:

- open raw (never-analyzed) binaries and check the open ack smoke test
- full op surface on a real database (read + write + decompile + save)
- dual-session concurrent analysis in ONE manager (two real worker processes)
- write-op persistence: rename -> close(save=True) -> reopen -> name survives
- worker crash -> descriptive error -> restart_session revives the same id
- SIGTERM to a live worker saves and exits (checks idalib did not clobber the
  worker's signal handler behind our back)

Uses the small samples under test/samples/ so a full run stays in the
minutes range. Run:  python3 -m pytest test/test_real_ida.py -v
"""
import asyncio
import importlib.util
import json
import os
import shutil
import signal
import sys
import time

import pytest

if importlib.util.find_spec("ida") is None:
    pytest.skip("idalib (python package 'ida') not available", allow_module_level=True)

from headless_ida_mcp_server.session import SessionManager

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(REPO_ROOT, "test", "samples")
LIBSAL = os.path.join(SAMPLES, "tiny", "libz.so")              # ~113 KB, zlib
LIBCCPKG = os.path.join(SAMPLES, "tiny", "libbz2.so")          # ~79 KB, bzip2
LIBISIS = os.path.join(SAMPLES, "medium", "liblzma.so")        # ~203 KB, xz

for _p in (LIBSAL, LIBCCPKG, LIBISIS):
    assert os.path.exists(_p), f"sample missing: {_p}"


@pytest.fixture
async def manager():
    m = SessionManager()
    yield m
    try:
        await asyncio.wait_for(m.shutdown_all(), timeout=600)
    except asyncio.TimeoutError:
        pytest.fail("shutdown_all timed out during fixture teardown")


async def wait_state(session, state, timeout=600):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if session.state == state:
            return
        await asyncio.sleep(0.2)
    pytest.fail(f"session never reached {state} (now {session.state})")


async def test_open_raw_binary_and_full_op_surface(manager, tmp_path):
    """Open a never-analyzed binary and exercise every tool through the worker."""
    sid = await manager.open_session(LIBISIS)
    session = manager.sessions[sid]
    assert session.state == "READY"
    ack = session.open_result
    assert ack["function_count"] > 0, "open ack smoke test: no functions found"
    assert ack["image_size"] > 0

    # ── read ops ──
    assert await manager.ping_session(sid) == "pong"
    assert await manager.call(sid, "get_image_size", {}) == ack["image_size"]
    functions = await manager.call(sid, "list_functions", {})
    assert isinstance(functions, list) and len(functions) == ack["function_count"]
    fn = functions[0]
    addr, name = fn["address"], fn["name"]
    assert (await manager.call(sid, "get_function", {"address": addr}))["name"] == name
    assert (await manager.call(sid, "get_function_by_name", {"name": name}))["name"] == name
    assert (await manager.call(sid, "get_function_by_address", {"address": addr}))["name"] == name
    code = await manager.call(sid, "decompile_function", {"address": addr})
    assert isinstance(code, str) and code, "decompilation returned nothing"
    disasm = await manager.call(sid, "disassemble_function", {"address": addr})
    assert isinstance(disasm, str) and ":" in disasm
    xrefs = await manager.call(sid, "get_xrefs_to", {"address": addr})
    assert isinstance(xrefs, list)
    entries = await manager.call(sid, "get_entry_points", {})
    assert isinstance(entries, list)

    # ── write ops ──
    r = await manager.call(sid, "rename_function",
                           {"function_address": addr, "new_name": "pwned_by_real_test"})
    assert "renamed" in r and "pwned_by_real_test" in r
    r = await manager.call(sid, "set_function_prototype",
                           {"function_address": addr, "prototype": "int func(void);"})
    assert "prototype set successfully" in r
    r = await manager.call(sid, "set_disassembly_comment",
                           {"address": addr, "comment": "real ida comment"})
    assert "Comment set successfully" in r
    r = await manager.call(sid, "set_decompiler_comment",
                           {"address": addr, "comment": "real pseudocode comment"})
    assert isinstance(r, str)
    r = await manager.call(sid, "rename_local_variable",
                           {"function_address": addr, "old_name": "definitely_not_a_var",
                            "new_name": "x"})
    assert isinstance(r, str)          # op-level failure = normal result string
    r = await manager.call(sid, "save_idb_file", {"save_path": str(tmp_path / "saved.i64")})
    assert os.path.exists(tmp_path / "saved.i64"), "save_idb_file wrote nothing"

    # ── session ops ──
    listing = manager.list_sessions()
    entry = next(s for s in listing if s["session_id"] == sid)
    assert entry["state"] == "READY" and entry["rss_bytes"] > 0
    result = await manager.close_session(sid, save=True)
    assert "closed" in result and session.close_reason == "closed"
    assert session.proc.returncode is not None      # reaped, no zombie


async def test_dual_session_concurrent_analysis(manager, tmp_path):
    """§6.3 acceptance #1 with real idalib: two binaries, two workers, one
    manager; interleaved calls stay independent AND each decompilation is
    provably its own function's (content attribution, not just 'is a str')."""
    # tmp COPIES: this test renames functions — never mutate the shared
    # sample files (a persisted rename made the name-attribution assertion
    # nondeterministic once; shared state must stay read-only across runs)
    work1 = str(tmp_path / "dual_a.so")
    work2 = str(tmp_path / "dual_b.so")
    shutil.copy(LIBSAL, work1)
    shutil.copy(LIBCCPKG, work2)
    sid1, sid2 = await asyncio.gather(manager.open_session(work1),
                                      manager.open_session(work2))
    assert sid1 != sid2
    s1, s2 = manager.sessions[sid1], manager.sessions[sid2]
    assert s1.proc.pid != s2.proc.pid               # genuinely two processes
    live = [s for s in manager.list_sessions() if s["state"] == "READY"]
    assert len(live) == 2

    def pick_real(fns):                             # skip thunks/init glue
        for f in fns:
            if not f["name"].startswith(".") and (f["end_address"] - f["address"]) >= 50:
                return f
        return fns[0]

    fns1 = await manager.call(sid1, "list_functions", {})
    fns2 = await manager.call(sid2, "list_functions", {})
    assert len(fns1) > 0 and len(fns2) > 0
    target1, target2 = pick_real(fns1), pick_real(fns2)
    # interleave: decompile on both, results must not mix
    c1, c2 = await asyncio.gather(
        manager.call(sid1, "decompile_function", {"address": target1["address"]}),
        manager.call(sid2, "decompile_function", {"address": target2["address"]}),
    )
    assert isinstance(c1, str) and isinstance(c2, str)
    # content attribution: each pseudocode names ITS function...
    assert target1["name"] in c1, "session 1 returned session 2's decompilation!"
    assert target2["name"] in c2, "session 2 returned session 1's decompilation!"

    # a rename in session 1 must not leak into session 2
    await manager.call(sid1, "rename_function",
                       {"function_address": target1["address"], "new_name": "session1_only"})
    leaked = await manager.call(sid2, "get_function_by_name", {"name": "session1_only"})
    assert "No function found" in leaked
    await asyncio.gather(manager.close_session(sid1), manager.close_session(sid2))


async def test_write_persistence_across_reopen(manager, tmp_path):
    """rename -> close(save=True) -> reopen -> the name survives."""
    work = str(tmp_path / "persist.so")
    shutil.copy(LIBCCPKG, work)
    sid = await manager.open_session(work)
    fn = (await manager.call(sid, "list_functions", {}))[0]
    await manager.call(sid, "rename_function",
                       {"function_address": fn["address"], "new_name": "persisted_name"})
    await manager.close_session(sid, save=True)
    assert os.path.exists(work + ".i64"), "close(save=True) did not write the database"

    sid2 = await manager.open_session(work)         # reopens the saved .i64
    found = await manager.call(sid2, "get_function_by_name", {"name": "persisted_name"})
    assert "No function found" not in str(found), found
    assert found["name"] == "persisted_name"
    await manager.close_session(sid2, save=True)


async def test_worker_crash_restart(manager, tmp_path):
    work = str(tmp_path / "crash.so")
    shutil.copy(LIBSAL, work)
    sid = await manager.open_session(work)
    session = manager.sessions[sid]
    os.kill(session.proc.pid, signal.SIGKILL)
    await wait_state(session, "DEAD")
    assert session.close_reason == "crashed"
    with pytest.raises(ValueError, match="restart_session"):
        await manager.call(sid, "ping", {})
    assert "already dead" in await manager.close_session(sid)
    result = await manager.restart_session(sid)
    assert f"session {sid} restarted" in result
    assert await manager.ping_session(sid) == "pong"
    await manager.close_session(sid, save=True)


async def test_loaded_the_right_file_cross_tool(manager):
    """Independent proof that IDA really loaded THIS file and finished
    analysis: exported symbols from readelf(1) must be found BY NAME at the
    EXACT same address through the worker, and the image size must cover the
    ELF's LOAD segments."""
    import re
    import subprocess
    symbols = []
    out = subprocess.run(["readelf", "--dyn-syms", "-W", LIBSAL],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        # Num: Value Size Type Bind Vis Ndx Name
        m = re.match(r"\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+FUNC\s+(\w+)\s+(\w+)\s+(\S+)\s+(\S+)", line)
        if m and int(m.group(1), 16) > 0:
            symbols.append((m.group(6).split("@")[0], int(m.group(1), 16)))
    assert len(symbols) >= 3, "readelf found no defined FUNC symbols?"

    # ELF LOAD segments: the analyzed image must cover them
    loads = subprocess.run(["readelf", "-lW", LIBSAL], capture_output=True,
                           text=True, check=True).stdout
    seg_ends = []
    for line in loads.splitlines():
        parts = line.split()
        if parts and parts[0] == "LOAD" and len(parts) >= 6:
            seg_ends.append(int(parts[2], 16) + int(parts[5], 16))
    assert seg_ends, "no LOAD segments parsed"

    sid = await manager.open_session(LIBSAL)
    ack = manager.sessions[sid].open_result
    assert max(seg_ends) <= ack["image_size"], \
        f"image_size {ack['image_size']:#x} does not cover ELF LOAD segments (max end {max(seg_ends):#x})"

    checked = 0
    for name, addr in symbols[:10]:
        found = await manager.call(sid, "get_function_by_name", {"name": name})
        if isinstance(found, str):        # some dynsyms are data symbols, not functions
            continue
        assert found["address"] == addr, \
            f"{name}: worker says {found['address']:#x}, readelf says {addr:#x}"
        checked += 1
    assert checked >= 3, "not enough FUNC symbols cross-checked"
    await manager.close_session(sid, save=False)


async def test_sigterm_to_live_worker_saves_and_exits(manager, tmp_path):
    """The worker's SIGTERM handler must still work after idalib initialized
    (idalib registers its own process hooks) — graceful save, exit code 0."""
    work = str(tmp_path / "sigterm.so")
    shutil.copy(LIBCCPKG, work)
    sid = await manager.open_session(work)
    session = manager.sessions[sid]
    fn = (await manager.call(sid, "list_functions", {}))[0]
    await manager.call(sid, "rename_function",
                       {"function_address": fn["address"], "new_name": "sigterm_saved"})
    session.proc.send_signal(signal.SIGTERM)
    await wait_state(session, "DEAD", timeout=60)
    # the reader EOF path marks it crashed (no close op was sent) — but the
    # WORKER must have exited cleanly (code 0) and saved its database
    assert session.proc.returncode == 0, f"worker exit code {session.proc.returncode}"
    assert os.path.exists(work + ".i64"), "SIGTERM handler did not save the database"
    sid2 = await manager.open_session(work)
    found = await manager.call(sid2, "get_function_by_name", {"name": "sigterm_saved"})
    assert "No function found" not in str(found), "SIGTERM save lost the rename"
    await manager.close_session(sid2, save=True)


# ── gap-closing tests (real-IDA review round) ────────────────────────────────

async def test_sigint_to_live_worker_saves_and_exits(manager, tmp_path):
    """Ctrl+C in a terminal SIGINTs the whole process GROUP — the worker gets
    SIGINT directly (not via the server). It must take the KeyboardInterrupt
    path: save the database and exit 0. (SIGINT handler is restored after
    idalib init — same TVision hazard as SIGTERM.)"""
    work = str(tmp_path / "sigint.so")
    shutil.copy(LIBCCPKG, work)
    sid = await manager.open_session(work)
    session = manager.sessions[sid]
    fn = (await manager.call(sid, "list_functions", {}))[0]
    await manager.call(sid, "rename_function",
                       {"function_address": fn["address"], "new_name": "sigint_saved"})
    session.proc.send_signal(signal.SIGINT)
    await wait_state(session, "DEAD", timeout=60)
    assert session.proc.returncode == 0, f"worker exit code {session.proc.returncode}"
    assert os.path.exists(work + ".i64"), "SIGINT handler did not save the database"
    sid2 = await manager.open_session(work)
    found = await manager.call(sid2, "get_function_by_name", {"name": "sigint_saved"})
    assert "No function found" not in str(found), "SIGINT save lost the rename"
    await manager.close_session(sid2, save=False)


async def test_symlink_same_file_is_idempotent(manager, tmp_path):
    """realpath idempotency: two paths to ONE file must reuse one worker —
    a second worker on the same file corrupts the unpacked .id0 (verified:
    'Read error. The database is corrupted beyond repair' + garbage ack)."""
    work = str(tmp_path / "lib.so")
    shutil.copy(LIBSAL, work)
    link = str(tmp_path / "link_to_lib.so")
    os.symlink(work, link)
    sid1 = await manager.open_session(work)
    sid2 = await manager.open_session(link)
    assert sid1 == sid2, "symlinked open spawned a second session on the same file"
    assert len([s for s in manager.sessions.values() if s.state != "DEAD"]) == 1
    assert await manager.ping_session(sid1) == "pong"
    await manager.close_session(sid1, save=False)


async def test_open_garbage_inputs_fail_or_load_cleanly(manager, tmp_path):
    """Garbage inputs must never hang or hand out a broken session."""
    text_file = tmp_path / "not_a_binary.txt"
    text_file.write_text("hello world, definitely not an ELF " * 10)
    empty_file = tmp_path / "empty.bin"
    empty_file.write_text("")
    directory = tmp_path / "a_directory"
    directory.mkdir()
    ro_dir = tmp_path / "readonly_dir"
    ro_dir.mkdir()
    shutil.copy(LIBCCPKG, ro_dir / "lib.so")
    os.chmod(ro_dir, 0o500)               # r-x: IDA cannot create the database

    # unrecognized/empty payloads load as raw binary sessions (IDA semantics)
    for path, label in ((text_file, "text"), (empty_file, "empty")):
        sid = await manager.open_session(str(path))
        assert manager.sessions[sid].open_result["function_count"] == 0
        assert await manager.ping_session(sid) == "pong"
        await manager.close_session(sid, save=False)

    # a directory kills the worker's open → clean error, DEAD, reaped
    with pytest.raises(RuntimeError):
        await manager.open_session(str(directory))
    dead = [s for s in manager.sessions.values() if s.state == "DEAD"]
    assert any(s.close_reason == "crashed" for s in dead)

    # read-only directory → ack-validation rejects the silently-broken DB
    with pytest.raises(RuntimeError, match="database initialization failed"):
        await manager.open_session(str(ro_dir / "lib.so"))
    os.chmod(ro_dir, 0o755)


async def test_open_unicode_and_spaces_path(manager, tmp_path):
    workdir = tmp_path / "带 空格 的目录"
    workdir.mkdir()
    work = workdir / "库 文件.so"
    shutil.copy(LIBCCPKG, work)
    sid = await manager.open_session(str(work))
    assert manager.sessions[sid].open_result["function_count"] == 107
    assert await manager.ping_session(sid) == "pong"
    await manager.close_session(sid, save=False)


async def test_open_i64_directly(manager, tmp_path):
    """The documented .i64 entry path: opening the saved database directly
    must reproduce the same function count as the raw open."""
    work = str(tmp_path / "direct.so")
    shutil.copy(LIBCCPKG, work)
    sid_raw = await manager.open_session(work)
    raw_count = manager.sessions[sid_raw].open_result["function_count"]
    await manager.close_session(sid_raw, save=True)
    assert os.path.exists(work + ".i64")

    sid_i64 = await manager.open_session(work + ".i64")
    assert manager.sessions[sid_i64].open_result["function_count"] == raw_count
    assert await manager.ping_session(sid_i64) == "pong"
    await manager.close_session(sid_i64, save=True)


async def test_concurrent_same_path_open_spawns_one_worker(manager):
    sid1, sid2 = await asyncio.gather(manager.open_session(LIBSAL),
                                      manager.open_session(LIBSAL))
    assert sid1 == sid2
    assert len([s for s in manager.sessions.values() if s.state != "DEAD"]) == 1
    await manager.close_session(sid1, save=False)


async def test_interleaved_concurrent_calls_no_crosstalk(manager):
    """15 concurrent calls on ONE session: every response must carry the
    address its own request asked for (id association under real payloads)."""
    sid = await manager.open_session(LIBISIS)
    fns = await manager.call(sid, "list_functions", {})
    targets = fns[::len(fns) // 15 or 1][:15]
    results = await asyncio.gather(*[
        manager.call(sid, "get_function", {"address": f["address"]}) for f in targets])
    for requested, got in zip(targets, results):
        assert got["address"] == requested["address"], \
            f"crosstalk: asked {requested['address']:#x}, got {got['address']:#x}"
        assert got["name"] == requested["name"]
    await manager.close_session(sid, save=False)


async def test_cross_session_not_blocked_by_long_op(manager):
    """A ~0.7s real decompilation in session A must not delay session B."""
    sid_a = await manager.open_session(os.path.join(SAMPLES, "medium", "libcrypto.so"))
    sid_b = await manager.open_session(LIBSAL)
    target = await manager.call(sid_a, "get_function_by_name",
                                {"name": "DES_encrypt1"})
    assert "No function found" not in str(target)
    slow = asyncio.create_task(manager.call(sid_a, "decompile_function",
                                            {"address": target["address"]}))
    await asyncio.sleep(0.05)
    t0 = time.monotonic()
    for _ in range(5):
        assert await manager.ping_session(sid_b) == "pong"
    per_ping = (time.monotonic() - t0) / 5
    await slow
    assert per_ping < 0.15, f"session B pings blocked by session A: {per_ping*1000:.0f}ms/ping"
    await asyncio.gather(manager.close_session(sid_a, save=False),
                         manager.close_session(sid_b, save=False))


async def test_orphan_worker_saves_on_parent_death(manager, tmp_path):
    """Parent killed (stdin write end closed) → REAL worker saves via the
    stdin-EOF path and exits 0 — verified against real idalib, not the FAKE."""
    import select
    import subprocess
    work = str(tmp_path / "orphan.so")
    shutil.copy(LIBCCPKG, work)
    env = dict(os.environ)                 # conftest pins FAKE_IDA="" (real backend)
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "headless_ida_mcp_server.worker"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=env, cwd=REPO_ROOT)

    def send(obj):
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        proc.stdin.flush()

    def recv(timeout=120):
        r, _, _ = select.select([proc.stdout], [], [], timeout)
        assert r, "timed out waiting for worker reply"
        line = proc.stdout.readline()
        assert line, "worker exited before replying"
        return json.loads(line)

    send({"id": 1, "op": "open", "args": {"binary_path": work}})
    ack = recv()
    assert ack["ok"] and ack["result"]["function_count"] == 107
    send({"id": 2, "op": "list_functions", "args": {}})
    fns = recv()["result"]
    send({"id": 3, "op": "rename_function",
          "args": {"function_address": fns[0]["address"], "new_name": "orphan_saved_name"}})
    assert recv()["ok"]

    proc.stdin.close()                     # parent dies; worker sees EOF
    proc.wait(timeout=180)
    assert proc.returncode == 0, f"orphan worker exit code {proc.returncode}"
    assert os.path.exists(work + ".i64"), "orphan worker did not save"

    # the rename actually persisted in the saved database
    sid = await manager.open_session(work)
    found = await manager.call(sid, "get_function_by_name", {"name": "orphan_saved_name"})
    assert "No function found" not in str(found), "orphan save lost the rename"
    await manager.close_session(sid, save=False)


async def test_four_real_sessions_coexist_with_partial_failure(manager, tmp_path):
    """Multi-session coexistence at scale (real idalib workers, not FAKE):

    - 4 sessions alive at once (half the default limit), distinct processes
    - 12 concurrent calls spread across all 4, every response attributed right
    - closing ONE session leaves the other three fully working
    - kill -9 ONE worker (design acceptance #3): survivors unaffected, the
      dead session reports DEAD(crashed) and guides the caller to restart
    - shutdown_all reaps everything, survivors' saves included
    """
    samples = []
    for name in ("libbz2.so", "libz.so", "liblzma.so", "libssl.so"):
        tier = "tiny" if name in ("libbz2.so", "libz.so") else "medium"
        src = os.path.join(SAMPLES, tier, name)
        dst = tmp_path / f"coexist_{name}"
        shutil.copy(src, dst)
        samples.append(str(dst))

    sids = await asyncio.gather(*[manager.open_session(p) for p in samples])
    assert len(set(sids)) == 4
    live = [s for s in manager.list_sessions() if s["state"] == "READY"]
    assert len(live) == 4
    assert len({s["pid"] for s in live}) == 4          # 4 distinct worker processes
    assert all(s["rss_bytes"] > 0 for s in live)

    # 12 concurrent calls across all 4 sessions (3 each), correct attribution
    async def call_and_check(sid):
        fns = await manager.call(sid, "list_functions", {})
        fn = fns[len(fns) // 2]
        got = await manager.call(sid, "get_function", {"address": fn["address"]})
        assert got["address"] == fn["address"] and got["name"] == fn["name"]
        return got
    results = await asyncio.gather(*[call_and_check(sid) for sid in sids for _ in range(3)])
    assert len(results) == 12

    # close one → the other three keep working
    await manager.close_session(sids[0], save=False)
    for sid in sids[1:]:
        assert await manager.ping_session(sid) == "pong"

    # kill -9 another worker while the rest are alive (acceptance #3)
    victim = manager.sessions[sids[1]]
    os.kill(victim.proc.pid, signal.SIGKILL)
    await wait_state(victim, "DEAD")
    assert victim.close_reason == "crashed"
    with pytest.raises(ValueError, match="restart_session"):
        await manager.call(sids[1], "ping", {})
    for sid in sids[2:]:
        assert await manager.ping_session(sid) == "pong"

    await manager.shutdown_all()
    for sid in sids:
        assert manager.sessions[sid].state == "DEAD"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if all(s.proc.returncode is not None for s in manager.sessions.values()):
            break
        await asyncio.sleep(0.2)
    for sid in sids:
        assert manager.sessions[sid].proc.returncode is not None, \
            f"session {sid} worker not reaped"


async def test_concurrent_raw_opens_of_two_libs_overlap(manager, tmp_path):
    """Two REAL auto-analyses running at the same time must overlap in wall
    time (coexistence during the heaviest phase), not queue behind each other.
    Fresh copies guarantee raw opens even on repeated runs."""
    for name in ("libssl.so", "liblzma.so"):
        shutil.copy(os.path.join(SAMPLES, "medium", name), tmp_path / name)

    async def timed_open(path):
        t0 = time.monotonic()
        sid = await manager.open_session(path)
        return sid, time.monotonic() - t0

    (sid1, t1), (sid2, t2) = await asyncio.gather(
        timed_open(str(tmp_path / "libssl.so")),
        timed_open(str(tmp_path / "liblzma.so")))
    both = manager.sessions[sid1].open_result["function_count"], \
        manager.sessions[sid2].open_result["function_count"]
    assert both[0] == 2772 and both[1] == 410          # both analyses completed
    ratio = max(t1, t2) / (t1 + t2)
    # fully serialized would be ~1.0; genuinely parallel ~0.5-0.7
    assert ratio < 0.8, (f"raw opens did not overlap: t1={t1:.1f}s t2={t2:.1f}s "
                         f"(ratio {ratio:.2f})")
    print(f"\n    concurrent raw opens: {t1:.1f}s + {t2:.1f}s, overlap ratio {ratio:.2f}")
    await asyncio.gather(manager.close_session(sid1, save=False),
                         manager.close_session(sid2, save=False))
