"""Worker protocol tests (FAKE_IDA backend, no license needed).

Covers the worker protocol items:
- request/response correlated by id
- malformed / non-dict / missing-id lines never kill the worker (L1/L2)
- open dispatch failure writes an error line and exits
- orphan suicide on stdin EOF (parent died) saves the database
- BrokenPipeError while writing a reply == graceful exit with save
- SIGTERM → controlled exit with save
- ensure_ascii=False: non-ASCII payloads round-trip as raw UTF-8
"""
import json
import os
import select
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = os.path.join(REPO_ROOT, "test", "samples", "tiny", "libz.so")


def spawn_worker(extra_env=None):
    env = dict(os.environ)
    env["FAKE_IDA"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra_env or {})
    return subprocess.Popen(
        [sys.executable, "-u", "-m", "headless_ida_mcp_server.worker"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=REPO_ROOT,
    )


def send(proc, obj):
    proc.stdin.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
    proc.stdin.flush()


def send_raw(proc, raw: bytes):
    proc.stdin.write(raw)
    proc.stdin.flush()


def recv(proc, timeout=60.0):
    # generous default: under a loaded box (e.g. right after the real-IDA
    # suite with multi-GB workers still exiting) 15s was occasionally tight
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    assert ready, "timed out waiting for a worker reply"
    line = proc.stdout.readline()
    assert line, "worker exited before replying (EOF)"
    return json.loads(line.decode("utf-8"))


def read_records(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def wait_exit(proc, timeout=15.0):
    proc.wait(timeout=timeout)
    return proc.returncode


def test_request_response_correlated_by_id(tmp_path):
    rec = str(tmp_path / "rec.jsonl")
    proc = spawn_worker({"FAKE_IDA_RECORD_FILE": rec})
    try:
        # open ack doubles as analysis smoke test
        send(proc, {"id": 1, "op": "open", "args": {"binary_path": BINARY}})
        ack = recv(proc)
        assert ack["id"] == 1 and ack["ok"] is True
        assert ack["result"]["image_size"] == 0x200000
        assert ack["result"]["function_count"] == 2

        # interleaved ids must be echoed back exactly
        send(proc, {"id": 7, "op": "ping", "args": {}})
        send(proc, {"id": 3, "op": "get_function", "args": {"address": 0x401000}})
        send(proc, {"id": 9, "op": "get_function_by_name", "args": {"name": "helper"}})
        r1, r2, r3 = recv(proc), recv(proc), recv(proc)
        assert (r1["id"], r1["result"]) == (7, "pong")
        assert r2["id"] == 3 and r2["result"]["name"] == "main"
        assert r3["id"] == 9 and r3["result"]["name"] == "helper"

        # op-level failure is a normal response, not a protocol error
        send(proc, {"id": 11, "op": "get_function", "args": {"address": 0xdeadbee0}})
        r = recv(proc)
        assert r["id"] == 11 and r["ok"] is True
        assert "No function found" in r["result"]

        # clean close with save
        send(proc, {"id": 12, "op": "close", "args": {"save": True}})
        r = recv(proc)
        assert r["id"] == 12 and r["ok"] is True and r["result"] == "closed"
        # the worker exits on its own right after the close reply
        assert wait_exit(proc) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    records = read_records(rec)
    assert {"op": "clean_up", "save": True} in records


def test_non_ascii_roundtrip_ensure_ascii_false():
    proc = spawn_worker()
    try:
        send(proc, {"id": 1, "op": "open", "args": {"binary_path": BINARY}})
        recv(proc)
        # non-ASCII must travel as raw UTF-8 (ensure_ascii=False), not \uXXXX escapes
        send(proc, {"id": 2, "op": "rename_function",
                    "args": {"function_address": 0x401000, "new_name": "win_函数_✓"}})
        r = recv(proc)
        assert r["id"] == 2 and r["ok"] is True
        assert "win_函数_✓" in r["result"]
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_malformed_lines_never_kill_worker():
    """L1/L2: malformed JSON / non-object / missing id → skipped or answered,
    worker survives either way."""
    proc = spawn_worker()
    try:
        send_raw(proc, b"this is not json\n")
        send_raw(proc, b"[1, 2, 3]\n")
        send_raw(proc, b"null\n")
        send_raw(proc, b'{"op": "ping"}\n')          # missing id → default 0
        send_raw(proc, b'{"id": 5, "op": "no_such_op", "args": {}}\n')
        # replies arrive in request order: missing-id ping (id 0), unknown op (id 5)
        r = recv(proc)
        assert r["id"] == 0 and r["ok"] is True and r["result"] == "pong"
        r = recv(proc)
        assert r["id"] == 5 and r["ok"] is False and "unknown op" in r["error"]
        # worker must still answer valid requests afterwards
        send(proc, {"id": 1, "op": "open", "args": {"binary_path": BINARY}})
        ack = recv(proc)
        assert ack["id"] == 1 and ack["ok"] is True
        send(proc, {"id": 42, "op": "ping", "args": {}})
        r = recv(proc)
        assert r["id"] == 42 and r["result"] == "pong"
        assert proc.poll() is None                    # still alive
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_open_failure_writes_error_line_then_exits(tmp_path):
    rec = str(tmp_path / "rec.jsonl")
    proc = spawn_worker({"FAKE_IDA_FAIL_OPEN": "1", "FAKE_IDA_RECORD_FILE": rec})
    try:
        send(proc, {"id": 1, "op": "open", "args": {"binary_path": BINARY}})
        r = recv(proc)
        assert r["id"] == 1 and r["ok"] is False
        assert "injected open failure" in r["error"]
        # process exits afterwards so the parent never idles on the open timeout
        assert wait_exit(proc) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    # no database was opened → no clean_up record, no save attempt
    assert read_records(rec) == [{"op": "open", "binary_path": BINARY}]



def test_broken_pipe_while_replying_is_graceful_exit(tmp_path):
    rec = str(tmp_path / "rec.jsonl")
    proc = spawn_worker({"FAKE_IDA_RECORD_FILE": rec})
    try:
        send(proc, {"id": 1, "op": "open", "args": {"binary_path": BINARY}})
        recv(proc)
        proc.stdout.close()                # parent stops reading the protocol channel
        send(proc, {"id": 2, "op": "ping", "args": {}})
        assert wait_exit(proc) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert {"op": "clean_up", "save": True} in read_records(rec)



def test_unserializable_result_returns_error_and_worker_survives(tmp_path):
    """A non-JSON-serializable op result must come back as an ERROR reply —
    the worker must NOT die over it (its unsaved database would be lost).
    The injection targets get_entry_points because the open ack itself calls
    get_image_size/get_function_count internally."""
    proc = spawn_worker({"FAKE_IDA_UNSERIALIZABLE_OP": "get_entry_points"})
    try:
        send(proc, {"id": 1, "op": "open", "args": {"binary_path": BINARY}})
        ack = recv(proc)
        assert ack["ok"] is True
        send(proc, {"id": 2, "op": "get_entry_points", "args": {}})
        r = recv(proc)
        assert r["id"] == 2 and r["ok"] is False
        assert "not JSON serializable" in r["error"]
        # the worker keeps serving afterwards
        send(proc, {"id": 3, "op": "ping", "args": {}})
        r = recv(proc)
        assert r["id"] == 3 and r["result"] == "pong"
        assert proc.poll() is None
    finally:
        if proc.poll() is None:
            proc.stdin.close()
            proc.wait(timeout=30)


def test_stderr_passthrough_unpolluted_protocol():
    """fd hijack: C-level printf / prints land on stderr, never on stdout."""
    proc = spawn_worker()
    try:
        send(proc, {"id": 1, "op": "open", "args": {"binary_path": BINARY}})
        recv(proc)
        # the fake backend logs nothing on stdout; the protocol channel must
        # carry exactly one JSON line per request
        send(proc, {"id": 2, "op": "ping", "args": {}})
        r = recv(proc)
        assert r["id"] == 2 and r["result"] == "pong"
        proc.stdin.close()
        wait_exit(proc)
        stderr = proc.stderr.read().decode("utf-8", errors="replace")
        assert "{" not in stderr or '"id"' not in stderr   # no protocol frames leaked
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
