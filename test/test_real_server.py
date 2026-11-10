"""MCP-server-level tests against REAL idalib workers (stdio, SSE, streamable-http).

Closes the gap left by the FAKE-only end-to-end suite: the actual server
process — FastMCP tool dispatch, the lifespan shutdown under uvicorn (SSE,
streamable-http) and stdio_client (stdio), and orphan-freedom after the
server exits — had never run with real IDA workers.

The deep tests are parametrized over all three transports (multi-client
tests over the HTTP pair — stdio is single-client by design). The server is
started with explicit CLI args, so the tests never depend on launch-time
defaults (CLI flags are the only configuration channel — no .env / env).
"""
import asyncio
import contextlib
import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager

import pytest

if importlib.util.find_spec("ida") is None:
    pytest.skip("idalib (python package 'ida') not available", allow_module_level=True)

import anyio
import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from headless_ida_mcp_server.session import SessionManager

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIBSAL = os.path.join(REPO_ROOT, "test", "samples", "tiny", "libz.so")
assert os.path.exists(LIBSAL), "sample missing: copy test/samples per README"

# the deep tests run over ALL transports; multi-client tests only over the
# HTTP pair (stdio is single-client by design)
TRANSPORTS = ["stdio", "sse", "streamable-http"]
HTTP_TRANSPORTS = ["sse", "streamable-http"]


def clean_env():
    # conftest pins FAKE_IDA="" (real workers: empty != "1"); every other
    # knob is CLI+defaults only — there is no env/.env configuration left
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def worker_pids():
    out = subprocess.run(["pgrep", "-f", "headless_ida_mcp_server[.]worker"],
                         capture_output=True, text=True).stdout.split()
    return {int(p) for p in out if p.strip()}


@asynccontextmanager
async def sse_server(transport="sse"):
    """Spawn the real server on a free loopback port; yields the port.
    transport=None spawns WITHOUT the argument (exercises the default)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    args = [sys.executable, "-m", "headless_ida_mcp_server"]
    if transport is not None:
        args.append(transport)
    proc = subprocess.Popen(
        [*args, "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO_ROOT, env=clean_env(),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if proc.poll() is not None:
                    raise RuntimeError("SSE server died during startup")
                await asyncio.sleep(0.2)
        else:
            raise RuntimeError("SSE server never started listening")
        yield port
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)


@asynccontextmanager
async def sse_client_to(port, timeout=5.0):
    """An initialized MCP client connected over real HTTP/SSE."""
    async with sse_client(f"http://127.0.0.1:{port}/sse", timeout=timeout) as (read, write):
        async with ClientSession(read, write) as client:
            await client.initialize()
            yield client


@asynccontextmanager
async def open_client(transport, extra_args=()):
    if transport == "stdio":
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "headless_ida_mcp_server", "stdio", *extra_args],
            env=clean_env(), cwd=REPO_ROOT)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                yield client
    else:
        async with sse_server(transport=transport) as port:
            async with http_client_to(port, transport) as client:
                yield client


@asynccontextmanager
async def http_client_to(port, transport, timeout=5.0):
    """An initialized MCP client over any HTTP transport (sse → /sse,
    streamable-http → /mcp)."""
    if transport == "streamable-http":
        async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as (read, write, _):
            async with ClientSession(read, write) as client:
                await client.initialize()
                yield client
    else:
        async with sse_client_to(port, timeout=timeout) as client:
            yield client


@asynccontextmanager
async def server_for(transport):
    """The server half of the transport pair: HTTP transports spawn one on a
    free loopback port; stdio needs no server here (its client spawns the
    server in-pipe) and yields None."""
    if transport == "stdio":
        yield None
    else:
        async with sse_server(transport=transport) as port:
            yield port


@asynccontextmanager
async def client_for(port, transport, timeout=5.0):
    """The client half of the transport pair (companion of server_for):
    stdio spawns its own in-pipe server (port ignored); HTTP connects to it."""
    if transport == "stdio":
        async with open_client("stdio") as client:
            yield client
    else:
        async with http_client_to(port, transport, timeout=timeout) as client:
            yield client


async def exercise_real_session(client):
    import json

    def text_of(result):
        for block in result.content:
            if getattr(block, "text", None):
                return block.text
        return ""

    tools = {t.name for t in (await client.list_tools()).tools}
    assert "open_session" in tools
    result = await client.call_tool("open_session", {"path": LIBSAL})
    assert not getattr(result, "isError", False), text_of(result)
    payload = json.loads(text_of(result))
    sid = payload["session_id"]
    assert payload["function_count"] > 0

    pong = await client.call_tool("ping_session", {"session_id": sid})
    assert "pong" in text_of(pong)

    entries = await client.call_tool("get_entry_points", {"session_id": sid})
    assert not getattr(entries, "isError", False), text_of(entries)

    closed = await client.call_tool("close_session", {"session_id": sid, "save": True})
    assert not getattr(closed, "isError", False), text_of(closed)


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_mcp_server_real_ida(transport):
    """Full server process + real idalib worker over all three transports;
    the server exit must not leak worker processes."""
    before = worker_pids()
    async with open_client(transport) as client:
        await exercise_real_session(client)
    # server is gone (stdio: client terminates it; sse: we terminated it) —
    # uvicorn/stdio lifespan shutdown_all must have reaped every worker
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        leaked = worker_pids() - before
        if not leaked:
            break
        await asyncio.sleep(0.5)
    leaked = worker_pids() - before
    assert not leaked, f"orphan worker processes after server exit: {leaked}"


# ── Ctrl+C (SIGINT to the whole foreground process group) ────────────────────

LIBCCPKG = os.path.join(REPO_ROOT, "test", "samples", "tiny", "libbz2.so")
LIBIKE = os.path.join(REPO_ROOT, "test", "samples", "medium", "libcrypto.so")


async def _tool(client, name, arguments):
    """Call one MCP tool over the network and return its parsed payload.
    The SDK serializes unannotated list returns as one text block per item —
    aggregate those back into a list."""
    result = await client.call_tool(name, arguments)
    return _payload_of(result, name)


def _payload_of(result, name=""):
    """Parse a CallToolResult: error-checked, multi-block aware."""
    texts = [b.text for b in result.content if getattr(b, "text", None)]
    assert not getattr(result, "isError", False), f"{name}: {''.join(texts)}"
    if not texts:
        return None
    if len(texts) == 1:
        try:
            return json.loads(texts[0])
        except (json.JSONDecodeError, TypeError):
            return texts[0]
    try:
        return [json.loads(t) for t in texts]
    except (json.JSONDecodeError, TypeError):
        return texts


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_full_tool_surface_and_big_payload(transport, tmp_path):
    """ALL 21 MCP tools called through a REAL connection (each transport:
    stdio pipes / SSE / streamable-http over loopback TCP) with real idalib
    workers — plus a multi-megabyte list_functions response through the
    framing."""
    async with server_for(transport) as port:
        async with client_for(port, transport, timeout=60.0) as client:
            tools = {t.name for t in (await client.list_tools()).tools}
            assert len(tools) == 21

            # ── session lifecycle + full analysis sweep over the network ──
            ack = await _tool(client, "open_session", {"path": LIBCCPKG})
            sid = ack["session_id"]
            assert ack["function_count"] == 107 and ack["image_size"] > 0

            fns = await _tool(client, "list_functions", {"session_id": sid})
            if isinstance(fns, dict):
                fns = [fns]
            fn = next(f for f in fns if not f["name"].startswith("."))
            addr = fn["address"]

            got = await _tool(client, "get_function", {"session_id": sid, "address": addr})
            assert got["name"] == fn["name"]
            got = await _tool(client, "get_function_by_name",
                              {"session_id": sid, "name": fn["name"]})
            assert got["name"] == fn["name"]
            got = await _tool(client, "get_function_by_address",
                              {"session_id": sid, "address": addr})
            assert got["name"] == fn["name"]
            assert await _tool(client, "get_image_size", {"session_id": sid}) == ack["image_size"]
            code = await _tool(client, "decompile_function",
                               {"session_id": sid, "address": addr})
            assert isinstance(code, str) and code
            disasm = await _tool(client, "disassemble_function",
                                 {"session_id": sid, "address": addr})
            assert isinstance(disasm, str) and ":" in disasm
            xrefs = await _tool(client, "get_xrefs_to", {"session_id": sid, "address": addr})
            assert isinstance(xrefs, list)
            entries = await _tool(client, "get_entry_points", {"session_id": sid})
            assert isinstance(entries, list)
            r = await _tool(client, "set_disassembly_comment",
                           {"session_id": sid, "address": addr, "comment": "net test"})
            assert "Comment set successfully" in str(r)
            r = await _tool(client, "set_decompiler_comment",
                            {"session_id": sid, "address": addr, "comment": "net test 2"})
            assert isinstance(r, str)
            r = await _tool(client, "rename_function",
                            {"session_id": sid, "function_address": addr, "new_name": "net_renamed"})
            assert "renamed to net_renamed" in str(r)
            r = await _tool(client, "set_function_prototype",
                            {"session_id": sid, "function_address": addr,
                             "prototype": "int func(void);"})
            assert "prototype set successfully" in str(r)
            r = await _tool(client, "rename_local_variable",
                            {"session_id": sid, "function_address": addr,
                             "old_name": "definitely_not_a_var", "new_name": "x"})
            assert isinstance(r, str)          # op-level failure = normal result
            await _tool(client, "save_idb_file",
                        {"session_id": sid, "save_path": str(tmp_path / "net_saved.i64")})
            assert (tmp_path / "net_saved.i64").exists()
            conv = await _tool(client, "convert_number", {"text": "0x41414141", "size": 4})
            assert conv["ascii"] == "AAAA"
            listing = await _tool(client, "list_sessions", {})
            if isinstance(listing, dict):
                listing = [listing]
            assert any(s["session_id"] == sid and s["state"] == "READY" for s in listing)
            assert await _tool(client, "ping_session", {"session_id": sid}) == "pong"
            await _tool(client, "close_session", {"session_id": sid, "save": False})
            # restart over the network, same id
            r = await _tool(client, "restart_session", {"session_id": sid})
            assert "restarted" in str(r)
            assert await _tool(client, "ping_session", {"session_id": sid}) == "pong"
            await _tool(client, "close_session", {"session_id": sid, "save": False})

            # ── multi-megabyte payload through HTTP/SSE framing ──
            t0 = time.monotonic()
            ack2 = await _tool(client, "open_session", {"path": LIBIKE})
            sid2 = ack2["session_id"]
            fns2 = await _tool(client, "list_functions", {"session_id": sid2})
            dt = time.monotonic() - t0
            if isinstance(fns2, dict):
                fns2 = [fns2]
            payload_mb = len(json.dumps(fns2)) / 1048576
            print(f"\n    network list_functions: {len(fns2)} entries, "
                  f"{payload_mb:.2f} MB over {transport} in {dt:.1f}s")
            assert len(fns2) == 10661, len(fns2)
            assert all("address" in f and "name" in f for f in fns2[:100])
            await _tool(client, "close_session", {"session_id": sid2, "save": False})


@pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
async def test_two_concurrent_clients(transport):
    """Two HTTP clients connected to ONE server at the same time, each driving
    its own real worker; interleaved calls must stay isolated. (stdio is
    single-client by design, so this runs on the HTTP transports only.)"""
    async with server_for(transport) as port:
        async with client_for(port, transport) as c1, client_for(port, transport) as c2:
            ack1 = await _tool(c1, "open_session", {"path": LIBSAL})
            ack2 = await _tool(c2, "open_session", {"path": LIBCCPKG})
            sid1, sid2 = ack1["session_id"], ack2["session_id"]
            assert sid1 != sid2

            # interleaved: each client sees ITS binary's function count
            r1, r2 = await asyncio.gather(
                _tool(c1, "list_functions", {"session_id": sid1}),
                _tool(c2, "list_functions", {"session_id": sid2}))
            if isinstance(r1, dict):
                r1 = [r1]
            if isinstance(r2, dict):
                r2 = [r2]
            assert len(r1) == 181 and len(r2) == 107

            # writes through client 1 must not leak into client 2's session
            fn1 = next(f for f in r1 if not f["name"].startswith("."))
            await _tool(c1, "rename_function",
                        {"session_id": sid1, "function_address": fn1["address"],
                         "new_name": "client1_only"})
            leaked = await _tool(c2, "get_function_by_name",
                                  {"session_id": sid2, "name": "client1_only"})
            assert "No function found" in str(leaked)

            # cross-client non-blocking over HTTP: a ~0.7s REAL decompilation
            # requested through client 1 must not delay client 2's pings
            ack_i = await _tool(c1, "open_session", {"path": LIBIKE})
            sid_i = ack_i["session_id"]
            target = await _tool(c1, "get_function_by_name",
                                 {"session_id": sid_i, "name": "DES_encrypt1"})
            assert "No function found" not in str(target)
            slow = asyncio.create_task(_tool(c1, "decompile_function",
                                            {"session_id": sid_i,
                                             "address": target["address"]}))
            await asyncio.sleep(0.05)
            t0 = time.monotonic()
            for _ in range(5):
                assert await _tool(c2, "ping_session", {"session_id": sid2}) == "pong"
            per_ping = (time.monotonic() - t0) / 5
            code = await slow
            assert isinstance(code, str) and target["name"] in code
            assert per_ping < 0.15, f"client 2 blocked by client 1's long op: {per_ping*1000:.0f}ms/ping"

            await asyncio.gather(
                _tool(c1, "close_session", {"session_id": sid1, "save": False}),
                _tool(c2, "close_session", {"session_id": sid2, "save": False}),
                _tool(c1, "close_session", {"session_id": sid_i, "save": False}))


async def _assert_tool_error_paths(client):
    """Tool-level error behavior (transport-independent)."""
    def text_of(result):
        return "".join(b.text for b in result.content if getattr(b, "text", None))

    r = await client.call_tool("no_such_tool", {})
    assert getattr(r, "isError", False), text_of(r)
    assert "Unknown tool" in text_of(r)

    r = await client.call_tool("get_function", {"session_id": 999, "address": 0})
    assert getattr(r, "isError", False), text_of(r)
    assert "list_sessions" in text_of(r)          # guidance for the agent


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_error_paths_and_protocol_compliance(transport):
    """Error behavior per transport. Transport-level: unknown route → 404
    everywhere; the SSE /messages endpoint rejects bogus/missing session ids
    (400); the streamable-http /mcp route exists and enforces the protocol —
    requests without the proper Accept handshake get 406 (probed values).
    stdio has no HTTP surface: tool-level only."""
    if transport == "stdio":
        async with open_client("stdio") as client:
            await _assert_tool_error_paths(client)
        return
    async with server_for(transport) as port:
        base = f"http://127.0.0.1:{port}"
        async with httpx.AsyncClient(timeout=10) as hc:
            r = await hc.get(f"{base}/no-such-path")
            assert r.status_code == 404
            if transport == "sse":
                r = await hc.post(f"{base}/messages/?session_id=bogus",
                                  json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
                assert r.status_code == 400 and "session" in r.text.lower()
                r = await hc.post(f"{base}/messages/",
                                  json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
                assert r.status_code == 400
            else:      # streamable-http: route exists + protocol enforced
                r = await hc.get(f"{base}/mcp")
                assert r.status_code == 406
                r = await hc.post(f"{base}/mcp", content=b"not json",
                                  headers={"Content-Type": "application/json"})
                assert r.status_code == 406

        async with client_for(port, transport) as client:
            await _assert_tool_error_paths(client)


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_big_request_payload(transport):
    """A ~1MB tool ARGUMENT through each transport's request path (stdio pipe
    write / uvicorn body parsing, JSON-RPC decode, worker pipe write) —
    symmetric to the big-response tests — and the payload round-trips through
    IDA."""
    async with server_for(transport) as port:
        async with client_for(port, transport, timeout=60.0) as client:
            ack = await _tool(client, "open_session", {"path": LIBSAL})
            sid = ack["session_id"]
            fns = await _tool(client, "list_functions", {"session_id": sid})
            if isinstance(fns, dict):
                fns = [fns]
            fn = next(f for f in fns if not f["name"].startswith("."))
            big = "B" * (1024 * 1024)
            r = await _tool(client, "set_disassembly_comment",
                            {"session_id": sid, "address": fn["address"], "comment": big})
            assert "Comment set successfully" in str(r), r
            disasm = await _tool(client, "disassemble_function",
                                 {"session_id": sid, "address": fn["address"]})
            assert isinstance(disasm, str) and big[:1000] in disasm, \
                "1MB comment did not round-trip through the disassembly"
            await _tool(client, "close_session", {"session_id": sid, "save": False})


@pytest.mark.parametrize("transport", TRANSPORTS)
async def test_same_client_concurrent_requests(transport):
    """Several requests in flight AT THE SAME TIME on one client connection:
    every response must carry its own request's result (id correlation over
    each transport, worker serialization via call_lock)."""
    async with server_for(transport) as port:
        async with client_for(port, transport) as client:
            ack = await _tool(client, "open_session", {"path": LIBCCPKG})
            sid = ack["session_id"]
            fns = await _tool(client, "list_functions", {"session_id": sid})
            if isinstance(fns, dict):
                fns = [fns]
            fn = next(f for f in fns if not f["name"].startswith("."))

            results = await asyncio.gather(
                client.call_tool("ping_session", {"session_id": sid}),
                client.call_tool("ping_session", {"session_id": sid}),
                client.call_tool("get_image_size", {"session_id": sid}),
                client.call_tool("get_function", {"session_id": sid, "address": fn["address"]}),
                client.call_tool("get_function_by_name", {"session_id": sid, "name": fn["name"]}),
                client.call_tool("list_functions", {"session_id": sid}),
            )
            assert not any(getattr(r, "isError", False) for r in results)

            assert _payload_of(results[0]) == "pong" and _payload_of(results[1]) == "pong"
            assert _payload_of(results[2]) == ack["image_size"]
            assert _payload_of(results[3])["name"] == fn["name"]
            assert _payload_of(results[4])["name"] == fn["name"]
            lf = _payload_of(results[5])
            if isinstance(lf, dict):
                lf = [lf]
            assert len(lf) == ack["function_count"]
            await _tool(client, "close_session", {"session_id": sid, "save": False})


async def test_default_transport_is_streamable_http():
    """No CLI transport argument → the server must come up on its DEFAULT
    transport, streamable-http (serving POST /mcp). The streamable_http_client
    connection itself is the probe: the sse transport would serve /sse instead
    and this handshake would fail."""
    async with sse_server(transport=None) as port:
        async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as (read, write, _):
            async with ClientSession(read, write) as client:
                await client.initialize()
                tools = {t.name for t in (await client.list_tools()).tools}
                assert "open_session" in tools
                assert len(tools) == 21


async def _open_and_rename(client, binary, new_name="ctrl_c_saved"):
    def text_of(result):
        for block in result.content:
            if getattr(block, "text", None):
                return block.text
        return ""

    r = await client.call_tool("open_session", {"path": binary})
    assert not getattr(r, "isError", False), text_of(r)
    sid = json.loads(text_of(r))["session_id"]
    fns = json.loads(text_of(await client.call_tool("list_functions", {"session_id": sid})))
    if isinstance(fns, dict):          # single-entry SDK serialization
        fns = [fns]
    target = next((f for f in fns if not f["name"].startswith(".")
                   and f["end_address"] - f["address"] >= 50), fns[0])
    r = await client.call_tool("rename_function",
                              {"session_id": sid, "function_address": target["address"],
                               "new_name": new_name})
    assert not getattr(r, "isError", False), text_of(r)


async def _assert_clean_ctrl_c_shutdown(before_pids, work, timeout=90):
    """No orphans, database saved, and the unsaved rename made it to disk."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not (worker_pids() - before_pids):
            break
        await asyncio.sleep(0.5)
    leaked = worker_pids() - before_pids
    assert not leaked, f"orphan workers after Ctrl+C: {leaked}"
    assert os.path.exists(work + ".i64"), "worker did not save its database on Ctrl+C"

    manager = SessionManager()
    try:
        sid = await manager.open_session(work)
        found = await manager.call(sid, "get_function_by_name", {"name": "ctrl_c_saved"})
        assert "No function found" not in str(found), "Ctrl+C save lost the rename"
        await manager.close_session(sid, save=False)
    finally:
        await manager.shutdown_all()


class RawJsonRpcStdioClient:
    """Minimal MCP JSON-RPC client over an externally-spawned server's pipes
    (anyio byte streams). Avoids mcp.client.stdio's own process management so
    the test controls the server's process group for faithful Ctrl+C."""

    def __init__(self, process):
        self.process = process
        self._buf = b""
        self._next_id = 0

    async def _readline(self):
        while b"\n" not in self._buf:
            data = await self.process.stdout.receive()
            if not data:
                raise EOFError("server closed its stdout")
            self._buf += data
        line, _, self._buf = self._buf.partition(b"\n")
        return line

    async def request(self, method, params=None):
        rid = self._next_id
        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        await self.process.stdin.send((json.dumps(msg) + "\n").encode())
        while True:                      # skip notifications in between
            resp = json.loads(await self._readline())
            if resp.get("id") == rid:
                return resp

    async def notify(self, method):
        await self.process.stdin.send(
            (json.dumps({"jsonrpc": "2.0", "method": method}) + "\n").encode())

    async def call_tool(self, name, arguments):
        resp = await self.request("tools/call", {"name": name, "arguments": arguments})
        result = resp.get("result", {})
        assert not result.get("isError"), f"tool {name} failed: {result}"
        return result["content"][0]["text"]


def acceptable_ctrl_c_exit(code):
    """After the fix, Ctrl+C must exit CLEANLY: uvicorn (>= 0.39) completes
    its graceful shutdown (workers saved and reaped) and then re-raises the
    captured SIGINT — server.py main() intercepts that re-raise, so the exit
    code is 0 with no KeyboardInterrupt traceback."""
    return code == 0


async def test_ctrl_c_terminates_stdio_server_and_workers(tmp_path):
    """Ctrl+C in a terminal sends SIGINT to the whole foreground process
    group: the stdio server AND its workers all get it simultaneously. The
    workers must still save (their own KeyboardInterrupt path racing against
    the server's lifespan shutdown_all) and nothing may leak."""
    from mcp.types import LATEST_PROTOCOL_VERSION

    work = str(tmp_path / "ctrlc_stdio.so")
    shutil.copy(LIBSAL, work)
    before = worker_pids()

    process = await anyio.open_process(
        [sys.executable, "-m", "headless_ida_mcp_server", "stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=clean_env(), cwd=REPO_ROOT, start_new_session=True)
    client = RawJsonRpcStdioClient(process)
    try:
        resp = await client.request("initialize", {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ctrlc-test", "version": "0"},
        })
        assert "result" in resp, resp
        await client.notify("notifications/initialized")
        payload = json.loads(await client.call_tool("open_session", {"path": work}))
        sid = payload["session_id"]
        fns = json.loads(await client.call_tool("list_functions", {"session_id": sid}))
        if isinstance(fns, dict):
            fns = [fns]
        target = next((f for f in fns if not f["name"].startswith(".")
                       and f["end_address"] - f["address"] >= 50), fns[0])
        await client.call_tool("rename_function",
                               {"session_id": sid, "function_address": target["address"],
                                "new_name": "ctrl_c_saved"})
        os.killpg(process.pid, signal.SIGINT)      # faithful terminal Ctrl+C
    finally:
        with contextlib.suppress(Exception):
            await process.stdin.aclose()
        with contextlib.suppress(Exception):
            await process.stdout.aclose()

    t0 = time.monotonic()
    await asyncio.wait_for(process.wait(), timeout=120)
    print(f"\n    stdio server exited with code {process.returncode} "
          f"after {time.monotonic()-t0:.1f}s")
    assert acceptable_ctrl_c_exit(process.returncode), process.returncode
    await _assert_clean_ctrl_c_shutdown(before, work)


async def test_sigint_to_server_only_still_saves_workers(tmp_path):
    """Variant that isolates the SERVER-side rescue chain: SIGINT only to the
    server process (not the group, so workers get no direct signal). Workers
    must still close+save via the lifespan shutdown_all (close op) and/or the
    stdin-EOF orphan path when the server dies."""
    from mcp.types import LATEST_PROTOCOL_VERSION

    work = str(tmp_path / "sigint_server_only.so")
    shutil.copy(LIBSAL, work)
    before = worker_pids()

    process = await anyio.open_process(
        [sys.executable, "-m", "headless_ida_mcp_server", "stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=clean_env(), cwd=REPO_ROOT, start_new_session=True)
    client = RawJsonRpcStdioClient(process)
    try:
        await client.request("initialize", {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "sigint-test", "version": "0"},
        })
        await client.notify("notifications/initialized")
        payload = json.loads(await client.call_tool("open_session", {"path": work}))
        sid = payload["session_id"]
        fns = json.loads(await client.call_tool("list_functions", {"session_id": sid}))
        if isinstance(fns, dict):
            fns = [fns]
        target = next((f for f in fns if not f["name"].startswith(".")
                       and f["end_address"] - f["address"] >= 50), fns[0])
        await client.call_tool("rename_function",
                               {"session_id": sid, "function_address": target["address"],
                                "new_name": "ctrl_c_saved"})
        os.kill(process.pid, signal.SIGINT)     # server ONLY, not the group
    finally:
        with contextlib.suppress(Exception):
            await process.stdin.aclose()
        with contextlib.suppress(Exception):
            await process.stdout.aclose()

    t0 = time.monotonic()
    await asyncio.wait_for(process.wait(), timeout=120)
    print(f"\n    stdio server (SIGINT, no group) exited with code {process.returncode} "
          f"after {time.monotonic()-t0:.1f}s")
    assert acceptable_ctrl_c_exit(process.returncode), process.returncode
    await _assert_clean_ctrl_c_shutdown(before, work)


@pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
async def test_ctrl_c_terminates_http_server_and_workers(transport, tmp_path):
    """Same scenario for both HTTP transports: uvicorn's own SIGINT handler
    runs a graceful shutdown → lifespan → shutdown_all."""
    work = str(tmp_path / "ctrlc_http.so")
    shutil.copy(LIBSAL, work)
    before = worker_pids()

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    proc = subprocess.Popen(
        [sys.executable, "-m", "headless_ida_mcp_server", transport,
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO_ROOT, env=clean_env(),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                if proc.poll() is not None:
                    raise RuntimeError("HTTP server died during startup")
                await asyncio.sleep(0.2)
        else:
            raise RuntimeError("HTTP server never started listening")

        if transport == "sse":
            cm = sse_client(f"http://127.0.0.1:{port}/sse")
            read, write = await cm.__aenter__()
        else:
            cm = streamable_http_client(f"http://127.0.0.1:{port}/mcp")
            read, write, _session_id = await cm.__aenter__()
        client = ClientSession(read, write)
        await client.__aenter__()
        try:
            await client.initialize()
            await _open_and_rename(client, work)
            os.killpg(proc.pid, signal.SIGINT)    # faithful terminal Ctrl+C
        finally:
            with contextlib.suppress(Exception):
                await client.__aexit__(None, None, None)
            with contextlib.suppress(Exception):
                await cm.__aexit__(None, None, None)

        t0 = time.monotonic()
        await asyncio.wait_for(asyncio.to_thread(proc.wait), timeout=120)
        print(f"\n    http server exited with code {proc.returncode} "
              f"after {time.monotonic()-t0:.1f}s")
        assert acceptable_ctrl_c_exit(proc.returncode), proc.returncode
        await _assert_clean_ctrl_c_shutdown(before, work)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)


async def test_cli_knob_flags_override_env_and_envfile():
    """--max-sessions / --dead-session-retention / --max-response-bytes are the
    full configuration surface. The spawned server uses CLI flags + built-in
    defaults only (MAX_SESSIONS=16, DEAD_SESSION_RETENTION=4,
    MAX_RESPONSE_BYTES=256MB — there is no env/.env configuration), so every
    effect observed here can only come from the flags."""
    async with open_client("stdio", extra_args=[
            "--max-sessions", "2",
            "--dead-session-retention", "1",
            "--max-response-bytes", "2048"]) as client:

        def text_of(result):
            for block in result.content:
                if getattr(block, "text", None):
                    return block.text
            return ""

        def ok(result):
            assert not getattr(result, "isError", False), text_of(result)
            # list-valued tools: the SDK wraps the array as structuredContent
            # {"result": [...]} while text blocks carry one JSON blob per item
            sc = getattr(result, "structuredContent", None)
            if isinstance(sc, dict) and isinstance(sc.get("result"), list):
                return sc["result"]
            text = text_of(result)
            if text:
                return json.loads(text)
            return sc

        # 1) two sessions fit the CLI limit
        s1 = ok(await client.call_tool("open_session", {"path": LIBSAL}))["session_id"]
        s2 = ok(await client.call_tool("open_session", {"path": LIBCCPKG}))["session_id"]

        # 2) the third distinct path is rejected, naming the CLI value
        rejected = await client.call_tool("open_session", {"path": LIBIKE})
        assert getattr(rejected, "isError", False)
        assert "session limit reached: MAX_SESSIONS=2" in text_of(rejected)

        # 3) closing one frees a slot (DEAD tombstones never count);
        #    close_session returns None — assert, don't parse
        closed = await client.call_tool("close_session", {"session_id": s1, "save": False})
        assert not getattr(closed, "isError", False), text_of(closed)
        s3 = ok(await client.call_tool("open_session", {"path": LIBIKE}))["session_id"]

        # 4) the CLI response cap bites: list_functions on libbz2 (107 entries,
        #    several KB of JSON) exceeds the 2048-byte line limit → protocol
        #    error → the tool call fails naming the cap; the session goes DEAD
        big = await client.call_tool("list_functions", {"session_id": s2})
        assert getattr(big, "isError", False)
        assert "exceeds MAX_RESPONSE_BYTES" in text_of(big)

        deadline = time.monotonic() + 60      # wait out the protocol-error ladder
        while time.monotonic() < deadline:
            entries = ok(await client.call_tool("list_sessions", {}))
            if any(e["session_id"] == s2 and e["state"] == "DEAD" for e in entries):
                break
            await asyncio.sleep(0.3)
        else:
            raise AssertionError(f"session {s2} never reached DEAD after the protocol error")

        # 5) retention=1: closing s3 leaves exactly ONE tombstone, the newest
        closed = await client.call_tool("close_session", {"session_id": s3, "save": False})
        assert not getattr(closed, "isError", False), text_of(closed)
        entries = ok(await client.call_tool("list_sessions", {}))
        dead = [e for e in entries if e["state"] == "DEAD"]
        assert len(dead) == 1, f"--dead-session-retention 1 must keep one tombstone: {dead}"
        assert dead[0]["session_id"] == s3


async def test_cli_rejects_invalid_values():
    """Every CLI knob validates: garbage dies in argparse (exit 2, stderr
    message) and never reaches server startup — including an unknown
    transport value (choices-guarded, not a mid-boot traceback)."""
    bad = [
        (["--max-sessions", "0"], "--max-sessions must be >= 1"),
        (["--dead-session-retention", "-2"], "--dead-session-retention must be >= -1"),
        (["--max-response-bytes", "0"], "--max-response-bytes must be >= 1"),
        (["--open-timeout-base", "0"], "--open-timeout-base must be > 0"),
        (["bogus-transport"], "invalid choice"),
    ]
    for args, expect in bad:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "headless_ida_mcp_server", *args,
            cwd=REPO_ROOT, env=clean_env(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, err = await asyncio.wait_for(proc.communicate(), timeout=60)
        stderr = err.decode("utf-8", errors="replace")
        assert proc.returncode == 2, (args, proc.returncode, stderr)
        assert expect in stderr, (args, stderr)


async def test_environment_is_not_configuration():
    """The CLI-only design, encoded as a regression test: environment
    variables that LOOK like the legacy config knobs must have ZERO effect.
    A hostile env (MAX_SESSIONS=2 would reject the 3rd open,
    OPEN_TIMEOUT_BASE=0.001 would kill every open, MAX_RESPONSE_BYTES=16
    would protocol-error even the smallest response, TRANSPORT=sse would
    break the explicit stdio launch) must not change anything. FAKE_IDA is
    deliberately NOT in the hostile set: it is an internal test seam, not
    user configuration."""
    hostile = {
        "MAX_SESSIONS": "2",
        "OPEN_TIMEOUT": "999",
        "OPEN_TIMEOUT_BASE": "0.001",
        "OPEN_TIMEOUT_PER_MB": "0",
        "OPEN_TIMEOUT_POWER": "1",
        "OPEN_TIMEOUT_MAX": "1",
        "DEAD_SESSION_RETENTION": "1",
        "MAX_RESPONSE_BYTES": "16",
        "TRANSPORT": "sse",
        "PORT": "9",
        "HOST": "0.0.0.0",
    }
    env = clean_env()
    env.update(hostile)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_ida_mcp_server", "stdio"],
        env=env, cwd=REPO_ROOT)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as client:
            await client.initialize()
            # three real opens succeed: limit, timeout, response cap, transport
            # — every hostile value proven ignored at once
            for path in (LIBSAL, LIBCCPKG, LIBIKE):
                r = await client.call_tool("open_session", {"path": path})
                text = next((b.text for b in r.content if getattr(b, "text", None)), "")
                assert not getattr(r, "isError", False), text


async def test_open_timeout_base_flag_wires_to_formula(tmp_path):
    """--open-timeout-base feeds the size-aware formula end-to-end: a 0.3s
    base against a RAW libz copy (no .i64 — auto-analysis takes ~1.5s) must
    time the open out. The fixed formula tail (0.3 + 6·MB^1.5 ≈ 0.6s for a
    0.13MB file) leaves a >2x margin, so the timeout is deterministic."""
    raw = tmp_path / "cold_libz.so"
    shutil.copy(LIBSAL, raw)
    async with open_client("stdio", extra_args=["--open-timeout-base", "0.3"]) as client:
        r = await client.call_tool("open_session", {"path": str(raw)})
        text = next((b.text for b in r.content if getattr(b, "text", None)), "")
        assert getattr(r, "isError", False), "0.3s base should have killed the raw open"
        assert "timed out" in text, text
