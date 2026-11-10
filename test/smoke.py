#!/usr/bin/env python3
"""Complete smoke test for headless-ida-mcp-server.

Spawns its own server on a free loopback port (real idalib if installed, or
--fake for the deterministic FAKE backend) — or targets an already-running
deployment via --url (transport auto-detected: streamable-http /mcp or SSE
/sse) — then exercises the complete tool surface over real HTTP and prints a
PASS/FAIL report. Exit code 0 = everything passed.

Usage:
  python3 test/smoke.py                      # spawn + smoke (real idalib, default transport)
  python3 test/smoke.py --fake               # spawn + smoke (FAKE backend)
  python3 test/smoke.py --url http://127.0.0.1:8888
  python3 test/smoke.py --binary /path/to/lib.so
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from mcp import ClientSession                       # noqa: E402
from mcp.client.sse import sse_client               # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def detect_transport(base):
    """Which HTTP transport does the deployment speak? A streamable-http
    server serves POST /mcp — a plain GET there answers 405/400 (the route
    exists); an SSE-only server has no /mcp route and answers 404."""
    try:
        urllib.request.urlopen(f"{base}/mcp", timeout=5).close()
        return "streamable-http"     # 2xx is unusual but the route exists
    except urllib.error.HTTPError as e:
        return "sse" if e.code == 404 else "streamable-http"
    except urllib.error.URLError as e:
        raise RuntimeError(f"cannot reach {base}: {e}") from e


def pick_binary(explicit):
    if explicit:
        return explicit
    samples_dir = os.path.join(REPO_ROOT, "test", "samples")
    if os.path.isdir(samples_dir):
        candidates = []
        for tier in ("tiny", "medium", "big"):
            d = os.path.join(samples_dir, tier)
            if os.path.isdir(d):
                candidates += [os.path.join(d, f) for f in os.listdir(d)
                               if not f.endswith((".i64", ".id0", ".id1", ".id2", ".nam", ".til"))]
        if candidates:
            return min(candidates, key=os.path.getsize)
    # no samples: smoke on a throwaway copy of /bin/ls (never write .i64 to /bin)
    copy = os.path.join(tempfile.mkdtemp(prefix="smoke_sse_"), "ls")
    shutil.copy("/bin/ls", copy)
    return copy


class Report:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, ok, name, detail=""):
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}" + (f"  — {detail}" if detail else ""), flush=True)
        if ok:
            self.passed += 1
        else:
            self.failed += 1
        return ok


def payload(result):
    """Error-checked, multi-block aware payload extraction. The SDK serializes
    unannotated list returns as one text block per ITEM (a single-element list
    therefore arrives as one block containing that item) — callers that expect
    a list must pass the result through as_list()."""
    texts = [b.text for b in result.content if getattr(b, "text", None)]
    assert not getattr(result, "isError", False), f"tool error: {''.join(texts)}"
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


def as_list(p):
    """Normalize the SDK's per-item block serialization back to a list."""
    if isinstance(p, list):
        return p
    return [p]


@asynccontextmanager
async def connected_client(args):
    if args.url:
        yield args.url.rstrip("/"), None
        return
    port = free_port()
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    if args.fake:
        env["FAKE_IDA"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-m", "headless_ida_mcp_server",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO_ROOT, env=env,
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
                    raise RuntimeError(f"server died during startup (code {proc.returncode})")
                await asyncio.sleep(0.2)
        else:
            raise RuntimeError("server never started listening")
        yield f"http://127.0.0.1:{port}", proc
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)


def worker_pids():
    out = subprocess.run(["pgrep", "-f", "headless_ida_mcp_server[.]worker"],
                         capture_output=True, text=True).stdout.split()
    return {int(p) for p in out if p.strip()}


async def run_smoke(args):
    binary = pick_binary(args.binary)
    backend = "FAKE" if args.fake else ("real idalib" if not args.url else "remote")
    print(f"smoke target : {args.url or 'spawned server'} ({backend})")
    print(f"sample binary: {binary} ({os.path.getsize(binary)} bytes)\n")
    report = Report()
    before_workers = worker_pids()

    async with connected_client(args) as (base, _proc):
        transport = detect_transport(base)
        print(f"transport   : {transport}")
        client_cm = (streamable_http_client(f"{base}/mcp") if transport == "streamable-http"
                     else sse_client(f"{base}/sse", timeout=60))
        async with client_cm as (read, write, *_):
            async with ClientSession(read, write) as client:
                await client.initialize()

                tools = {t.name for t in (await client.list_tools()).tools}
                report.check(len(tools) == 21, "list_tools returns all 21 tools", f"{len(tools)} tools")

                r = await client.call_tool("open_session", {"path": binary})
                ok = not getattr(r, "isError", False)
                info = payload(r) if ok else {}
                report.check(ok and info.get("function_count", 0) > 0,
                             "open_session", f"function_count={info.get('function_count')}, "
                             f"image_size={info.get('image_size')}")
                sid = info.get("session_id")

                r = await client.call_tool("ping_session", {"session_id": sid})
                report.check(payload(r) == "pong", "ping_session")

                fns = as_list(payload(await client.call_tool("list_functions", {"session_id": sid})))
                report.check(len(fns) == info.get("function_count"),
                             "list_functions", f"{len(fns)} entries")
                fn = next((f for f in fns if not f["name"].startswith(".")
                           and f["end_address"] - f["address"] >= 50), fns[0] if fns else None)

                if fn:
                    addr = fn["address"]
                    got = payload(await client.call_tool(
                        "get_function", {"session_id": sid, "address": addr}))
                    report.check(got.get("name") == fn["name"], "get_function", fn["name"])
                    got = payload(await client.call_tool(
                        "get_function_by_name", {"session_id": sid, "name": fn["name"]}))
                    report.check(got.get("name") == fn["name"], "get_function_by_name")
                    got = payload(await client.call_tool(
                        "get_function_by_address", {"session_id": sid, "address": addr}))
                    report.check(got.get("name") == fn["name"], "get_function_by_address")
                    code = payload(await client.call_tool(
                        "decompile_function", {"session_id": sid, "address": addr}))
                    report.check(isinstance(code, str) and len(code) > 0,
                                 "decompile_function", f"{len(code)} chars")
                    disasm = payload(await client.call_tool(
                        "disassemble_function", {"session_id": sid, "address": addr}))
                    report.check(isinstance(disasm, str) and ":" in disasm, "disassemble_function")
                    xrefs = as_list(payload(await client.call_tool(
                        "get_xrefs_to", {"session_id": sid, "address": addr})))
                    report.check(len(xrefs) >= 1 and isinstance(xrefs[0], dict)
                                 and "address" in xrefs[0],
                                 "get_xrefs_to", f"{len(xrefs)} refs")
                    r = payload(await client.call_tool(
                        "set_disassembly_comment",
                        {"session_id": sid, "address": addr, "comment": "smoke"}))
                    report.check("Comment set successfully" in str(r), "set_disassembly_comment")
                    r = payload(await client.call_tool(
                        "rename_function",
                        {"session_id": sid, "function_address": addr, "new_name": "smoke_renamed"}))
                    report.check("smoke_renamed" in str(r), "rename_function")
                    r = payload(await client.call_tool(
                        "set_function_prototype",
                        {"session_id": sid, "function_address": addr,
                         "prototype": "int func(void);"}))
                    report.check("prototype set successfully" in str(r), "set_function_prototype")

                entries = as_list(payload(await client.call_tool("get_entry_points", {"session_id": sid})))
                report.check(len(entries) >= 1 and isinstance(entries[0], dict)
                             and "address" in entries[0],
                             "get_entry_points", f"{len(entries)} entries")
                conv = payload(await client.call_tool("convert_number",
                                                      {"text": "0x41414141", "size": 4}))
                report.check(conv.get("ascii") == "AAAA", "convert_number")
                listing = as_list(payload(await client.call_tool("list_sessions", {})))
                report.check(any(e.get("session_id") == sid and e.get("state") == "READY"
                                 for e in listing), "list_sessions")

                # error path: guidance must reach the caller
                r = await client.call_tool("get_function", {"session_id": 99999, "address": 0})
                err_text = "".join(b.text for b in r.content if getattr(b, "text", None))
                report.check(getattr(r, "isError", False) and "list_sessions" in err_text,
                             "tool error carries guidance", err_text[:80])

                r = await client.call_tool("close_session", {"session_id": sid, "save": False})
                report.check(not getattr(r, "isError", False), "close_session")

    # spawned mode: no orphan workers left behind
    if not args.url:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if not (worker_pids() - before_workers):
                break
            await asyncio.sleep(0.5)
        report.check(not (worker_pids() - before_workers), "no orphan workers after shutdown")

    print(f"\n{'=' * 60}\nSMOKE RESULT: {report.passed} passed, {report.failed} failed")
    return report.failed == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=None,
                    help="smoke-test an already-running server, e.g. http://127.0.0.1:8888")
    ap.add_argument("--fake", action="store_true",
                    help="spawn with the FAKE backend (no IDA license needed)")
    ap.add_argument("--binary", default=None,
                    help="binary to open (default: smallest test/samples file, else a copy of /bin/ls)")
    args = ap.parse_args()
    ok = asyncio.run(run_smoke(args))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
