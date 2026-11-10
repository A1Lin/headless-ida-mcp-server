#!/usr/bin/env python3
"""Audit + re-benchmark of decompilation TARGET selection.

Challenge: were the decompiled functions representative, or tiny thunks that
make decompilation look artificially cheap?

1. AUDIT: what did the previous benchmarks actually pick? Prints name + code
   size of fns[0], fns[3], fns[100:120], fns[200:220], fns[mid] and the size
   distribution (percentiles) of ALL functions.
2. STRATIFIED COLD BENCHMARK: functions picked by CODE SIZE (≈64B, 256B, 1KB,
   4KB, 16KB, and the largest ones), each decompiled EXACTLY ONCE per side —
   worker (IPC) vs in-process baseline — reporting per-function times, the
   IPC delta, and the decompiled output size.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from headless_ida_mcp_server.session import SessionManager  # noqa: E402


@contextlib.contextmanager
def silence_fd1():
    """C-level printf (hexrays warnings) bypasses sys.stdout — silence fd 1."""
    saved = os.dup(1)
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, 1)
        yield
    finally:
        os.dup2(saved, 1)
        os.close(devnull)
        os.close(saved)

SAMPLE = os.path.join(REPO_ROOT, "test", "samples", "medium", "libcrypto.so")
BASE_DIR = "/tmp/opencode/verify_baseline"

TARGET_SIZES = [64, 256, 1024, 4096, 16384]   # bytes of code
N_LARGEST = 3


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p))]


async def main():
    logging.getLogger("headless_ida_mcp_server").setLevel(logging.WARNING)
    manager = SessionManager()
    sid = await manager.open_session(SAMPLE)
    fns = await manager.call(sid, "list_functions", {})
    for f in fns:
        f["size"] = f["end_address"] - f["address"]

    # ── 1) AUDIT of previous picks ──────────────────────────────────────────
    print("═" * 86)
    print("1) AUDIT — what the previous benchmarks actually decompiled")
    print("═" * 86)
    sizes = [f["size"] for f in fns]
    print(f"libcrypto.so: {len(fns)} functions, code size percentiles (bytes):")
    print(f"  p10={pct(sizes, .10)}  p50={pct(sizes, .50)}  p90={pct(sizes, .90)}  "
          f"p99={pct(sizes, .99)}  max={max(sizes)}")
    def show(label, f):
        print(f"  {label:18s} {f['name'][:44]:46s} addr={f['address']:#010x} size={f['size']:6d}B")
    show("fns[0]", fns[0])
    show("fns[3]", fns[3])
    show("fns[mid]", fns[len(fns) // 2])
    print(f"  fns[100:120] sizes: min={min(f['size'] for f in fns[100:120])} "
          f"max={max(f['size'] for f in fns[100:120])} "
          f"median={pct([f['size'] for f in fns[100:120]], .5)}")
    print(f"  fns[200:220] sizes: min={min(f['size'] for f in fns[200:220])} "
          f"max={max(f['size'] for f in fns[200:220])} "
          f"median={pct([f['size'] for f in fns[200:220]], .5)}")
    print(f"  (population median for comparison: {pct(sizes, .5)}B)", flush=True)

    # ── 2) stratified selection ─────────────────────────────────────────────
    print("\n" + "═" * 86)
    print("2) STRATIFIED cold decompilation by function code size")
    print("═" * 86)
    # Selection is by DECOMPILABILITY, probed at runtime: a candidate whose
    # cold decompile fails (IDA misclassifies data tables as functions at ANY
    # size — the biggest offenders are 100KB+ crypto lookup tables, but small
    # ones exist too) is reported and replaced by the next candidate of the
    # same slot. Every function is still decompiled exactly once, so all
    # timings stay cold.
    used: set[int] = set()
    excluded = []

    def next_candidate(order):
        for f in order:
            if f["address"] not in used:
                return f
        return None

    slots = [(f"~{t // 1024}KB" if t >= 1024 else f"~{t}B", t,
              sorted(fns, key=lambda f: abs(f["size"] - t)))
             for t in TARGET_SIZES]
    slots += [("largest", None, sorted(fns, key=lambda f: -f["size"]))] * N_LARGEST

    # ── worker side: each function decompiled exactly ONCE (cold) ──────────
    print(f"\n{'slot':8s} {'function':38s} {'size':>8s} {'worker':>9s} {'output':>8s}")
    worker_rows = []
    for label, _target, order in slots:
        while True:
            f = next_candidate(order)
            if f is None:
                print(f"{label:8s} (no more candidates)", flush=True)
                break
            used.add(f["address"])
            t0 = time.perf_counter_ns()
            code = await manager.call(sid, "decompile_function", {"address": f["address"]})
            dt = (time.perf_counter_ns() - t0) / 1e6
            if isinstance(code, str) and code.startswith("Failed"):
                excluded.append((label, f))
                print(f"{label:8s} {f['name'][:38]:38s} {f['size']:7d}B   ---- not decompilable"
                      " (data table?), replaced by next candidate", flush=True)
                continue
            out_len = len(code) if isinstance(code, str) else -1
            worker_rows.append((f, dt, out_len))
            print(f"{label:8s} {f['name'][:38]:38s} {f['size']:7d}B {dt:8.1f}ms {out_len:7d}c",
                  flush=True)
            break
    await manager.close_session(sid, save=False)

    # ── in-process baseline on an identical copy, same addresses, cold ──────
    os.makedirs(BASE_DIR, exist_ok=True)
    base = os.path.join(BASE_DIR, "verify.so")
    if os.path.exists(base):
        os.remove(base)
    shutil.copy(SAMPLE, base)
    from headless_ida_mcp_server import helper
    idapro = helper._import_idapro()
    with silence_fd1():
        idapro.open_database(base, True)
    helper._load_idalib_modules()
    ida = helper.IDA()

    print(f"\n{'function':44s} {'size':>8s} {'baseline':>9s} {'worker':>9s} {'delta':>8s} {'output':>8s} {'match':>6s}")
    deltas = []
    with open(os.path.join(REPO_ROOT, "test", "samples", "bench_decompile_audit.jsonl"), "w") as jf:
        for f, w_ms, out_len in worker_rows:
            t0 = time.perf_counter_ns()
            with silence_fd1():
                b_code = ida.decompile_function(f["address"])
            b_ms = (time.perf_counter_ns() - t0) / 1e6
            match = "yes" if isinstance(b_code, str) and len(b_code) == out_len else "no"
            delta = w_ms - b_ms
            deltas.append(delta)
            print(f"{f['name'][:44]:44s} {f['size']:7d}B {b_ms:8.1f}ms {w_ms:8.1f}ms {delta:+7.1f}ms "
                  f"{out_len:7d}c {match:>6s}", flush=True)
            jf.write(json.dumps({"function": f["name"], "address": f["address"], "size": f["size"],
                                 "baseline_ms": round(b_ms, 2), "worker_ms": round(w_ms, 2),
                                 "delta_ms": round(delta, 2), "output_chars": out_len,
                                 "match": match}) + "\n")
    idapro.close_database(False)
    await manager.shutdown_all()

    print("\nSUMMARY")
    if deltas:
        deltas.sort()
        print(f"  IPC delta over stratified cold decompiles: "
              f"min={deltas[0]:+.1f}ms  p50={deltas[len(deltas)//2]:+.1f}ms  max={deltas[-1]:+.1f}ms")
    print(f"  measured (decompilable) picks: {len(worker_rows)}/{len(slots)}")
    if excluded:
        print(f"  excluded non-decompilable candidates "
              f"(hexrays reports 'Failed to decompile' — typically data tables "
              f"misread as functions; this is IDA's classification limit, not an IPC issue):")
        for label, f in excluded:
            print(f"    [{label:8s}] {f['name']} @ {f['size']}B")


if __name__ == "__main__":
    asyncio.run(main())
