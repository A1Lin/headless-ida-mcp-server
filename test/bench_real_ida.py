#!/usr/bin/env python3
"""Real-IDA benchmark: open timings per binary size + worker-IPC overhead.

Answers two questions about the multi-session worker architecture:

1. **Open cost of raw (never-analyzed) binaries** across sizes (tens of KB to
   tens of MB), compared against the size-aware OPEN_TIMEOUT formula — does
   the computed timeout keep enough headroom on real hardware?
2. **Per-call overhead of the inter-process hop** (server -> pipe -> worker ->
   idalib -> reply) vs calling the same helper.IDA methods in-process — i.e.
   what the v0.2 architecture did. This isolates the IPC cost from IDA's own
   compute time, which is identical either way.

Usage:
  python3 test/bench_real_ida.py [--tiers tiny,medium] [--skip-open]
                                 [--skip-ipc] [--out FILE]

Each measurement is appended as one JSON line to --out (default
test/samples/bench_results.jsonl) the moment it completes, so partial
results survive long runs and interrupts. """
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import shutil
import statistics
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from headless_ida_mcp_server.session import SessionManager, _open_timeout_for  # noqa: E402

SAMPLES = os.path.join(REPO_ROOT, "test", "samples")
TIER_DIRS = {"tiny": "tiny", "medium": "medium", "big": "big"}
DB_SIDECARS = (".i64", ".id0", ".id1", ".id2", ".nam", ".til")

# silence the stderr drain logger chatter (IDA prints thousands of lines while
# loading); the pipe is still drained by the background task
os.environ.setdefault("PYTEST_HIDE", "1")


def samples_for_tiers(tiers):
    out = []
    for tier in tiers:
        d = os.path.join(SAMPLES, TIER_DIRS[tier])
        for name in sorted(os.listdir(d)):
            path = os.path.join(d, name)
            if os.path.isfile(path) and not path.endswith(DB_SIDECARS):
                out.append((tier, path))
    return out


def clean_db(path):
    """Remove IDA database sidecars so the next open is a RAW open."""
    for ext in DB_SIDECARS:
        try:
            os.remove(path + ext)
        except FileNotFoundError:
            pass


def stats_ns(times):
    times = sorted(times)
    if not times:
        return {}
    return {
        "n": len(times),
        "mean_ms": statistics.fmean(times) / 1e6,
        "p50_ms": times[len(times) // 2] / 1e6,
        "p95_ms": times[int(len(times) * 0.95)] / 1e6,
        "min_ms": times[0] / 1e6,
    }


class Recorder:
    def __init__(self, out_path):
        self.out_path = out_path
        self._fh = open(out_path, "a", encoding="utf-8")

    def write(self, kind, **fields):
        rec = {"kind": kind, "ts": time.time(), **fields}
        self._fh.write(json.dumps(rec) + "\n")
        self._fh.flush()
        return rec


async def bench_open(manager, rec, tiers):
    """Raw-open timing per sample: delete sidecars, open, close(save=True)."""
    for tier, path in samples_for_tiers(tiers):
        size = os.path.getsize(path)
        computed = _open_timeout_for(path)
        clean_db(path)
        print(f"[open] {tier:9s} {os.path.basename(path):45s} "
              f"{size/1048576:8.2f} MB  timeout={computed/60:6.1f} min ...", flush=True)
        t0 = time.monotonic()
        try:
            sid = await manager.open_session(path)
            open_s = time.monotonic() - t0
            fn_count = manager.sessions[sid].open_result["function_count"]
            t1 = time.monotonic()
            await manager.close_session(sid, save=True)      # measures the save too
            close_s = time.monotonic() - t1
            saved_mb = os.path.getsize(path + ".i64") / 1048576 if os.path.exists(path + ".i64") else 0
            rec.write("open", tier=tier, file=path, size_bytes=size,
                      timeout_s=computed, open_s=round(open_s, 3),
                      close_save_s=round(close_s, 3), function_count=fn_count,
                      saved_i64_mb=round(saved_mb, 1), status="ok")
            print(f"        open {open_s:7.1f}s  save {close_s:6.1f}s  "
                  f"fns {fn_count:6d}  .i64 {saved_mb:7.1f} MB  "
                  f"headroom {computed/max(open_s,0.001):5.0f}x", flush=True)
        except Exception as e:
            rec.write("open", tier=tier, file=path, size_bytes=size,
                      timeout_s=computed, status="error", error=repr(e))
            print(f"        FAILED after {time.monotonic()-t0:.1f}s: {e!r}", flush=True)


def _baseline_ops(helper_ida, addr, counts):
    """Run the identical helper.IDA op mix in-process (the v0.2 architecture)."""
    out = {}
    t = []
    for _ in range(counts["get_function"]):
        t0 = time.perf_counter_ns()
        helper_ida.get_function(addr)
        t.append(time.perf_counter_ns() - t0)
    out["get_function"] = t
    t = []
    for _ in range(counts["get_image_size"]):
        t0 = time.perf_counter_ns()
        helper_ida.get_image_size()
        t.append(time.perf_counter_ns() - t0)
    out["get_image_size"] = t
    t = []
    for _ in range(counts["decompile_function"]):
        t0 = time.perf_counter_ns()
        with silence_fd1():
            helper_ida.decompile_function(addr)
        t.append(time.perf_counter_ns() - t0)
    out["decompile_function"] = t
    t = []
    for _ in range(counts["list_functions"]):
        t0 = time.perf_counter_ns()
        helper_ida.list_functions()
        t.append(time.perf_counter_ns() - t0)
    out["list_functions"] = t
    return out


@contextlib.contextmanager
def silence_fd1():
    """C-level printf (IDA/hexrays chatter) bypasses sys.stdout — silence fd 1
    around in-process baseline calls so the report stays readable."""
    saved = os.dup(1)
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, 1)
        yield
    finally:
        os.dup2(saved, 1)
        os.close(devnull)
        os.close(saved)


async def bench_ipc(manager, rec, ipc_sample=None):
    """IPC overhead: same ops through SessionManager.call vs in-process helper.

    Uses two DIFFERENT copies of the same binary so the worker side and the
    baseline side each hold their own database (idalib: one DB per process).
    """
    ipc_sample = ipc_sample or os.path.join(SAMPLES, "tiny", "libz.so")
    base_dir = os.path.join(SAMPLES, "_bench_baseline")
    os.makedirs(base_dir, exist_ok=True)
    base_sample = os.path.join(base_dir, "baseline.so")
    # IDA marks the input file read-only while its database is open and only
    # restores it on a saving close — a leftover baseline.so from a previous
    # run cannot be overwritten, unlink it first.
    if os.path.exists(base_sample):
        os.remove(base_sample)
    shutil.copy(ipc_sample, base_sample)

    counts = {"ping": 300, "get_image_size": 300, "get_function": 300,
              "decompile_function": 30, "list_functions": 10}

    # ── worker side (the new architecture) ──
    print(f"[ipc ] worker side on {os.path.basename(ipc_sample)}", flush=True)
    sid = await manager.open_session(ipc_sample)
    fns = await manager.call(sid, "list_functions", {})
    for f in fns:
        f["size"] = f["end_address"] - f["address"]
    sizes = sorted(f["size"] for f in fns)
    # TARGET SELECTION MATTERS: in stripped system libs the median function is a
    # ~6-byte thunk (stripped system libs are full of them) — decompiling those makes the
    # decompiler look absurdly fast. Pick a representative REAL function
    # around p90 of the code-size distribution and record its size.
    p90 = sizes[int(len(sizes) * 0.90)]
    target = min(fns, key=lambda f: abs(f["size"] - p90))
    addr = target["address"]
    # warm hexrays on a DIFFERENT function so the target stays cold
    await manager.call(sid, "decompile_function", {"address": fns[1]["address"]})

    ipc = {}
    t = []
    for _ in range(counts["ping"]):
        t0 = time.perf_counter_ns()
        await manager.call(sid, "ping", {})
        t.append(time.perf_counter_ns() - t0)
    ipc["ping"] = t

    # ONE cold decompile of the representative target (never decompiled before)
    t0 = time.perf_counter_ns()
    cold_result = await manager.call(sid, "decompile_function", {"address": addr})
    ipc["decompile_cold"] = [time.perf_counter_ns() - t0]
    rec.write("ipc", side="worker", op="decompile_cold",
              payload_bytes=len(json.dumps(cold_result, ensure_ascii=False).encode()),
              target_name=target["name"], target_size=target["size"],
              **{f"worker_{k}": v for k, v in stats_ns(ipc["decompile_cold"]).items()})

    for op, args in (("get_image_size", {}), ("get_function", {"address": addr}),
                     ("decompile_function", {"address": addr}), ("list_functions", {})):
        t = []
        payload_bytes = 0
        for _ in range(counts[op]):
            t0 = time.perf_counter_ns()
            result = await manager.call(sid, op, args)
            t.append(time.perf_counter_ns() - t0)
            payload_bytes = len(json.dumps(result, ensure_ascii=False).encode())
        ipc[op] = t
        rec.write("ipc", side="worker", op=op, payload_bytes=payload_bytes,
                  target_size=target["size"] if "decompile" in op or op == "get_function" else None,
                  **{f"worker_{k}": v for k, v in stats_ns(ipc[op]).items()})
    await manager.close_session(sid, save=False)

    # ── baseline: in-process helper (the v0.2 architecture) ──
    print(f"[ipc ] in-process baseline on {base_sample}", flush=True)
    from headless_ida_mcp_server import helper
    idapro = helper._import_idapro()
    t0 = time.monotonic()
    with silence_fd1():
        idapro.open_database(base_sample, True)
    print(f"        baseline open: {time.monotonic()-t0:.1f}s", flush=True)
    helper._load_idalib_modules()
    helper_ida = helper.IDA()
    base_fns = helper_ida.list_functions()
    # same size-stratified target as the worker side (identical analysis → same address)
    for f in base_fns:
        if f["address"] == target["address"]:
            base_addr = f["address"]
            break
    else:
        base_addr = base_fns[0]["address"]

    # ONE cold decompile at the same target, then the warm loop
    t0 = time.perf_counter_ns()
    with silence_fd1():
        helper_ida.decompile_function(base_addr)
    rec.write("ipc", side="baseline", op="decompile_cold",
              **{"baseline_mean_ms": (time.perf_counter_ns() - t0) / 1e6})

    base = _baseline_ops(helper_ida, base_addr, counts)
    for op in ("get_image_size", "get_function", "decompile_function", "list_functions"):
        rec.write("ipc", side="baseline", op=op,
                  **{f"baseline_{k}": v for k, v in stats_ns(base[op]).items()})
    idapro.close_database(False)
    try:
        os.remove(base_sample + ".i64")
    except FileNotFoundError:
        pass
    try:
        os.remove(base_sample)
    except FileNotFoundError:
        pass

    # ── comparison table ──
    print(f"\n    {'op':20s} {'worker p50':>12s} {'baseline p50':>14s} {'delta':>10s}", flush=True)
    rows = [("ping", ipc["ping"], None)] + \
           [(op, ipc[op], base.get(op)) for op in
            ("get_image_size", "get_function", "decompile_function", "list_functions")]
    for op, worker_times, baseline_times in rows:
        w = stats_ns(worker_times)
        wp = w.get("p50_ms", float("nan"))
        if baseline_times:
            bp = stats_ns(baseline_times).get("p50_ms", float("nan"))
            delta = wp - bp
        else:
            bp, delta = float("nan"), wp
        print(f"    {op:20s} {wp:9.3f}ms {bp:12.3f}ms {delta:+8.3f}ms", flush=True)
        rec.write("ipc_summary", op=op, worker_p50_ms=round(wp, 3),
                  baseline_p50_ms=round(bp, 3) if baseline_times else None,
                  delta_ms=round(delta, 3))
    print(f"    (target for get_function/decompile: {target['name']} "
          f"@ {target['size']}B — p90 of the size distribution)", flush=True)


async def bench_mount_io(manager, rec):
    """Raw-open the same sample from /mnt/d (Windows fs) and /tmp (native) to
    show how much of the open time is filesystem, not analysis."""
    src = os.path.join(SAMPLES, "medium", "libssl.so")
    for label, path in (("mnt_d", src), ("tmp_native", "/tmp/opencode/bench_fs_sample.so")):
        if label == "tmp_native":
            shutil.copy(src, path)
        clean_db(path)
        t0 = time.monotonic()
        sid = await manager.open_session(path)
        open_s = time.monotonic() - t0
        await manager.close_session(sid, save=True)
        rec.write("mount_io", fs=label, file=path, open_s=round(open_s, 3))
        print(f"[fs  ] {label:10s} raw open {open_s:6.1f}s  ({path})", flush=True)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tiers", default="tiny,medium",
                    help="comma list of: tiny,medium,big (default tiny,medium)")
    ap.add_argument("--ipc-sample", default=None,
                    help="binary to use for the IPC comparison (default tiny/libz.so)")
    ap.add_argument("--skip-open", action="store_true")
    ap.add_argument("--skip-ipc", action="store_true")
    ap.add_argument("--skip-fs", action="store_true")
    ap.add_argument("--out", default=os.path.join(SAMPLES, "bench_results.jsonl"))
    args = ap.parse_args()
    tiers = [t.strip() for t in args.tiers.split(",") if t.strip()]

    import logging
    logging.getLogger("headless_ida_mcp_server").setLevel(logging.WARNING)

    rec = Recorder(args.out)
    print(f"results -> {args.out}\n", flush=True)
    manager = SessionManager()
    try:
        if not args.skip_open:
            await bench_open(manager, rec, tiers)
        if not args.skip_ipc:
            await bench_ipc(manager, rec, ipc_sample=args.ipc_sample)
        if not args.skip_fs and "medium" in tiers:
            await bench_mount_io(manager, rec)
    finally:
        await asyncio.wait_for(manager.shutdown_all(), timeout=600)
    print("\nDONE", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
