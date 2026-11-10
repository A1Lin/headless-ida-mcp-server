#!/usr/bin/env python3
"""Deep verification of real-IDA worker responses.

Answers three challenges about the worker-architecture benchmark:

1. **Are sub-millisecond responses plausible?**
   - ping is the pure transport floor (no backend work at all): pipe write +
     worker wakeup + JSON of ~30 bytes + reply + reader wakeup. Distribution
     over 1000 calls.
   - The earlier "decompile 0.08ms" figure was a hexrays-CACHED result (the
     cfunc is cached after the first decompile). Here we measure COLD
     decompiles: N different functions, each decompiled exactly once, through
     the worker AND in-process — the per-call delta is the honest IPC cost on
     top of real IDA work.

2. **Is the response content correct?**
   Field-by-field equality between worker responses and an in-process
   helper.IDA baseline on the same binary: image_size, get_function dict,
   decompile_function string, disassemble_function string, and the FULL
   list_functions JSON.

3. **Did IDA actually load the file?**
   readelf(1) cross-checks: exported symbols found by name at the exact
   dynsym address, image size covering all LOAD segments, list length equal
   to the open-ack function count, decompiled text naming its own function.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from headless_ida_mcp_server.session import SessionManager  # noqa: E402

SAMPLE = os.path.join(REPO_ROOT, "test", "samples", "medium", "libcrypto.so")
BASE_DIR = "/tmp/opencode/verify_baseline"
N_COLD = 20


def hr(title):
    print(f"\n{'─' * 78}\n{title}\n{'─' * 78}", flush=True)


def stats_ms(times):
    times = sorted(t / 1e6 for t in times)
    return {
        "n": len(times),
        "min_ms": times[0],
        "p50_ms": times[len(times) // 2],
        "p95_ms": times[int(len(times) * 0.95)],
        "max_ms": times[-1],
    }


def fmt(st):
    return (f"n={st['n']:4d}  min={st['min_ms']:8.3f}  p50={st['p50_ms']:8.3f}  "
            f"p95={st['p95_ms']:8.3f}  max={st['max_ms']:8.3f}  (ms)")


def readelf_symbols(path):
    """(name, address, type) for defined dynsym entries, via readelf -W."""
    out = subprocess.run(["readelf", "--dyn-syms", "-W", path],
                         capture_output=True, text=True, check=True).stdout
    syms = []
    for line in out.splitlines():
        # Num: Value Size Type Bind Vis Ndx Name
        m = re.match(r"\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(FUNC|OBJECT)\s+(\w+)\s+(\w+)\s+(\S+)\s+(\S+)", line)
        if m and int(m.group(1), 16) > 0:
            name = m.group(7).split("@")[0]     # strip symbol versioning
            syms.append((name, int(m.group(1), 16), m.group(3)))
    return syms


def readelf_load_ends(path):
    """End address (vaddr + memsz) of every LOAD segment, via readelf -lW."""
    out = subprocess.run(["readelf", "-lW", path], capture_output=True, text=True,
                         check=True).stdout
    ends = []
    for line in out.splitlines():
        parts = line.split()
        # LOAD Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
        if parts and parts[0] == "LOAD" and len(parts) >= 6:
            vaddr, memsz = int(parts[2], 16), int(parts[5], 16)
            ends.append(vaddr + memsz)
    return ends


def equal_report(label, a, b):
    same = a == b
    print(f"  {'MATCH' if same else 'DIFF!':6s} {label}", flush=True)
    if not same:
        if isinstance(a, dict) and isinstance(b, dict):
            for k in sorted(set(a) | set(b)):
                if a.get(k) != b.get(k):
                    print(f"      field {k!r}: worker={str(a.get(k))[:100]!r} baseline={str(b.get(k))[:100]!r}")
        elif isinstance(a, list) and isinstance(b, list):
            print(f"      lens: worker={len(a)} baseline={len(b)}")
            for i, (x, y) in enumerate(zip(a, b)):
                if x != y:
                    print(f"      first diff at [{i}]: {str(x)[:80]!r} vs {str(y)[:80]!r}")
                    break
        else:
            print(f"      worker  : {str(a)[:150]!r}")
            print(f"      baseline: {str(b)[:150]!r}")
    return same


async def main():
    logging.getLogger("headless_ida_mcp_server").setLevel(logging.WARNING)

    # ── 3) did IDA really load THIS file? (readelf cross-check) ────────────
    hr("3) IDA loaded the right file? — readelf cross-check")
    syms = readelf_symbols(SAMPLE)
    load_ends = readelf_load_ends(SAMPLE)
    func_syms = [s for s in syms if s[2] == "FUNC"]
    print(f"readelf: {len(syms)} dynsyms ({len(func_syms)} FUNC), "
          f"max LOAD segment end {max(load_ends):#x}", flush=True)

    manager = SessionManager()
    sid = await manager.open_session(SAMPLE)
    ack = manager.sessions[sid].open_result
    print(f"worker open ack: image_size={ack['image_size']:#x} function_count={ack['function_count']}",
          flush=True)
    ok = True
    if max(load_ends) > ack["image_size"]:
        ok = False
        print("  DIFF! image_size does not cover the ELF LOAD segments", flush=True)
    else:
        print("  MATCH  image_size covers every LOAD segment", flush=True)

    checked = mismatched = 0
    for name, addr, _kind in func_syms[:40]:
        found = await manager.call(sid, "get_function_by_name", {"name": name})
        if isinstance(found, str):        # data symbols etc. are not functions
            continue
        if found["address"] != addr:
            ok = False
            mismatched += 1
            print(f"  DIFF! {name}: worker {found['address']:#x} != readelf {addr:#x}", flush=True)
        else:
            checked += 1
    print(f"  MATCH  {checked} exported FUNC symbols found by name at the exact "
          f"readelf address ({mismatched} mismatches)", flush=True)

    fns = await manager.call(sid, "list_functions", {})
    print(f"  {'MATCH' if len(fns) == ack['function_count'] else 'DIFF!'}  "
          f"list_functions length == ack.function_count ({len(fns)})", flush=True)
    ok = ok and len(fns) == ack["function_count"]

    target = fns[len(fns) // 2]
    code = await manager.call(sid, "decompile_function", {"address": target["address"]})
    ok_code = isinstance(code, str) and len(code) > 40 and ";" in code and target["name"] in code
    print(f"  {'MATCH' if ok_code else 'DIFF!'}  decompiled text of {target['name']}: "
          f"{len(code)} chars, contains ';', mentions its own name", flush=True)
    ok = ok and ok_code

    # ── 1a) transport floor: ping distribution ─────────────────────────────
    hr("1a) transport floor — ping x1000 (no backend work at all)")
    t = []
    for _ in range(1000):
        t0 = time.perf_counter_ns()
        await manager.call(sid, "ping", {})
        t.append(time.perf_counter_ns() - t0)
    print(f"  ping          {fmt(stats_ms(t))}", flush=True)

    # ── 1b) COLD decompiles through the worker: N different functions ──────
    hr(f"1b) COLD decompilation — {N_COLD} different functions, each decompiled once")
    cold = fns[100:100 + N_COLD]          # never touched above
    t_worker_cold, worker_cold = [], []
    for f in cold:
        t0 = time.perf_counter_ns()
        worker_cold.append(await manager.call(sid, "decompile_function",
                                              {"address": f["address"]}))
        t_worker_cold.append(time.perf_counter_ns() - t0)
    print(f"  worker  cold  {fmt(stats_ms(t_worker_cold))}", flush=True)

    # warm (cached) decompile for contrast — this is where the old 0.08ms came from
    t_warm = []
    for f in cold[:5]:
        t0 = time.perf_counter_ns()
        await manager.call(sid, "decompile_function", {"address": f["address"]})
        t_warm.append(time.perf_counter_ns() - t0)
    print(f"  worker  warm  {fmt(stats_ms(t_warm))}   <- cached (the old 0.08ms figure)", flush=True)

    # ── 2) in-process baseline on an identical copy ─────────────────────────
    hr("2) in-process baseline (v0.2 architecture) on an identical copy")
    os.makedirs(BASE_DIR, exist_ok=True)
    base = os.path.join(BASE_DIR, "verify.so")
    if os.path.exists(base):
        os.remove(base)                    # may be read-only from a previous IDA run
    shutil.copy(SAMPLE, base)
    from headless_ida_mcp_server import helper
    idapro = helper._import_idapro()
    t0 = time.monotonic()
    idapro.open_database(base, True)
    print(f"  baseline raw open: {time.monotonic() - t0:.1f}s", flush=True)
    helper._load_idalib_modules()
    ida = helper.IDA()
    base_fns = ida.list_functions()

    # content equality, field by field
    all_ok = ok
    all_ok &= equal_report("get_image_size",
                           await manager.call(sid, "get_image_size", {}),
                           ida.get_image_size())
    probe = fns[3]
    all_ok &= equal_report(f"get_function({probe['name']!r})",
                           await manager.call(sid, "get_function", {"address": probe["address"]}),
                           ida.get_function(probe["address"]))
    all_ok &= equal_report(f"decompile_function({probe['name']!r})",
                           await manager.call(sid, "decompile_function", {"address": probe["address"]}),
                           ida.decompile_function(probe["address"]))
    all_ok &= equal_report(f"disassemble_function({probe['name']!r})",
                           await manager.call(sid, "disassemble_function", {"address": probe["address"]}),
                           ida.disassemble_function(probe["address"]))
    all_ok &= equal_report("list_functions (FULL JSON, 10661 entries)",
                           json.dumps(fns, sort_keys=True),
                           json.dumps(base_fns, sort_keys=True))

    # baseline COLD decompiles on functions the baseline has never touched
    fresh = base_fns[200:200 + N_COLD]
    t_base_cold, base_fresh = [], []
    for f in fresh:
        t0 = time.perf_counter_ns()
        base_fresh.append(ida.decompile_function(f["address"]))
        t_base_cold.append(time.perf_counter_ns() - t0)
    print(f"\n  baseline cold {fmt(stats_ms(t_base_cold))}", flush=True)
    # worker COLD on the SAME function set (worker never decompiled [200:220] either)
    t_worker_fresh, worker_fresh = [], []
    for f in fresh:
        t0 = time.perf_counter_ns()
        worker_fresh.append(await manager.call(sid, "decompile_function",
                                               {"address": f["address"]}))
        t_worker_fresh.append(time.perf_counter_ns() - t0)
    print(f"  worker   cold {fmt(stats_ms(t_worker_fresh))}", flush=True)
    deltas = [w - b for w, b in zip(t_worker_fresh, t_base_cold)]
    print(f"  IPC delta     {fmt(stats_ms(deltas))}", flush=True)
    match = sum(1 for w, b in zip(worker_fresh, base_fresh) if w == b)
    print(f"  cold decompile text equality: {match}/{N_COLD} identical to baseline", flush=True)
    all_ok = all_ok and match == N_COLD

    idapro.close_database(False)
    await manager.close_session(sid, save=False)
    await manager.shutdown_all()

    hr("VERDICT")
    print("3) file really loaded (readelf cross-check):", "PASS" if ok else "FAIL", flush=True)
    print("2) response content identical to in-process: ", "PASS" if all_ok else "FAIL", flush=True)
    print("1) see ping floor / cold-vs-warm / delta rows above", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
