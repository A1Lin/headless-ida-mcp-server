"""Shared pytest fixtures for the test suite.

The .i64 databases next to the sample binaries are git-ignored, so a fresh
clone starts without them. Tests that open samples DIRECTLY (not via tmp
copies) would re-run full auto-analysis on every run — libcrypto alone costs
~45s per open. This session fixture generates the missing .i64 files once,
before the first test; subsequent runs skip it entirely (zero overhead).

Only the samples that are opened directly are warmed. Samples used via tmp
copies (libssl, libvulkan_intel) are deliberately left cold: their tests
assert on raw-open behavior/timing.
"""
import asyncio
import importlib.util
import os

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(REPO_ROOT, "test", "samples")

# ── test-hermeticity: neutralize the FAKE_IDA worker hook BEFORE any test
# imports the package. The server/session knobs are CLI+defaults only (the
# .env / environment configuration was removed), so they cannot leak from
# the shell; FAKE_IDA remains an internal, env-based test seam (fault
# injection into spawned fake workers) and must be pinned empty so
# REAL-worker tests never pick up a shell leak. FAKE tests set "1"
# explicitly per spawn, which overwrites this.
os.environ["FAKE_IDA"] = ""

# opened directly by tests (see test_real_ida / test_real_server)
DIRECT_SAMPLES = [
    os.path.join(SAMPLES, "tiny", "libz.so"),
    os.path.join(SAMPLES, "tiny", "libbz2.so"),
    os.path.join(SAMPLES, "medium", "liblzma.so"),
    os.path.join(SAMPLES, "medium", "libcrypto.so"),
]


@pytest.fixture(scope="session", autouse=True)
def ensure_sample_databases():
    missing = [p for p in DIRECT_SAMPLES
               if os.path.exists(p) and not os.path.exists(p + ".i64")]
    if not missing or importlib.util.find_spec("ida") is None:
        yield
        return

    from headless_ida_mcp_server.session import SessionManager

    async def _warm():
        manager = SessionManager()
        try:
            for path in missing:
                print(f"\n[test setup] generating missing database for {os.path.basename(path)} "
                      "(git-ignored .i64, first run only)...")
                sid = await manager.open_session(path)
                await manager.close_session(sid, save=True)
        finally:
            await manager.shutdown_all()

    asyncio.run(_warm())
    yield
