# -*- coding: utf-8 -*-
"""Deterministic fake IDA backend (FAKE_IDA=1) for CI without an IDA license.

NOTE ON PLACEMENT: this module intentionally lives INSIDE the package (not
under test/): it is imported by the worker SUBPROCESS (``open_backend`` in
worker.py), which is started as ``python -m headless_ida_mcp_server.worker``
and can only import from the installed package — sys.path is not inherited by
child processes, and a non-editable install has no test/ directory at all.
Moving it under test/ breaks every FAKE test in a hard-to-diagnose way.

``FakeIDA`` implements the exact op surface that ``worker.py`` dispatches to
(see ``worker._OP_WHITELIST``), so the full protocol / lifecycle / timeout /
crash-recovery chain is testable headlessly. Real IDA semantics are covered by
the integration tests against a licensed installation.

Fault injection (all optional, all deterministic, read from the environment
at the moment they are used):

===============================  ==================================================
``FAKE_IDA_FAIL_OPEN``            raise from ``__init__`` (open dispatch failure)
``FAKE_IDA_SLOW_OPEN_SECONDS``    sleep in ``__init__`` (auto-analysis simulation)
``FAKE_IDA_SLOW_OP_SECONDS``      sleep before ops ("N" = every op, "OP:N" = one op)
``FAKE_IDA_UNSERIALIZABLE_OP``  make one op return a non-JSON-serializable object
``FAKE_IDA_CRASH_OP``             hard-crash (``os._exit(1)``) when op is called
``FAKE_IDA_HUGE_RESPONSE_BYTES``  ``list_functions`` returns a ~N byte string
``FAKE_IDA_SLOW_CLOSE_SECONDS``   ``clean_up`` sleeps (close ladder → SIGTERM)
``FAKE_IDA_HANG_CLOSE``           ``clean_up`` ignores SIGTERM and hangs (→ SIGKILL)
``FAKE_IDA_STDERR_LINE_BYTES``    emit an oversized (newline-less) stderr line at open
``FAKE_IDA_RECORD_FILE``          append one JSON line per call (assert save paths)
===============================  ==================================================
"""
import functools
import json
import os
import signal
import time


class FakeIDA:
    """Drop-in replacement for ``helper.IDA`` with deterministic fault injection."""

    # Deterministic fake function table shared by all fake instances.
    FUNCTIONS = {
        0x401000: ("main", "int __fastcall main(int argc, const char **argv)"),
        0x401100: ("helper", "void __fastcall helper(void)"),
    }

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.open = True
        self._closing = False
        self._record("open", binary_path=binary_path)
        slow_open = os.environ.get("FAKE_IDA_SLOW_OPEN_SECONDS")
        if slow_open:
            time.sleep(float(slow_open))
        stderr_line = os.environ.get("FAKE_IDA_STDERR_LINE_BYTES")
        if stderr_line:
            # Oversized stderr line WITHOUT a trailing newline: the parent's
            # stderr drain task must discard it and keep draining (I1).
            os.write(2, b"E" * int(stderr_line))
        if os.environ.get("FAKE_IDA_FAIL_OPEN"):
            raise RuntimeError("FakeIDA: injected open failure (FAKE_IDA_FAIL_OPEN=1)")

    # ── lifecycle ──────────────────────────────────────────────────────────

    def clean_up(self, save_db=False):
        if self._closing:
            return                     # re-entry guard (SIGTERM during close)
        self._closing = True
        self._record("clean_up", save=bool(save_db))
        slow_close = os.environ.get("FAKE_IDA_SLOW_CLOSE_SECONDS")
        if slow_close:
            time.sleep(float(slow_close))    # interruptible: SIGTERM ends it
        if os.environ.get("FAKE_IDA_HANG_CLOSE"):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            time.sleep(3600)                  # not interruptible: SIGKILL needed
        self.open = False

    # ── op surface (worker._OP_WHITELIST) ───────────────────────────────────

    def get_image_size(self):
        return 0x200000

    def get_function_count(self) -> int:
        return len(self.FUNCTIONS)

    def get_function(self, address, *, raise_error=True):
        fn = self._function(address)
        if fn is None:
            return f"No function found at address {address}" if raise_error else None
        return fn

    def get_function_by_name(self, name):
        for address, (fname, prototype) in self.FUNCTIONS.items():
            if fname == name:
                return self._function(address)
        return f"No function found with name {name}"

    def get_function_by_address(self, address):
        return self.get_function(address)

    def list_functions(self):
        huge = os.environ.get("FAKE_IDA_HUGE_RESPONSE_BYTES")
        if huge:
            # Giant single-line JSON response: exercises MAX_RESPONSE_BYTES.
            return "A" * int(huge)
        return [self._function(a) for a in sorted(self.FUNCTIONS)]

    def decompile_function(self, address):
        fn = self._function(address)
        if fn is None:
            return f"No function found at address {address}"
        return f"int __fastcall {fn['name']}() {{ return 0; }}"

    def disassemble_function(self, address):
        fn = self._function(address)
        if fn is None:
            return f"No function found at address {address}"
        return "\n".join(f"{fn['address'] + i}: push rbp" for i in range(0, 0x20, 2))

    def get_xrefs_to(self, address):
        return [{"address": 0x401000, "type": "code", "function": self._function(0x401000)}]

    def get_entry_points(self):
        return [self._function(min(self.FUNCTIONS))]

    def set_decompiler_comment(self, address, comment):
        return "Comment set successfully"

    def set_disassembly_comment(self, address, comment):
        return "Comment set successfully"

    def rename_local_variable(self, function_address, old_name, new_name):
        fn = self._function(function_address)
        if fn is None:
            return f"No function found at address {function_address}"
        return f"Local variable {old_name} renamed to {new_name} in function {fn['address']}"

    def rename_function(self, function_address, new_name):
        fn = self._function(function_address)
        if fn is None:
            return f"No function found at address {function_address}"
        return f"Function {fn['address']} renamed to {new_name}"

    def set_function_prototype(self, function_address, prototype):
        fn = self._function(function_address)
        if fn is None:
            return f"No function found at address {function_address}"
        return "Function prototype set successfully"

    def save_idb_file(self, save_path):
        return f"Database saved to {save_path}"

    # ── helpers ─────────────────────────────────────────────────────────────

    def _function(self, address):
        entry = self.FUNCTIONS.get(address)
        if entry is None:
            return None
        return {
            "address": address,
            "end_address": address + 0x100,
            "name": entry[0],
            "prototype": entry[1],
        }

    def _record(self, op, **fields):
        """Append this call to the FAKE_IDA_RECORD_FILE (flushed immediately so
        even hard crashes keep earlier records)."""
        self._calls = getattr(self, "_calls", 0) + 1
        path = os.environ.get("FAKE_IDA_RECORD_FILE")
        if not path:
            return
        record = {"op": op, **fields}
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass


    def _pre_call(self, name):
        """Fault injection hook (runs before every public op method).

        FAKE_IDA_SLOW_OP_SECONDS accepts either "SECONDS" (slow every op) or
        "OPNAME:SECONDS" (slow one op — keeps the open ack's smoke-test calls
        unaffected when a test needs a hung op without slowing the open)."""
        slow = os.environ.get("FAKE_IDA_SLOW_OP_SECONDS")
        if slow:
            target, sep, secs = slow.partition(":")
            if not sep:
                time.sleep(float(slow))          # plain form: slow every op
            elif target == name:
                time.sleep(float(secs))          # "OP:N": slow this op only
        if os.environ.get("FAKE_IDA_CRASH_OP") == name:
            os._exit(1)               # simulate worker crash (no save, no reply)


def _instrument(cls):
    """Wrap every public op method with record + fault injection hooks.

    clean_up is excluded: it performs its own recording and hangs/faults.
    """
    for name in list(vars(cls)):
        if name.startswith("_") or name == "clean_up" or not callable(vars(cls)[name]):
            continue
        method = getattr(cls, name)

        @functools.wraps(method)
        def wrapper(self, *args, _method=method, _name=name, **kwargs):
            self._record(_name)
            if os.environ.get("FAKE_IDA_STDERR_LINE_BYTES"):
                # keep normal stderr lines flowing after the oversized one
                os.write(2, f"fake-op {_name}\n".encode())
            self._pre_call(_name)
            result = _method(self, *args, **kwargs)
            if os.environ.get("FAKE_IDA_UNSERIALIZABLE_OP") == _name:
                return object()           # exercises the worker's serialization guard
            return result

        setattr(cls, name, wrapper)
    return cls


_instrument(FakeIDA)
