# -*- coding: utf-8 -*-
"""Worker process: one idalib database per process, JSON lines over stdio.

Parent → worker request::

    {"id": 7, "op": "decompile_function", "args": {"address": 4198400}}

worker → parent response (exactly one per request ``id``)::

    {"id": 7, "ok": true,  "result": "int __fastcall main(...)"}
    {"id": 7, "ok": false, "error": "Decompilation failed at 4198400: ..."}

Startup only performs the fd hijack and touches **no** idalib code: the
database is opened when the first ``open`` request arrives, via
``open_backend(binary_path)`` which branches to the FAKE backend *before*
importing idalib. The idalib import order (idapro first, ida_* only after
``open_database``) is owned by ``open_backend`` and the helper loaders; the
rest of this module contains no idalib imports.

Exit paths (all funnel into the ``finally`` → ``graceful_exit(save_flag)``):

* ``close`` op          — carries its own ``save`` flag (saves, replies, exits)
* stdin EOF             — parent died: save (True) and exit (orphan protection)
* SIGTERM               — controlled ``GracefulExit``: save (True) and exit
* KeyboardInterrupt     — same as SIGTERM
* BrokenPipeError       — parent closed the pipe: same as EOF
"""
import json
import os
import signal
import sys
import traceback

ERROR_TRACEBACK_LIMIT = 2000

# Set when a database was successfully opened; guards graceful_exit() so every
# exit path closes the database exactly once.
_database_opened = False
_backend = None           # helper.IDA or fake_backend.FakeIDA once opened


class GracefulExit(Exception):
    """Raised by the SIGTERM handler (and used to unwind the main loop)."""


def _on_sigterm(signum, frame):
    """SIGTERM → controlled exit: the finally block in main() saves the DB.

    Only runs once the current op returns from C code; it cannot rescue an op
    stuck inside idalib (the parent's SIGKILL escalation covers that).
    """
    raise GracefulExit(f"SIGTERM ({signum}) received")


def _reinstall_signal_handlers() -> None:
    """(Re)take control of signal handling.

    idalib's init_library (run on ``import ida`` inside open_backend) installs
    TVision's own OS-level SIGTERM disposition, which ABORTS the process
    without saving ("TVision error: Stopped at signal 15", exit -6 — verified
    against real IDA 9.0). This worker is headless and owns the process, so the
    graceful-save handler must be re-installed after idalib initializes.
    """
    signal.signal(signal.SIGTERM, _on_sigterm)
    signal.signal(signal.SIGINT, signal.default_int_handler)


def open_backend(binary_path: str):
    """Construct the analysis backend for ``binary_path``.

    The FAKE branch must happen BEFORE any idalib import so CI can run the
    full protocol without a license or an IDA installation.
    """
    global _database_opened, _backend
    if os.environ.get("FAKE_IDA") == "1":
        from .fake_backend import FakeIDA
        _backend = FakeIDA(binary_path)
        _database_opened = True
        _reinstall_signal_handlers()
        return _backend
    # idalib import order: import idapro and open the database FIRST, only
    # then may the remaining ida_* modules be imported (helper loader).
    from . import helper
    idapro = helper._import_idapro()
    idapro.open_database(binary_path, True)
    helper._load_idalib_modules()
    _backend = helper.IDA()
    _database_opened = True
    # idalib's init_library replaced our SIGTERM handler (see docstring):
    # take it back or a ladder SIGTERM aborts the process without saving.
    _reinstall_signal_handlers()
    return _backend


def graceful_exit(save: bool) -> None:
    """Single funnel for all exit paths: ``close_database(save)``; no-op when
    no database was ever opened, and safe to call twice."""
    global _database_opened, _backend
    if not _database_opened:
        return
    _database_opened = False
    backend, _backend = _backend, None
    try:
        if backend is not None:
            backend.clean_up(save)
        else:
            helper._import_idapro().close_database(save)
    except Exception as e:  # never let cleanup break the exit path
        print(f"worker: error during close_database: {e}", file=sys.stderr)


def fmt_err(exc: BaseException) -> str:
    """Error string with a truncated traceback (cap ERROR_TRACEBACK_LIMIT)."""
    text = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
    if len(text) > ERROR_TRACEBACK_LIMIT:
        text = text[:ERROR_TRACEBACK_LIMIT] + "..."
    return text


# Whitelisted op → backend method mapping. Dispatch NEVER getattr's on
# arbitrary strings.
_OP_WHITELIST = {
    "get_function": "get_function",
    "get_function_by_name": "get_function_by_name",
    "get_function_by_address": "get_function_by_address",
    "get_image_size": "get_image_size",
    "list_functions": "list_functions",
    "decompile_function": "decompile_function",
    "disassemble_function": "disassemble_function",
    "get_xrefs_to": "get_xrefs_to",
    "get_entry_points": "get_entry_points",
    "set_decompiler_comment": "set_decompiler_comment",
    "set_disassembly_comment": "set_disassembly_comment",
    "rename_local_variable": "rename_local_variable",
    "rename_function": "rename_function",
    "set_function_prototype": "set_function_prototype",
    "save_idb_file": "save_idb_file",
}

_exit_after_reply = False
save_flag = True          # close op may override; all other exit paths keep True


def dispatch(op, args):
    """Dispatch one request; ``op`` must be whitelisted or one of the
    session-control ops (open / close / ping)."""
    global _exit_after_reply, save_flag
    if op == "open":
        if not isinstance(args, dict) or "binary_path" not in args:
            raise ValueError("op 'open' requires args.binary_path")
        if _database_opened:
            raise RuntimeError("a database is already open in this worker")
        backend = open_backend(str(args["binary_path"]))
        # open ack doubles as the "auto-analysis actually ran" smoke test —
        # and as a validity guard: idalib does NOT raise when database
        # initialization fails (e.g. loading an .id0 another worker holds),
        # it happily reports image_size = -1 and function_count = 0. Reject
        # that garbage instead of handing out a broken session.
        image_size = backend.get_image_size()
        function_count = backend.get_function_count()
        if not (0 < image_size < (1 << 47)):
            raise RuntimeError(
                f"database initialization failed for {args['binary_path']!r} "
                f"(image_size={image_size}, function_count={function_count}); "
                "the file may be locked by another IDA process or corrupted"
            )
        return {
            "image_size": image_size,
            "function_count": function_count,
        }
    if op == "close":
        save_flag = bool(args.get("save", True)) if isinstance(args, dict) else True
        # Save BEFORE replying, then reply "closed" and exit (design §5.4
        # ladder step 1): the parent's close wait (unbounded by default)
        # therefore covers the whole on-disk save.
        graceful_exit(save_flag)
        _exit_after_reply = True
        return "closed"
    if op == "ping":
        return "pong"
    method_name = _OP_WHITELIST.get(op)
    if method_name is None:
        raise ValueError(f"unknown op: {op!r}")
    if not isinstance(args, dict):
        raise TypeError(f"args must be a JSON object for op {op!r}")
    if _backend is None:
        raise RuntimeError(f"no database open (op {op!r} before 'open')")
    return getattr(_backend, method_name)(**args)


def main() -> None:
    global save_flag
    # ── process startup: fd hijack ONLY ─────────────────────────────────────
    # Rescue the real protocol channel (parent's pipe), then point fd 1 at
    # stderr: every C-level printf (IDA kernel) and every print() lands on
    # stderr from now on and the protocol stream can never be polluted.
    saved = os.dup(1)
    os.dup2(2, 1)
    proto = os.fdopen(saved, "w", encoding="utf-8")

    def write_reply(reply: dict) -> None:
        proto.write(json.dumps(reply, ensure_ascii=False) + "\n")
        proto.flush()

    signal.signal(signal.SIGTERM, _on_sigterm)
    signal.signal(signal.SIGINT, signal.default_int_handler)

    try:
        for line in sys.stdin:            # single-threaded sync loop
            rid = 0                       # preset default: no NameError below
            try:
                req = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"worker: malformed request line: {e}", file=sys.stderr)
                continue                  # never kill the worker (§4.1)
            if not isinstance(req, dict):
                print(f"worker: request is not a JSON object: {line[:200]!r}", file=sys.stderr)
                continue
            rid = req.get("id", 0)
            op = req.get("op")
            args = req.get("args", {})
            ok = True
            error = None
            try:
                result = dispatch(op, args)
            except GracefulExit:
                break                     # SIGTERM mid-op: exit without reply
            except Exception as e:
                ok = False
                error = fmt_err(e)
            try:
                if ok:
                    write_reply({"id": rid, "ok": True, "result": result})
                else:
                    write_reply({"id": rid, "ok": False, "error": error})
            except BrokenPipeError:
                break                     # parent is gone: same as EOF
            except Exception as e:
                # e.g. the op result is not JSON-serializable: report it as an
                # op error instead of killing the worker (its unsaved database
                # would be lost) and keep serving
                try:
                    write_reply({"id": rid, "ok": False, "error": fmt_err(e)})
                except BrokenPipeError:
                    break
            if not ok and op == "open":
                break                     # open failed: error delivered → exit
            if _exit_after_reply:
                break                     # close op: reply delivered → exit
    except KeyboardInterrupt:
        pass
    except GracefulExit:                 # SIGTERM while blocked reading stdin
        pass
    finally:
        graceful_exit(save_flag)
        try:
            proto.close()
        except BrokenPipeError:
            pass


if __name__ == "__main__":
    main()
