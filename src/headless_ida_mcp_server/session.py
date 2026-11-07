# -*- coding: utf-8 -*-
"""Parent-process session management: one worker subprocess per binary.

The parent (MCP server) NEVER imports idalib. Every analysis session is a
``headless_ida_mcp_server.worker`` child process speaking JSON lines over
stdin/stdout; sessions are addressed by ``session_id`` (1-based, LLM friendly).

Cross-session calls run in parallel (one worker process each); calls inside a
single session are serialized by ``call_lock`` (matching the IDA kernel's
single-threaded model). ``close``/``ping`` bypass ``call_lock`` and share the
session ``write_lock`` with normal calls so line frames never interleave.

Timeout philosophy: only OPEN has a timeout by default and it is size-aware
(``_open_timeout_for``); calls and saves wait as long as they legitimately
take, with optional per-call ``timeout=`` bounds for callers that want them.
Deadlock safety never depends on call timeouts — the close ladder owns a
bounded write_lock acquire plus SIGTERM/SIGKILL escalation, and a crashed
worker fails in-flight futures through the reader EOF path.
"""
from __future__ import annotations

import asyncio
import atexit
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from . import (DEAD_SESSION_RETENTION, MAX_RESPONSE_BYTES, MAX_SESSIONS, OPEN_TIMEOUT,
               OPEN_TIMEOUT_BASE, OPEN_TIMEOUT_MAX, OPEN_TIMEOUT_PER_MB, OPEN_TIMEOUT_POWER)
from .logger import logger

# ── close-ladder tuning knobs (seconds; module-level for test overriding) ────
_CLOSE_LOCK_TIMEOUT = 10.0    # §5.4 step 0: bounded write_lock acquire
_POST_CLOSE_EXIT_WAIT = 10.0   # worker replied to close: bounded wait for exit
_TERM_EXIT_WAIT = 5.0          # §5.4 step 2: wait for exit after SIGTERM


class WorkerError(RuntimeError):
    """A worker replied {"ok": false} to a request."""


def _open_timeout_for(binary_path: str) -> float:
    """Size-aware open timeout (seconds).

    IDA auto-analysis grows super-linearly with binary size, so a flat value
    either false-fails big samples or makes small broken ones wait forever.

    * ``OPEN_TIMEOUT`` env set to a positive number → flat override (escape hatch);
    * raw binary: ``BASE + PER_MB * MB ** POWER`` (default 120 + 6·MB^1.5):
        1 MB→2min, 10 MB→5min, 100 MB→1.7h;
    * ``.i64``/``.idb``: already analyzed, loading only → linear ``BASE + PER_MB·MB``;
    * capped at ``OPEN_TIMEOUT_MAX`` (default 24h) as a sanity ceiling.
    """
    if OPEN_TIMEOUT > 0:
        return OPEN_TIMEOUT
    try:
        size_mb = os.path.getsize(binary_path) / (1024 * 1024)
    except OSError:
        size_mb = 0.0
    if binary_path.lower().endswith((".i64", ".idb")):
        timeout = OPEN_TIMEOUT_BASE + OPEN_TIMEOUT_PER_MB * size_mb
    else:
        timeout = OPEN_TIMEOUT_BASE + OPEN_TIMEOUT_PER_MB * (size_mb ** OPEN_TIMEOUT_POWER)
    return min(timeout, OPEN_TIMEOUT_MAX)


def _silence_future_exception(fut: asyncio.Future) -> None:
    """Mark a future's exception as retrieved (avoids 'exception was never
    retrieved' GC noise for futures abandoned by a timeout)."""
    if not fut.cancelled():
        try:
            fut.exception()
        except Exception:
            pass


def _silence_abandoned_future(fut: asyncio.Future) -> None:
    """Retrieve an abandoned future's exception now (already done) or later."""
    if fut.done():
        _silence_future_exception(fut)
    else:
        fut.add_done_callback(_silence_future_exception)


@dataclass
class Session:
    id: int
    binary_path: str                       # already abspath (raw binary or .i64)
    proc: asyncio.subprocess.Process
    pending: dict[int, asyncio.Future] = field(default_factory=dict)
    open_future: Optional[asyncio.Future] = None   # STARTING only; shared by concurrent idempotent opens
    open_result: Optional[dict] = None
    open_rid: Optional[int] = None                 # request id of the in-flight open
    open_timeout: float = 0.0                      # size-aware timeout computed at spawn
    open_deadline: float = 0.0             # monotonic deadline for the open
    call_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    state: str = "STARTING"                # STARTING / READY / DEAD
    close_reason: Optional[str] = None     # closed/crashed/timeout-killed/term-killed/protocol-error
    reader_alive: bool = True
    opened_at: float = field(default_factory=time.time)
    next_id: int = 0                       # restart resets to 0 (old pending all failed)
    generation: int = 0                    # incremented on restart; old reader tasks become inert
    closing_task: Optional[asyncio.Task] = None     # dedupe/ownership of the close ladder


class SessionManager:
    """Owns all worker processes and the session lifecycle."""

    def __init__(self):
        self.sessions: dict[int, Session] = {}
        self._path_index: dict[str, int] = {}       # abspath → session_id (STARTING/READY only)
        self._open_lock = asyncio.Lock()            # serializes lookup+spawn+register
        self._shutting_down = False                 # open/restart rejected while set
        self._next_session_id = 0
        self._atexit_registered = False
        self._tasks: set[asyncio.Task] = set()      # strong refs for background tasks

    # ── public API ───────────────────────────────────────────────────────────

    async def open_session(self, binary_path: str) -> int:
        """Open (or reuse) a worker for ``binary_path``; returns the session id.

        Idempotent per abspath; concurrent opens of the same path share the
        in-flight open future instead of spawning a second worker.
        """
        if not os.path.exists(binary_path):
            raise ValueError(f"binary path does not exist: {binary_path}")
        # realpath (not abspath): the idempotency key must survive symlinks,
        # relative paths and // variants — two workers on one file corrupt the
        # unpacked .id0/.id1 database IDA keeps next to the input (verified:
        # "Read error. The database is corrupted beyond repair" + a garbage
        # open ack with image_size=-1).
        apath = os.path.realpath(binary_path)
        async with self._open_lock:
            if self._shutting_down:
                raise RuntimeError("session manager is shutting down; open_session is rejected")
            session: Session | None = None
            shared: asyncio.Future | None = None
            existing_id = self._path_index.get(apath)
            if existing_id is not None:
                session = self.sessions[existing_id]
                if session.state == "READY":
                    return existing_id                     # idempotent hit
                if session.state == "STARTING":
                    shared = session.open_future           # share the open in flight
            if shared is None:
                if self._active_count() >= MAX_SESSIONS:
                    raise ValueError(
                        f"session limit reached: MAX_SESSIONS={MAX_SESSIONS} "
                        f"active={self._active_count()} "
                        f"({', '.join(f'{s.id}:{os.path.basename(s.binary_path)}' for s in self.sessions.values() if s.state != 'DEAD')}); "
                        "close a session with close_session first"
                    )
                self._next_session_id += 1
                session = Session(id=self._next_session_id, binary_path=apath,
                                  proc=None)  # type: ignore[arg-type]
                # register only AFTER a successful spawn: a failed
                # create_subprocess_exec must not leave a STARTING zombie
                # (proc=None) behind — it would permanently occupy a
                # MAX_SESSIONS slot and break close_session's STARTING path
                await self._start(session)                 # spawn + open request sent
                self.sessions[session.id] = session
                shared = session.open_future
        assert session is not None
        # Wait OUTSIDE _open_lock so opens of different paths proceed in parallel.
        try:
            ack = await asyncio.wait_for(asyncio.shield(shared), session.open_timeout)
        except asyncio.TimeoutError:
            await self._close_ladder(session, save=False, reason="crashed", send_close=False)
            # the worker's death will fail open_future asynchronously; mark the
            # exception as retrieved to avoid "never retrieved" noise at GC
            _silence_abandoned_future(shared)
            raise TimeoutError(
                f"open of {apath} timed out after {session.open_timeout:.0f}s "
                "(auto-analysis of large samples can take much longer; the timeout "
                "is size-aware — tune OPEN_TIMEOUT_BASE/OPEN_TIMEOUT_PER_MB or set "
                "OPEN_TIMEOUT for a flat override)"
            ) from None
        except WorkerError as e:
            await self._close_ladder(session, save=False, reason="crashed", send_close=False)
            raise RuntimeError(f"open failed for {apath}: {e}") from e
        except asyncio.CancelledError:
            raise
        except Exception as e:                             # pipe broken, EOF, ...
            await self._close_ladder(session, save=False, reason="crashed", send_close=False)
            raise RuntimeError(f"open failed for {apath}: {e}") from e
        finally:
            if session.open_rid is not None:
                session.pending.pop(session.open_rid, None)
        if session.state == "DEAD":                       # e.g. protocol error raced the open
            raise RuntimeError(f"session {session.id} died while opening ({session.close_reason})")
        session.state = "READY"
        session.open_result = ack
        logger.info("[session %d] ready: %s (image_size=%s, function_count=%s)",
                    session.id, apath, ack.get("image_size"), ack.get("function_count"))
        return session.id

    async def call(self, session_id: int, op: str, args: dict, timeout: float | None = None) -> Any:
        """Route one op to a session's worker; end-to-end timeout (queue + write +
        drain + wait for the response all count toward it)."""
        return await self._call(session_id, op, args, timeout=timeout, bypass_call_lock=False)

    async def ping_session(self, session_id: int) -> str:
        """Protocol responsiveness check. NOT a liveness check: while a worker
        runs a long op, ping queues behind it. Use list_sessions for liveness."""
        return await self._call(session_id, "ping", {}, bypass_call_lock=True)

    async def close_session(self, session_id: int, save: bool = True, timeout: float | None = None):
        """Close a session. Idempotent: DEAD → no-op. STARTING → waits for the
        open to finish first (open_database runs in C and cannot be
        interrupted; killing it leaves a stale .i64 lock — design §7-7).

        ``timeout`` (seconds) optionally bounds the close/save wait; by default
        a database save takes as long as it takes (GB-scale .i64 files need
        minutes — a fixed bound would SIGKILL them half-written). The bounded
        write_lock acquire and the SIGTERM/SIGKILL escalation inside the close
        ladder are what guarantee progress, not this timeout.
        """
        session = self._get(session_id)
        if session.state == "DEAD":
            return f"already dead: {session.close_reason}"
        if session.state == "STARTING":
            remaining = max(0.0, session.open_deadline - time.monotonic())
            try:
                await asyncio.wait_for(asyncio.shield(session.open_future), remaining)
            except asyncio.TimeoutError:
                # open is still stuck inside native code: SIGTERM then SIGKILL
                await self._close_ladder(session, save=save, reason="timeout-killed", send_close=False)
                _silence_abandoned_future(session.open_future)
                return (f"session {session_id} killed: open still running after OPEN_TIMEOUT "
                        f"(close_reason: {session.close_reason})")
            except asyncio.CancelledError:
                raise
            except Exception:
                # open failed; open_session's failure path already runs the ladder
                return f"already dead: {session.close_reason}"
            # open succeeded → the session is READY now (set by open_session)
        reason = await self._close_ladder(session, save=save, close_timeout=timeout)
        return f"session {session_id} closed (close_reason: {reason})"

    async def restart_session(self, session_id: int, force: bool = False):
        """Restart a DEAD session under the SAME id (conversation history keeps
        pointing at it). READY requires force=True (runs the full close ladder,
        saving first). Data semantics: recovery to the last PERSISTED state —
        reopening the raw binary re-runs auto-analysis (unsaved edits lost);
        reopening a .i64 keeps everything ever saved via save_idb_file."""
        if self._shutting_down:
            raise RuntimeError("session manager is shutting down; restart_session is rejected")
        session = self._get(session_id)
        if session.state == "STARTING":
            raise ValueError(f"session {session_id} is still starting; wait for open_session to finish first")
        if session.state == "READY":
            if not force:
                raise ValueError(
                    f"session {session_id} is READY; pass force=True to restart it "
                    "(the database is saved and closed first)"
                )
            await self.close_session(session_id, save=True)
        # Same-abspath conflict check: two workers on one path → .i64 lock clash
        async with self._open_lock:
            if self._shutting_down:
                raise RuntimeError("session manager is shutting down; restart_session is rejected")
            if session.state != "DEAD":
                # re-check INSIDE the lock: two concurrent restarts of the same
                # id both passed the pre-lock state check — the loser must be
                # rejected, or the second _start would overwrite session.proc
                # and orphan the first worker (which still holds the .id0)
                raise RuntimeError(
                    f"session {session_id} is {session.state} (a concurrent restart won); "
                    "call list_sessions to see its current state")
            other_id = self._path_index.get(session.binary_path)
            if other_id is not None and other_id != session_id:
                raise ValueError(
                    f"cannot restart session {session_id}: {session.binary_path} is already open "
                    f"in session {other_id} (use that session instead)"
                )
            await self._start(session)     # respawn + open request, same session id
        try:
            ack = await asyncio.wait_for(asyncio.shield(session.open_future), session.open_timeout)
        except asyncio.TimeoutError:
            await self._close_ladder(session, save=False, reason="crashed", send_close=False)
            _silence_abandoned_future(session.open_future)
            raise TimeoutError(f"restart of session {session_id} ({session.binary_path}) "
                               f"timed out after {session.open_timeout:.0f}s") from None
        except asyncio.CancelledError:
            raise
        except Exception as e:
            await self._close_ladder(session, save=False, reason="crashed", send_close=False)
            raise RuntimeError(f"restart of session {session_id} failed: {e}") from e
        finally:
            if session.open_rid is not None:
                session.pending.pop(session.open_rid, None)
        session.state = "READY"
        session.open_result = ack
        logger.info("[session %d] restarted: %s", session.id, session.binary_path)
        return f"session {session_id} restarted ({session.binary_path})"

    def list_sessions(self) -> list[dict]:
        """Session table including DEAD history (close_reason) for the LLM."""
        out = []
        for s in self.sessions.values():
            out.append({
                "session_id": s.id,
                "binary_path": s.binary_path,
                "pid": s.proc.pid if s.proc is not None else None,
                "state": s.state,
                "close_reason": s.close_reason,
                "rss_bytes": self._rss_bytes(s) if s.state != "DEAD" else None,
                "opened_at": datetime.fromtimestamp(s.opened_at).isoformat(
                    sep=" ", timespec="seconds"),
            })
        return out

    async def shutdown_all(self):
        """Parallel close ladder for every live session (FastMCP lifespan and
        atexit fallback both end up here)."""
        self._shutting_down = True
        targets = [s for s in self.sessions.values() if s.state != "DEAD"]

        async def _one(s: Session):
            if s.state == "STARTING":
                # Nothing to save yet; open_database cannot be interrupted from
                # Python, so go straight to SIGTERM/SIGKILL (no orphan workers).
                await self._close_ladder(s, save=False, reason="crashed", send_close=False)
            else:
                await self._close_ladder(s, save=True)

        if targets:
            await asyncio.gather(*(_one(s) for s in targets), return_exceptions=True)

    # ── internals ───────────────────────────────────────────────────────────

    def _get(self, session_id: int) -> Session:
        session = self.sessions.get(session_id)
        if session is None:
            raise ValueError(f"session {session_id} not found, "
                             "call list_sessions to see available sessions")
        return session

    def _active_count(self) -> int:
        return sum(1 for s in self.sessions.values() if s.state != "DEAD")

    async def _call(self, session_id: int, op: str, args: dict,
                    timeout: float | None = None, bypass_call_lock: bool = False) -> Any:
        """Route one op to a session's worker.

        No timeout by default: analysis ops legitimately run for minutes and a
        fixed bound would fail them while they still execute. Callers that want
        a bound pass ``timeout``; when set it is END-TO-END (lock queueing +
        write + drain + response wait all count). Deadlock safety never depends
        on it — the close ladder's bounded write_lock + SIGTERM/SIGKILL
        escalation recover a hung worker, and a crashed worker fails the
        in-flight future via the reader EOF path.
        """
        session = self._get(session_id)
        if session.state != "READY":
            raise ValueError(
                f"session {session_id} is {session.state}"
                + (f" (close_reason: {session.close_reason})" if session.close_reason else "")
                + "; call restart_session to restart it, or open_session for a new binary"
            )
        if session.closing_task is not None:
            raise RuntimeError(f"session {session_id} is closing")

        async def _span() -> Any:
            if not bypass_call_lock:
                await session.call_lock.acquire()
            try:
                session.next_id += 1
                rid = session.next_id
                fut: asyncio.Future = asyncio.get_running_loop().create_future()
                session.pending[rid] = fut
                try:
                    try:
                        async with session.write_lock:    # write+drain atomic pair (§4.3)
                            line = json.dumps({"id": rid, "op": op, "args": args},
                                              ensure_ascii=False).encode("utf-8") + b"\n"
                            session.proc.stdin.write(line)
                            await session.proc.stdin.drain()
                    except Exception as e:
                        raise RuntimeError(
                            f"session {session_id}: failed to send op {op!r} "
                            f"(worker pipe broken?): {e}"
                        ) from e
                    return await fut
                finally:
                    session.pending.pop(rid, None)
            finally:
                if not bypass_call_lock:
                    session.call_lock.release()

        if timeout is None:
            return await _span()               # wait as long as the op takes
        try:
            # Explicit end-to-end timeout: lock acquisition (queueing), write,
            # drain and the response wait ALL count — a hung drain can never
            # hold both locks forever (design v1.2 D1).
            return await asyncio.wait_for(_span(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"session {session_id} call timed out after {timeout}s; "
                "the operation may still have been executed"
            ) from None

    async def _start(self, session: Session) -> None:
        """(Re)spawn the worker for ``session`` and send the open request."""
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-u", "-m", "headless_ida_mcp_server.worker",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=MAX_RESPONSE_BYTES,          # default 64KB would explode on big responses (§4.1)
            env=env,
        )
        session.proc = proc
        session.pending = {}
        session.open_future = None
        session.open_result = None
        session.call_lock = asyncio.Lock()
        session.write_lock = asyncio.Lock()
        session.state = "STARTING"
        session.close_reason = None
        session.reader_alive = True
        session.closing_task = None
        session.opened_at = time.time()
        session.next_id = 0                   # old pending are all failed already
        session.generation += 1
        session.open_timeout = _open_timeout_for(session.binary_path)
        session.open_deadline = time.monotonic() + session.open_timeout
        self._index(session)
        self._spawn_task(self._reader_task(session), f"session-{session.id}-reader")
        self._spawn_task(self._stderr_task(session), f"session-{session.id}-stderr")
        self._register_atexit_guard()

        # open request = first protocol call (rid 1)
        session.next_id += 1
        rid = session.next_id
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        session.pending[rid] = fut
        session.open_future = fut
        session.open_rid = rid
        try:
            async with session.write_lock:
                line = json.dumps({"id": rid, "op": "open",
                                   "args": {"binary_path": session.binary_path}},
                                  ensure_ascii=False).encode("utf-8") + b"\n"
                proc.stdin.write(line)
                await proc.stdin.drain()
        except Exception as e:
            if not fut.done():
                fut.set_exception(RuntimeError(f"failed to send open request: {e}"))
        logger.info("[session %d] worker spawned (pid %s) for %s", session.id, proc.pid, session.binary_path)

    def _spawn_task(self, coro, name: str) -> None:
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _index(self, session: Session) -> None:
        self._path_index[session.binary_path] = session.id

    def _unindex(self, session: Session) -> None:
        if self._path_index.get(session.binary_path) == session.id:
            del self._path_index[session.binary_path]

    def _rss_bytes(self, session: Session) -> Optional[int]:
        if session.proc is None:
            return None
        try:
            with open(f"/proc/{session.proc.pid}/status", "r") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            return None
        return None

    def _register_atexit_guard(self) -> None:
        """Synchronous last-resort orphan guard: broadcast SIGTERM at exit.

        The primary path is the FastMCP lifespan shutdown (loop still alive →
        full close ladder). This atexit hook only matters on abnormal exits
        where the lifespan never ran: it never waits, workers finish saving via
        their own SIGTERM handler / stdin-EOF path."""
        if self._atexit_registered:
            return
        self._atexit_registered = True

        def _sigterm_all():
            for s in self.sessions.values():
                if s.state != "DEAD" and s.proc is not None and s.proc.returncode is None:
                    try:
                        os.kill(s.proc.pid, signal.SIGTERM)
                    except (ProcessLookupError, PermissionError):
                        pass

        atexit.register(_sigterm_all)

    # ── background IO tasks ─────────────────────────────────────────────────

    async def _reader_task(self, session: Session) -> None:
        """Pump worker stdout: resolve pending futures by response id."""
        gen = session.generation
        proc = session.proc
        protocol_error: Optional[str] = None
        cancelled = False
        try:
            while True:
                try:
                    raw = await proc.stdout.readline()
                except (ValueError, asyncio.LimitOverrunError) as exc:
                    # Single line exceeds MAX_RESPONSE_BYTES → protocol error.
                    protocol_error = f"response line exceeds MAX_RESPONSE_BYTES: {exc}"
                    break
                if not raw:
                    break                                     # EOF: worker exited
                try:
                    msg = json.loads(raw.decode("utf-8", errors="replace"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    logger.warning("[session %d] dropping malformed response line", session.id)
                    continue
                if not isinstance(msg, dict):
                    logger.warning("[session %d] dropping non-object response line", session.id)
                    continue
                rid = msg.get("id")
                fut = session.pending.get(rid) if isinstance(rid, int) else None
                if fut is None or fut.done():
                    # late response (call already timed out) or unknown id: drop
                    logger.debug("[session %d] late/unknown response id=%r dropped", session.id, rid)
                    continue
                try:
                    if msg.get("ok"):
                        fut.set_result(msg.get("result"))
                    else:
                        fut.set_exception(WorkerError(str(msg.get("error", "unknown worker error"))))
                except asyncio.InvalidStateError:
                    pass    # future cancelled meanwhile (timeout race)
        except asyncio.CancelledError:
            # Teardown of a still-live session (e.g. event loop closing while
            # the session was never closed): do NOT await anything in the
            # finally below — proc.wait() would block the loop shutdown forever.
            cancelled = True
            raise
        except Exception:
            logger.exception("[session %d] reader task crashed", session.id)
            protocol_error = protocol_error or "reader task crashed"
        finally:
            if not cancelled:
                await self._reader_exited(session, gen, protocol_error)

    async def _reader_exited(self, session: Session, gen: int, protocol_error: Optional[str]) -> None:
        if session.generation != gen:
            return                       # stale reader of a previous worker incarnation
        if protocol_error is not None:
            logger.warning("[session %d] protocol error, closing session: %s", session.id, protocol_error)
            session.reader_alive = False
            self._fail_all_pending(session, f"protocol error in session {session.id}: {protocol_error}")
            # reader is dead → ladder skips the "wait for close response" step
            # and SIGTERMs directly (the worker's SIGTERM handler still saves)
            await self._close_ladder(session, save=True, reason="protocol-error")
            return
        self._fail_all_pending(session, f"worker exited (session {session.id}, pid {session.proc.pid})")
        if session.closing_task is not None:
            return                       # a close ladder owns reaping + final state
        try:
            await session.proc.wait()    # reap: no zombie processes
        except Exception:
            pass
        self._mark_dead(session, "crashed")

    async def _stderr_task(self, session: Session) -> None:
        """Relay worker stderr to the logger, prefixed [session N].

        This task must NEVER die: if it did, the stderr pipe would fill up and
        IDA's native printf would block the worker's main thread, freezing the
        whole session. Oversized lines are discarded (asyncio already clears
        the buffer) and reading continues to the next newline (§5.2.2)."""
        proc = session.proc
        prefix = f"[session {session.id}]"
        while True:
            try:
                raw = await proc.stderr.readline()
            except (ValueError, asyncio.LimitOverrunError):
                logger.debug("%s discarded oversized stderr line", prefix)
                continue
            if not raw:
                return                    # EOF: worker stderr closed
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if text:
                logger.info("%s %s", prefix, text)

    def _fail_all_pending(self, session: Session, message: str) -> None:
        pending = list(session.pending.items())
        session.pending.clear()
        for _, fut in pending:
            if not fut.done():
                try:
                    fut.set_exception(RuntimeError(message))
                except asyncio.InvalidStateError:
                    pass

    # ── close ladder (§5.4) ──────────────────────────────────────────────────

    async def _close_ladder(self, session: Session, save: bool = True,
                            reason: Optional[str] = None, send_close: bool = True,
                            close_timeout: float | None = None) -> str:
        """The ONE path that turns a session DEAD (idempotent, deduplicated).

        0. bounded write_lock acquire (10s)      — stuck holder → skip to SIGTERM
        1. send {"op":"close","save":...}, wait  — unbounded by default (a save
           takes as long as it takes); ``close_timeout`` bounds it when given;
           skipped entirely when the reader is dead (nobody would parse the
           response anyway)
        2. SIGTERM (worker saves gracefully)     — wait _TERM_EXIT_WAIT for exit
        3. SIGKILL                               — data loss, no orphan
        4. await proc.wait() → DEAD, record close_reason, unindex

        A worker hung inside a never-returning op/save with no close_timeout
        makes step 1 wait indefinitely; the documented escape hatch is killing
        the pid from list_sessions (the reader EOF path then fails the close
        request and the ladder reaps the process).
        """
        if session.state == "DEAD":
            return session.close_reason or "closed"
        if session.closing_task is None:   # atomic on the event loop: no await between
            session.closing_task = asyncio.create_task(
                self._ladder_body(session, save=save, reason=reason, send_close=send_close,
                                  close_timeout=close_timeout),
                name=f"session-{session.id}-close-ladder")
        try:
            await session.closing_task
        except asyncio.CancelledError:
            raise
        except Exception:
            pass                            # ladder body already logged; state is final
        return session.close_reason or "closed"

    async def _ladder_body(self, session: Session, save: bool,
                           reason: Optional[str], send_close: bool,
                           close_timeout: Optional[float]) -> None:
        proc = session.proc
        try:
            reply_ok = False
            if send_close and session.reader_alive:
                reply_ok = await self._send_close_and_wait(session, save, close_timeout)
                if reply_ok:
                    try:                    # worker replied: it must exit now
                        await asyncio.wait_for(proc.wait(), _POST_CLOSE_EXIT_WAIT)
                        self._mark_dead(session, reason or "closed")
                        return
                    except TimeoutError:
                        pass                # fell over somewhere after replying
            # SIGTERM (worker's handler saves and exits)
            if proc.returncode is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(proc.wait(), _TERM_EXIT_WAIT)
                    self._mark_dead(session, reason or "term-killed")
                    return
                except TimeoutError:
                    pass
            elif session.state != "DEAD" and not reply_ok and reason is None:
                # exited by itself while we were closing (e.g. crashed mid-save)
                self._mark_dead(session, "crashed")
                return
            # SIGKILL
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            try:
                await proc.wait()
            except Exception:
                pass
            if session.state != "DEAD":
                self._mark_dead(session, reason or ("timeout-killed" if send_close else "term-killed"))
        except Exception:
            logger.exception("[session %d] close ladder failed", session.id)
            if session.state != "DEAD":
                self._mark_dead(session, reason or "crashed")

    async def _send_close_and_wait(self, session: Session, save: bool,
                                   timeout: float | None = None) -> bool:
        """Steps 0+1 of the ladder. Returns True if the worker replied.

        The reply wait is UNBOUNDED by default: the worker first drains any
        queued ops and then runs close_database, and a GB-scale .i64 save
        legitimately takes minutes — cutting it off would SIGKILL a half-written
        database. ``timeout`` bounds the wait for callers that want it.
        """
        try:
            acquired = await asyncio.wait_for(session.write_lock.acquire(), _CLOSE_LOCK_TIMEOUT)
        except TimeoutError:
            logger.warning("[session %d] write_lock stuck >%.0fs; skipping close op, escalating",
                           session.id, _CLOSE_LOCK_TIMEOUT)
            return False
        # allocate the request and write+drain under the lock (§4.3: the lock
        # covers exactly the atomic write+drain pair, nothing more)
        try:
            session.next_id += 1
            rid = session.next_id
            fut: asyncio.Future = asyncio.get_running_loop().create_future()
            session.pending[rid] = fut
            try:
                line = json.dumps({"id": rid, "op": "close", "args": {"save": bool(save)}},
                                  ensure_ascii=False).encode("utf-8") + b"\n"
                session.proc.stdin.write(line)
                await session.proc.stdin.drain()
            except Exception as e:
                logger.warning("[session %d] failed to send close op: %r", session.id, e)
                return False
        finally:
            session.write_lock.release()
        # response wait happens OUTSIDE the lock; shield keeps the future alive
        # if this close_session caller is itself cancelled
        try:
            if timeout is None:
                await asyncio.shield(fut)
            else:
                await asyncio.wait_for(asyncio.shield(fut), timeout)
            return True
        except TimeoutError:
            logger.warning("[session %d] no close response within %ss; escalating",
                           session.id, timeout)
            return False
        except Exception as e:
            logger.warning("[session %d] worker died before close completed: %r", session.id, e)
            return False
        finally:
            session.pending.pop(rid, None)

    def _mark_dead(self, session: Session, reason: str) -> None:
        session.state = "DEAD"
        if session.close_reason is None:
            session.close_reason = reason
        self._unindex(session)
        self._prune_dead_tombstones()
        logger.info("[session %d] dead (%s)", session.id, session.close_reason)

    def _prune_dead_tombstones(self) -> None:
        """Bound the DEAD-session records kept for history / restart_session.

        A tombstone is metadata only (the worker process and its database are
        already released), so the cost per entry is tiny — but an unbounded
        list makes `list_sessions` output grow forever on a long-lived
        server. Keep the newest DEAD_SESSION_RETENTION entries (oldest are
        dropped; restart_session on a dropped id then reports "not found"),
        -1 disables pruning entirely.
        """
        if DEAD_SESSION_RETENTION < 0:
            return
        dead = sorted((s for s in self.sessions.values() if s.state == "DEAD"),
                      key=lambda s: s.id)
        excess = len(dead) - DEAD_SESSION_RETENTION
        for stale in dead[:max(0, excess)]:
            self.sessions.pop(stale.id, None)
