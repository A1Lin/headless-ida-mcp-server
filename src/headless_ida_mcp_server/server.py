# -*- coding: utf-8 -*-
"""MCP tool surface for headless-ida-mcp-server ≥ 0.3.0 (multi-session).

Every binary is analyzed in a dedicated worker subprocess (one idalib
database per process); tools route by ``session_id``. THIS process never
imports idalib — the session lifecycle lives in ``session.py``.

Workflow for agents:

1. ``open_session(path)`` → ``session_id`` (+ image size / function count)
2. pass that ``session_id`` as the first parameter of every analysis tool
3. ``close_session(session_id)`` when done (``save=True`` persists edits)

Sessions survive tool calls (workers stay resident); multiple binaries can be
open at the same time and are analyzed in parallel.
"""
import argparse
from contextlib import asynccontextmanager
from typing import Optional, Annotated

from mcp.server import FastMCP
from mcp.server.fastmcp.prompts import base

from headless_ida_mcp_server.logger import logger
from headless_ida_mcp_server.session import SessionManager, apply_cli_overrides

sessions = SessionManager()


@asynccontextmanager
async def _lifespan(app):
    """Guaranteed worker shutdown on server exit (design §5.4 main path).

    Runs while the event loop is still alive (SSE/uvicorn and stdio both
    execute the lifespan), so awaiting ``proc.wait()`` is legal here. The
    synchronous atexit SIGTERM broadcast in session.py is only a fallback for
    abnormal exits where the lifespan never ran.
    """
    try:
        yield
    finally:
        await sessions.shutdown_all()


# port default lives here (a --port flag still overrides it via settings);
# host keeps FastMCP's own default (127.0.0.1), overridable with --host.
mcp = FastMCP("IDA MCP Server", port=8888, lifespan=_lifespan)


# ── session lifecycle tools ─────────────────────────────────────────────────

@mcp.tool()
async def open_session(path: Annotated[str, "Path to the binary file (raw binary or .i64) to analyze"]):
    """Open a new analysis session for a binary (or reuse the existing session
    for that path). Returns the session_id that every other tool requires.
    First open of a large binary can take minutes (auto-analysis)."""
    session_id = await sessions.open_session(path)
    ack = sessions.sessions[session_id].open_result or {}
    return {
        "session_id": session_id,
        "image_size": ack.get("image_size"),
        "function_count": ack.get("function_count"),
    }

@mcp.tool()
async def close_session(session_id: Annotated[int, "ID of the session to close"],
                        save: Annotated[bool, "Save the database to disk before closing"] = True):
    """Close an analysis session and shut its worker process down. Set
    save=False to discard unsaved renames/comments. Idempotent."""
    return await sessions.close_session(session_id, save)

@mcp.tool()
def list_sessions() -> list[dict]:
    """List all sessions (live and dead), with pid, state, close_reason and
    RSS. Use this to discover session ids or to check whether a worker crashed."""
    return sessions.list_sessions()

@mcp.tool()
async def restart_session(session_id: Annotated[int, "ID of the session to restart"],
                          force: Annotated[bool, "Required when the session is still READY: saves and closes it first"] = False):
    """Restart a crashed/closed session under the SAME session_id. The database
    reopens from its last persisted state (a raw binary re-runs auto-analysis;
    a .i64 keeps everything ever saved). Pass force=True to restart a live session."""
    return await sessions.restart_session(session_id, force)

@mcp.tool()
async def ping_session(session_id: Annotated[int, "ID of the session to ping"]):
    """Health check for the session's protocol channel. Queues behind any
    long-running operation (it is a responsiveness check, not a liveness check;
    use list_sessions for liveness)."""
    return await sessions.ping_session(session_id)


# ── analysis tools (one session per binary; worker executes them serially) ──

@mcp.tool()
async def get_function(session_id: Annotated[int, "ID of the session"],
                       address: Annotated[int, "Address of the function"]):
    """Get a function by address"""
    return await sessions.call(session_id, "get_function", {"address": address})

@mcp.tool()
async def get_function_by_name(session_id: Annotated[int, "ID of the session"],
                               name: Annotated[str, "Name of the function"]):
    """Get a function by name"""
    return await sessions.call(session_id, "get_function_by_name", {"name": name})

@mcp.tool()
async def get_function_by_address(session_id: Annotated[int, "ID of the session"],
                                  address: Annotated[int, "Address of the function"]):
    """Get a function by address"""
    return await sessions.call(session_id, "get_function_by_address", {"address": address})

@mcp.tool()
async def get_image_size(session_id: Annotated[int, "ID of the session"]):
    """Get the size of the binary image loaded in this session"""
    return await sessions.call(session_id, "get_image_size", {})

@mcp.tool()
async def list_functions(session_id: Annotated[int, "ID of the session"]):
    """List all functions in this session's binary. Can be a very large
    response for big binaries."""
    return await sessions.call(session_id, "list_functions", {})

@mcp.tool()
async def decompile_function(session_id: Annotated[int, "ID of the session"],
                             address: Annotated[int, "Address of the function to decompile"]):
    """Decompile a function at the given address"""
    return await sessions.call(session_id, "decompile_function", {"address": address})

@mcp.tool()
async def disassemble_function(session_id: Annotated[int, "ID of the session"],
                               address: Annotated[int, "Address of the function to disassemble"]):
    """Disassemble a function at the given address"""
    return await sessions.call(session_id, "disassemble_function", {"address": address})

@mcp.tool()
async def get_xrefs_to(session_id: Annotated[int, "ID of the session"],
                       address: Annotated[int, "Address to get cross references to"]):
    """Get cross references to a given address"""
    return await sessions.call(session_id, "get_xrefs_to", {"address": address})

@mcp.tool()
async def get_entry_points(session_id: Annotated[int, "ID of the session"]):
    """Get all entry points of this session's binary"""
    return await sessions.call(session_id, "get_entry_points", {})

@mcp.tool()
async def set_decompiler_comment(session_id: Annotated[int, "ID of the session"],
                                address: Annotated[int, "Address in the function to set the comment for"],
                                comment: Annotated[str, "Comment text (not shown in the disassembly)"]):
    """Set a comment for a given address in the function pseudocode"""
    return await sessions.call(session_id, "set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
async def set_disassembly_comment(session_id: Annotated[int, "ID of the session"],
                                  address: Annotated[int, "Address in the function to set the comment for"],
                                  comment: Annotated[str, "Comment text (not shown in the pseudocode)"]):
    """Set a comment for a given address in the function disassembly"""
    return await sessions.call(session_id, "set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
async def rename_local_variable(session_id: Annotated[int, "ID of the session"],
                                function_address: Annotated[int, "Address of the function containing the variable"],
                                old_name: Annotated[str, "Current name of the variable"],
                                new_name: Annotated[str, "New name for the variable"]):
    """Rename a local variable in a function"""
    return await sessions.call(session_id, "rename_local_variable",
                               {"function_address": function_address, "old_name": old_name, "new_name": new_name})

@mcp.tool()
async def rename_function(session_id: Annotated[int, "ID of the session"],
                          function_address: Annotated[int, "Address of the function to rename"],
                          new_name: Annotated[str, "New name for the function"]):
    """Rename a function"""
    return await sessions.call(session_id, "rename_function",
                               {"function_address": function_address, "new_name": new_name})

@mcp.tool()
async def set_function_prototype(session_id: Annotated[int, "ID of the session"],
                                function_address: Annotated[int, "Address of the function"],
                                prototype: Annotated[str, "New function prototype"]):
    """Set a function's prototype"""
    return await sessions.call(session_id, "set_function_prototype",
                               {"function_address": function_address, "prototype": prototype})

@mcp.tool()
async def save_idb_file(session_id: Annotated[int, "ID of the session"],
                        save_path: Annotated[str, "Path to save the IDB file"]):
    """Save the session's database to an IDB file (persist renames/comments/
    prototypes; also the recommended way to avoid losing edits)."""
    return await sessions.call(session_id, "save_idb_file", {"save_path": save_path})


# ── parent-side pure utility (no IPC, no session) ───────────────────────────

@mcp.tool()
def convert_number(text: Annotated[str, "Textual representation of the number to convert"],
                   size: Annotated[Optional[int], "Size of the variable in bytes"] = None):
    """Convert a number (decimal, hexadecimal) to different representations
    (decimal, hex, bytes, ascii, binary)"""
    try:
        value = int(text, 0)
    except ValueError:
        return f"Invalid number: {text}"

    # Estimate the size of the number
    if not size:
        size = 0
        n = abs(value)
        while n:
            size += 1
            n >>= 1
        size += 7
        size //= 8

    # Convert the number to bytes
    try:
        raw = value.to_bytes(size, "little", signed=True)
    except OverflowError:
        return f"Number {text} is too big for {size} bytes"

    # Convert the bytes to ASCII
    ascii_repr = ""
    for byte in raw.rstrip(b"\x00"):
        if byte >= 32 and byte <= 126:
            ascii_repr += chr(byte)
        else:
            ascii_repr = None
            break

    return {
        "decimal": str(value),
        "hexadecimal": hex(value),
        "bytes": raw.hex(" "),
        "ascii": ascii_repr,
        "binary": bin(value)
    }


# ── prompts ─────────────────────────────────────────────────────────────────

@mcp.prompt()
def exploit_prompt():
    """Exploit prompt"""

    messages = [
        base.UserMessage("You are a helpful assistant that can help me with my exploit."),
        base.UserMessage("""
        You need to follow these steps to complete the exploit:
        0. Start an analysis session
            - First call open_session(path) with the binary file path; it returns a session_id
            - Every subsequent analysis tool call must pass this session_id as its first parameter
            - You can open several binaries at the same time (each gets its own session_id) and analyze them in parallel
            - Call list_sessions() to see all sessions; close_session(session_id) when you are done
        1. Reverse analyze the binary file to locate vulnerabilities and analyze vulnerability types
            - Locate vulnerabilities: Use IDA Pro's analysis features to find vulnerability locations
            - Need to first gather binary file information, such as using checksec tool to check binary protection mechanisms
                - If you find NX protection is disabled, you can use ret2shellcode method to get a shell
        2. Choose appropriate exploitation method based on vulnerability type
            - For stack overflow vulnerabilities, analyze the overflow pattern and check if there are backdoor functions in the binary. If there are backdoor functions, modify the return address to point to the backdoor function address
            - If there are no backdoor functions, need to use ret2libc method. Don't assume the binary contains the gadgets you want - you need to use ROPgadget to find gadgets and combine them to construct the pop chain.
        """),
    ]
    return messages


def main():
    """Run the MCP server.

    CLI flags are the ONLY configuration channel — anything not passed uses
    the built-in defaults (there is no .env / environment-variable
    configuration by design):
    ``headless_ida_mcp_server [transport] [--host HOST] [--port PORT]
    [--max-sessions N] [--dead-session-retention N] [--max-response-bytes N]
    [--open-timeout-base SECONDS]``.
    """
    parser = argparse.ArgumentParser(prog="headless_ida_mcp_server")
    parser.add_argument("transport", nargs="?", default="streamable-http",
                        choices=("sse", "stdio", "streamable-http"),
                        help="sse | stdio | streamable-http (default: streamable-http)")
    parser.add_argument("--host", default=None, help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="bind port (default: 8888)")
    parser.add_argument("--max-sessions", type=int, default=None, metavar="N",
                        help="concurrent worker limit (default: 16)")
    parser.add_argument("--dead-session-retention", type=int, default=None, metavar="N",
                        help="DEAD tombstones kept by list_sessions, -1 = forever (default: 4)")
    parser.add_argument("--max-response-bytes", type=int, default=None, metavar="N",
                        help="single-line protocol response limit in bytes (default: 268435456)")
    parser.add_argument("--open-timeout-base", type=float, default=None, metavar="SECONDS",
                        help="base seconds of the size-aware open timeout; the fixed "
                             "formula adds 6*MB^1.5 for raw binaries / 6*MB for .i64, "
                             "capped at 24h (default: 120)")
    args = parser.parse_args()
    if args.host is not None:
        mcp.settings.host = args.host
    if args.port is not None:
        mcp.settings.port = args.port
    if args.max_sessions is not None and args.max_sessions < 1:
        parser.error("--max-sessions must be >= 1")
    if args.dead_session_retention is not None and args.dead_session_retention < -1:
        parser.error("--dead-session-retention must be >= -1 (-1 keeps tombstones forever)")
    if args.max_response_bytes is not None and args.max_response_bytes < 1:
        parser.error("--max-response-bytes must be >= 1")
    if args.open_timeout_base is not None and args.open_timeout_base <= 0:
        parser.error("--open-timeout-base must be > 0")
    apply_cli_overrides(max_sessions=args.max_sessions,
                        dead_retention=args.dead_session_retention,
                        max_response_bytes=args.max_response_bytes,
                        open_timeout_base=args.open_timeout_base)
    try:
        mcp.run(transport=args.transport)
    except KeyboardInterrupt:
        # Graceful-shutdown completion, not a crash: uvicorn (>= 0.39) runs
        # its full graceful shutdown — including our lifespan shutdown_all()
        # that saves and reaps every worker — and then DELIBERATELY re-raises
        # the captured SIGINT so the process looks like a canonical Ctrl+C
        # death to the shell. By the time we get here cleanup has already
        # happened, so intercept the re-raise for a clean, traceback-free
        # exit. (The stdio transport raises KeyboardInterrupt directly during
        # unwinding; its lifespan cleanup has also completed by then.)
        logger.info("interrupted after graceful shutdown; all workers saved and reaped")

if __name__ == "__main__":
    main()
