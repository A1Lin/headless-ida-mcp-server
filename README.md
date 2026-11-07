# Acknowledgments

This project builds upon the work of:
- Tools code adapted from [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by mrexodia
- Utilizes the [headless-ida](https://github.com/DennyDai/headless-ida) library by DennyDai
- Fork and develop from [headless-ida-mcp-server](https://github.com/cnitlrt/headless-ida-mcp-server) by cnitlrt

# Headless IDA MCP Server

If you want to run the server directly as a cli app, rather than an IDA plugin interactively,you can chose it.

## v1
Forked from https://github.com/cnitlrt/headless-ida-mcp-server with async support added.

## v2
Rewrite all functions in `helper.py` using `idalib` sdk, removing the dependency on `headless_ida`, improve invocation speed.

v2 analyzes each binary in a dedicated **worker subprocess** (one idalib database per process) and routes every tool call by `session_id`, so several binaries can be analyzed concurrently in a single server.

#### Multi-session workflow

```
open_session(path)                      → session_id + image_size + function_count
get_function(session_id, address)       → function info (every analysis tool is like this)
rename_function(session_id, addr, name) → write op (persists via save_idb_file / close_session)
close_session(session_id, save=True)    → persist and shut the worker down
```

- `list_sessions()` shows live and dead sessions with `pid`, `state`, `close_reason` and `rss_bytes` — call it first to discover existing session ids
- opening the same path twice reuses the existing session
- after a worker crash the session is `DEAD` with a `close_reason`; `restart_session(session_id)` revives it **under the same id**, recovering the last persisted state (open a `.i64` to keep everything you saved; opening the raw binary re-runs auto-analysis and loses unsaved edits)
- `ping_session` checks protocol responsiveness (it queues behind a long-running op — use `list_sessions` for liveness)
- on server exit every worker is closed and saved automatically (FastMCP lifespan); a hard `kill -9` of the server still makes workers save and exit via the stdin-EOF path; `Ctrl+C` in the terminal is safe too — SIGINT goes to the whole process group, the server runs its graceful shutdown and the workers treat SIGINT as "save and exit 0"
- opening a database that is interrupted mid-open (SIGKILL during `open_session`) can leave a stale `.i64` lock file; remove it manually if a subsequent open of the same database refuses to start
- running N concurrent idalib instances may be restricted by your Hex-Rays license — check your terms
- `save_idb_file` can write to arbitrary paths and the server binds `0.0.0.0` by default: run it in a trusted environment

## Project Description

This project uses IDA Pro's headless mode to analyze binary files and provides a suite of tools via MCP to manage and manipulate functions, variables, and more.

## Prerequisites
### v1
- Python 3.12 or higher
- IDA Pro with headless support (idat) https://github.com/DennyDai/headless-ida

### v2
- ida pro >= 9.0
- python idalib https://docs.hex-rays.com/user-guide/idalib

## Installation

1. Clone the project locally:

   ```bash
   git clone https://github.com/A1Lin/headless-ida-mcp-server.git 
   cd headless-ida-mcp-server
   git checkout v1/v2
   ```

2. Install dependencies:

   ```bash
   uv python install 3.12
   uv venv --python 3.12
   uv pip install -e .
   ```

## Configuration

1. Copy the example environment file:
   ```bash
   cp .env_example .env
   ```

2. Configure the following environment variables in `.env`:

   - `IDA_PATH`: Path to IDA Pro's headless executable (idat), e.g., `/home/ubuntu/idapro/idat` (v1 only)
   - `PORT`: Port number for the MCP server, e.g., `8888`
   - `HOST`: Host address for the MCP server, e.g., `127.0.0.1`
   - `TRANSPORT`: MCP transport mode (`sse` 、 `stdio` or `streamable-http`)
   - `MAX_SESSIONS`: Concurrent worker limit (default `8`; only non-DEAD sessions count — each worker holds a whole database in memory, typically GB-scale)
   - `DEAD_SESSION_RETENTION`: How many closed/crashed session records stay visible in `list_sessions` (for `close_reason` history and `restart_session`); older ones are pruned. Default `4`, `-1` keeps them forever
   - `OPEN_TIMEOUT`: optional flat override (seconds) for the open timeout. **Unset/0 by default → size-aware formula**: `OPEN_TIMEOUT_BASE + OPEN_TIMEOUT_PER_MB × MB^OPEN_TIMEOUT_POWER` for raw binaries (auto-analysis grows super-linearly with code size; defaults `120 + 6·MB^1.5` → 1 MB≈2 min, 10 MB≈5 min, 100 MB≈1.7 h), linear `BASE + PER_MB·MB` for `.i64`/`.idb` (load only), capped at `OPEN_TIMEOUT_MAX` (default 24 h)
   - `OPEN_TIMEOUT_BASE` (default `120`), `OPEN_TIMEOUT_PER_MB` (default `6`), `OPEN_TIMEOUT_POWER` (default `1.5`), `OPEN_TIMEOUT_MAX` (default `86400`): the formula knobs
   - `MAX_RESPONSE_BYTES`: Protocol single-line limit in bytes (default `268435456` = 256MB; huge responses such as `list_functions` exceed the 64KB asyncio default)

   There are **no `CALL_TIMEOUT` / `SAVE_TIMEOUT`**: analysis operations (decompiling huge functions, `list_functions`) and saving GB-scale `.i64` databases legitimately take many minutes — a fixed bound would kill them half-way. Calls and close/save therefore wait as long as they need. Recovery from a genuinely hung worker: `close_session` / `restart_session` (SIGTERM → SIGKILL escalation), or `kill -9` the `pid` shown by `list_sessions`. **Note**: the *client* side may still have its own request timeout (MCP clients commonly default to 60s) — if it fires, the operation continues server-side and later replies are dropped; configure the client timeout up for very long analyses.
   Transports: `TRANSPORT` in `.env` (`sse` default or `stdio`), or the CLI argument (`headless_ida_mcp_server stdio`); `streamable-http` (the modern MCP transport) also works, with `--host`/`--port` overrides available.

## Usage

Start the server:

```bash
uv run headless_ida_mcp_server
```

An optional CLI argument overrides the transport from `.env` (handy for launchers):
```bash
uv run headless_ida_mcp_server stdio
```
