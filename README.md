# Acknowledgments

This project builds upon the work of:
- Tools code adapted from [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by mrexodia
- Utilizes the [headless-ida](https://github.com/DennyDai/headless-ida) library by DennyDai
- Fork and develop from [headless-ida-mcp-server](https://github.com/cnitlrt/headless-ida-mcp-server) by cnitlrt

# Headless IDA MCP Server

If you want to run the server directly as a cli app, rather than an IDA plugin interactively,you can chose it.

## v2
Rewrite all functions in `helper.py` using `idalib` sdk, removing the dependency on `headless_ida`, improve invocation speed.

v2 supports **multi-session concurrent analysis**: every binary is analyzed in its own worker process and every tool call is routed by `session_id`, so several binaries can be analyzed at the same time in one server (up to `MAX_SESSIONS`).

### Tools

Session management:

| Tool | Description |
| ---- | ----------- |
| `open_session(path)` | Open a binary (raw ELF or a saved `.i64`), run auto-analysis, return `session_id` + `image_size` + `function_count`. The first open of a large binary can take minutes |
| `close_session(session_id, save=True)` | Save and close the session, releasing the worker's memory |
| `list_sessions()` | List all sessions with `session_id`, `state`, `pid`, `rss_bytes` — call it to discover existing session ids |
| `restart_session(session_id, force=False)` | Revive a crashed or closed session under the **same id**, resuming from its last saved state; `force=True` restarts a live session |
| `ping_session(session_id)` | Quick responsiveness check |

Analysis (each takes `session_id` as its first argument):

| Tool | Description |
| ---- | ----------- |
| `get_function(session_id, address)` | Function info at an address: name, start/end, prototype |
| `get_function_by_name(session_id, name)` | Function info by name |
| `get_function_by_address(session_id, address)` | Function info by address |
| `get_image_size(session_id)` | Size of the loaded image |
| `list_functions(session_id)` | All functions (can be a very large response) |
| `decompile_function(session_id, address)` | Hex-Rays pseudocode of a function |
| `disassemble_function(session_id, address)` | Assembly listing of a function |
| `get_xrefs_to(session_id, address)` | Cross-references to an address |
| `get_entry_points(session_id)` | Entry points of the binary |

Write operations (persist via `save_idb_file` or `close_session(save=True)`):

| Tool | Description |
| ---- | ----------- |
| `rename_function(session_id, function_address, new_name)` | Rename a function |
| `rename_local_variable(session_id, function_address, old_name, new_name)` | Rename a local variable |
| `set_function_prototype(session_id, function_address, prototype)` | Set a function prototype, e.g. `int func(void);` |
| `set_disassembly_comment(session_id, address, comment)` | Comment shown in the disassembly |
| `set_decompiler_comment(session_id, address, comment)` | Comment shown in the pseudocode |
| `save_idb_file(session_id, save_path)` | Save the database to an IDB file |

Utility (no session required):

| Tool | Description |
| ---- | ----------- |
| `convert_number(text, size)` | Convert a number to decimal / hex / bytes / ascii / binary |

## Project Description

This project uses IDA Pro's headless mode to analyze binary files and provides a suite of tools via MCP to manage and manipulate functions, variables, and more.

## Prerequisites
- ida pro >= 9.0
- python idalib https://docs.hex-rays.com/user-guide/idalib

## Installation

1. Clone the project locally:

   ```bash
   git clone https://github.com/A1Lin/headless-ida-mcp-server.git 
   cd headless-ida-mcp-server
   ```

2. Install dependencies:

   ```bash
   uv python install 3.12
   uv venv --python 3.12
   uv pip install -e .
   ```

## Configuration

All configuration is CLI-only — every knob is a command-line flag with a built-in default (there is no `.env` / environment-variable configuration):

```bash
headless_ida_mcp_server [transport] [--host HOST] [--port PORT]
                        [--max-sessions N] [--dead-session-retention N]
                        [--max-response-bytes N] [--open-timeout-base SECONDS]
```

| Flag | Default | Meaning |
|---|---|---|
| `transport` | `streamable-http` | `sse` / `stdio` / `streamable-http` |
| `--host` | `127.0.0.1` | bind host |
| `--port` | `8888` | bind port |
| `--max-sessions` | `16` | concurrent worker limit; only non-DEAD sessions count — each worker holds a whole database in memory, typically GB-scale |
| `--dead-session-retention` | `4` | closed/crashed session records kept in `list_sessions`; `-1` keeps them all |
| `--max-response-bytes` | `268435456` | protocol single-line limit in bytes (256MB) |
| `--open-timeout-base` | `120` | base seconds of the size-aware open timeout |

The open timeout is size-aware and computed from `--open-timeout-base` alone (the rest of the formula is fixed): raw binaries get `BASE + 6·MB^1.5` (1 MB≈2 min, 10 MB≈5 min, 100 MB≈1.7 h), `.i64`/`.idb` files (already analyzed) get the linear `BASE + 6·MB`, and everything is capped at a fixed 24 h sanity ceiling.

There is **no per-call or save timeout**: long analyses and big database saves run to completion. If a worker truly hangs, `close_session` / `restart_session` recovers it. Note the *client* may have its own request timeout — the operation continues server-side even if the client gives up.

## Usage

Start the server:

```bash
uv run headless_ida_mcp_server
```

The optional CLI argument selects the transport (default `streamable-http`):

```bash
uv run headless_ida_mcp_server stdio
```

Every server/session knob is a CLI flag with a built-in default (see [Configuration](#configuration)):

```bash
uv run headless_ida_mcp_server sse --host 127.0.0.1 --port 8888 \
    --max-sessions 16 --dead-session-retention 4 --max-response-bytes 268435456 \
    --open-timeout-base 120
```

### Consuming the tools

The tools are MCP tools, built for **LLM agents**: an agent invokes them over MCP, or through a thin CLI wrapper paired with a skill file that documents the commands. Either way the loop is:

1. `open_session(path)` returns a `session_id`
2. pass that `session_id` as the first argument of every analysis tool
3. persist writes with `save_idb_file` or `close_session(save=True)`

Wrapping the server as a CLI only needs a client config pointing at the running server, e.g.:

```json
{ "mcpServers": { "ida": { "url": "http://127.0.0.1:8888/mcp" } } }
```

Pair the CLI wrapper with a skill file listing the tool invocations, and the agent can drive the whole analyze → rename → save → close workflow by itself.

Notes:

- Opening the same path twice reuses the existing session; open several different binaries for parallel analysis.
- Renames / comments / prototypes live in memory until `save_idb_file` or `close_session(save=True)` persists them. Open the saved `.i64` (instead of the raw binary) to resume with all edits.
- A crashed session shows up as `DEAD` in `list_sessions`; `restart_session` revives it under the same id — anything not saved before the crash is lost.
- Running N concurrent idalib instances may be restricted by your Hex-Rays license — check your terms.
