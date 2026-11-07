"""
headless-ida-mcp-server
"""
from dotenv import load_dotenv,find_dotenv,dotenv_values
import os
from .logger import*

__all__ = ['PORT', 'HOST', 'TRANSPORT',
           'MAX_SESSIONS', 'DEAD_SESSION_RETENTION', 'OPEN_TIMEOUT',
           'OPEN_TIMEOUT_BASE', 'OPEN_TIMEOUT_PER_MB', 'OPEN_TIMEOUT_POWER',
           'OPEN_TIMEOUT_MAX', 'MAX_RESPONSE_BYTES']

load_dotenv(find_dotenv(),override=True)
PORT = int(os.environ.get("PORT", 8888))
HOST = os.environ.get("HOST", "0.0.0.0")
TRANSPORT = os.environ.get("TRANSPORT", "sse")

# ── multi-session worker configuration ──
MAX_SESSIONS = int(os.environ.get("MAX_SESSIONS", 8))          # non-DEAD sessions only

# how many DEAD session records (tombstones) to keep for list_sessions history
# and restart_session; older ones are pruned. -1 keeps them forever.
DEAD_SESSION_RETENTION = int(os.environ.get("DEAD_SESSION_RETENTION", 4))

# Open timeout is SIZE-AWARE by default (bigger binary → disproportionately
# longer auto-analysis): see session._open_timeout_for().
#   OPEN_TIMEOUT set to a positive number → flat override in seconds;
#   unset/0 → auto: BASE + PER_MB * MB**POWER   (raw binary, POWER=1.5)
#                  BASE + PER_MB * MB           (.i64/.idb: load only, linear)
#              capped at OPEN_TIMEOUT_MAX.
OPEN_TIMEOUT = float(os.environ.get("OPEN_TIMEOUT", 0))
OPEN_TIMEOUT_BASE = float(os.environ.get("OPEN_TIMEOUT_BASE", 120))       # floor: spawn + idalib init + load
OPEN_TIMEOUT_PER_MB = float(os.environ.get("OPEN_TIMEOUT_PER_MB", 6))    # seconds per MB**POWER
OPEN_TIMEOUT_POWER = float(os.environ.get("OPEN_TIMEOUT_POWER", 1.5))    # analysis is super-linear in code size
OPEN_TIMEOUT_MAX = float(os.environ.get("OPEN_TIMEOUT_MAX", 86400))      # 24h sanity ceiling

MAX_RESPONSE_BYTES = int(os.environ.get("MAX_RESPONSE_BYTES", 268435456))  # 256MB line limit

# NOTE: there is intentionally no CALL_TIMEOUT / SAVE_TIMEOUT:
#  * analysis ops (decompile of huge functions, list_functions) and database
#    saves of GB-scale .i64 files legitimately run for many minutes — a fixed
#    bound would kill them half-way;
#  * deadlock safety does not depend on them: the close ladder uses a bounded
#    write_lock acquire plus SIGTERM/SIGKILL escalation (session.py §5.4);
#  * callers that DO want a bound can pass per-call `timeout=` (manager API).
