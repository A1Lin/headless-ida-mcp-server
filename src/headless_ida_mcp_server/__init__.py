"""
headless-ida-mcp-server

Configuration is CLI-only by design: every knob is a command-line flag with
a built-in default (see ``headless_ida_mcp_server --help``). There is no
.env / environment-variable configuration.
"""
from .logger import*
