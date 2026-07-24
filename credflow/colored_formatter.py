"""Colored logging formatter with zero additional dependencies.

Adds ANSI color to log level names and ✓/✗ markers in messages.
Automatically disables color when stdout is piped or NO_COLOR is set.
"""

import logging
import os
import sys

# ── ANSI codes ──────────────────────────────────────────────────

RESET = "\033[0m"

LEVEL_COLORS: dict[int, str] = {
    logging.DEBUG: "\033[38;5;245m",  # grey
    logging.INFO: "",                  # default (no color)
    logging.WARNING: "\033[33m",       # yellow
    logging.ERROR: "\033[31m",         # red
    logging.CRITICAL: "\033[31;1m",    # bold red
}

PATTERN_COLORS: dict[str, str] = {
    "✓": "\033[32m",   # green
    "✗": "\033[31m",   # red
}


# ── TTY detection ───────────────────────────────────────────────

def _should_use_color() -> bool:
    """Determine whether to emit ANSI escape codes.

    Respects https://no-color.org and https://force-color.org conventions.
    """
    if os.environ.get("FORCE_COLOR", "").strip():
        return True
    if os.environ.get("NO_COLOR", "").strip():
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return sys.stdout.isatty()


# ── formatter ───────────────────────────────────────────────────

class ColoredFormatter(logging.Formatter):
    """Formatter that applies ANSI color based on log level and message content.

    - Level names: ERROR=red, WARNING=yellow, INFO=default, DEBUG=grey
    - Message patterns: ✓ = green, ✗ = red (applied after level coloring)

    Color is automatically disabled when stdout is not a TTY (piped/redirected)
    or when the ``NO_COLOR`` environment variable is set.
    Use ``FORCE_COLOR=1`` to override.
    """

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        use_color: bool | None = None,
    ):
        super().__init__(fmt, datefmt)
        self._use_color = use_color if use_color is not None else _should_use_color()

    def format(self, record: logging.LogRecord) -> str:
        if self._use_color:
            self._colorize(record)
        return super().format(record)

    def _colorize(self, record: logging.LogRecord) -> None:
        """Mutate *record* in-place to inject ANSI escapes."""
        # Color the level name
        color = LEVEL_COLORS.get(record.levelno)
        if color:
            record.levelname = f"{color}{record.levelname}{RESET}"

        # Color ✓ / ✗ in the message.
        # We mutate record.msg in-place rather than copying first:
        # Python's logging records are single-use — LogRecord objects are
        # created fresh for each emit and never shared across handlers.
        # This makes in-place mutation safe and avoids an unnecessary
        # string copy on every log line.
        msg = record.msg
        if isinstance(msg, str):
            for pattern, pcolor in PATTERN_COLORS.items():
                if pattern in msg:
                    msg = msg.replace(pattern, f"{pcolor}{pattern}{RESET}")
            record.msg = msg
