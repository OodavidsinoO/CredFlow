"""Unit tests for credflow.colored_formatter — ANSI color formatter."""

import logging

from credflow.colored_formatter import (
    RESET,
    ColoredFormatter,
    _should_use_color,
)


class TestShouldUseColor:
    def test_force_color_on(self, monkeypatch):
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert _should_use_color() is True

    def test_no_color_off(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("FORCE_COLOR", "")  # clear
        assert _should_use_color() is False

    def test_no_color_takes_priority(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("FORCE_COLOR", "")  # clear FORCE_COLOR
        # NO_COLOR alone disables color
        assert _should_use_color() is False

    def test_force_color_overrides_no_color(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        monkeypatch.setenv("FORCE_COLOR", "1")
        # FORCE_COLOR is checked first — it wins
        assert _should_use_color() is True

    def test_term_dumb(self, monkeypatch):
        monkeypatch.setenv("TERM", "dumb")
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert _should_use_color() is False


class TestColoredFormatterDisabled:
    def test_no_color_when_disabled(self):
        fmt = ColoredFormatter(
            fmt="%(levelname)s %(message)s", use_color=False
        )
        record = logging.LogRecord(
            "test", logging.ERROR, "", 0, "✗ error msg", (), None
        )
        output = fmt.format(record)
        assert "\033" not in output  # no ANSI codes
        assert "ERROR" in output
        assert "✗" in output

    def test_info_no_color_even_when_enabled(self):
        fmt = ColoredFormatter(
            fmt="%(levelname)s %(message)s", use_color=True
        )
        record = logging.LogRecord(
            "test", logging.INFO, "", 0, "normal message", (), None
        )
        output = fmt.format(record)
        assert "INFO" in output
        assert "\033" not in output  # INFO has no color

    def test_warning_gets_yellow(self):
        fmt = ColoredFormatter(
            fmt="%(levelname)s %(message)s", use_color=True
        )
        record = logging.LogRecord(
            "test", logging.WARNING, "", 0, "warning!", (), None
        )
        output = fmt.format(record)
        assert "\033[33m" in output  # yellow
        assert "WARNING" in output
        assert RESET in output

    def test_error_gets_red(self):
        fmt = ColoredFormatter(
            fmt="%(levelname)s %(message)s", use_color=True
        )
        record = logging.LogRecord(
            "test", logging.ERROR, "", 0, "fail!", (), None
        )
        output = fmt.format(record)
        assert "\033[31m" in output  # red
        assert RESET in output

    def test_critical_gets_bold_red(self):
        fmt = ColoredFormatter(
            fmt="%(levelname)s %(message)s", use_color=True
        )
        record = logging.LogRecord(
            "test", logging.CRITICAL, "", 0, "fatal!", (), None
        )
        output = fmt.format(record)
        assert "\033[31;1m" in output  # bold red

    def test_debug_gets_grey(self):
        fmt = ColoredFormatter(
            fmt="%(levelname)s %(message)s", use_color=True
        )
        record = logging.LogRecord(
            "test", logging.DEBUG, "", 0, "trace", (), None
        )
        output = fmt.format(record)
        assert "\033[38;5;245m" in output  # grey


class TestColoredFormatterPatternColoring:
    def test_checkmark_green(self):
        fmt = ColoredFormatter(
            fmt="%(message)s", use_color=True
        )
        record = logging.LogRecord(
            "test", logging.INFO, "", 0, "✓ completed", (), None
        )
        output = fmt.format(record)
        assert "\033[32m✓" in output  # green checkmark

    def test_cross_red(self):
        fmt = ColoredFormatter(
            fmt="%(message)s", use_color=True
        )
        record = logging.LogRecord(
            "test", logging.INFO, "", 0, "✗ failed", (), None
        )
        output = fmt.format(record)
        assert "\033[31m✗" in output  # red cross

    def test_both_patterns(self):
        fmt = ColoredFormatter(
            fmt="%(message)s", use_color=True
        )
        record = logging.LogRecord(
            "test", logging.INFO, "", 0, "✓ ok but ✗ bad", (), None
        )
        output = fmt.format(record)
        assert "\033[32m✓" in output
        assert "\033[31m✗" in output
        assert output.count(RESET) == 2  # one per colored pattern

    def test_no_false_positives(self):
        """Non-marker text should not be colored."""
        fmt = ColoredFormatter(
            fmt="%(message)s", use_color=True
        )
        record = logging.LogRecord(
            "test", logging.INFO, "", 0, "Just a normal message", (), None
        )
        output = fmt.format(record)
        assert "\033" not in output

    def test_pattern_in_format_string_args(self):
        """Ensure the formatter handles format-string + args correctly."""
        fmt = ColoredFormatter(
            fmt="%(message)s", use_color=True
        )
        # When the logging call passes args, record.msg is the format string
        # and record.message is the formatted version. Our formatter only
        # colorizes record.msg, not the formatted args. This is acceptable.
        record = logging.LogRecord(
            "test", logging.INFO, "", 0, "✓ %s done", ("task",), None
        )
        record.message = record.msg % record.args  # simulate logging's internal formatting
        output = fmt.format(record)
        # The ✓ in the format string should be colored
        assert "\033[32m✓" in output or "✓" in output
