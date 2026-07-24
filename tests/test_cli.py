"""Unit tests for credflow.cli — CSV parsing and argument parsing."""

import pytest

from credflow.cli import (
    build_parser,
    parse_targets_csv,
)


class TestParseTargetsCsv:
    def test_parses_valid_csv(self, valid_csv):
        targets = parse_targets_csv(valid_csv)
        assert len(targets) == 3
        assert targets[0].ip == "10.0.0.1"
        assert targets[0].username == "root"
        assert targets[0].password == "secret1"
        assert targets[0].os_type == "linux"

    def test_windows_target(self, valid_csv):
        targets = parse_targets_csv(valid_csv)
        assert targets[1].os_type == "windows"

    def test_handles_bom(self, csv_with_bom):
        targets = parse_targets_csv(csv_with_bom)
        assert len(targets) == 1
        assert targets[0].ip == "10.0.0.1"

    def test_strips_whitespace(self, csv_with_blanks):
        targets = parse_targets_csv(csv_with_blanks)
        ips = {t.ip for t in targets}
        assert "10.0.0.1" in ips
        assert len(targets) >= 1

    def test_missing_username_skipped(self, csv_with_blanks):
        targets = parse_targets_csv(csv_with_blanks)
        ips = {t.ip for t in targets}
        assert "10.0.0.2" not in ips  # missing username → skipped

    def test_missing_password_is_accepted(self, tmp_dir):
        """Empty password should be warned but not skipped — only ip+username required."""
        path = str(tmp_dir / "no_pw.csv")
        with open(path, "w") as f:
            f.write("ip,username,password,os_type\n")
            f.write("10.0.0.1,root,,linux\n")
        targets = parse_targets_csv(path)
        assert len(targets) == 1
        assert targets[0].password == ""

    def test_default_os_type(self, csv_with_blanks):
        targets = parse_targets_csv(csv_with_blanks)
        for t in targets:
            if t.ip == "10.0.0.3":
                assert t.os_type == "linux"  # default

    def test_invalid_os_type_warns_defaults_linux(self, tmp_dir):
        path = str(tmp_dir / "bad_os.csv")
        with open(path, "w") as f:
            f.write("ip,username,password,os_type\n")
            f.write("10.0.0.1,root,pw,macos\n")
        targets = parse_targets_csv(path)
        assert len(targets) == 1
        assert targets[0].os_type == "linux"  # corrected

    def test_empty_file(self, tmp_dir):
        path = str(tmp_dir / "empty.csv")
        with open(path, "w") as f:
            f.write("ip,username,password,os_type\n")
        with pytest.raises(SystemExit):
            parse_targets_csv(path)

    def test_file_not_found(self):
        with pytest.raises(SystemExit):
            parse_targets_csv("/nonexistent/path.csv")

    def test_case_insensitive_headers(self, tmp_dir):
        path = str(tmp_dir / "case.csv")
        with open(path, "w") as f:
            f.write("IP,UserName,Password,OS_TYPE\n")
            f.write("10.0.0.1,root,pw,linux\n")
        targets = parse_targets_csv(path)
        assert len(targets) == 1
        assert targets[0].ip == "10.0.0.1"


class TestBuildParser:
    def test_parser_has_all_commands(self):
        parser = build_parser()
        # Just verify it builds without errors
        assert parser is not None

    def test_check_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["check"])
        assert args.command == "check"

    def test_run_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["run", "--targets", "test.csv"])
        assert args.command == "run"
        assert args.targets == "test.csv"

    def test_run_with_all_new_args(self):
        parser = build_parser()
        args = parser.parse_args([
            "run",
            "--targets", "t.csv",
            "--source-scan", "MyScan",
            "--disabled-families", "DoS,Web",
            "--scan-name-prefix", "Audit",
            "--workers", "3",
        ])
        assert args.source_scan == "MyScan"
        assert args.disabled_families == "DoS,Web"
        assert args.scan_name_prefix == "Audit"
        assert args.workers == 3

    def test_status_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["status"])
        assert args.command == "status"

    def test_retry_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["retry"])
        assert args.command == "retry"

    def test_clean_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["clean"])
        assert args.command == "clean"

    def test_clean_with_yes(self):
        parser = build_parser()
        args = parser.parse_args(["clean", "--yes"])
        assert args.yes is True

    def test_version(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--version"])
