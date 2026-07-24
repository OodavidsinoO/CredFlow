"""Unit tests for credflow.reporter — summary and progress output."""

import json
import os
from datetime import UTC

from credflow.reporter import (
    generate_summary_json,
    print_progress_table,
    print_summary,
)


class TestPrintProgressTable:
    def test_empty_progress(self, capsys):
        print_progress_table({})
        captured = capsys.readouterr()
        assert "No targets" in captured.out

    def test_mixed_progress(self, capsys):
        progress = {"completed": 5, "running": 2, "pending": 3, "failed": 1}
        print_progress_table(progress)
        captured = capsys.readouterr()
        assert "completed" in captured.out
        assert "5" in captured.out
        assert "running" in captured.out
        assert "failed" in captured.out
        assert "total" in captured.out
        assert "11" in captured.out  # 5+2+3+1

    def test_only_completed(self, capsys):
        progress = {"completed": 10}
        print_progress_table(progress)
        captured = capsys.readouterr()
        assert "completed" in captured.out
        assert "10" in captured.out
        assert "running" not in captured.out  # zero count not shown

    def test_keys_with_zero_not_shown(self, capsys):
        progress = {"completed": 3, "running": 0, "pending": 0, "failed": 0}
        print_progress_table(progress)
        captured = capsys.readouterr()
        assert captured.out.count("completed") == 1  # shown
        assert "running" not in captured.out  # zero → hidden


class TestPrintSummary:
    def test_all_completed(self, capsys):
        summary = {
            "total": 10,
            "completed": 10,
            "failed": 0,
            "pending": 0,
            "failures": [],
            "reports": [
                {"ip": "10.0.0.1", "report_nessus": "n.nessus", "report_db": "n.db"}
            ],
        }
        print_summary(summary)
        captured = capsys.readouterr()
        assert "Total targets:    10" in captured.out
        assert "Completed:        10" in captured.out
        assert "10.0.0.1" in captured.out
        assert "n.nessus" in captured.out

    def test_with_failures(self, capsys):
        summary = {
            "total": 3,
            "completed": 1,
            "failed": 2,
            "pending": 0,
            "failures": [
                {"ip": "10.0.0.2", "error": "timeout"},
                {"ip": "10.0.0.3", "error": "auth failed"},
            ],
            "reports": [],
        }
        print_summary(summary)
        captured = capsys.readouterr()
        assert "Failed:" in captured.out
        assert "2" in captured.out
        assert "timeout" in captured.out
        assert "auth failed" in captured.out

    def test_no_reports(self, capsys):
        summary = {
            "total": 0,
            "completed": 0,
            "failed": 0,
            "pending": 0,
            "failures": [],
            "reports": [],
        }
        print_summary(summary)
        captured = capsys.readouterr()
        assert "Total targets:    0" in captured.out


class TestGenerateSummaryJson:
    def test_writes_json_file(self, tmp_dir):
        summary = {"total": 1, "completed": 1, "failed": 0, "pending": 0}
        path = generate_summary_json(summary, str(tmp_dir))
        assert os.path.isfile(path)
        assert path.endswith(".json")

    def test_json_content_is_valid(self, tmp_dir):
        summary = {"total": 2, "completed": 1, "failed": 1, "pending": 0}
        path = generate_summary_json(summary, str(tmp_dir))
        with open(path) as f:
            data = json.load(f)
        assert data["total"] == 2
        assert data["completed"] == 1
        assert data["failed"] == 1

    def test_creates_reports_dir_if_missing(self, tmp_dir):
        reports = str(tmp_dir / "nested" / "reports")
        summary = {"total": 0, "completed": 0, "failed": 0, "pending": 0}
        path = generate_summary_json(summary, reports)
        assert os.path.isfile(path)
        assert os.path.isdir(reports)

    def test_handles_datetime_serialization(self, tmp_dir):
        from datetime import datetime

        summary = {
            "total": 1,
            "completed": 1,
            "failed": 0,
            "pending": 0,
            "timestamp": datetime.now(UTC),
        }
        path = generate_summary_json(summary, str(tmp_dir))
        with open(path) as f:
            data = json.load(f)
        assert "timestamp" in data
