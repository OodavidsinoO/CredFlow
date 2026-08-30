"""Unit tests for credflow.report_parser — .nessus report parsing."""

import pytest

from credflow.report_parser import ReportParseError, parse_nessus_report

SAMPLE_REPORT = """<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Report name="test-scan">
    <ReportHost name="192.168.1.242">
      <HostProperties>
        <tag name="HOST_START">2026-08-30T10:00:00Z</tag>
        <tag name="host-ip">192.168.1.242</tag>
        <tag name="host-fqdn">hermes.local</tag>
        <tag name="operating-system">Linux Kernel 6.1</tag>
      </HostProperties>
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0" pluginID="56984" pluginName="SSH Server Type and Version Information" pluginFamily="Service detection">
        <synopsis>SSH server banner</synopsis>
      </ReportItem>
      <ReportItem port="80" svc_name="www" protocol="tcp" severity="3" pluginID="12345" pluginName="Apache Outdated Version" pluginFamily="Web Servers">
        <synopsis>Old Apache</synopsis>
        <description>Apache 2.2 is outdated.</description>
        <solution>Upgrade Apache.</solution>
        <cvss_base_score>7.5</cvss_base_score>
        <risk_factor>High</risk_factor>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="4" pluginID="99999" pluginName="Critical RCE" pluginFamily="Misc.">
        <synopsis>Remote code execution</synopsis>
        <cvss_base_score>10.0</cvss_base_score>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


class TestParseNessusReport:
    def test_parses_host_properties(self, tmp_dir):
        path = tmp_dir / "r.nessus"
        path.write_text(SAMPLE_REPORT)
        summary = parse_nessus_report(str(path))
        assert summary["ip"] == "192.168.1.242"
        assert summary["hostname"] == "hermes.local"
        assert summary["os"] == "Linux Kernel 6.1"

    def test_severity_counts(self, tmp_dir):
        path = tmp_dir / "r.nessus"
        path.write_text(SAMPLE_REPORT)
        summary = parse_nessus_report(str(path))
        assert summary["total_findings"] == 3
        assert summary["severity_counts"] == {
            "info": 1, "low": 0, "medium": 0, "high": 1, "critical": 1,
        }

    def test_top_findings_sorted_by_severity(self, tmp_dir):
        path = tmp_dir / "r.nessus"
        path.write_text(SAMPLE_REPORT)
        summary = parse_nessus_report(str(path))
        top = summary["top_findings"]
        assert len(top) == 2  # only severity > 0
        assert top[0]["name"] == "Critical RCE"
        assert top[0]["severity"] == "critical"
        assert top[1]["name"] == "Apache Outdated Version"
        assert top[1]["cvss"] == 7.5

    def test_open_ports_deduplicated(self, tmp_dir):
        path = tmp_dir / "r.nessus"
        path.write_text(SAMPLE_REPORT)
        summary = parse_nessus_report(str(path))
        ports = summary["open_ports"]
        assert {"port": 22, "protocol": "tcp", "service": "ssh"} in ports
        assert {"port": 80, "protocol": "tcp", "service": "www"} in ports
        assert len(ports) == 2  # port 0 excluded

    def test_empty_report_returns_zero_summary(self, tmp_dir):
        path = tmp_dir / "empty.nessus"
        path.write_text(
            '<?xml version="1.0"?><NessusClientData_v2><Report name="x"></Report></NessusClientData_v2>'
        )
        summary = parse_nessus_report(str(path))
        assert summary["total_findings"] == 0
        assert summary["severity_counts"]["critical"] == 0
        assert "note" in summary

    def test_missing_file_raises(self, tmp_dir):
        with pytest.raises(ReportParseError):
            parse_nessus_report(str(tmp_dir / "nope.nessus"))

    def test_malformed_xml_raises(self, tmp_dir):
        path = tmp_dir / "bad.nessus"
        path.write_text("<NessusClientData_v2><unclosed>")
        with pytest.raises(ReportParseError):
            parse_nessus_report(str(path))

    def test_wrong_root_tag_raises(self, tmp_dir):
        path = tmp_dir / "wrong.nessus"
        path.write_text("<NotNessus></NotNessus>")
        with pytest.raises(ReportParseError):
            parse_nessus_report(str(path))
