"""Parse Nessus .nessus report files into structured vulnerability summaries.

The .nessus format is ``NessusClientData_v2`` XML: a ``Report`` containing one
``ReportHost`` per scanned host, each with ``HostProperties`` and a list of
``ReportItem`` elements (one per finding/port/service).

Severity mapping (Nessus convention):
    0 = info, 1 = low, 2 = medium, 3 = high, 4 = critical
"""

import contextlib
import logging
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

_SEVERITY_NAMES = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

# HostProperties keys worth surfacing in the summary
_HOST_PROPERTY_KEYS = {
    "host-ip": "ip",
    "host-fqdn": "fqdn",
    "hostname": "hostname",
    "operating-system": "os",
    "os-name": "os",
    "system-type": "system_type",
}


class ReportParseError(Exception):
    """Raised when a .nessus file cannot be parsed."""


def _severity_name(severity: int) -> str:
    return _SEVERITY_NAMES.get(severity, "unknown")


def _parse_host_properties(host: ET.Element) -> dict:
    """Extract interesting HostProperties from a ReportHost element."""
    props: dict[str, str] = {}
    for tag in host.findall("HostProperties/tag"):
        name = tag.get("name", "")
        mapped = _HOST_PROPERTY_KEYS.get(name)
        if mapped and tag.text:
            props[mapped] = tag.text.strip()
    return props


def _parse_report_item(item: ET.Element) -> dict:
    """Extract a single finding from a ReportItem element."""
    try:
        severity = int(item.get("severity", "0"))
    except ValueError:
        severity = 0

    finding: dict = {
        "plugin_id": int(item.get("pluginID", "0") or 0),
        "name": item.get("pluginName", ""),
        "family": item.get("pluginFamily", ""),
        "severity": _severity_name(severity),
        "severity_value": severity,
        "port": int(item.get("port", "0") or 0),
        "protocol": item.get("protocol", ""),
        "service": item.get("svc_name", ""),
    }

    for child in item:
        tag = child.tag
        if tag in ("synopsis", "description", "solution", "risk_factor"):
            finding[tag] = (child.text or "").strip()
        elif tag == "cvss_base_score":
            with contextlib.suppress(ValueError):
                finding["cvss"] = float(child.text or 0)
    return finding


def parse_nessus_report(path: str) -> dict:
    """Parse a .nessus file into a structured summary dict.

    Returns a dict with host info, severity counts, top findings, and open
    ports. Raises ReportParseError on unreadable or malformed files.
    """
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError) as e:
        raise ReportParseError(f"Could not parse {path}: {e}") from e

    root = tree.getroot()
    if root.tag != "NessusClientData_v2":
        raise ReportParseError(
            f"{path} is not a NessusClientData_v2 report (root tag: {root.tag})"
        )

    hosts = root.findall("Report/ReportHost")
    if not hosts:
        logger.warning("No ReportHost elements found in %s", path)
        return _empty_summary(path)

    # Merge findings across hosts (a scan targets a single host, but be safe)
    findings: list[dict] = []
    host_props: dict = {}
    for host in hosts:
        host_props.update(_parse_host_properties(host))
        for item in host.findall("ReportItem"):
            findings.append(_parse_report_item(item))

    findings.sort(key=lambda f: (f["severity_value"], f.get("cvss", 0)), reverse=True)

    severity_counts = dict.fromkeys(_SEVERITY_NAMES.values(), 0)
    for f in findings:
        severity_counts[f["severity"]] += 1

    # Open ports: unique (port, protocol, service) triples from findings
    ports: list[dict] = []
    seen: set[tuple] = set()
    for f in findings:
        key = (f["port"], f["protocol"], f["service"])
        if f["port"] > 0 and key not in seen:
            seen.add(key)
            ports.append(
                {"port": f["port"], "protocol": f["protocol"], "service": f["service"]}
            )
    ports.sort(key=lambda p: p["port"])

    # Top findings: everything above info severity, capped at 20
    top = [f for f in findings if f["severity_value"] > 0][:20]

    summary = {
        "ip": host_props.get("ip", ""),
        "hostname": host_props.get("hostname") or host_props.get("fqdn", ""),
        "os": host_props.get("os", ""),
        "scan_date": datetime.now(UTC).isoformat(),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "open_ports": ports,
        "top_findings": top,
    }
    return summary


def _empty_summary(path: str) -> dict:
    """Return a summary for a report with no hosts (e.g. host unreachable)."""
    return {
        "ip": "",
        "hostname": "",
        "os": "",
        "scan_date": datetime.now(UTC).isoformat(),
        "total_findings": 0,
        "severity_counts": dict.fromkeys(_SEVERITY_NAMES.values(), 0),
        "open_ports": [],
        "top_findings": [],
        "note": f"No hosts in report: {path}",
    }
