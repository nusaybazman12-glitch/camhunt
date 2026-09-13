"""Report generator - export scan results to JSON/TXT"""

import json
import os
from datetime import datetime


class ReportGenerator:
    def __init__(self, logger):
        self.logger = logger
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.report_dir = os.path.join(base_dir, "reports")
        os.makedirs(self.report_dir, exist_ok=True)

    def export_json(self, data):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.report_dir, f"camhunt_report_{ts}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self.logger.info(f"Report saved: {path}")
        return path

    def export_txt(self, data):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.report_dir, f"camhunt_report_{ts}.txt")

        lines = []
        lines.append("=" * 70)
        lines.append("CamHunt v2.0 - Network Scan Report")
        lines.append("=" * 70)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        net = data.get("network", {})
        lines.append("NETWORK INFO")
        lines.append("-" * 70)
        lines.append(f"SSID        : {net.get('ssid', 'Unknown')}")
        lines.append(f"Local IP    : {net.get('local_ip', 'Unknown')}")
        lines.append(f"Range       : {net.get('network_range', 'Unknown')}")
        lines.append(f"Gateway     : {net.get('gateway', 'Unknown')}")
        lines.append("")

        lines.append("DEVICES")
        lines.append("-" * 70)
        for d in data.get("devices", []):
            lines.append(f"IP       : {d.get('ip')}")
            lines.append(f"MAC      : {d.get('mac')}")
            lines.append(f"Hostname : {d.get('hostname')}")
            lines.append(f"Type     : {d.get('device_type', 'Unknown')}")
            lines.append(f"Risk     : {d.get('risk_level', 'N/A')} ({d.get('risk_score', 0)}/100)")
            lines.append(f"Ports    : {d.get('open_ports', [])}")
            lines.append(f"Reasons  : {d.get('reasons', [])}")
            lines.append("")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        self.logger.info(f"Report saved: {path}")
        return path
