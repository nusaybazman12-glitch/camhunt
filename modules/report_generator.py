"""Report generator"""

import json
import os
from datetime import datetime


class ReportGenerator:
    def __init__(self, logger):
        self.logger = logger
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.report_dir = os.path.join(base, "reports")
        os.makedirs(self.report_dir, exist_ok=True)

    def export_json(self, data):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.report_dir, f"camhunt_report_{ts}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return path

    def export_txt(self, data):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.report_dir, f"camhunt_report_{ts}.txt")
        lines = ["=" * 70,
                 "CamHunt v2.0 - Network Scan Report",
                 "=" * 70,
                 f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 ""]
        net = data.get("network", {})
        lines += ["NETWORK INFO", "-" * 70,
                  f"SSID    : {net.get('ssid', 'Unknown')}",
                  f"Local IP: {net.get('local_ip', 'Unknown')}",
                  f"Range   : {net.get('network_range', 'Unknown')}",
                  f"Gateway : {net.get('gateway', 'Unknown')}", ""]
        lines += ["DEVICES", "-" * 70]
        for d in data.get("devices", []):
            lines += [f"IP       : {d.get('ip')}",
                      f"MAC      : {d.get('mac')}",
                      f"Hostname : {d.get('hostname')}",
                      f"Type     : {d.get('device_type')}",
                      f"Risk     : {d.get('risk_level')} ({d.get('risk_score')}/100)",
                      f"Ports    : {d.get('open_ports')}",
                      f"Reasons  : {d.get('reasons')}", ""]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path
