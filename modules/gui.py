cat > ~/camhunt/modules/gui.py << 'ENDOFFILE'
"""CamHunt v2.0 - CLI Interface (Termux-friendly)"""
import os
import sys
from modules.network_scanner import NetworkScanner
from modules.ip_blocker import IPBlocker
from modules.device_fingerprint import DeviceFingerprint
from modules.camera_detector import CameraDetector
from modules.report_generator import ReportGenerator


class CamHuntCLI:
    def __init__(self, logger):
        self.logger = logger
        self.scanner = NetworkScanner(logger)
        self.blocker = IPBlocker(logger)
        self.fingerprint = DeviceFingerprint()
        self.detector = CameraDetector(logger)
        self.reporter = ReportGenerator(logger)
        self.network_info = None
        self.analysis = []

    def clear(self):
        os.system("clear")

    def banner(self):
        print("=" * 70)
        print("  ██████╗ █████╗ ███╗   ███╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗")
        print(" ██╔════╝██╔══██╗████╗ ████║██║  ██║██║   ██║████╗  ██║╚══██╔══╝")
        print(" ██║     ███████║██╔████╔██║███████║██║   ██║██╔██╗ ██║   ██║   ")
        print(" ██║     ██╔══██║██║╚██╔╝██║██╔══██║██║   ██║██║╚██╗██║   ██║   ")
        print(" ╚██████╗██║  ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ")
        print("  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ")
        print("=" * 70)
        print("       Hidden Camera Detector & Network Security Tool")
        print("                    Version 2.0.0 (CLI)")
        print("=" * 70)

    def show_network(self):
        print("\n" + "-" * 70)
        print("  [*] Your Network Info")
        print("-" * 70)
        if not self.network_info:
            self.network_info = self.scanner.get_my_network()
        if self.network_info:
            print(f"  [SSID]    : {self.network_info['ssid']}")
            print(f"  [Your IP] : {self.network_info['local_ip']}")
            print(f"  [Range]   : {self.network_info['network_range']}")
            print(f"  [Gateway] : {self.network_info['gateway']}")
        else:
            print("  [!] Network info unavailable")
        print("-" * 70)

    def menu(self):
        print("\n  +-----------------------------------------------+")
        print("  |              MAIN MENU                        |")
        print("  +-----------------------------------------------+")
        print("  |  1. Scan network (show all devices)           |")
        print("  |  2. Detect hidden cameras                     |")
        print("  |  3. Block an IP address                       |")
        print("  |  4. Show blocked IPs                          |")
        print("  |  5. View activity log                         |")
        print("  |  6. Export report (JSON + TXT)                |")
        print("  |  7. Refresh network info                      |")
        print("  |  8. Exit                                      |")
        print("  +-----------------------------------------------+")

    def pause(self):
        input("\n  [Enter] to continue...")

    def do_scan(self):
        if not self.network_info:
            self.network_info = self.scanner.get_my_network()
        if not self.network_info:
            print("  [X] Cannot determine network.")
            return

        print(f"\n  [*] Scanning {self.network_info['network_range']}...")
        devices = self.scanner.scan(self.network_info["network_range"])

        if not devices:
            print("  [!] No devices found.")
            print("  [TIP] Install nmap: pkg install nmap")
            return

        print(f"  [OK] Found {len(devices)} device(s). Analyzing...\n")

        analysis = []
        for d in devices:
            r = self.detector.analyze(d["ip"], d["mac"], self.fingerprint)
            r["hostname"] = d.get("hostname", "Unknown")
            analysis.append(r)
        self.analysis = analysis

        print("  +----+-----------------+-------------------+-----------------+---------+")
        print("  | #  | IP Address      | MAC Address       | Type            | Risk    |")
        print("  +----+-----------------+-------------------+-----------------+---------+")
        for i, a in enumerate(analysis, 1):
            dev_type = a['device_type'][:15]
            print(f"  | {i:<2} | {a['ip']:<15} | {a['mac']:<17} | {dev_type:<15} | {a['risk_level']:<7} |")
        print("  +----+-----------------+-------------------+-----------------+---------+")

    def do_camera_detect(self):
        if not self.analysis:
            print("  [!] Run option 1 first.")
            return

        cams = [a for a in self.analysis if a["risk_level"] in ("HIGH", "MEDIUM")]
        print("\n  [*] Camera Detection Results")
        print("-" * 70)

        if not cams:
            print("  [OK] No suspicious cameras detected.")
            return

        print(f"  [!] Found {len(cams)} suspicious device(s):\n")
        for c in cams:
            print("  " + "=" * 60)
            print(f"  IP       : {c['ip']}")
            print(f"  MAC      : {c['mac']}")
            print(f"  Type     : {c['device_type']}")
            print(f"  Risk     : {c['risk_level']} ({c['risk_score']}/100)")
            print(f"  Ports    : {c['open_ports']}")
            print("  Reasons  :")
            for r in c["reasons"]:
                print(f"    - {r}")
            print()

    def do_block(self):
        if not self.analysis:
            print("  [!] Run scan first.")
            return

        print("\n  [*] Devices from last scan:")
        for i, a in enumerate(self.analysis, 1):
            print(f"    {i}. {a['ip']}  ({a['mac']})")

        ip = input("\n  Enter IP to block: ").strip()
        if not ip:
            print("  [X] No IP entered.")
            return

        confirm = input(f"  [?] Block {ip}? (y/n): ").strip().lower()
        if confirm != "y":
            print("  Cancelled.")
            return

        print("  [*] Blocking...")
        ok, msg = self.blocker.block_ip(ip)
        print(f"  {'[OK]' if ok else '[X]'} {msg}")

    def do_blocked_list(self):
        print("\n  [*] Blocked IPs")
        print("-" * 70)
        blocked = self.blocker.get_blocked_list()
        if not blocked:
            print("  (none)")
        else:
            for i, ip in enumerate(blocked, 1):
                print(f"  {i}. {ip}")

    def do_view_log(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_file = os.path.join(base, "logs", "camhunt.log")

        print("\n  [*] Activity Log (last 40 lines)")
        print("-" * 70)

        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()[-40:]
            for line in lines:
                print("  " + line.rstrip())
        else:
            print("  (no log yet)")

    def do_export(self):
        if not self.analysis:
            print("  [!] Run scan first.")
            return

        from datetime import datetime
        data = {
            "network": self.network_info,
            "devices": self.analysis,
            "timestamp": datetime.now().isoformat()
        }
        j = self.reporter.export_json(data)
        t = self.reporter.export_txt(data)
        print(f"\n  [OK] JSON: {j}")
        print(f"  [OK] TXT : {t}")

    def do_refresh(self):
        self.network_info = self.scanner.get_my_network()
        self.analysis = []
        print("  [OK] Network info refreshed.")

    def run(self):
        self.clear()
        self.banner()
        self.show_network()
        print("\n  [!] Legal Notice: Use ONLY on your own network.")
        self.pause()

        while True:
            self.clear()
            self.banner()
            self.show_network()
            self.menu()

            choice = input("\n  > Choose (1-8): ").strip()

            if choice == "1":
                self.do_scan()
                self.pause()
            elif choice == "2":
                self.do_camera_detect()
                self.pause()
            elif choice == "3":
                self.do_block()
                self.pause()
            elif choice == "4":
                self.do_blocked_list()
                self.pause()
            elif choice == "5":
                self.do_view_log()
                self.pause()
            elif choice == "6":
                self.do_export()
                self.pause()
            elif choice == "7":
                self.do_refresh()
                self.pause()
            elif choice == "8":
                print("\n  Bye! CamHunt stopped.\n")
                sys.exit(0)
            else:
                print("\n  [X] Invalid choice (1-8).")
                self.pause()
ENDOFFILE
echo "DONE: gui.py updated"
