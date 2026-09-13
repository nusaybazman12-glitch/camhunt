"""GUI - menu, scan, block, logs all in one"""

import os
import sys
import subprocess
from modules.network_scanner import NetworkScanner
from modules.ip_blocker import IPBlocker


class CamHuntGUI:
    def __init__(self, logger):
        self.logger = logger
        self.scanner = NetworkScanner(logger)
        self.blocker = IPBlocker(logger)
        self.network_info = None
        self.last_scan = []
        self.packet_monitor = None  # placeholder for future

    # ---------- UI helpers ----------
    def clear(self):
        os.system("cls" if os.name == "nt" else "clear")

    def banner(self):
        print("=" * 70)
        print("   ██████╗ █████╗ ███╗   ███╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗")
        print("  ██╔════╝██╔══██╗████╗ ████║██║  ██║██║   ██║████╗  ██║╚══██╔══╝")
        print("  ██║     ███████║██╔████╔██║███████║██║   ██║██╔██╗ ██║   ██║   ")
        print("  ██║     ██╔══██║██║╚██╔╝██║██╔══██║██║   ██║██║╚██╗██║   ██║   ")
        print("  ╚██████╗██║  ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ")
        print("   ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ")
        print("=" * 70)
        print("         Hidden Camera Detector & Network Security Tool")
        print("                      Version 1.0.0")
        print("=" * 70)

    def show_my_network(self):
        """Display current network info"""
        print("\n" + "-" * 70)
        print("  [*] Your Network Info")
        print("-" * 70)

        if not self.network_info:
            self.network_info = self.scanner.get_my_network()

        if self.network_info:
            ssid = self.network_info.get("ssid", "Unknown")
            print(f"  [SSID]     : {ssid}")
            print(f"  [Your IP]  : {self.network_info['local_ip']}")
            print(f"  [Range]    : {self.network_info['network_range']}")
        else:
            print("  [!] Network info unavailable")

        print("-" * 70)

    # ---------- Main menu ----------
    def show_menu(self):
        print("\n  +-----------------------------------------------+")
        print("  |              MAIN MENU                        |")
        print("  +-----------------------------------------------+")
        print("  |  1. Show connected IPs on network             |")
        print("  |  2. Block an IP address                       |")
        print("  |  3. View console & activity log               |")
        print("  |  4. Show blocked IPs                          |")
        print("  |  5. Exit                                      |")
        print("  +-----------------------------------------------+")

    # ---------- Option 1: Scan ----------
    def option_scan(self):
        self.clear()
        self.banner()
        print("\n  [*] Scanning network... please wait\n")

        if not self.network_info:
            self.network_info = self.scanner.get_my_network()

        if not self.network_info:
            print("  [X] Could not determine network. Check Wi-Fi connection.")
            input("\n  [Enter] to return...")
            return

        devices = self.scanner.scan(self.network_info["network_range"])
        self.last_scan = devices

        print(f"\n  [OK] Found {len(devices)} device(s)\n")

        if devices:
            print("  +----+-----------------+-------------------+----------------------+")
            print("  | #  | IP Address      | MAC Address       | Hostname             |")
            print("  +----+-----------------+-------------------+----------------------+")

            for i, d in enumerate(devices, 1):
                host = d['hostname'][:20] if d['hostname'] else "Unknown"
                print(
                    f"  | {i:<2} | {d['ip']:<15} | {d['mac']:<17} | {host:<20} |"
                )

            print("  +----+-----------------+-------------------+----------------------+")
        else:
            print("  [!] No devices found.")
            print("  [TIP] Try running with sudo for ARP scan.")
            print("  [TIP] Install nmap: pkg install nmap (Termux)")

        input("\n  [Enter] to return...")

    # ---------- Option 2: Block IP ----------
    def option_block(self):
        self.clear()
        self.banner()
        print("\n  [*] Block an IP Address")
        print("-" * 70)

        if self.last_scan:
            print("\n  Devices from last scan:")
            for i, d in enumerate(self.last_scan, 1):
                print(f"    {i}. {d['ip']}  ({d['mac']})")
        else:
            print("\n  [!] No scan yet. Run option 1 first.")

        ip = input("\n  Enter IP to block: ").strip()

        if not ip:
            print("  [X] No IP entered.")
            input("\n  [Enter] to return...")
            return

        confirm = input(f"  [?] Block {ip}? (y/n): ").strip().lower()
        if confirm != 'y':
            print("  Cancelled.")
            input("\n  [Enter] to return...")
            return

        print("\n  [*] Blocking... (sudo password may be required)")
        ok, msg = self.blocker.block_ip(ip)

        if ok:
            print(f"\n  [OK] {msg}")
        else:
            print(f"\n  [X] Failed: {msg}")

        input("\n  [Enter] to return...")

    # ---------- Option 3: Console & Activity Log ----------
    def option_logs(self):
        self.clear()
        self.banner()
        print("\n  [*] Console & Activity Log")
        print("-" * 70)

        # Live snapshot of who is doing what
        self._show_live_activity()

        print("\n" + "-" * 70)
        print("  [*] Recent log entries (last 30):")
        print("-" * 70)

        log_file = "logs/camhunt.log"
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            recent = lines[-30:]
            for line in recent:
                print("  " + line.rstrip())

            print(f"\n  Log file: {log_file}")
            print(f"  Total entries: {len(lines)}")
        else:
            print("  [!] No log file yet.")

        print("\n  [i] Options:")
        print("      1. Refresh")
        print("      2. Open full log file")
        print("      3. Back to main menu")

        choice = input("\n  Choose: ").strip()

        if choice == "1":
            self.option_logs()
        elif choice == "2":
            self._open_full_log(log_file)
        else:
            return

    def _show_live_activity(self):
        """Show live network activity snapshot"""
        print("\n  [*] Live Network Snapshot")
        print("-" * 70)

        if not self.network_info:
            self.network_info = self.scanner.get_my_network()

        if not self.network_info:
            print("  [!] Network info unavailable.")
            return

        # Show all currently connected devices
        devices = self.last_scan if self.last_scan else self.scanner.scan(
            self.network_info["network_range"], timeout=3
        )

        if not devices:
            print("  [!] No devices detected. Run option 1 first.")
            return

        print(f"  Total devices online: {len(devices)}\n")
        print("  +----+-----------------+-------------------+-------------------------+")
        print("  | #  | IP Address      | MAC Address       | What it is doing        |")
        print("  +----+-----------------+-------------------+-------------------------+")

        for i, d in enumerate(devices, 1):
            activity = self._guess_activity(d['ip'], d['mac'])
            print(
                f"  | {i:<2} | {d['ip']:<15} | {d['mac']:<17} | {activity:<23} |"
            )

        print("  +----+-----------------+-------------------+-------------------------+")

        # Blocked IPs
        blocked = self.blocker.get_blocked_list()
        if blocked:
            print(f"\n  Blocked IPs ({len(blocked)}):")
            for ip in blocked:
                print(f"    - {ip}  [BLOCKED]")

        # Active connections
        print("\n  [*] Active TCP connections from this device:")
        self._show_active_connections()

    def _guess_activity(self, ip, mac):
        """Try to identify device type and activity"""
        # Known camera vendor MAC prefixes
        camera_prefixes = {
            "44:19:B6": "Hikvision CAM",
            "C0:56:E3": "Hikvision CAM",
            "BC:AD:28": "Hikvision CAM",
            "3C:EF:8C": "Dahua CAM",
            "90:02:A9": "Dahua CAM",
            "4C:11:BF": "Dahua CAM",
            "00:40:8C": "Axis CAM",
            "AC:CC:8E": "Axis CAM",
            "A4:2B:B0": "TP-Link (possible CAM)",
            "50:C7:BF": "TP-Link (possible CAM)",
            "B0:4E:26": "TP-Link",
            "2C:AA:8E": "Wyze CAM",
            "7C:78:B2": "Wyze CAM",
            "EC:71:DB": "Reolink CAM",
            "00:62:6E": "Foscam CAM",
            "9C:8E:CD": "Amcrest CAM",
            "C4:2F:90": "EZVIZ CAM",
            "BC:7E:8B": "EZVIZ CAM",
        }

        prefix = mac[:8].upper()
        if prefix in camera_prefixes:
            return camera_prefixes[prefix]

        # Check open ports to guess service
        ports = self._check_ports(ip)
        if 554 in ports or 8554 in ports:
            return "RTSP stream (camera?)"
        if 8000 in ports or 37777 in ports:
            return "Camera SDK port"
        if 80 in ports or 8080 in ports:
            return "HTTP service"
        if 22 in ports:
            return "SSH server"
        if 445 in ports:
            return "SMB / file share"
        if 3389 in ports:
            return "RDP / Windows"

        return "Idle / unknown"

    def _check_ports(self, ip):
        """Quick check of common camera ports"""
        import socket
        open_ports = []
        common_ports = [22, 80, 443, 445, 554, 3389, 8000, 8080, 8554, 37777]

        for port in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass

        return open_ports

    def _show_active_connections(self):
        """Show active TCP connections (netstat/ss)"""
        try:
            if os.name == "nt":
                result = subprocess.run(
                    ["netstat", "-n"],
                    capture_output=True, text=True, timeout=10
                )
                output = result.stdout
            else:
                # Linux / Termux / macOS
                result = subprocess.run(
                    ["ss", "-tn"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    result = subprocess.run(
                        ["netstat", "-tn"],
                        capture_output=True, text=True, timeout=10
                    )
                output = result.stdout

            lines = output.split("\n")
            count = 0
            for line in lines:
                if "ESTAB" in line or "ESTABLISHED" in line:
                    print(f"    {line.strip()}")
                    count += 1
                    if count >= 10:
                        break

            if count == 0:
                print("    (no active connections)")

        except Exception as e:
            print(f"    [!] Could not read connections: {e}")

    def _open_full_log(self, log_file):
        """Show full log file"""
        self.clear()
        self.banner()
        print(f"\n  [*] Full Log: {log_file}")
        print("-" * 70)

        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                print(f.read())
        else:
            print("  [!] File not found.")

        input("\n  [Enter] to return...")

    # ---------- Option 4: Blocked list ----------
    def option_blocked_list(self):
        self.clear()
        self.banner()
        print("\n  [*] Blocked IP List")
        print("-" * 70)

        blocked = self.blocker.get_blocked_list()
        if not blocked:
            print("  No IPs blocked yet.")
        else:
            for i, ip in enumerate(blocked, 1):
                print(f"  {i}. {ip}")

        input("\n  [Enter] to return...")

    # ---------- Main loop ----------
    def run(self):
        self.clear()
        self.banner()
        self.show_my_network()

        print("\n  [!] Legal Notice:")
        print("  Use this tool ONLY on your own network.")
        print("  Unauthorized use is illegal in Bangladesh.")

        input("\n  [Enter] to begin...")

        while True:
            self.clear()
            self.banner()
            self.show_my_network()
            self.show_menu()

            choice = input("\n  > Choose (1-5): ").strip()

            if choice == "1":
                self.option_scan()
            elif choice == "2":
                self.option_block()
            elif choice == "3":
                self.option_logs()
            elif choice == "4":
                self.option_blocked_list()
            elif choice == "5":
                self.logger.info("User exited")
                print("\n  Bye! CamHunt stopped.\n")
                sys.exit(0)
            else:
                print("\n  [X] Invalid choice! Enter 1-5")
                input("  [Enter] to continue...")
