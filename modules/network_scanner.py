"""Network scanner - discovers connected devices"""

import subprocess
import socket
import json
import platform
import re

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkScanner:
    def __init__(self, logger):
        self.logger = logger

    # ---------- Own network info ----------
    def get_my_network(self):
        """Get SSID, local IP and network range"""
        try:
            local_ip = self._get_local_ip()
            if not local_ip:
                self.logger.error("Could not determine local IP")
                return None

            ip_parts = local_ip.split(".")
            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

            ssid = self._get_wifi_ssid()

            self.logger.info(f"Network SSID: {ssid}")
            self.logger.info(f"Local IP: {local_ip}")
            self.logger.info(f"Network range: {network_range}")

            return {
                "ssid": ssid,
                "local_ip": local_ip,
                "network_range": network_range
            }
        except Exception as e:
            self.logger.error(f"Network detection failed: {e}")
            return None

    def _get_local_ip(self):
        """Get active interface IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return None

    def _get_wifi_ssid(self):
        """Get Wi-Fi SSID across platforms"""
        os_type = platform.system()

        # Termux / Android
        if os.path.exists("/data/data/com.termux"):
            try:
                r = subprocess.run(
                    ["termux-wifi-connectioninfo"],
                    capture_output=True, text=True, timeout=5
                )
                if r.returncode == 0:
                    data = json.loads(r.stdout)
                    ssid = data.get("ssid", "")
                    if ssid:
                        return ssid
            except Exception:
                pass

        # Linux
        if os_type == "Linux":
            try:
                r = subprocess.run(
                    ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                    capture_output=True, text=True, timeout=5
                )
                for line in r.stdout.split("\n"):
                    if line.startswith("yes:"):
                        return line.split(":", 1)[1].strip()
            except Exception:
                pass

            try:
                r = subprocess.run(
                    ["iwgetid", "-r"],
                    capture_output=True, text=True, timeout=5
                )
                if r.stdout.strip():
                    return r.stdout.strip()
            except Exception:
                pass

        # macOS
        if os_type == "Darwin":
            try:
                r = subprocess.run(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework/"
                     "Versions/Current/Resources/airport", "-I"],
                    capture_output=True, text=True, timeout=5
                )
                for line in r.stdout.split("\n"):
                    if " SSID:" in line:
                        return line.split("SSID:")[1].strip()
            except Exception:
                pass

        # Windows
        if os_type == "Windows":
            try:
                r = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True, text=True, timeout=5, shell=True
                )
                for line in r.stdout.split("\n"):
                    if "SSID" in line and "BSSID" not in line:
                        return line.split(":", 1)[1].strip()
            except Exception:
                pass

        return "Unknown"

    # ---------- Device scanning ----------
    def scan(self, network_range, timeout=4):
        """Scan network - try scapy first, then nmap, then arp-scan"""
        self.logger.info(f"Scanning: {network_range}")

        devices = []

        # Method 1: scapy ARP
        if SCAPY_AVAILABLE:
            devices = self._scapy_scan(network_range, timeout)
            if devices:
                self.logger.info(f"scapy found {len(devices)} devices")
                return devices

        # Method 2: nmap
        devices = self._nmap_scan(network_range)
        if devices:
            self.logger.info(f"nmap found {len(devices)} devices")
            return devices

        # Method 3: arp-scan
        devices = self._arpscan_scan(network_range)
        if devices:
            self.logger.info(f"arp-scan found {len(devices)} devices")
            return devices

        # Method 4: /proc/net/arp (Linux fallback)
        devices = self._proc_arp_scan()
        if devices:
            self.logger.info(f"proc/arp found {len(devices)} devices")
            return devices

        self.logger.warning("All scan methods failed")
        return []

    def _scapy_scan(self, network_range, timeout):
        """ARP scan with scapy"""
        devices = []
        try:
            arp = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            result = srp(packet, timeout=timeout, verbose=False)[0]

            for _, received in result:
                device = {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "hostname": self._get_hostname(received.psrc)
                }
                devices.append(device)
                self.logger.info(f"Found: {device['ip']} | {device['mac']}")

        except PermissionError:
            self.logger.warning("scapy: permission denied (need root)")
        except Exception as e:
            self.logger.warning(f"scapy scan failed: {e}")

        return devices

    def _nmap_scan(self, network_range):
        """Scan with nmap"""
        devices = []
        try:
            result = subprocess.run(
                ["nmap", "-sn", "-n", network_range],
                capture_output=True, text=True, timeout=120
            )

            current_ip = None
            current_host = None

            for line in result.stdout.split("\n"):
                line = line.strip()

                if "Nmap scan report for" in line:
                    parts = line.replace("Nmap scan report for", "").strip()
                    if "(" in parts and parts.endswith(")"):
                        current_host = parts.split("(")[0].strip()
                        current_ip = parts.split("(")[1].strip(")")
                    else:
                        current_ip = parts
                        current_host = parts

                elif "MAC Address:" in line and current_ip:
                    mac = line.split("MAC Address:")[1].strip().split()[0]
                    devices.append({
                        "ip": current_ip,
                        "mac": mac,
                        "hostname": current_host or "Unknown"
                    })
                    self.logger.info(f"nmap: {current_ip} | {mac}")
                    current_ip = None
                    current_host = None

                # Some devices have no MAC (router itself, etc.)
                elif "Nmap scan report for" in line and current_ip:
                    pass

            # If nmap found IPs without MAC, add them too
            for line in result.stdout.split("\n"):
                m = re.match(r"Nmap scan report for (.+)", line.strip())
                if m:
                    entry = m.group(1).strip()
                    if "(" in entry:
                        ip = entry.split("(")[1].strip(")")
                    else:
                        ip = entry
                    if not any(d["ip"] == ip for d in devices):
                        devices.append({
                            "ip": ip,
                            "mac": "N/A",
                            "hostname": "Unknown"
                        })

        except FileNotFoundError:
            self.logger.warning("nmap not installed")
        except Exception as e:
            self.logger.warning(f"nmap failed: {e}")

        return devices

    def _arpscan_scan(self, network_range):
        """Scan with arp-scan (Linux only)"""
        devices = []
        try:
            result = subprocess.run(
                ["arp-scan", "--localnet"],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.split("\n"):
                m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)", line)
                if m:
                    ip, mac, vendor = m.groups()
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": vendor.strip() or "Unknown"
                    })
                    self.logger.info(f"arp-scan: {ip} | {mac}")
        except FileNotFoundError:
            pass
        except Exception as e:
            self.logger.warning(f"arp-scan failed: {e}")

        return devices

    def _proc_arp_scan(self):
        """Read /proc/net/arp (Linux last-resort)"""
        devices = []
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]  # skip header
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00":
                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "hostname": "Unknown"
                        })
                        self.logger.info(f"proc/arp: {ip} | {mac}")
        except Exception as e:
            self.logger.warning(f"proc/arp failed: {e}")

        return devices

    def _get_hostname(self, ip):
        """Reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"
