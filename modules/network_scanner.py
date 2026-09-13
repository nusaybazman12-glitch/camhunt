"""Network scanner - discovers devices on local network"""

import subprocess
import socket
import json
import platform
import os
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
        """Get SSID, local IP and network range - no permission prompts"""
        try:
            local_ip = self._get_local_ip()
            if not local_ip:
                self.logger.error("Could not determine local IP")
                return None

            ip_parts = local_ip.split(".")
            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
            ssid = self._get_wifi_ssid()
            mac = self._get_my_mac()

            info = {
                "ssid": ssid,
                "local_ip": local_ip,
                "network_range": network_range,
                "gateway": gateway,
                "my_mac": mac,
                "hostname": self._get_hostname()
            }

            self.logger.info(f"Network: {ssid} | IP: {local_ip} | Range: {network_range}")
            return info

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

    def _get_hostname(self):
        try:
            return socket.gethostname()
        except Exception:
            return "Unknown"

    def _get_my_mac(self):
        """Get own MAC address"""
        try:
            import uuid
            mac = uuid.getnode()
            mac_str = ':'.join(['{:02x}'.format((mac >> ele) & 0xff)
                                for ele in range(40, -1, -8)])
            return mac_str.upper()
        except Exception:
            return "Unknown"

    def _get_wifi_ssid(self):
        """Get Wi-Fi SSID - no permission prompts, multiple fallbacks"""
        os_type = platform.system()

        # Method 1: Termux API
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

            # Method 2: Android dumpsys
            try:
                r = subprocess.run(
                    ["dumpsys", "wifi", "|", "grep", "SSID"],
                    capture_output=True, text=True, timeout=5, shell=True
                )
                for line in r.stdout.split("\n"):
                    m = re.search(r'SSID:\s*"?([^",]+)"?', line)
                    if m and m.group(1).strip() not in ("", "<unknown ssid>"):
                        return m.group(1).strip()
            except Exception:
                pass

        # Linux
        if os_type == "Linux":
            for cmd in [
                ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                ["iwgetid", "-r"],
                ["iw", "dev"],
            ]:
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if "nmcli" in cmd[0]:
                        for line in r.stdout.split("\n"):
                            if line.startswith("yes:"):
                                return line.split(":", 1)[1].strip()
                    elif "iwgetid" in cmd[0]:
                        if r.stdout.strip():
                            return r.stdout.strip()
                    else:
                        for line in r.stdout.split("\n"):
                            if "ssid" in line.lower():
                                return line.split("ssid", 1)[1].strip()
                except Exception:
                    continue

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
        """Scan network - try multiple methods"""
        self.logger.info(f"Scanning: {network_range}")
        devices = []

        if SCAPY_AVAILABLE:
            devices = self._scapy_scan(network_range, timeout)
            if devices:
                return devices

        devices = self._nmap_scan(network_range)
        if devices:
            return devices

        devices = self._arpscan_scan()
        if devices:
            return devices

        devices = self._proc_arp_scan()
        if devices:
            return devices

        self.logger.warning("All scan methods failed")
        return []

    def _scapy_scan(self, network_range, timeout):
        devices = []
        try:
            arp = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=timeout, verbose=False)[0]

            for _, received in result:
                devices.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc.upper(),
                    "hostname": self._get_hostname_by_ip(received.psrc)
                })
            self.logger.info(f"scapy: found {len(devices)} devices")
        except PermissionError:
            self.logger.warning("scapy: permission denied")
        except Exception as e:
            self.logger.warning(f"scapy failed: {e}")
        return devices

    def _nmap_scan(self, network_range):
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
                        "mac": mac.upper(),
                        "hostname": current_host or "Unknown"
                    })
                    current_ip = None
                    current_host = None

            # Add IPs without MAC
            for line in result.stdout.split("\n"):
                m = re.match(r"Nmap scan report for (.+)", line.strip())
                if m:
                    entry = m.group(1).strip()
                    ip = entry.split("(")[1].strip(")") if "(" in entry else entry
                    if not any(d["ip"] == ip for d in devices):
                        devices.append({"ip": ip, "mac": "N/A", "hostname": "Unknown"})
            self.logger.info(f"nmap: found {len(devices)} devices")
        except FileNotFoundError:
            self.logger.warning("nmap not installed")
        except Exception as e:
            self.logger.warning(f"nmap failed: {e}")
        return devices

    def _arpscan_scan(self):
        devices = []
        try:
            result = subprocess.run(
                ["arp-scan", "--localnet"],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.split("\n"):
                m = re.match(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)", line
                )
                if m:
                    ip, mac, vendor = m.groups()
                    devices.append({
                        "ip": ip,
                        "mac": mac.upper(),
                        "hostname": vendor.strip() or "Unknown"
                    })
        except FileNotFoundError:
            pass
        except Exception as e:
            self.logger.warning(f"arp-scan failed: {e}")
        return devices

    def _proc_arp_scan(self):
        devices = []
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3].upper()
                    if mac != "00:00:00:00:00:00":
                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "hostname": "Unknown"
                        })
        except Exception:
            pass
        return devices

    def _get_hostname_by_ip(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"
