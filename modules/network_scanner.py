"""Network scanner"""

import subprocess
import socket
import json
import platform
import os
import re

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkScanner:
    def __init__(self, logger):
        self.logger = logger

    def get_my_network(self):
        try:
            local_ip = self._get_local_ip()
            if not local_ip:
                return None

            parts = local_ip.split(".")
            network_range = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            gateway = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            ssid = self._get_wifi_ssid()

            return {
                "ssid": ssid,
                "local_ip": local_ip,
                "network_range": network_range,
                "gateway": gateway
            }
        except Exception as e:
            self.logger.error(f"Network detection failed: {e}")
            return None

    def _get_local_ip(self):
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
        os_type = platform.system()

        if os.path.exists("/data/data/com.termux"):
            try:
                r = subprocess.run(["termux-wifi-connectioninfo"],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    data = json.loads(r.stdout)
                    ssid = data.get("ssid", "")
                    if ssid:
                        return ssid
            except Exception:
                pass

            try:
                r = subprocess.run("dumpsys wifi | grep SSID",
                                   capture_output=True, text=True,
                                   timeout=5, shell=True)
                for line in r.stdout.split("\n"):
                    m = re.search(r'SSID:\s*"?([^",]+)"?', line)
                    if m and m.group(1).strip() not in ("", "<unknown ssid>"):
                        return m.group(1).strip()
            except Exception:
                pass

        if os_type == "Linux":
            for cmd in [["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                        ["iwgetid", "-r"]]:
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if "nmcli" in cmd[0]:
                        for line in r.stdout.split("\n"):
                            if line.startswith("yes:"):
                                return line.split(":", 1)[1].strip()
                    else:
                        if r.stdout.strip():
                            return r.stdout.strip()
                except Exception:
                    continue

        if os_type == "Darwin":
            try:
                r = subprocess.run(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework/"
                     "Versions/Current/Resources/airport", "-I"],
                    capture_output=True, text=True, timeout=5)
                for line in r.stdout.split("\n"):
                    if " SSID:" in line:
                        return line.split("SSID:")[1].strip()
            except Exception:
                pass

        if os_type == "Windows":
            try:
                r = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                   capture_output=True, text=True,
                                   timeout=5, shell=True)
                for line in r.stdout.split("\n"):
                    if "SSID" in line and "BSSID" not in line:
                        return line.split(":", 1)[1].strip()
            except Exception:
                pass

        return "Unknown"

    def scan(self, network_range, timeout=4):
        self.logger.info(f"Scanning: {network_range}")

        if SCAPY_AVAILABLE:
            devices = self._scapy_scan(network_range, timeout)
            if devices:
                return devices

        devices = self._nmap_scan(network_range)
        if devices:
            return devices

        devices = self._proc_arp_scan()
        if devices:
            return devices

        return []

    def _scapy_scan(self, network_range, timeout):
        devices = []
        try:
            arp = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            result = srp(ether/arp, timeout=timeout, verbose=False)[0]
            for _, recv in result:
                devices.append({
                    "ip": recv.psrc,
                    "mac": recv.hwsrc.upper(),
                    "hostname": self._get_hostname(recv.psrc)
                })
            self.logger.info(f"scapy: {len(devices)} devices")
        except Exception as e:
            self.logger.warning(f"scapy failed: {e}")
        return devices

    def _nmap_scan(self, network_range):
        devices = []
        try:
            r = subprocess.run(["nmap", "-sn", "-n", network_range],
                               capture_output=True, text=True, timeout=120)
            current_ip = None
            current_host = None

            for line in r.stdout.split("\n"):
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
                    devices.append({"ip": current_ip, "mac": mac.upper(),
                                    "hostname": current_host or "Unknown"})
                    current_ip = None

            for line in r.stdout.split("\n"):
                m = re.match(r"Nmap scan report for (.+)", line.strip())
                if m:
                    e = m.group(1).strip()
                    ip = e.split("(")[1].strip(")") if "(" in e else e
                    if not any(d["ip"] == ip for d in devices):
                        devices.append({"ip": ip, "mac": "N/A", "hostname": "Unknown"})
            self.logger.info(f"nmap: {len(devices)} devices")
        except FileNotFoundError:
            self.logger.warning("nmap not installed")
        except Exception as e:
            self.logger.warning(f"nmap failed: {e}")
        return devices

    def _proc_arp_scan(self):
        devices = []
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
            for line in lines:
                p = line.split()
                if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                    devices.append({"ip": p[0], "mac": p[3].upper(),
                                    "hostname": "Unknown"})
        except Exception:
            pass
        return devices

    def _get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"
