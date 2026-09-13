"""নেটওয়ার্ক স্ক্যানার — কোন কোন IP সংযুক্ত আছে তা বের করে"""

import subprocess
import socket
import json
import platform

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkScanner:
    def __init__(self, logger):
        self.logger = logger

    # ---------- নিজের নেটওয়ার্ক তথ্য ----------
    def get_my_network(self):
        """নিজের Wi-Fi নেটওয়ার্কের নাম (SSID), IP ও রেঞ্জ বের করে"""
        try:
            local_ip = self._get_local_ip()
            if not local_ip:
                self.logger.error("নিজের IP পাওয়া যায়নি")
                return None

            ip_parts = local_ip.split(".")
            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

            ssid = self._get_wifi_ssid()

            self.logger.info(f"নেটওয়ার্ক নাম (SSID): {ssid}")
            self.logger.info(f"আমার IP: {local_ip}")
            self.logger.info(f"নেটওয়ার্ক রেঞ্জ: {network_range}")

            return {
                "ssid": ssid,
                "local_ip": local_ip,
                "network_range": network_range
            }
        except Exception as e:
            self.logger.error(f"নেটওয়ার্ক বের করতে সমস্যা: {e}")
            return None

    def _get_local_ip(self):
        """সক্রিয় ইন্টারফেসের লোকাল IP বের করে"""
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
        """Wi-Fi নেটওয়ার্কের নাম (SSID) বের করে — সব প্লাটফর্মে"""
        os_type = platform.system()

        # ---------- Termux / Android ----------
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

        # ---------- Linux ----------
        if os_type == "Linux":
            # nmcli
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

            # iwgetid
            try:
                r = subprocess.run(
                    ["iwgetid", "-r"],
                    capture_output=True, text=True, timeout=5
                )
                if r.stdout.strip():
                    return r.stdout.strip()
            except Exception:
                pass

            # iw dev
            try:
                r = subprocess.run(
                    ["iw", "dev"],
                    capture_output=True, text=True, timeout=5
                )
                for line in r.stdout.split("\n"):
                    if "ssid" in line.lower():
                        return line.split("ssid", 1)[1].strip()
            except Exception:
                pass

        # ---------- macOS ----------
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

        # ---------- Windows ----------
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

    # ---------- ডিভাইস স্ক্যান ----------
    def scan(self, network_range, timeout=3):
        """ARP স্ক্যান — নেটওয়ার্কে সংযুক্ত সব ডিভাইস"""
        self.logger.info(f"স্ক্যান শুরু: {network_range}")

        devices = []

        if SCAPY_AVAILABLE:
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
                    self.logger.info(
                        f"পাওয়া গেছে: {device['ip']} | {device['mac']}"
                    )

                if devices:
                    self.logger.info(f"মোট ডিভাইস: {len(devices)}")
                    return devices

            except PermissionError:
                self.logger.warning("রুট নেই! nmap fallback ব্যবহার করছি...")
            except Exception as e:
                self.logger.error(f"scapy স্ক্যান ত্রুটি: {e}")

        # Fallback: nmap
        return self._nmap_scan(network_range)

    def _nmap_scan(self, network_range):
        """nmap দিয়ে fallback স্ক্যান"""
        try:
            result = subprocess.run(
                ["nmap", "-sn", network_range],
                capture_output=True, text=True, timeout=60
            )

            devices = []
            current_ip = None
            current_host = None

            for line in result.stdout.split("\n"):
                if "Nmap scan report for" in line:
                    parts = line.replace("Nmap scan report for", "").strip()
                    if "(" in parts:
                        current_host = parts.split("(")[0].strip()
                        current_ip = parts.split("(")[1].strip(")")
                    else:
                        current_ip = parts
                        current_host = parts
                elif "MAC Address:" in line and current_ip:
                    mac = line.split("MAC Address:")[1].split()[0]
                    devices.append({
                        "ip": current_ip,
                        "mac": mac,
                        "hostname": current_host or "Unknown"
                    })
                    current_ip = None

            self.logger.info(f"nmap: মোট {len(devices)} ডিভাইস")
            return devices

        except FileNotFoundError:
            self.logger.error("nmap ইনস্টল নেই!")
            return []
        except Exception as e:
            self.logger.error(f"nmap ব্যর্থ: {e}")
            return []

    def _get_hostname(self, ip):
        """IP থেকে হোস্টনেম বের করার চেষ্টা"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"      
