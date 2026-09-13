"""IP Blocker"""

import subprocess
import platform
import os


class IPBlocker:
    def __init__(self, logger):
        self.logger = logger
        self.blocked_ips = []
        self.os_type = platform.system()
        self.is_termux = "termux" in os.environ.get("PREFIX", "")

    def _is_root(self):
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

    def block_ip(self, ip):
        if ip in self.blocked_ips:
            return False, "Already blocked"

        if self.is_termux and not self._is_root():
            return False, "Root required on Termux (run: sudo python camhunt.py)"

        try:
            if self.os_type == "Linux":
                cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if r.returncode == 0:
                    self.blocked_ips.append(ip)
                    return True, f"{ip} blocked"
                return False, r.stderr.strip() or "iptables failed"

            elif self.os_type == "Windows":
                name = f"CamHunt_Block_{ip}"
                cmd = (f'netsh advfirewall firewall add rule name="{name}" '
                       f'dir=in action=block remoteip={ip}')
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=15, shell=True)
                if r.returncode == 0:
                    self.blocked_ips.append(ip)
                    return True, f"{ip} blocked"
                return False, r.stderr.strip()

            elif self.os_type == "Darwin":
                cmd = ["sudo", "pfctl", "-t", "blocked_ips", "-T", "add", ip]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if r.returncode == 0:
                    self.blocked_ips.append(ip)
                    return True, f"{ip} blocked"
                return False, r.stderr.strip()

            return False, f"Unsupported OS: {self.os_type}"
        except Exception as e:
            return False, str(e)

    def unblock_ip(self, ip):
        try:
            if self.os_type == "Linux":
                subprocess.run(["sudo", "iptables", "-D", "INPUT",
                                "-s", ip, "-j", "DROP"], timeout=15)
            elif self.os_type == "Windows":
                cmd = f'netsh advfirewall firewall delete rule name="CamHunt_Block_{ip}"'
                subprocess.run(cmd, timeout=15, shell=True)
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            return True, f"{ip} unblocked"
        except Exception as e:
            return False, str(e)

    def get_blocked_list(self):
        return self.blocked_ips
