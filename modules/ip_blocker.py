"""IP Blocker - blocks IPs via firewall (works with sudo, no extra perms)"""

import subprocess
import platform
import os


class IPBlocker:
    def __init__(self, logger):
        self.logger = logger
        self.blocked_ips = []
        self.os_type = platform.system()
        self.is_termux = "termux" in os.environ.get("PREFIX", "")
        self.is_root = self._check_root()

    def _check_root(self):
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

    def block_ip(self, ip):
        if ip in self.blocked_ips:
            return False, "Already blocked"

        if self.is_termux and not self.is_root:
            return False, "Root required on Termux (run: sudo python camhunt.py)"

        try:
            if self.os_type == "Linux":
                cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    self.blocked_ips.append(ip)
                    self.logger.info(f"Blocked: {ip}")
                    return True, f"{ip} blocked successfully"
                return False, result.stderr.strip() or "iptables failed"

            elif self.os_type == "Windows":
                rule_name = f"CamHunt_Block_{ip}"
                cmd = (f'netsh advfirewall firewall add rule '
                       f'name="{rule_name}" dir=in action=block remoteip={ip}')
                result = subprocess.run(cmd, capture_output=True, text=True,
                                        timeout=15, shell=True)
                if result.returncode == 0:
                    self.blocked_ips.append(ip)
                    return True, f"{ip} blocked successfully"
                return False, result.stderr.strip()

            elif self.os_type == "Darwin":
                cmd = ["sudo", "pfctl", "-t", "blocked_ips", "-T", "add", ip]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    self.blocked_ips.append(ip)
                    return True, f"{ip} blocked successfully"
                return False, result.stderr.strip()

            return False, f"Unsupported OS: {self.os_type}"

        except subprocess.TimeoutExpired:
            return False, "Timeout - sudo password may be required"
        except Exception as e:
            self.logger.error(f"Block error: {e}")
            return False, str(e)

    def unblock_ip(self, ip):
        try:
            if self.os_type == "Linux":
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                               timeout=15)
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
