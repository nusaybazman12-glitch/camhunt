"""IP ব্লকার — নির্দিষ্ট IP কে নিজের নেটওয়ার্ক থেকে ব্লক করে"""

import subprocess
import platform
import os


class IPBlocker:
    def __init__(self, logger):
        self.logger = logger
        self.blocked_ips = []
        self.os_type = platform.system()
    
    def block_ip(self, ip):
        """নিজের ডিভাইসে firewall rule দিয়ে IP ব্লক"""
        
        if ip in self.blocked_ips:
            self.logger.warning(f"{ip} আগেই ব্লক করা আছে")
            return False, "আগেই ব্লক করা আছে"
        
        try:
            if self.os_type == "Linux":
                # iptables দিয়ে ব্লক
                cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    self.blocked_ips.append(ip)
                    self.logger.info(f"✓ ব্লক করা হয়েছে: {ip}")
                    return True, f"{ip} সফলভাবে ব্লক হয়েছে"
                else:
                    self.logger.error(f"ব্লক ব্যর্থ: {result.stderr}")
                    return False, result.stderr
            
            elif self.os_type == "Windows":
                rule_name = f"CamHunt_Block_{ip}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in", "action=block", f"remoteip={ip}"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True)
                
                if result.returncode == 0:
                    self.blocked_ips.append(ip)
                    self.logger.info(f"✓ ব্লক করা হয়েছে: {ip}")
                    return True, f"{ip} সফলভাবে ব্লক হয়েছে"
                else:
                    return False, result.stderr
            
            elif self.os_type == "Darwin":  # macOS
                cmd = ["sudo", "pfctl", "-t", "blocked_ips", "-T", "add", ip]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    self.blocked_ips.append(ip)
                    return True, f"{ip} সফলভাবে ব্লক হয়েছে"
                else:
                    return False, result.stderr
            
            else:
                return False, f"অসমর্থিত OS: {self.os_type}"
        
        except subprocess.TimeoutExpired:
            return False, "টাইমআউট — sudo পাসওয়ার্ড দরকার হতে পারে"
        except Exception as e:
            self.logger.error(f"ব্লক ত্রুটি: {e}")
            return False, str(e)
    
    def unblock_ip(self, ip):
        """ব্লক তুলে নেওয়া"""
        try:
            if self.os_type == "Linux":
                cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, timeout=10)
            elif self.os_type == "Windows":
                rule_name = f"CamHunt_Block_{ip}"
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(cmd, timeout=10, shell=True)
            
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            
            self.logger.info(f"✓ আনব্লক: {ip}")
            return True, f"{ip} আনব্লক করা হয়েছে"
        except Exception as e:
            return False, str(e)
    
    def get_blocked_list(self):
        return self.blocked_ips
