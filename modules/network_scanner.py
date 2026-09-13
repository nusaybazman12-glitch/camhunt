"""নেটওয়ার্ক স্ক্যানার — কোন কোন IP সংযুক্ত আছে তা বের করে"""

import subprocess
import re
from scapy.all import ARP, Ether, srp
import socket


class NetworkScanner:
    def __init__(self, logger):
        self.logger = logger
    
    def get_my_network(self):
        """নিজের নেটওয়ার্ক আইপি ও রেঞ্জ বের করে"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # /24 রেঞ্জ বানানো
            ip_parts = local_ip.split(".")
            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            self.logger.info(f"আমার IP: {local_ip}")
            self.logger.info(f"নেটওয়ার্ক রেঞ্জ: {network_range}")
            
            return {
                "local_ip": local_ip,
                "hostname": hostname,
                "network_range": network_range
            }
        except Exception as e:
            self.logger.error(f"নেটওয়ার্ক বের করতে সমস্যা: {e}")
            return None
    
    def scan(self, network_range, timeout=3):
        """ARP স্ক্যান — নেটওয়ার্কে সংযুক্ত সব ডিভাইস"""
        self.logger.info(f"স্ক্যান শুরু: {network_range}")
        
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
                self.logger.info(f"পাওয়া গেছে: {device['ip']} | {device['mac']}")
        
        except PermissionError:
            self.logger.error("রুট পারমিশন দরকার! sudo দিয়ে চালান।")
        except Exception as e:
            self.logger.error(f"স্ক্যান ত্রুটি: {e}")
        
        self.logger.info(f"মোট ডিভাইস পাওয়া গেছে: {len(devices)}")
        return devices
    
    def _get_hostname(self, ip):
        """IP থেকে হোস্টনেম বের করার চেষ্টা"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
