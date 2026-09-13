"""GUI ইন্টারফেস — মেনু, স্ক্যান, ব্লক, লগ সব একসাথে"""

import os
import sys
from modules.network_scanner import NetworkScanner
from modules.ip_blocker import IPBlocker


class CamHuntGUI:
    def __init__(self, logger):
        self.logger = logger
        self.scanner = NetworkScanner(logger)
        self.blocker = IPBlocker(logger)
        self.network_info = None
        self.last_scan = []

    # ---------- UI হেল্পার ----------
    def clear(self):
        os.system("cls" if os.name == "nt" else "clear")

    def banner(self):
        print("=" * 65)
        print("   ██████╗ █████╗ ███╗   ███╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗")
        print("  ██╔════╝██╔══██╗████╗ ████║██║  ██║██║   ██║████╗  ██║╚══██╔══╝")
        print("  ██║     ███████║██╔████╔██║███████║██║   ██║██╔██╗ ██║   ██║   ")
        print("  ██║     ██╔══██║██║╚██╔╝██║██╔══██║██║   ██║██║╚██╗██║   ██║   ")
        print("  ╚██████╗██║  ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ")
        print("   ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ")
        print("=" * 65)
        print("        Hidden Camera Detector & Network Security Tool")
        print("                    Version 1.0.0")
        print("=" * 65)
        print()

    def show_my_network(self):
        """নিজের Wi-Fi নেটওয়ার্ক দেখায়"""
        print("\n" + "─" * 65)
        print("  📡 আপনার নেটওয়ার্ক তথ্য")
        print("─" * 65)

        if not self.network_info:
            self.network_info = self.scanner.get_my_network()

        if self.network_info:
            ssid = self.network_info.get("ssid", "Unknown")
            print(f"  📶 নেটওয়ার্ক নাম : {ssid}")
            print(f"  🌐 আপনার IP     : {self.network_info['local_ip']}")
            print(f"  🔗 নেটওয়ার্ক রেঞ্জ: {self.network_info['network_range']}")
        else:
            print("  ✗ নেটওয়ার্ক তথ্য পাওয়া যায়নি")

        print("─" * 65)

    # ---------- মূল মেনু ----------
    def show_menu(self):
        print("\n  ┌─────────────────────────────────────────────┐")
        print("  │           📋 মূল মেনু                        │")
        print("  ├─────────────────────────────────────────────┤")
        print("  │  1. নেটওয়ার্কে সংযুক্ত IP দেখুন             │")
        print("  │  2. IP ব্লক করুন                            │")
        print("  │  3. কনসোল ও লগ দেখুন                        │")
        print("  │  4. ব্লকড IP তালিকা                         │")
        print("  │  5. প্রস্থান করুন                           │")
        print("  └─────────────────────────────────────────────┘")

    # ---------- অপশন ১ ----------
    def option_scan(self):
        self.clear()
        self.banner()
        print("\n  🔍 নেটওয়ার্ক স্ক্যান চলছে... অপেক্ষা করুন\n")

        if not self.network_info:
            self.network_info = self.scanner.get_my_network()

        devices = self.scanner.scan(self.network_info["network_range"])
        self.last_scan = devices

        print(f"\n  ✓ মোট {len(devices)} টি ডিভাইস পাওয়া গেছে\n")

        if devices:
            print("  ┌────┬─────────────────┬───────────────────┬──────────────────────┐")
            print("  │ #  │ IP Address      │ MAC Address       │ Hostname             │")
            print("  ├────┼─────────────────┼───────────────────┼──────────────────────┤")

            for i, d in enumerate(devices, 1):
                host = d['hostname'][:20] if d['hostname'] else "Unknown"
                print(
                    f"  │ {i:<2} │ {d['ip']:<15} │ {d['mac']:<17} │ {host:<20} │"
                )

            print("  └────┴─────────────────┴───────────────────┴──────────────────────┘")
        else:
            print("  [!] কোনো ডিভাইস পাওয়া যায়নি")
            print("  💡 টিপস: sudo দিয়ে চালান বা nmap ইনস্টল করুন")

        input("\n  [Enter] চাপুন ফিরে যেতে...")

    # ---------- অপশন ২ ----------
    def option_block(self):
        self.clear()
        self.banner()
        print("\n  🚫 IP ব্লক করার অপশন")
        print("─" * 65)

        if self.last_scan:
            print("\n  শেষ স্ক্যান থেকে পাওয়া IP সমূহ:")
            for i, d in enumerate(self.last_scan, 1):
                print(f"    {i}. {d['ip']}  ({d['mac']})")
        else:
            print("\n  [!] আগে অপশন ১ থেকে স্ক্যান করুন")

        ip = input("\n  📌 যে IP ব্লক করবেন সেটি লিখুন: ").strip()

        if not ip:
            print("  ✗ কোনো IP দেওয়া হয়নি")
            input("\n  [Enter] চাপুন...")
            return

        confirm = input(f"  ⚠️  {ip} ব্লক করতে চান? (y/n): ").strip().lower()
        if confirm != 'y':
            print("  বাতিল করা হলো।")
            input("\n  [Enter] চাপুন...")
            return

        print("\n  ⏳ ব্লক করা হচ্ছে... (sudo পাসওয়ার্ড লাগতে পারে)")
        ok, msg = self.blocker.block_ip(ip)

        if ok:
            print(f"\n  ✅ {msg}")
        else:
            print(f"\n  ❌ ব্যর্থ: {msg}")

        input("\n  [Enter] চাপুন...")

    # ---------- অপশন ৩ ----------
    def option_logs(self):
        self.clear()
        self.banner()
        print("\n  📜 কনসোল ও লগ — সাম্প্রতিক কার্যক্রম")
        print("─" * 65)

        log_file = "logs/camhunt.log"
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()

            recent = lines[-30:]
            for line in recent:
                print("  " + line.rstrip())

            print(f"\n  📁 পূর্ণ লগ: {log_file}")
            print(f"  📊 মোট লাইন: {len(lines)}")
        else:
            print("  [!] কোনো লগ ফাইল নেই")

        input("\n  [Enter] চাপুন...")

    # ---------- অপশন ৪ ----------
    def option_blocked_list(self):
        self.clear()
        self.banner()
        print("\n  🚫 ব্লক করা IP তালিকা")
        print("─" * 65)

        blocked = self.blocker.get_blocked_list()
        if not blocked:
            print("  কোনো IP ব্লক করা হয়নি")
        else:
            for i, ip in enumerate(blocked, 1):
                print(f"  {i}. {ip}")

        input("\n  [Enter] চাপুন...")

    # ---------- মূল লুপ ----------
    def run(self):
        self.clear()
        self.banner()
        self.show_my_network()

        print("\n  ⚠️  আইনি সতর্কতা:")
        print("  এই টুল শুধুমাত্র নিজের নেটওয়ার্কে ব্যবহার করুন।")
        print("  অন্যের নেটওয়ার্কে ব্যবহার করা বাংলাদেশে অবৈধ।")

        input("\n  [Enter] চাপুন শুরু করতে...")

        while True:
            self.clear()
            self.banner()
            self.show_my_network()
            self.show_menu()

            choice = input("\n  ➤ আপনার পছন্দ (1-5): ").strip()

            if choice == "1":
                self.option_scan()
            elif choice == "2":
                self.option_block()
            elif choice == "3":
                self.option_logs()
            elif choice == "4":
                self.option_blocked_list()
            elif choice == "5":
                self.logger.info("ব্যবহারকারী প্রস্থান করলেন")
                print("\n  👋 CamHunt বন্ধ করা হলো। বিদায়!\n")
                sys.exit(0)
            else:
                print("\n  ✗ ভুল পছন্দ! 1-5 এর মধ্যে দিন")
                input("  [Enter] চাপুন...")
