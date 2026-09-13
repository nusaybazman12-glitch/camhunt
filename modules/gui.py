"""CamHunt v2.0 - Tkinter GUI (no extra permissions needed)"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import os
import json
from datetime import datetime

from modules.network_scanner import NetworkScanner
from modules.ip_blocker import IPBlocker
from modules.device_fingerprint import DeviceFingerprint
from modules.camera_detector import CameraDetector
from modules.report_generator import ReportGenerator


class CamHuntApp:
    def __init__(self, logger):
        self.logger = logger
        self.scanner = NetworkScanner(logger)
        self.blocker = IPBlocker(logger)
        self.fingerprint = DeviceFingerprint()
        self.detector = CameraDetector(logger)
        self.reporter = ReportGenerator(logger)

        self.network_info = None
        self.devices = []
        self.analysis = []

        self.root = tk.Tk()
        self.root.title("CamHunt v2.0 - Hidden Camera Detector")
        self.root.geometry("1100x700")
        self.root.minsize(900, 600)

        self._build_ui()

    # ---------- UI ----------
    def _build_ui(self):
        # Top banner
        top = tk.Frame(self.root, bg="#1e2a38", height=60)
        top.pack(fill="x")
        tk.Label(top, text="  CamHunt v2.0", bg="#1e2a38", fg="#00d4ff",
                 font=("Helvetica", 20, "bold")).pack(side="left", padx=10, pady=10)
        tk.Label(top, text="Hidden Camera Detector & Network Security",
                 bg="#1e2a38", fg="#aaaaaa", font=("Helvetica", 10)).pack(side="left")

        # Network info bar
        info = tk.Frame(self.root, bg="#2b3a4a", height=40)
        info.pack(fill="x")
        self.lbl_ssid = tk.Label(info, text="SSID: loading...", bg="#2b3a4a",
                                  fg="white", font=("Helvetica", 10))
        self.lbl_ssid.pack(side="left", padx=15, pady=8)
        self.lbl_ip = tk.Label(info, text="IP: -", bg="#2b3a4a",
                                fg="white", font=("Helvetica", 10))
        self.lbl_ip.pack(side="left", padx=15)
        self.lbl_range = tk.Label(info, text="Range: -", bg="#2b3a4a",
                                   fg="white", font=("Helvetica", 10))
        self.lbl_range.pack(side="left", padx=15)

        # Buttons
        btns = tk.Frame(self.root, bg="#f0f0f0", pady=10)
        btns.pack(fill="x")
        tk.Button(btns, text="🔍 Scan Network", command=self._on_scan,
                  bg="#00a8ff", fg="white", font=("Helvetica", 11, "bold"),
                  padx=20, pady=8).pack(side="left", padx=10)
        tk.Button(btns, text="🚫 Block Selected", command=self._on_block,
                  bg="#e74c3c", fg="white", font=("Helvetica", 11, "bold"),
                  padx=20, pady=8).pack(side="left", padx=5)
        tk.Button(btns, text="📄 Export Report", command=self._on_export,
                  bg="#27ae60", fg="white", font=("Helvetica", 11, "bold"),
                  padx=20, pady=8).pack(side="left", padx=5)
        tk.Button(btns, text="🔄 Refresh", command=self._refresh_network,
                  bg="#f39c12", fg="white", font=("Helvetica", 11, "bold"),
                  padx=20, pady=8).pack(side="left", padx=5)

        # Notebook (tabs)
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab 1: Devices
        tab1 = tk.Frame(self.nb)
        self.nb.add(tab1, text="📱 Devices")
        self._build_device_tab(tab1)

        # Tab 2: Cameras
        tab2 = tk.Frame(self.nb)
        self.nb.add(tab2, text="🎥 Cameras")
        self._build_camera_tab(tab2)

        # Tab 3: Log
        tab3 = tk.Frame(self.nb)
        self.nb.add(tab3, text="📜 Activity Log")
        self._build_log_tab(tab3)

        # Tab 4: Blocked
        tab4 = tk.Frame(self.nb)
        self.nb.add(tab4, text="🚫 Blocked IPs")
        self._build_blocked_tab(tab4)

        # Status bar
        self.status = tk.Label(self.root, text="Ready", anchor="w",
                                bg="#1e2a38", fg="white", padx=10)
        self.status.pack(fill="x", side="bottom")

    def _build_device_tab(self, parent):
        cols = ("IP", "MAC", "Hostname", "Type", "Ports", "Risk")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings", height=20)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=150 if c != "Risk" else 100, anchor="w")
        self.tree.column("IP", width=130)
        self.tree.column("MAC", width=160)
        self.tree.column("Ports", width=180)

        sb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Row colors for camera detection
        self.tree.tag_configure("camera", background="#ffcccc")
        self.tree.tag_configure("suspicious", background="#ffe0b3")

    def _build_camera_tab(self, parent):
        self.camera_text = scrolledtext.ScrolledText(
            parent, wrap="word", font=("Courier", 10), bg="#1e2a38", fg="#00ff88"
        )
        self.camera_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.camera_text.insert("end", "No camera scan yet. Click 'Scan Network'.\n")

    def _build_log_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(
            parent, wrap="word", font=("Courier", 10)
        )
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

    def _build_blocked_tab(self, parent):
        self.blocked_list = tk.Listbox(parent, font=("Courier", 11), height=20)
        self.blocked_list.pack(fill="both", expand=True, padx=5, pady=5)

    # ---------- Callbacks ----------
    def _refresh_network(self):
        self.status.config(text="Refreshing network info...")
        self.root.update()
        self.network_info = self.scanner.get_my_network()
        self._update_network_bar()
        self.status.config(text="Network refreshed")

    def _update_network_bar(self):
        if self.network_info:
            self.lbl_ssid.config(text=f"SSID: {self.network_info['ssid']}")
            self.lbl_ip.config(text=f"IP: {self.network_info['local_ip']}")
            self.lbl_range.config(text=f"Range: {self.network_info['network_range']}")

    def _on_scan(self):
        self.status.config(text="Scanning... please wait")
        self.log("Starting scan...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            if not self.network_info:
                self.network_info = self.scanner.get_my_network()
                self.root.after(0, self._update_network_bar)

            if not self.network_info:
                self.root.after(0, lambda: self.status.config(
                    text="Could not determine network"))
                return

            devices = self.scanner.scan(self.network_info["network_range"])
            self.devices = devices

            # Analyze each device
            analysis = []
            for d in devices:
                result = self.detector.analyze(d["ip"], d["mac"], self.fingerprint)
                result["hostname"] = d.get("hostname", "Unknown")
                analysis.append(result)

            self.analysis = analysis
            self.root.after(0, self._populate_devices)
            self.root.after(0, self._populate_cameras)
            self.root.after(0, lambda: self.status.config(
                text=f"Scan complete - {len(devices)} devices found"))
            self.log(f"Scan complete: {len(devices)} devices")

        except Exception as e:
            self.logger.error(f"Scan worker error: {e}")
            self.root.after(0, lambda: self.status.config(text=f"Error: {e}"))

    def _populate_devices(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for a in self.analysis:
            tag = ""
            if a["risk_level"] == "HIGH":
                tag = "camera"
            elif a["risk_level"] == "MEDIUM":
                tag = "suspicious"

            ports = ",".join(str(p) for p in a["open_ports"][:4])
            self.tree.insert("", "end", values=(
                a["ip"], a["mac"], a["hostname"][:20],
                a["device_type"][:25], ports,
                f"{a['risk_level']} ({a['risk_score']})"
            ), tags=(tag,))

    def _populate_cameras(self):
        self.camera_text.delete("1.0", "end")
        cams = [a for a in self.analysis if a["risk_level"] in ("HIGH", "MEDIUM")]

        if not cams:
            self.camera_text.insert("end",
                "✅ No suspicious cameras detected on this network.\n")
            return

        self.camera_text.insert("end",
            f"⚠️  Found {len(cams)} suspicious device(s):\n\n")

        for c in cams:
            self.camera_text.insert("end", "=" * 60 + "\n")
            self.camera_text.insert("end", f"IP       : {c['ip']}\n")
            self.camera_text.insert("end", f"MAC      : {c['mac']}\n")
            self.camera_text.insert("end", f"Type     : {c['device_type']}\n")
            self.camera_text.insert("end", f"Risk     : {c['risk_level']} ({c['risk_score']}/100)\n")
            self.camera_text.insert("end", f"Ports    : {c['open_ports']}\n")
            self.camera_text.insert("end", "Reasons  :\n")
            for r in c["reasons"]:
                self.camera_text.insert("end", f"  - {r}\n")
            self.camera_text.insert("end", "\n")

    def _on_block(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No selection", "Select a device first.")
            return

        values = self.tree.item(sel[0])["values"]
        ip = values[0]

        if not messagebox.askyesno("Confirm", f"Block {ip}?"):
            return

        ok, msg = self.blocker.block_ip(ip)
        self.log(f"Block {ip}: {msg}")
        if ok:
            messagebox.showinfo("Success", msg)
            self._refresh_blocked()
        else:
            messagebox.showerror("Failed", msg)

    def _refresh_blocked(self):
        self.blocked_list.delete(0, "end")
        for ip in self.blocker.get_blocked_list():
            self.blocked_list.insert("end", f"  {ip}  [BLOCKED]")

    def _on_export(self):
        if not self.analysis:
            messagebox.showwarning("No data", "Run a scan first.")
            return

        data = {
            "network": self.network_info,
            "devices": self.analysis,
            "timestamp": datetime.now().isoformat(),
        }

        json_path = self.reporter.export_json(data)
        txt_path = self.reporter.export_txt(data)

        messagebox.showinfo(
            "Report Exported",
            f"Saved to:\n{json_path}\n{txt_path}"
        )
        self.log(f"Report exported: {json_path}")

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        self.log_text.insert("end", line)
        self.log_text.see("end")

    # ---------- Main loop ----------
    def run(self):
        self.log("CamHunt v2.0 started")
        self.log("Auto-detecting network...")
        self.root.after(100, self._refresh_network)
        self.root.after(500, self._on_scan)

        # Load log file content
        log_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "logs", "camhunt.log"
        )
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()[-50:]
                for line in lines:
                    self.log_text.insert("end", line)
                self.log_text.see("end")
            except Exception:
                pass

        self.root.mainloop()
