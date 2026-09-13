"""Camera detector - port scan + risk scoring"""

import socket


class CameraDetector:
    CAMERA_PORTS = {
        554: "RTSP", 8554: "RTSP-alt", 37777: "Dahua SDK",
        8000: "Hikvision SDK", 80: "HTTP", 8080: "HTTP-alt",
        443: "HTTPS", 9000: "Camera API",
    }
    COMMON_PORTS = [22, 80, 443, 445, 554, 3389, 8000, 8080, 8554, 37777, 9000]

    def __init__(self, logger):
        self.logger = logger

    def scan_ports(self, ip, timeout=0.4):
        open_ports = []
        for port in self.COMMON_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
        return open_ports

    def analyze(self, ip, mac, fingerprint):
        open_ports = self.scan_ports(ip)
        cam_ports = [p for p in open_ports if p in self.CAMERA_PORTS]

        risk = 0
        reasons = []

        if fingerprint.is_camera(mac):
            risk += 60
            reasons.append(f"MAC matches camera vendor ({fingerprint.identify(mac)})")

        if 554 in open_ports or 8554 in open_ports:
            risk += 30
            reasons.append("RTSP streaming port open")

        if 37777 in open_ports or 8000 in open_ports:
            risk += 25
            reasons.append("Camera SDK port open")

        if len(cam_ports) >= 2:
            risk += 10
            reasons.append(f"Multiple camera ports open: {cam_ports}")

        if not reasons:
            reasons.append("No camera signature detected")

        risk = min(risk, 100)
        level = "HIGH" if risk >= 70 else "MEDIUM" if risk >= 40 else "LOW"

        return {
            "ip": ip, "mac": mac,
            "device_type": fingerprint.identify(mac),
            "open_ports": open_ports,
            "risk_score": risk,
            "risk_level": level,
            "reasons": reasons,
        }
