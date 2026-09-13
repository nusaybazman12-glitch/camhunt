"""Camera detector - identifies hidden cameras via port scan + fingerprint"""

import socket


class CameraDetector:
    """Detect cameras via open ports + MAC vendor"""

    CAMERA_PORTS = {
        554: "RTSP (video stream)",
        8554: "RTSP (alt)",
        37777: "Dahua SDK",
        8000: "Hikvision SDK",
        80: "HTTP web interface",
        8080: "HTTP alt web interface",
        443: "HTTPS web interface",
        9000: "Camera API",
    }

    COMMON_PORTS = [22, 80, 443, 445, 554, 3389, 8000, 8080, 8554, 37777, 9000]

    def __init__(self, logger):
        self.logger = logger

    def scan_ports(self, ip, timeout=0.4):
        """Scan common ports on IP - fast, no permission needed"""
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
        """Analyze device - return risk info"""
        open_ports = self.scan_ports(ip)
        camera_ports = [p for p in open_ports if p in self.CAMERA_PORTS]

        risk = 0
        reasons = []

        if fingerprint.is_camera(mac):
            risk += 60
            reasons.append(f"MAC matches camera vendor: {fingerprint.identify(mac)}")

        if 554 in open_ports or 8554 in open_ports:
            risk += 30
            reasons.append("RTSP streaming port open (typical camera)")

        if 37777 in open_ports or 8000 in open_ports:
            risk += 25
            reasons.append("Camera SDK port open")

        if len(camera_ports) >= 2:
            risk += 10
            reasons.append(f"Multiple camera-typical ports open: {camera_ports}")

        if not reasons:
            reasons.append("No camera signature detected")

        risk = min(risk, 100)

        if risk >= 70:
            level = "HIGH"
        elif risk >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "ip": ip,
            "mac": mac,
            "device_type": fingerprint.identify(mac),
            "open_ports": open_ports,
            "camera_ports": camera_ports,
            "risk_score": risk,
            "risk_level": level,
            "reasons": reasons,
        }
