# 🎥 CamHunt

**Hidden Camera Detector & Network Security Tool**

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

CamHunt is an open-source cybersecurity tool that helps you detect
unauthorized cameras and suspicious devices on your own Wi-Fi network.
It uses ARP scanning, MAC vendor fingerprinting, and port analysis to
identify hidden cameras — all from a clean, cross-platform GUI.

> ⚠️ **Legal Notice:** Use this tool **only** on networks you own or
> have explicit permission to test. Unauthorized scanning is illegal in
> many countries, including Bangladesh.

---

## ⚡ Quick Install (Copy & Paste)

### 🐧 Termux (Android) — One-Liner

```bash
pkg update && pkg upgrade -y && pkg install python git nmap termux-api libpcap clang binutils -y && pip install scapy && git clone https://github.com/nusaybazman12-glitch/camhunt.git && cd camhunt && python camhunt.py
