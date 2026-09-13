#!/usr/bin/env python3
"""
CamHunt v2.0 CLI - Hidden Camera Detector & Network Security Tool
Termux-friendly (no GUI / no X11 required)

Usage:
    python camhunt.py
    sudo python camhunt.py    (for IP blocking)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.gui import CamHuntCLI
from modules.logger import setup_logger


def main():
    logger = setup_logger()
    logger.info("=" * 60)
    logger.info("CamHunt v2.0 CLI starting...")
    logger.info("=" * 60)

    try:
        app = CamHuntCLI(logger)
        app.run()
    except KeyboardInterrupt:
        logger.warning("User interrupted")
        print("\n[!] CamHunt stopped.")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"[X] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
