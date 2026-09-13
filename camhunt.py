#!/usr/bin/env python3
"""
CamHunt v2.0 - Hidden Camera Detector & Network Security Tool
GUI Edition - No extra permissions needed

Usage:
    python camhunt.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.gui import CamHuntApp
from modules.logger import setup_logger


def main():
    logger = setup_logger()
    logger.info("=" * 60)
    logger.info("CamHunt v2.0 starting...")
    logger.info("=" * 60)

    try:
        app = CamHuntApp(logger)
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
