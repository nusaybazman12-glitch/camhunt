#!/usr/bin/env python3
"""
CamHunt - Hidden Camera Detector & Network Security Tool
Usage: sudo python3 camhunt.py
"""

from modules.gui import CamHuntGUI
from modules.logger import setup_logger


def main():
    logger = setup_logger()
    logger.info("=" * 60)
    logger.info("CamHunt starting...")
    logger.info("=" * 60)

    try:
        app = CamHuntGUI(logger)
        app.run()
    except KeyboardInterrupt:
        logger.warning("User interrupted")
        print("\n[!] CamHunt stopped.")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"[X] Error: {e}")


if __name__ == "__main__":
    main()
