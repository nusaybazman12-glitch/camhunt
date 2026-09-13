#!/usr/bin/env python3
"""
CamHunt - Hidden Camera Detector & Network Security Tool
ব্যবহার: python3 camhunt.py
"""

from modules.gui import CamHuntGUI
from modules.logger import setup_logger


def main():
    logger = setup_logger()
    logger.info("=" * 60)
    logger.info("CamHunt শুরু হচ্ছে...")
    logger.info("=" * 60)
    
    try:
        app = CamHuntGUI(logger)
        app.run()
    except KeyboardInterrupt:
        logger.warning("ব্যবহারকারী বন্ধ করে দিয়েছেন")
        print("\n[!] CamHunt বন্ধ করা হলো।")
    except Exception as e:
        logger.error(f"ত্রুটি: {e}")
        print(f"[✗] ত্রুটি: {e}")


if __name__ == "__main__":
    main()
