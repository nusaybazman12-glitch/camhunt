"""লগিং সিস্টেম — সব কার্যক্রম logs/camhunt.log এ সেভ হবে"""

import logging
import os
from datetime import datetime


def setup_logger():
    """লগার তৈরি করে, ফাইল ও কনসোলে দুটোতেই লিখে"""
    
    os.makedirs("logs", exist_ok=True)
    log_file = "logs/camhunt.log"
    
    logger = logging.getLogger("CamHunt")
    logger.setLevel(logging.DEBUG)
    
    if logger.handlers:
        return logger
    
    # ফাইল হ্যান্ডলার
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_format)
    
    # কনসোল হ্যান্ডলার
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter("[%(levelname)s] %(message)s")
    console_handler.setFormatter(console_format)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger
