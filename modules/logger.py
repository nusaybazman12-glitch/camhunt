"""Logging system - saves all activity to logs/camhunt.log"""

import logging
import os


def setup_logger():
    """Create logger that writes to both file and console"""

    os.makedirs("logs", exist_ok=True)
    log_file = "logs/camhunt.log"

    logger = logging.getLogger("CamHunt")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    # File handler
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_format)

    # Console handler (only warnings+ to keep CLI clean)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_format = logging.Formatter("[%(levelname)s] %(message)s")
    console_handler.setFormatter(console_format)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
