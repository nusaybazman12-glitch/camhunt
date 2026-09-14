cat > ~/camhunt/camhunt.py << 'ENDOFFILE'
#!/usr/bin/env python3
"""CamHunt v2.0 CLI - Termux-friendly"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.gui import CamHuntCLI
from modules.logger import setup_logger


def main():
    logger = setup_logger()
    logger.info("CamHunt v2.0 CLI starting...")
    try:
        app = CamHuntCLI(logger)
        app.run()
    except KeyboardInterrupt:
        print("\n[!] CamHunt stopped.")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"[X] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
ENDOFFILE
echo "DONE: camhunt.py updated"
