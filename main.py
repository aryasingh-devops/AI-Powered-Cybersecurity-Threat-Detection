"""Entry point for the AI-powered cybersecurity threat detection project."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "src"))

from threat_detection.cli import main


if __name__ == "__main__":
    main()
