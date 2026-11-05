"""Pytest configuration: put the src layout on the import path so plain
``pytest`` passes from the project root, with or without an install."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
