"""Test bootstrap that isolates tests from the operator's local configuration."""
from __future__ import annotations

import os
from pathlib import Path

TEST_SETTINGS_PATH = Path(__file__).parent / "fixtures" / "settings.toml"
os.environ["VULNHUNT_SETTINGS_PATH"] = str(TEST_SETTINGS_PATH)
