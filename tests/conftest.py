"""Test bootstrap that supplies the operator config required at import time."""
from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETTINGS_PATH = ROOT / "settings.toml"
TEST_SETTINGS_PATH = Path(__file__).parent / "fixtures" / "settings.toml"
_CREATED_SETTINGS = not SETTINGS_PATH.exists()

if _CREATED_SETTINGS:
    shutil.copyfile(TEST_SETTINGS_PATH, SETTINGS_PATH)


def pytest_sessionfinish(session, exitstatus) -> None:
    """Remove only the settings file created by this test session."""
    if _CREATED_SETTINGS:
        SETTINGS_PATH.unlink(missing_ok=True)
