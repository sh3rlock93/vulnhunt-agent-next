"""Intentionally vulnerable URL fetcher for the Milestone 0 corpus."""
from urllib.request import urlopen


def fetch_url(target_url: str) -> bytes:
    """Fetch an attacker-controlled URL without any validation (CWE-918)."""
    with urlopen(target_url, timeout=3) as response:  # nosec: regression fixture
        return response.read()
