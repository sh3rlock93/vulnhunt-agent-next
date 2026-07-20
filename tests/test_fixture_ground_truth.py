from __future__ import annotations

import importlib.util
import json
from pathlib import Path

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "python_insecure_app"


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self) -> bytes:
        return b"metadata-response"


def test_fixture_demonstrates_unvalidated_url_reaching_sink(monkeypatch) -> None:
    module_path = FIXTURE_ROOT / "insecure_app" / "app.py"
    spec = importlib.util.spec_from_file_location("fixture_insecure_app", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls: list[tuple[str, int]] = []

    def fake_urlopen(url: str, timeout: int):
        calls.append((url, timeout))
        return FakeResponse()

    monkeypatch.setattr(module, "urlopen", fake_urlopen)
    attacker_url = "http://169.254.169.254/latest/meta-data/"

    assert module.fetch_url(attacker_url) == b"metadata-response"
    assert calls == [(attacker_url, 3)]

    ground_truth = json.loads((FIXTURE_ROOT / "ground_truth.json").read_text())
    assert ground_truth["weakness"] == "CWE-918"
    assert ground_truth["entrypoint"]["symbol"] == "fetch_url"
