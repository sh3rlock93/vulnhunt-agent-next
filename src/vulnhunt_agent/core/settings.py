"""Operator-facing config loaded from <repo>/settings.toml.

Non-secret configuration lives in settings.toml. Provider secrets can be
resolved from an explicitly named environment variable; dotenv files are not
loaded implicitly.
"""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = Path(
    os.environ.get("VULNHUNT_SETTINGS_PATH", _REPO_ROOT / "settings.toml")
).resolve()

if not _CONFIG_PATH.exists():
    raise RuntimeError(
        f"{_CONFIG_PATH} not found. Run: cp settings.example.toml settings.toml"
    )

_raw = tomllib.loads(_CONFIG_PATH.read_text())


# ----- providers -----

@dataclass(frozen=True)
class ProviderSpec:
    name: str
    kind: str                         # bedrock_converse | openai_compat | openai_auto
    region: str | None = None         # bedrock_converse: required
    endpoint: str | None = None       # OpenAI base URL; Bedrock VPCE when applicable
    api_key: str | None = None        # legacy inline key; prefer api_key_env
    api_key_env: str | None = None
    reasoning_effort: str | None = None
    codex_command: str = "codex"
    codex_timeout_seconds: int = 900
    codex_max_parallel: int = 2

    def __post_init__(self) -> None:
        if self.api_key_env and not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", self.api_key_env
        ):
            raise ValueError(
                f"provider {self.name!r} has invalid api_key_env {self.api_key_env!r}"
            )
        if self.reasoning_effort not in (None, "low", "medium", "high", "xhigh", "max"):
            raise ValueError(
                f"provider {self.name!r} has unsupported reasoning_effort "
                f"{self.reasoning_effort!r}"
            )
        if self.codex_timeout_seconds <= 0:
            raise ValueError("codex_timeout_seconds must be positive")
        if self.codex_max_parallel <= 0:
            raise ValueError("codex_max_parallel must be positive")


PROVIDERS: dict[str, ProviderSpec] = {
    p["name"]: ProviderSpec(**p) for p in _raw["providers"]
}


# ----- defaults -----

DEFAULT_PROVIDER: str = _raw["defaults"]["provider"]
MAX_TOKENS: int = int(_raw["defaults"]["max_tokens"])


# ----- sandbox -----

_sb = _raw.get("sandbox", {})
ENVIRONMENTS: list[str] = list(_sb.get("environments", []))
ENV_TO_IMAGE: dict[str, str] = dict(_sb.get("images", {}))


# ----- model catalog -----

@dataclass(frozen=True)
class ModelSpec:
    label: str
    model_id: str
    input_per_m: float | None = None
    output_per_m: float | None = None
    provider: str = ""                # "" => use DEFAULT_PROVIDER at lookup time
    supports_caching: bool = True

    @property
    def cache_read_per_m(self) -> float | None:
        if self.input_per_m is None:
            return None
        return round(self.input_per_m * 0.1, 4) if self.supports_caching else self.input_per_m

    @property
    def cache_write_per_m(self) -> float | None:
        if self.input_per_m is None:
            return None
        return round(self.input_per_m * 1.25, 4) if self.supports_caching else self.input_per_m


MODELS: list[ModelSpec] = [ModelSpec(**m) for m in _raw["models"]]
_BY_ID = {m.model_id: m for m in MODELS}
_BY_LABEL = {m.label: m for m in MODELS}

DEFAULT_MODEL: ModelSpec = _BY_ID[_raw["default_model"]["model_id"]]


def by_id(model_id: str) -> ModelSpec | None:
    return _BY_ID.get(model_id)


def by_label(label: str) -> ModelSpec | None:
    return _BY_LABEL.get(label)


def provider_for(model: ModelSpec) -> ProviderSpec:
    name = model.provider or DEFAULT_PROVIDER
    if name not in PROVIDERS:
        raise RuntimeError(
            f"model {model.model_id!r} references provider {name!r}, "
            f"not declared in settings.toml [[providers]]."
        )
    return PROVIDERS[name]


def resolve(model_id: str) -> tuple[ModelSpec, ProviderSpec]:
    """Look up a model and its provider together. Raises if model_id is unknown."""
    spec = _BY_ID.get(model_id)
    if spec is None:
        raise RuntimeError(f"unknown model_id: {model_id}")
    return spec, provider_for(spec)
