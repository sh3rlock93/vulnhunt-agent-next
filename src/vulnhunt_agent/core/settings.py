"""Operator-facing config loaded from <repo>/settings.toml.

Single source of truth: settings.toml. No env vars, no dotenv.
Copy settings.example.toml -> settings.toml and edit.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_PATH = _REPO_ROOT / "settings.toml"

if not _CONFIG_PATH.exists():
    raise RuntimeError(
        f"{_CONFIG_PATH} not found. Run: cp settings.example.toml settings.toml"
    )

_raw = tomllib.loads(_CONFIG_PATH.read_text())


# ----- providers -----

@dataclass(frozen=True)
class ProviderSpec:
    name: str
    kind: str                         # "bedrock_converse" | "openai_compat"
    region: str | None = None         # bedrock_converse: required
    endpoint: str | None = None       # openai_compat: required; bedrock_converse: optional (VPCE)
    api_key: str | None = None        # openai_compat: required


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
    input_per_m: float
    output_per_m: float
    provider: str = ""                # "" => use DEFAULT_PROVIDER at lookup time
    supports_caching: bool = True

    @property
    def cache_read_per_m(self) -> float:
        return round(self.input_per_m * 0.1, 4) if self.supports_caching else self.input_per_m

    @property
    def cache_write_per_m(self) -> float:
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
