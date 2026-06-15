"""Load .md prompt files from <repo>/prompts/."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
PROMPTS_DIR = _REPO_ROOT / "prompts"
HUNTERS_DIR = PROMPTS_DIR / "hunters"
RANKERS_DIR = PROMPTS_DIR / "rankers"


_LANG_ALIAS = {
    "py": "python",
}


@dataclass(frozen=True)
class HunterDef:
    name: str
    title: str
    description: str
    language: str          # "" = language-agnostic
    default: bool
    system_prompt: str
    path: Path


def normalize_language(lang: str | None) -> str:
    key = (lang or "").strip().lower()
    return _LANG_ALIAS.get(key, key)


def list_hunters() -> list[HunterDef]:
    """All hunters from HUNTERS_DIR (recursive). (language, name) must be unique."""
    seen: dict[tuple[str, str], Path] = {}
    out: list[HunterDef] = []
    for p in sorted(HUNTERS_DIR.rglob("*.md")):
        meta, body = _parse(p.read_text())
        h = HunterDef(
            name=meta.get("name") or p.stem,
            title=meta.get("title") or p.stem,
            description=meta.get("description", ""),
            language=normalize_language(meta.get("language")),
            default=_as_bool(meta.get("default")),
            system_prompt=body.strip(),
            path=p,
        )
        key = (h.language, h.name)
        if key in seen:
            raise RuntimeError(
                f"hunter conflict: language={h.language!r} name={h.name!r} "
                f"in {seen[key]} and {p}"
            )
        seen[key] = p
        out.append(h)
    return out


def hunters_for(language: str | None) -> list[HunterDef]:
    """Hunters relevant to the target language: that language + agnostic."""
    lang = normalize_language(language)
    matches = [h for h in list_hunters() if h.language in (lang, "")]
    nested = [h for h in matches if h.path.parent != HUNTERS_DIR]
    return nested or matches


def hunter_by_name(name: str, language: str | None = None) -> HunterDef | None:
    """Find by name; prefer the one matching `language` if multiple share a name."""
    lang = normalize_language(language)
    matches = [h for h in list_hunters() if h.name == name]
    if lang:
        for h in matches:
            if h.language == lang:
                return h
    for h in matches:
        if h.language == "":
            return h
    return matches[0] if matches else None


def ranker_addendum(language: str | None) -> str:
    """Per-language ranker hint, or '' if no file matches."""
    lang = normalize_language(language)
    if not lang:
        return ""
    p = next(RANKERS_DIR.rglob(f"{lang}.md"), None)
    if p is None:
        return ""
    _, body = _parse(p.read_text())
    return body.strip()


def _parse(text: str) -> tuple[dict, str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}, text
    meta: dict = {}
    for line in text[4:end].splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta, text[end + 5:]


def _as_bool(v: str | None) -> bool:
    return (v or "").strip().lower() in ("true", "yes", "1")
