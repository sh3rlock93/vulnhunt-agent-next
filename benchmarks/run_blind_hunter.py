"""Run one language-specific Hunter without exposing benchmark ground truth."""
from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from vulnhunt_agent.agents import HunterAgent
from vulnhunt_agent.agents.tools import HunterTools
from vulnhunt_agent.core.llm import LLMClient
from vulnhunt_agent.core.settings import DEFAULT_MODEL
from vulnhunt_agent.prompts import hunters_for
from vulnhunt_agent.sandbox import ContainerExecutor


async def run_blind_hunter(
    *,
    repo: Path,
    image: str,
    target: str,
    language: str,
    model_id: str,
    max_iterations: int,
    output: Path,
) -> dict:
    hunters = hunters_for(language)
    selected = next((hunter for hunter in hunters if hunter.default), None)
    if selected is None:
        raise RuntimeError(f"no default Hunter for language {language!r}")

    sandbox = ContainerExecutor(
        repo=repo,
        image=image,
        network="none",
        source_baked=True,
    )
    output.mkdir(parents=True, exist_ok=True)
    trace_path = output / "trace.jsonl"
    with trace_path.open("w") as trace:
        def on_event(event_type, **data):
            trace.write(json.dumps(
                {"type": event_type, **data}, ensure_ascii=False
            ) + "\n")
            trace.flush()

        try:
            await sandbox.start()
            tools = HunterTools(repo, sandbox=sandbox, poc_root=output / "pocs")
            agent = HunterAgent(
                client=LLMClient(model_id=model_id),
                tools=tools,
                arch={"language": language, "environment": "c:gcc-13"},
                hunter_prompt=selected.system_prompt,
                sandbox_info=(
                    "The target is sanitizer-built. Immutable source is at /code; "
                    "prepared artifacts are under /opt/vulnhunt/build. Network is disabled."
                ),
                max_iterations=max_iterations,
                on_event=on_event,
            )
            result = await agent.hunt(target)
            serialized = asdict(result)
            (output / "result.json").write_text(
                json.dumps(serialized, indent=2, ensure_ascii=False)
            )
            return serialized
        finally:
            await sandbox.stop()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--language", default="c")
    parser.add_argument("--model", default=DEFAULT_MODEL.model_id)
    parser.add_argument("--max-iterations", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = asyncio.run(run_blind_hunter(
        repo=args.repo.resolve(),
        image=args.image,
        target=args.target,
        language=args.language,
        model_id=args.model,
        max_iterations=args.max_iterations,
        output=args.output.resolve(),
    ))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["stopped"] == "final_json" else 1


if __name__ == "__main__":
    raise SystemExit(main())
