"""Step 4: FileRanker — LLM scores files 1..5 in parallel batches."""
from __future__ import annotations

import asyncio
from pathlib import Path

from ..core.events import EventBus
from ..core.jsonx import extract_array
from ..core.llm import LLMClient
from ..core.run_store import RunStore
from ..indexer import FileIndex, TreeSitterIndexer
from ..prompts import ranker_addendum
from ..sandbox import language_of
from .registry import Step, register


BATCH_SIZE = 150           # files per LLM call
MAX_CONCURRENCY = 5        # parallel batches
BATCH_MAX_TOKENS = 12000   # response budget per batch


SYSTEM_PROMPT = """You are a security auditor triaging files for vulnerability review.

Score each file 1..5 based on how likely it is to contain exploitable security bugs:
  5 = handles user input, auth, crypto, SQL/command execution, parsing untrusted data, network I/O
  4 = core business logic, data access, sensitive operations
  3 = internal helpers called by sensitive code
  2 = utilities with minor relevance
  1 = constants, type definitions, pure formatting, trivial

Respond ONLY with a JSON array, no prose. Schema:
[{"p": "<path>", "s": <1-5>}, ...]

Include ALL input paths. No reasoning, no prose, no markdown."""


def _summarize_file(fi: FileIndex, max_symbols: int = 8) -> str:
    sym_names = [s.name for s in fi.symbols[:max_symbols]]
    more = f"+{len(fi.symbols) - max_symbols}" if len(fi.symbols) > max_symbols else ""
    imp_str = ",".join(fi.imports[:5]) + ("..." if len(fi.imports) > 5 else "")
    return (
        f"{fi.path} (loc={fi.loc}) "
        f"imp:[{imp_str}] sym:[{','.join(sym_names)}{more}]"
    )


def _index_with_text_fallbacks(
    repo: Path, source_files: list[str], language: str
) -> list[FileIndex]:
    """Keep non-tree-sitter source formats visible to the Ranker.

    Native repositories commonly include Flex/Bison inputs. Their mixed grammar
    is not valid C syntax, but path and size are still valuable ranking signals.
    """
    indexed = TreeSitterIndexer().index_repo(repo, source_files)
    by_path = {item.path: item for item in indexed.files}
    files: list[FileIndex] = []
    for relative in source_files:
        item = by_path.get(relative)
        if item is None:
            source = (repo / relative).read_bytes()
            item = FileIndex(
                path=relative,
                language=language,
                loc=source.count(b"\n") + 1,
            )
        files.append(item)
    return files


async def _rank_batch(
    client: LLMClient,
    language: str,
    batch: list[str],
    sem: asyncio.Semaphore,
    bus: EventBus,
    batch_idx: int,
    system_prompt: str,
) -> tuple[list[dict], int, int]:
    async with sem:
        user_prompt = (
            f"# Language\n{language}\n\n"
            f"# Files ({len(batch)})\n" + "\n".join(batch)
        )
        bus.emit("rank_batch_start", batch=batch_idx, files=len(batch))
        resp = await client.chat(
            system=system_prompt,
            messages=[{"role": "user", "content": [{"text": user_prompt}]}],
            max_tokens=BATCH_MAX_TOKENS,
        )
        if resp.stop_reason == "max_tokens":
            raise RuntimeError(
                f"batch {batch_idx} truncated (max_tokens). "
                f"Reduce BATCH_SIZE or raise BATCH_MAX_TOKENS."
            )
        parsed = extract_array(resp.text)
        bus.emit("rank_batch_done", batch=batch_idx,
                 in_tokens=resp.input_tokens, out_tokens=resp.output_tokens,
                 ranked=len(parsed))
        return parsed, resp.input_tokens, resp.output_tokens


async def run_rank(store: RunStore, bus: EventBus) -> None:
    cfg = store.load_config() or {}
    filtered = store.load_step("filtered_files") or {}

    repo = Path(cfg["repo_path"])
    language = language_of(cfg["environment"])
    source_files = filtered.get("source_files", [])
    indexed_files = _index_with_text_fallbacks(repo, source_files, language)
    bus.emit("rank_indexed", indexed=len(indexed_files), total=len(source_files))

    summaries = [_summarize_file(f) for f in indexed_files]
    batches = [summaries[i:i + BATCH_SIZE] for i in range(0, len(summaries), BATCH_SIZE)]

    bus.emit("step_start", step="rank",
             file_count=len(summaries), batches=len(batches))

    ranker_model = cfg.get("model_id_ranker") or cfg["model_id"]
    client = LLMClient(model_id=ranker_model, max_tokens=BATCH_MAX_TOKENS)
    bus.emit(
        "model_transport",
        scope="ranker",
        model_id=ranker_model,
        transport=getattr(client, "transport", "bedrock_converse"),
    )
    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    system_prompt = SYSTEM_PROMPT
    addendum = ranker_addendum(language)
    if addendum:
        system_prompt += "\n\n" + addendum

    results = await asyncio.gather(*[
        _rank_batch(client, language, b, sem, bus, i, system_prompt)
        for i, b in enumerate(batches)
    ])

    ranked: list[dict] = []
    total_in = total_out = 0
    for parsed, tin, tout in results:
        for r in parsed:
            ranked.append({"path": r["p"], "score": r["s"]})
        total_in += tin
        total_out += tout

    ranked.sort(key=lambda r: r["score"], reverse=True)

    store.save_step("ranked_files", {
        "total_ranked": len(ranked),
        "all": ranked,
        "_usage": {"input_tokens": total_in, "output_tokens": total_out},
        "_batches": len(batches),
    })

    bus.emit("step_done", step="rank",
             total_ranked=len(ranked), batches=len(batches))


register(Step(
    name="ranked_files",
    title="4. File Ranker (optional)",
    fn=run_rank,
    depends_on=["analysis_graph"],
))
