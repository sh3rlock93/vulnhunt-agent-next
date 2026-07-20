from __future__ import annotations

import json

from vulnhunt_agent.agents.queue import HuntQueueStore
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.domain.states import FindingState
from vulnhunt_agent.infrastructure.artifacts import ArtifactStore
from vulnhunt_agent.infrastructure.legacy_import import LegacyRunImporter
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.interfaces.cli import main


def test_legacy_import_is_idempotent_and_cli_is_read_only(tmp_path, capsys) -> None:
    legacy = RunStore(tmp_path / "legacy-run")
    legacy.save_config(
        {
            "repo_source": "https://example.test/insecure.git",
            "repo_path": "/legacy/path",
        }
    )
    legacy.save_step("filter", {"source_files": ["insecure_app/app.py"]})
    queue_store = HuntQueueStore(legacy.dir / "hunters")
    task = queue_store.init_from_pairs([("insecure_app/app.py", "ssrf-network")]).tasks[0]
    hunt_dir = queue_store.hunt_dir(task, "ssrf-network")
    (hunt_dir / "findings.json").write_text(json.dumps({
        "findings": [{
            "title": "Unvalidated outbound URL",
            "type": "ssrf",
            "severity": "high",
            "status": "confirmed",
            "entry_file": "insecure_app/app.py",
            "entry_line": 6,
            "sink_file": "insecure_app/app.py",
            "sink_line": 8,
            "files_touched": ["insecure_app/app.py"],
            "description": "Attacker input reaches urlopen.",
            "attack": "Supply a metadata service URL.",
            "poc_file": "/workspace/poc.py",
            "exec_output": "LEAKED_SECRET=1",
        }]
    }))

    db_path = tmp_path / "v2" / "state.db"
    with SqliteRepository(db_path) as repository:
        importer = LegacyRunImporter(repository, ArtifactStore(tmp_path / "v2" / "artifacts"))
        first = importer.import_run(legacy.dir)
        second = importer.import_run(legacy.dir)
        assert first.findings_created == 1
        assert second.already_imported
        repository.connection.execute("DELETE FROM legacy_imports WHERE run_id = ?", ("legacy-run",))
        resumed = importer.import_run(legacy.dir)
        assert resumed.findings_created == 0
        assert resumed.findings_deduplicated == 1
        findings = repository.list_candidates("legacy-run")
        assert len(findings) == 1
        assert findings[0].state is FindingState.POC_READY
        assert findings[0].evidence_ids == ()

    assert main(["--db", str(db_path), "status", "legacy-run"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["run"]["run_id"] == "legacy-run"
    assert status["finding_count"] == 1

    assert main(
        ["--db", str(db_path), "findings", "legacy-run", "--state", "poc_ready"]
    ) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed[0]["candidate_id"].startswith("cand_legacy_")
