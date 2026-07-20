from vulnhunt_agent.prompts import hunter_by_name, hunters_for, ranker_addendum


def test_python_prompt_catalog_baseline() -> None:
    hunters = hunters_for("python")
    assert [hunter.name for hunter in hunters] == ["python"]
    assert hunters[0].default is True
    assert "security auditor" in hunters[0].system_prompt
    assert hunter_by_name("python", language="python") == hunters[0]
    assert "pickle" in ranker_addendum("python")
