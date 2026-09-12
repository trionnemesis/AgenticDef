import ast
import asyncio
from pathlib import Path

import pytest

from agenticdef.domain.runtime import TOOL_ARGUMENTS
from test_investigator import setup
from agenticdef.adapters.replay_model import ReplayModel


def test_exactly_four_capabilities_and_no_execution_imports():
    assert set(TOOL_ARGUMENTS) == {"get_change_event", "get_rbac_object", "get_subject_bindings", "get_approval_record"}
    root = Path(__file__).resolve().parents[1] / "src/agenticdef"
    forbidden = {"subprocess", "kubernetes", "google.cloud", "boto3"}
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import): assert not any(x.name in forbidden for x in node.names)
            if isinstance(node, ast.ImportFrom): assert node.module not in forbidden
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name): assert node.func.id not in {"exec", "eval", "compile"}
    for path in (root / "domain").glob("*.py"):
        assert "httpx" not in path.read_text() and "adapters" not in path.read_text()


def test_registered_but_disallowed_tool_never_runs(tmp_path):
    model = ReplayModel({"action": {"type": "tool_request", "tool": "get_approval_record", "arguments": {"change_id": "chg-S01"}}})
    inv, event, _, tools, _ = setup(tmp_path, model=model, changes={"allowed_tools": ["get_change_event"]})
    record = asyncio.run(inv.run(event))
    assert record["result"]["termination_reason"] == "ToolNotAllowedError" and not tools.executed


def test_failed_candidate_is_audited_but_not_accepted(tmp_path):
    inv, event, _, _, _ = setup(tmp_path, model=ReplayModel({"fabricate_evidence": True}))
    record = asyncio.run(inv.run(event))
    candidate = next(a["draft"] for a in record["audit"] if a["kind"] == "model_result_received")
    assert candidate["findings"][0]["evidence_ids"] == ["ev-" + "0" * 64]
    assert record["result"]["findings"] == [] and record["state"] == "FAILED"


def test_no_calls_after_terminal_audit(tmp_path):
    inv, event, _, _, _ = setup(tmp_path)
    record = asyncio.run(inv.run(event))
    assert record["audit"][-1]["kind"] == "terminal"
    assert [a["sequence"] for a in record["audit"]] == list(range(1, len(record["audit"]) + 1))
