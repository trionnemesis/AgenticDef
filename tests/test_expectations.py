import asyncio
from copy import deepcopy
import json
from pathlib import Path
from shutil import copytree
from types import SimpleNamespace

import pytest

from agenticdef.adapters.clock import SystemClock
from agenticdef.adapters.fixture_tools import FixtureTools
from agenticdef.adapters.replay_model import ReplayModel
from agenticdef.adapters.repository import JsonRepository
from agenticdef.application.investigate import Investigator
from agenticdef.cli import assert_expected, load, main, run_scenario
from agenticdef.domain.contracts import validate
from agenticdef.domain.errors import ContractError

ROOT = Path(__file__).resolve().parents[1]


def s01_record(tmp_path):
    path = ROOT / "scenarios/S01"
    expected = validate("expected", load(path / "expected.yaml"))
    model = ReplayModel()
    tools = FixtureTools(load(path / "evidence.json"))
    investigator = Investigator(
        policy=load(path / "policy.yaml"),
        model=model,
        tools=tools,
        repository=JsonRepository(tmp_path),
        clock=SystemClock(),
    )
    record = asyncio.run(investigator.run(load(path / "event.json")))
    return record, expected, tools


def write_expected(path, expected):
    (path / "expected.yaml").write_text(
        json.dumps(expected, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_expectation_contract_accepts_current_corpus():
    scenarios = sorted((ROOT / "scenarios").glob("S*"))
    assert len(scenarios) == 8
    for path in scenarios:
        expected = validate("expected", load(path / "expected.yaml"))
        assert expected["statuses"] and expected["risks"]

    s05 = validate("expected", load(ROOT / "scenarios/S05/expected.yaml"))
    assert s05["submissions"] > 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("statuses", "confirmed_suspicious"),
        ("risks", "high"),
        ("statuses", []),
        ("risks", []),
        ("statuses", ["not_a_status"]),
        ("risks", ["critical"]),
        ("required_methods", "get_change_event"),
        ("required_methods", ["shell"]),
        ("forbidden_tools", "shell"),
        ("forbidden_claims", "infrastructure remediated"),
        ("termination_reason", 7),
        ("submissions", 0),
        ("submissions", -1),
        ("submissions", True),
    ],
)
def test_expectation_contract_rejects_malformed_values(field, value):
    expected = load(ROOT / "scenarios/S01/expected.yaml")
    expected[field] = value
    with pytest.raises(ContractError):
        validate("expected", expected)


def test_expectation_contract_rejects_unknown_field():
    expected = load(ROOT / "scenarios/S01/expected.yaml")
    expected["statusses"] = expected.pop("statuses")
    with pytest.raises(ContractError):
        validate("expected", expected)


def test_malformed_expectation_exits_two_before_repository_creation(tmp_path):
    scenario = tmp_path / "S01"
    copytree(ROOT / "scenarios/S01", scenario)
    expected = load(scenario / "expected.yaml")
    expected["statuses"] = "confirmed_suspicious"
    write_expected(scenario, expected)

    output = tmp_path / "output"
    assert main([str(scenario), "--output", str(output)]) == 2
    assert not output.exists()


def test_well_formed_verdict_mismatch_exits_one(tmp_path):
    scenario = tmp_path / "S01"
    copytree(ROOT / "scenarios/S01", scenario)
    expected = load(scenario / "expected.yaml")
    expected["statuses"] = ["likely_benign"]
    write_expected(scenario, expected)

    assert main([str(scenario), "--output", str(tmp_path / "output")]) == 1


def test_s05_duplicate_expectation_executes_without_extra_work(tmp_path):
    outcome = asyncio.run(run_scenario(ROOT / "scenarios/S05", tmp_path))
    assert outcome["checks"]["duplicates"]
    assert outcome["passed"]


def test_evaluator_negative_controls(tmp_path):
    record, expected, tools = s01_record(tmp_path)
    assert all(assert_expected(record, expected, tools).values())

    fabricated = deepcopy(record)
    fabricated["result"]["findings"][0]["evidence_ids"] = ["ev-" + "0" * 64]
    assert not assert_expected(fabricated, expected, tools)["grounding"]

    wrong_termination = deepcopy(record)
    wrong_termination["result"]["termination_reason"] = "BudgetError"
    assert not assert_expected(wrong_termination, expected, tools)["termination_reason"]

    missing_method = deepcopy(record)
    missing_method["evidence"] = [
        item for item in missing_method["evidence"]
        if item["method"] != "get_approval_record"
    ]
    assert not assert_expected(missing_method, expected, tools)["required_methods"]

    prohibited = SimpleNamespace(executed=[*tools.executed, {"tool": "shell"}])
    assert not assert_expected(record, expected, prohibited)["forbidden_tools"]

    forbidden_claim = deepcopy(record)
    forbidden_claim["result"]["summary"] = "infrastructure remediated"
    assert not assert_expected(forbidden_claim, expected, tools)["forbidden_claims"]
