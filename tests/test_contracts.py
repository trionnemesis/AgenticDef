from copy import deepcopy
from pathlib import Path
import json

import pytest
import yaml
from jsonschema import Draft202012Validator

from agenticdef.domain.contracts import SCHEMAS, validate
from agenticdef.domain.errors import ContractError

ROOT = Path(__file__).resolve().parents[1]


def test_all_schemas_well_formed():
    for schema in SCHEMAS.values():
        Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("scenario", sorted((ROOT / "scenarios").glob("S*")))
def test_scenario_contracts(scenario):
    event = json.loads((scenario / "event.json").read_text())
    policy = yaml.safe_load((scenario / "policy.yaml").read_text())
    validate("event", event)
    validate("policy", policy)
    bad = deepcopy(event)
    bad["event_type"] = "run_shell"
    with pytest.raises(ContractError): validate("event", bad)
    bad = deepcopy(policy)
    bad["allowed_tools"].append("shell")
    with pytest.raises(ContractError): validate("policy", bad)
    bad = deepcopy(event)
    bad["observed_at"] = "yesterday"
    with pytest.raises(ContractError): validate("event", bad)


@pytest.mark.parametrize("value", [{"type": "finish", "policy": {}}, {"type": "tool_request", "tool": "x"}, {"type": "shell"}])
def test_invalid_actions(value):
    with pytest.raises(ContractError): validate("action", value)


def test_nonfinite_policy_rejected():
    with pytest.raises(ContractError): validate("policy", {"max_runtime_seconds": float("nan")})


def test_result_and_evidence_contracts():
    now = "2026-09-12T00:00:00Z"
    evidence = dict(evidence_id="ev-" + "a" * 64, source="fixture", observed_at=now,
                    acquired_at=now, method="get_change_event", content_ref="sha256:" + "a" * 64,
                    summary="Synthetic event", integrity=dict(algorithm="sha256", digest="a" * 64))
    validate("evidence", evidence)
    result = dict(investigation_id="inv-" + "b" * 64, event_id="evt-test",
                  status="confirmed_suspicious", risk="high", summary="Review required",
                  findings=[dict(claim="Privilege increase", evidence_ids=[evidence["evidence_id"]])],
                  missing_evidence=[], recommended_next_actions=["Human review"],
                  budget_usage=dict(model_calls=2, tool_calls=1, evidence_items=1, runtime_seconds=0.1),
                  termination_reason="model_finished", timestamps=dict(started_at=now, finished_at=now))
    validate("result", result)
    for field, value in [("status", "secure"), ("budget_usage", {}), ("findings", [{"claim": "X", "evidence_ids": []}])]:
        with pytest.raises(ContractError): validate("result", {**result, field: value})
    with pytest.raises(ContractError): validate("evidence", {**evidence, "integrity": {}})
