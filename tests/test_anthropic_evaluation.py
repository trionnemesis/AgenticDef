"""Offline M6 integration: AnthropicModel over httpx.MockTransport, fixture
evidence, the shared Investigator, then the replay expectation evaluator.

Provider responses are scripted test data. They do not measure a real model's
accuracy or prompt-injection resistance. Expected verdicts stay in the tests and
scenario files, never in runtime code.
"""
import asyncio
import json
from pathlib import Path

import httpx
import pytest

from agenticdef.adapters.anthropic_model import AnthropicModel, ENDPOINT
from agenticdef.adapters.clock import SystemClock
from agenticdef.adapters.fixture_tools import FixtureTools
from agenticdef.adapters.repository import JsonRepository
from agenticdef.application.investigate import Investigator
from agenticdef.cli import assert_expected, load
from agenticdef.domain.contracts import validate
from test_anthropic_model import message

ROOT = Path(__file__).resolve().parents[1]
FABRICATED = "ev-" + "0" * 64


def reads(event):
    # Written out rather than imported so the script does not reuse runtime grounding logic.
    resource, change = event["resource"], event["change"]
    return [("get_change_event", {"event_id": event["event_id"]}),
            ("get_rbac_object", {**resource, "version": change["before_version"]}),
            ("get_rbac_object", {**resource, "version": change["after_version"]}),
            ("get_subject_bindings", {"subject_id": event["actor"]["subject_id"]}),
            ("get_approval_record", {"change_id": change["change_id"]})]


class ScriptedProvider:
    """Answer Messages requests from a fixed script; the draft cites IDs the adapter actually sent."""

    def __init__(self, event, status, risk, cite=lambda ids: ids):
        self.actions = [{"type": "tool_request", "tool": t, "arguments": a} for t, a in reads(event)]
        self.actions.append({"type": "finish"})
        self.status, self.risk, self.cite = status, risk, cite
        self.envelopes = []

    def __call__(self, request):
        assert str(request.url) == ENDPOINT and request.method == "POST"
        envelope = json.loads(json.loads(request.content)["messages"][0]["content"])
        self.envelopes.append(envelope)
        evidence = envelope["untrusted_investigation_data"]["evidence"]
        if envelope["task"] == "choose_action":
            step = sum(e["task"] == "choose_action" for e in self.envelopes) - 1
            return httpx.Response(200, json=message(self.actions[step]))
        ids = self.cite([e["evidence"]["evidence_id"] for e in evidence])
        return httpx.Response(200, json=message(dict(
            status=self.status, risk=self.risk, summary="Scripted provider draft / 腳本化草稿",
            findings=[dict(claim="Scripted claim over collected evidence / 腳本化發現", evidence_ids=ids)],
            missing_evidence=[], recommended_next_actions=["Human review / 人工審查"])))


def run(tmp_path, scenario, status, risk, **script):
    path = ROOT / "scenarios" / scenario
    event = load(path / "event.json")
    expected = validate("expected", load(path / "expected.yaml"))
    provider = ScriptedProvider(event, status, risk, **script)
    model = AnthropicModel(model="operator-selected-model", api_key="test-placeholder",
                           transport=httpx.MockTransport(provider))
    tools = FixtureTools(load(path / "evidence.json"))
    investigator = Investigator(policy=load(path / "policy.yaml"), model=model, tools=tools,
                                repository=JsonRepository(tmp_path), clock=SystemClock())
    record = asyncio.run(investigator.run(event))
    return record, expected, tools, provider, event


@pytest.mark.parametrize(("scenario", "status", "risk"), [
    ("S01", "confirmed_suspicious", "high"),
    ("S02", "likely_benign", "low"),
])
def test_http_model_full_run_passes_scenario_expectations(tmp_path, scenario, status, risk):
    record, expected, tools, provider, event = run(tmp_path, scenario, status, risk)
    assert record["metadata"]["model_provider"] == "anthropic_api"
    assert record["metadata"]["evidence_provider"] == "synthetic_fixture"
    assert [e["task"] for e in provider.envelopes] == ["choose_action"] * 6 + ["produce_result"]
    # Each request carries the evidence returned so far; synthesis sees all five reads.
    assert [len(e["untrusted_investigation_data"]["evidence"]) for e in provider.envelopes] == [0, 1, 2, 3, 4, 5, 5]
    assert [(e["tool"], e["arguments"]) for e in tools.executed] == reads(event)
    result = record["result"]
    assert record["state"] == "COMPLETED" and result["termination_reason"] == "model_finished"
    assert (result["status"], result["risk"]) == (status, risk)
    assert {k: result["budget_usage"][k] for k in ("model_calls", "tool_calls", "evidence_items")} == \
        {"model_calls": 7, "tool_calls": 5, "evidence_items": 5}
    assert set(result["findings"][0]["evidence_ids"]) == {e["evidence_id"] for e in record["evidence"]}
    checks = assert_expected(record, expected, tools)
    assert all(checks.values()), checks


def test_inverted_grounded_verdict_fails_only_status_and_risk(tmp_path):
    record, expected, tools, _, _ = run(tmp_path, "S01", "likely_benign", "low")
    result = record["result"]
    # The runtime accepted the draft: references, exact reads and status/risk pairing are valid.
    assert record["state"] == "COMPLETED" and result["termination_reason"] == "model_finished"
    assert (result["status"], result["risk"]) == ("likely_benign", "low")
    checks = assert_expected(record, expected, tools)
    assert {k for k, ok in checks.items() if not ok} == {"status", "risk"}, checks


def test_http_model_fabricated_reference_fails_grounding(tmp_path):
    record, expected, tools, provider, _ = run(
        tmp_path, "S01", "confirmed_suspicious", "high", cite=lambda ids: ids[:-1] + [FABRICATED])
    result = record["result"]
    assert provider.envelopes[-1]["task"] == "produce_result"
    assert record["state"] == "FAILED" and result["termination_reason"] == "GroundingError"
    assert (result["status"], result["risk"], result["findings"]) == ("investigation_failed", "unknown", [])
    assert FABRICATED not in json.dumps(result)
    checks = assert_expected(record, expected, tools)
    assert not checks["status"] and not checks["termination_reason"]
