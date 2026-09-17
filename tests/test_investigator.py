import asyncio
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from agenticdef.adapters.clock import SystemClock
from agenticdef.adapters.fixture_tools import FixtureTools
from agenticdef.adapters.replay_model import ReplayModel
from agenticdef.adapters.repository import JsonRepository
from agenticdef.application.investigate import Investigator
from agenticdef.cli import load, main, run_scenario
from agenticdef.domain.contracts import canonical
from agenticdef.domain.errors import ContractError, PersistenceError, PolicyError
from agenticdef.domain.runtime import identity

ROOT = Path(__file__).resolve().parents[1]


def setup(tmp_path, model=None, entries=None, changes=None, repo=None):
    path = ROOT / "scenarios/S01"
    event, policy = load(path / "event.json"), load(path / "policy.yaml")
    policy.update(changes or {})
    tools = FixtureTools(load(path / "evidence.json") if entries is None else entries)
    model = model or ReplayModel()
    repo = repo or JsonRepository(tmp_path)
    return Investigator(policy=policy, model=model, tools=tools, repository=repo, clock=SystemClock()), event, model, tools, repo


@pytest.mark.parametrize("scenario", [f"S0{i}" for i in range(1, 9)])
def test_replay_scenarios(scenario, tmp_path):
    outcome = asyncio.run(run_scenario(ROOT / "scenarios" / scenario, tmp_path))
    assert outcome["passed"], outcome["checks"]


def test_invalid_event_calls_nothing(tmp_path):
    inv, event, model, tools, repo = setup(tmp_path)
    event["event_type"] = "shell"
    with pytest.raises(ContractError): asyncio.run(inv.run(event))
    assert model.calls == 0 and not tools.executed
    assert list(tmp_path.iterdir()) == []


def evidence_adapter(tools):
    # An independent duck-typed adapter: no FixtureTools inheritance.
    return SimpleNamespace(
        provenance=tools.provenance,
        get_change_event=tools.get_change_event,
        get_rbac_object=tools.get_rbac_object,
        get_subject_bindings=tools.get_subject_bindings,
        get_approval_record=tools.get_approval_record,
    )


@pytest.mark.parametrize("method", [
    "get_change_event", "get_rbac_object", "get_subject_bindings", "get_approval_record",
])
@pytest.mark.parametrize("defect", ["missing", "non_callable"])
def test_invalid_evidence_adapter_persists_failed_result(tmp_path, method, defect):
    inv, event, model, tools, repo = setup(tmp_path)
    inv.tools = evidence_adapter(tools)
    if defect == "missing":
        delattr(inv.tools, method)
    else:
        setattr(inv.tools, method, None)

    record = asyncio.run(inv.run(event))
    result = record["result"]
    assert record["state"] == "FAILED"
    assert result["status"] == "investigation_failed" and result["risk"] == "unknown"
    assert result["termination_reason"] == "ContractError"
    assert result["findings"] == [] and result["missing_evidence"] == []
    assert model.calls == 0 and not tools.executed
    assert all(result["budget_usage"][k] == 0 for k in ("model_calls", "tool_calls", "evidence_items"))
    assert any(a["kind"] == "adapter_rejected" and a["tool"] == method for a in record["audit"])
    assert any(a["kind"] == "failure" and a["error"] == "ContractError" for a in record["audit"])
    assert record["audit"][-1]["kind"] == "terminal"
    assert record["audit"][-1]["target"] == "FAILED"
    assert repo.get_by_idempotency_key(record["investigation_id"]) == record

    path = tmp_path / record["investigation_id"] / "record.json"
    persisted = path.read_bytes()
    assert asyncio.run(inv.run(event)) == record
    # Fixing the adapter must not silently authorize re-investigation of a terminal key.
    inv.tools = tools
    inv.repository = JsonRepository(tmp_path)
    assert asyncio.run(inv.run(event)) == record
    assert path.read_bytes() == persisted
    assert model.calls == 0 and not tools.executed


def test_complete_duck_typed_evidence_adapter_is_accepted(tmp_path):
    inv, event, _, tools, _ = setup(tmp_path)
    inv.tools = evidence_adapter(tools)
    record = asyncio.run(inv.run(event))
    assert record["state"] == "COMPLETED"
    assert record["result"]["status"] == "confirmed_suspicious"
    assert len(tools.executed) == 5


def test_event_scope_rejection_precedes_adapter_validation(tmp_path):
    inv, event, model, tools, _ = setup(tmp_path)
    event["event_id"] = "outside-trusted-scope"
    inv.tools = SimpleNamespace(provenance=tools.provenance)
    record = asyncio.run(inv.run(event))
    assert record["state"] == "FAILED"
    assert record["result"]["termination_reason"] == "PolicyError"
    assert not any(a["kind"] == "adapter_rejected" for a in record["audit"])
    assert model.calls == 0 and not tools.executed


def test_untrusted_policy_in_event_does_not_grant_tool(tmp_path):
    model = ReplayModel({"action": {"type": "tool_request", "tool": "shell", "arguments": {}}})
    inv, event, _, tools, _ = setup(tmp_path, model=model)
    event["attributes"] = {"allowed_tools": ["shell"], "max_tool_calls": 10000}
    result = asyncio.run(inv.run(event))
    assert result["result"]["termination_reason"] == "ToolNotAllowedError"
    assert not tools.executed
    assert any(a["kind"] == "policy_rejected" for a in result["audit"])


def test_scope_rejection_precedes_adapter(tmp_path):
    model = ReplayModel({"action": {"type": "tool_request", "tool": "get_change_event", "arguments": {"event_id": "foreign"}}})
    inv, event, _, tools, _ = setup(tmp_path, model=model)
    result = asyncio.run(inv.run(event))
    assert result["result"]["termination_reason"] == "ScopeError"
    assert not tools.executed


@pytest.mark.parametrize("field", ["max_model_calls", "max_tool_calls", "max_evidence_items"])
def test_limits_stop_cross_kind_calls(tmp_path, field):
    inv, event, model, tools, _ = setup(tmp_path, changes={field: 1})
    result = asyncio.run(inv.run(event))["result"]
    assert result["termination_reason"] == "BudgetError"
    assert model.calls == 1
    assert len(tools.executed) == (0 if field == "max_model_calls" else 1)


def test_result_synthesis_is_budgeted(tmp_path):
    inv, event, model, tools, _ = setup(tmp_path, changes={"max_model_calls": 6})
    result = asyncio.run(inv.run(event))["result"]
    assert result["status"] == "inconclusive"
    assert model.calls == 6 and len(tools.executed) == 5


@pytest.fixture
def deadline_clock():
    # Keep setup/audit I/O out of active-call tests; asyncio.wait_for still uses
    # the real event-loop clock and must cancel the suspended adapter.
    class Clock(SystemClock):
        value = 0.0
        def monotonic(self): return self.value
    return Clock()


def test_active_model_deadline_cancels(tmp_path, deadline_clock):
    class Slow(ReplayModel):
        started = cancelled = False
        async def choose_action(self, context, allowed_tools):
            self.calls += 1
            self.started = True
            try: await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled = True
                deadline_clock.value = 0.1
                raise
    model = Slow()
    inv, event, _, tools, _ = setup(tmp_path, model=model, changes={"max_runtime_seconds": 0.1})
    inv.clock = deadline_clock
    result = asyncio.run(asyncio.wait_for(inv.run(event), timeout=5))["result"]
    assert result["termination_reason"] == "BudgetError"
    assert model.started and model.cancelled and model.calls == 1
    assert not tools.executed


def test_active_tool_deadline_cancels(tmp_path, deadline_clock):
    inv, event, model, _, repo = setup(tmp_path, changes={"max_runtime_seconds": 0.1})
    inv.clock = deadline_clock
    class SlowTools(FixtureTools):
        started = cancelled = False
        async def get_change_event(self, event_id):
            self.started = True
            try: await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled = True
                deadline_clock.value = 0.1
                raise
    tools = SlowTools([]); inv.tools = tools
    record = asyncio.run(asyncio.wait_for(inv.run(event), timeout=5))
    result = record["result"]
    assert result["termination_reason"] == "BudgetError"
    assert tools.started and tools.cancelled and model.calls == 1
    assert result["budget_usage"]["tool_calls"] == 1
    assert record["state"] == "INCONCLUSIVE" and result["risk"] == "unknown"
    assert repo.get_by_idempotency_key(record["investigation_id"]) == record


def test_deadline_before_tool_invocation_blocks_tool(tmp_path, deadline_clock):
    class ExpiringRepository(JsonRepository):
        def append_audit_event(self, key, event):
            super().append_audit_event(key, event)
            if event["kind"] == "policy_permitted":
                deadline_clock.value = 0.1

    inv, event, model, tools, repo = setup(
        tmp_path, changes={"max_runtime_seconds": 0.1}, repo=ExpiringRepository(tmp_path),
    )
    inv.clock = deadline_clock
    record = asyncio.run(inv.run(event))
    result = record["result"]
    assert result["termination_reason"] == "BudgetError"
    assert model.calls == 1 and not tools.executed
    assert result["budget_usage"]["tool_calls"] == 0
    assert record["state"] == "INCONCLUSIVE" and result["risk"] == "unknown"
    assert repo.get_by_idempotency_key(record["investigation_id"]) == record


def test_terminal_duplicate_returns_identical_without_calls(tmp_path):
    inv, event, model, tools, repo = setup(tmp_path)
    first = asyncio.run(inv.run(event)); count = model.calls
    for _ in range(5): assert asyncio.run(inv.run(event)) == first
    assert model.calls == count and len(tools.executed) == 5
    with pytest.raises(PersistenceError): repo.append_audit_event(first["investigation_id"], {"kind": "x"})


def test_concurrent_claim_has_exactly_one_winner(tmp_path):
    key = identity("event", "v1")
    def claim(_): return JsonRepository(tmp_path).create_investigation(key, {})
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(claim, range(16))) == 1


def test_running_or_crashed_claim_does_not_restart(tmp_path):
    inv, event, model, tools, repo = setup(tmp_path)
    key = identity(event["event_id"], inv.policy.version)
    (tmp_path / key).mkdir()
    record = asyncio.run(inv.run(event))
    assert record["state"] == "RUNNING" and record["result"] is None
    assert model.calls == 0 and not tools.executed


def test_changed_event_with_same_key_is_rejected(tmp_path):
    inv, event, _, _, _ = setup(tmp_path)
    asyncio.run(inv.run(event))
    event["attributes"] = {"different": True}
    with pytest.raises(PolicyError): asyncio.run(inv.run(event))


def test_persistence_failure_cannot_return_benign(tmp_path):
    class Broken(JsonRepository):
        def append_evidence(self, *args): raise PersistenceError("disk full")
    inv, event, model, tools, _ = setup(tmp_path, repo=Broken(tmp_path))
    with pytest.raises(PersistenceError): asyncio.run(inv.run(event))
    assert model.calls == 1 and len(tools.executed) == 1


def test_evidence_digest_covers_body_and_request(tmp_path):
    inv, event, _, _, _ = setup(tmp_path)
    record = asyncio.run(inv.run(event))
    for evidence in record["evidence"]:
        digest = sha256(canonical(record["bodies"][evidence["evidence_id"]]).encode()).hexdigest()
        assert evidence["integrity"]["digest"] == digest
        assert evidence["evidence_id"] == "ev-" + digest


@pytest.mark.parametrize("mutation", ["missing", "oversized", "ambiguous"])
def test_invalid_evidence_cannot_become_benign(tmp_path, mutation):
    entries = load(ROOT / "scenarios/S01/evidence.json")
    if mutation == "missing": entries.pop()
    elif mutation == "oversized": entries[0]["data"]["attributes"] = {"x": "a" * 9000}
    else: entries.append(deepcopy(entries[0]))
    inv, event, _, _, _ = setup(tmp_path, entries=entries)
    result = asyncio.run(inv.run(event))["result"]
    assert result["status"] == "insufficient_evidence" and result["risk"] == "unknown"
    assert result["missing_evidence"]


def test_verdict_changes_with_evidence_not_scenario_id(tmp_path):
    entries = load(ROOT / "scenarios/S01/evidence.json")
    entries[-1]["data"]["approved"] = True
    inv, event, _, _, _ = setup(tmp_path, entries=entries)
    assert asyncio.run(inv.run(event))["result"]["status"] == "likely_benign"
    entries[-1]["data"]["subject_id"] = "wrong-person"
    inv, event, _, _, _ = setup(tmp_path / "other", entries=entries)
    assert asyncio.run(inv.run(event))["result"]["status"] == "confirmed_suspicious"


def test_early_benign_finish_is_rejected(tmp_path):
    class Early(ReplayModel):
        async def choose_action(self, context, allowed_tools): return {"type": "finish"}
        async def produce_result(self, context):
            return dict(status="likely_benign", risk="low", summary="fine", findings=[], missing_evidence=[], recommended_next_actions=[])
    inv, event, _, _, _ = setup(tmp_path, model=Early())
    assert asyncio.run(inv.run(event))["result"]["termination_reason"] == "GroundingError"


def test_cli_and_mismatch_exit_codes(tmp_path, capsys):
    assert main([str(ROOT / "scenarios"), "--all", "--output", str(tmp_path)]) == 0
    assert '"mode": "synthetic_replay"' in capsys.readouterr().out
    assert main([str(tmp_path / "absent")]) == 2
