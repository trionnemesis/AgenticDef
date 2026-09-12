from copy import deepcopy
import json
from pathlib import Path

import pytest

from agenticdef.domain.runtime import Budget, Policy, TERMINAL, identity, transition
from agenticdef.domain.errors import BudgetError, ContractError, PolicyError, ScopeError, ToolNotAllowedError

ROOT = Path(__file__).resolve().parents[1]


class Clock:
    value = 0
    def monotonic(self): return self.value
    def utcnow(self): return "2026-09-12T00:00:00Z"


def policy(): return json.loads((ROOT / "scenarios/S01/policy.yaml").read_text())


@pytest.mark.parametrize("terminal", TERMINAL)
def test_terminal_cannot_restart(terminal):
    with pytest.raises(PolicyError): transition(terminal, "INVESTIGATING")


def test_cannot_skip_validation():
    with pytest.raises(PolicyError): transition("RECEIVED", "INVESTIGATING")


@pytest.mark.parametrize("limit", ["max_model_calls", "max_tool_calls", "max_evidence_items"])
def test_every_zero_limit_blocks_all_calls(limit):
    value = policy(); value[limit] = 0
    budget = Budget(Policy(value), Clock())
    for kind in ["model_calls", "tool_calls"]:
        with pytest.raises(BudgetError): budget.reserve(kind)
    assert budget.model_calls == budget.tool_calls == 0


def test_monotonic_deadline_and_reservation():
    value = policy(); value["max_model_calls"] = 1
    clock = Clock(); budget = Budget(Policy(value), clock)
    budget.reserve("model_calls")
    with pytest.raises(BudgetError): budget.reserve("tool_calls")
    assert budget.model_calls == 1 and budget.tool_calls == 0
    budget = Budget(Policy(policy()), clock)
    clock.value = 11
    with pytest.raises(BudgetError): budget.reserve("model_calls")


def test_policy_defensive_copy_and_exact_scope():
    value = policy(); guard = Policy(value)
    value["allowed_tools"].append("shell")
    with pytest.raises(ToolNotAllowedError): guard.authorize("shell", {})
    args = deepcopy(value["resource_scope"]["rbac_objects"][0])
    guard.authorize("get_rbac_object", args)
    args["version"] = "latest"
    with pytest.raises(ScopeError): guard.authorize("get_rbac_object", args)
    with pytest.raises(ContractError): guard.authorize("get_change_event", {"event_id": "evt-S01", "url": "x"})


def test_identity_is_unambiguous_and_path_safe():
    assert identity("ab", "c") != identity("a", "bc")
    assert identity("../../escape", "1").startswith("inv-")
    assert "/" not in identity("../../escape", "1")
