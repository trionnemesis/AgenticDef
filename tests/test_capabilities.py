import inspect
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from agenticdef.adapters.fixture_tools import FixtureTools
from agenticdef.adapters.replay_model import requests_for
from agenticdef.domain.capabilities import CAPABILITIES, CAPABILITY_BY_NAME, TOOL_ARGUMENTS
from agenticdef.domain.contracts import SCHEMAS
from agenticdef.domain.errors import ContractError, ScopeError, ToolNotAllowedError
from agenticdef.domain.evidence import required_requests
from agenticdef.domain.runtime import Policy, TOOL_ARGUMENTS as RUNTIME_TOOL_ARGUMENTS
from agenticdef.ports import EvidenceTools
from agenticdef.cli import load


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "get_change_event": (("event_id",), "event_ids", "event_id"),
    "get_rbac_object": (("kind", "namespace", "name", "version"), "rbac_objects", None),
    "get_subject_bindings": (("subject_id",), "subject_ids", "subject_id"),
    "get_approval_record": (("change_id",), "change_ids", "change_id"),
}


def scenario():
    path = ROOT / "scenarios/S01"
    return load(path / "event.json"), load(path / "policy.yaml")


def test_fixed_catalog_matches_normative_schemas_ports_and_fixture_adapter():
    assert isinstance(CAPABILITIES, tuple)
    assert [(item.name, item.arguments, item.scope_field, item.scope_identifier)
            for item in CAPABILITIES] == [(name, *definition) for name, definition in EXPECTED.items()]
    assert dict(TOOL_ARGUMENTS) == {name: definition[0] for name, definition in EXPECTED.items()}
    assert RUNTIME_TOOL_ARGUMENTS is TOOL_ARGUMENTS

    policy_schema = SCHEMAS["policy.schema.json"]
    evidence_schema = SCHEMAS["evidence.schema.json"]
    assert policy_schema["properties"]["allowed_tools"]["items"]["enum"] == list(EXPECTED)
    assert evidence_schema["properties"]["method"]["enum"] == list(EXPECTED)
    scope = policy_schema["properties"]["resource_scope"]
    assert set(scope["properties"]) == {definition[1] for definition in EXPECTED.values()}
    assert tuple(scope["properties"]["rbac_objects"]["items"]["required"]) == EXPECTED["get_rbac_object"][0]

    for name, (arguments, _, _) in EXPECTED.items():
        for owner in (EvidenceTools, FixtureTools):
            method = getattr(owner, name)
            assert inspect.iscoroutinefunction(method)
            assert tuple(inspect.signature(method).parameters) == ("self", *arguments)


def test_catalog_and_compatibility_mapping_are_immutable():
    capability = CAPABILITIES[0]
    with pytest.raises(FrozenInstanceError):
        capability.name = "shell"
    with pytest.raises(TypeError):
        CAPABILITY_BY_NAME["shell"] = capability
    with pytest.raises(TypeError):
        TOOL_ARGUMENTS["get_change_event"] = ("url",)
    with pytest.raises(TypeError):
        RUNTIME_TOOL_ARGUMENTS["get_change_event"] = ("url",)
    with pytest.raises(TypeError):
        capability.arguments[0] = "url"


@pytest.mark.parametrize("tool,arguments,outside", [
    ("get_change_event", {"event_id": "evt-S01"}, {"event_id": "evt-foreign"}),
    ("get_rbac_object",
     {"kind": "ClusterRole", "namespace": "", "name": "release-operator", "version": "1"},
     {"kind": "ClusterRole", "namespace": "", "name": "release-operator", "version": "foreign"}),
    ("get_subject_bindings", {"subject_id": "serviceaccount:ops:deployer"}, {"subject_id": "foreign"}),
    ("get_approval_record", {"change_id": "chg-S01"}, {"change_id": "foreign"}),
])
def test_every_capability_is_allowed_disallowed_and_exactly_scoped(tool, arguments, outside):
    _, value = scenario()
    Policy(value).authorize(tool, arguments)

    disallowed = deepcopy(value)
    disallowed["allowed_tools"].remove(tool)
    with pytest.raises(ToolNotAllowedError):
        Policy(disallowed).authorize(tool, arguments)
    with pytest.raises(ScopeError):
        Policy(value).authorize(tool, outside)


@pytest.mark.parametrize("tool,valid,wrong_shape,invalid_identifier", [
    ("get_change_event", {"event_id": "evt-S01"}, {}, {"event_id": ""}),
    ("get_rbac_object",
     {"kind": "ClusterRole", "namespace": "", "name": "release-operator", "version": "1"},
     {"kind": "ClusterRole", "namespace": "", "name": "release-operator"},
     {"kind": "ClusterRole", "namespace": "", "name": "", "version": "1"}),
    ("get_subject_bindings", {"subject_id": "serviceaccount:ops:deployer"}, {}, {"subject_id": ""}),
    ("get_approval_record", {"change_id": "chg-S01"}, {}, {"change_id": ""}),
])
def test_every_capability_preserves_argument_validation_and_rejection_order(
        tool, valid, wrong_shape, invalid_identifier):
    _, value = scenario()
    allowed = Policy(value)
    with pytest.raises(ContractError):
        allowed.authorize(tool, wrong_shape)
    with pytest.raises(ContractError):
        allowed.authorize(tool, invalid_identifier)

    disallowed = deepcopy(value)
    disallowed["allowed_tools"].remove(tool)
    guard = Policy(disallowed)
    for arguments in (wrong_shape, invalid_identifier, valid):
        with pytest.raises(ToolNotAllowedError):
            guard.authorize(tool, arguments)


def test_required_read_plan_is_independent_exact_and_mutation_isolated():
    event, _ = scenario()
    original = deepcopy(event)
    expected = [
        ("get_change_event", {"event_id": "evt-S01"}),
        ("get_rbac_object", {"kind": "ClusterRole", "namespace": "", "name": "release-operator", "version": "1"}),
        ("get_rbac_object", {"kind": "ClusterRole", "namespace": "", "name": "release-operator", "version": "2"}),
        ("get_subject_bindings", {"subject_id": "serviceaccount:ops:deployer"}),
        ("get_approval_record", {"change_id": "chg-S01"}),
    ]
    first = required_requests(event)
    assert first == expected
    first[0][1]["event_id"] = "mutated"
    first[1][1]["namespace"] = "mutated"
    assert event == original
    assert required_requests(event) == expected

    expected_actions = [{"type": "tool_request", "tool": tool, "arguments": arguments}
                        for tool, arguments in expected]
    actions = requests_for(event)
    assert actions == expected_actions
    actions[2]["arguments"]["version"] = "mutated"
    assert event == original
    assert requests_for(event) == expected_actions
