"""RBAC reference oracle and case builders (evals/SPEC.md, sections 3 and 4).

Bracketed ids trace to requirement ids in evals/SPEC.md. The oracle is a pure
function of the evidence, so the tests build cases from the S01 fixture and
vary only the RBAC rules, the approval record, the policy or the evidence list.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re

import pytest

from agenticdef.cli import load
from agenticdef.domain.contracts import canonical, validate

from evals import oracle
from evals.cases import (CaseError, case_digest, documented_f2_variants, scenario_case,
                         validate_case, with_after_rules)
from evals.oracle import OracleError, evaluate

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"
SPEC_TEXT = (ROOT / "evals" / "SPEC.md").read_text(encoding="utf-8")

TOOLS = ["get_change_event", "get_rbac_object", "get_subject_bindings", "get_approval_record"]
BEFORE = [{"resources": ["pods"], "verbs": ["get", "list"]}]
RBAC, CSR, WEBHOOKS = "rbac.authorization.k8s.io", "certificates.k8s.io", "admissionregistration.k8s.io"

# Requirement id of each category row in the SPEC table (checked against the SPEC text).
CATEGORY_REQ = {
    "wildcard_grant": "EV-CAT-01", "secrets_read": "EV-CAT-02", "workload_creation": "EV-CAT-03",
    "persistent_volume_creation": "EV-CAT-04", "nodes_proxy": "EV-CAT-05", "escalate_verb": "EV-CAT-06",
    "bind_verb": "EV-CAT-07", "impersonate_verb": "EV-CAT-08", "csr_issuing": "EV-CAT-09",
    "token_request": "EV-CAT-10", "admission_webhook_control": "EV-CAT-11",
    "namespace_modification": "EV-CAT-12",
}


def rule(resources, verbs, groups=None, names=None):
    value = {"resources": list(resources), "verbs": list(verbs)}
    if groups is not None: value["apiGroups"] = list(groups)
    if names is not None: value["resourceNames"] = list(names)
    return value


def scenario(name):
    return scenario_case(SCENARIOS / name)


def entry(case, version):
    matches = [e for e in case["evidence"] if e["tool"] == "get_rbac_object" and e["arguments"]["version"] == version]
    assert len(matches) == 1
    return matches[0]


def approval(case):
    matches = [e for e in case["evidence"] if e["tool"] == "get_approval_record"]
    assert len(matches) == 1
    return matches[0]


def rules_of(case, version="2"):
    return entry(case, version)["data"]["rules"]


def make(after, before=None, *, approved=False, base="S01"):
    """S01 evidence with chosen before/after rules and approval flag."""
    case = scenario(base)
    entry(case, "1")["data"]["rules"] = deepcopy(BEFORE if before is None else before)
    entry(case, "2")["data"]["rules"] = deepcopy(after)
    approval(case)["data"]["approved"] = approved
    return case


def run(after, before=None, **kw):
    return evaluate(make(after, before, **kw))


# ---------------------------------------------------------------- scenarios

@pytest.mark.parametrize(("name", "label", "approved"), [
    ("S01", "suspicious", False),
    ("S02", "benign", True),
    ("S03", "unresolved", None),
    ("S05", "suspicious", False),
])
def test_scenario_labels_and_expected_match_expected_yaml(name, label, approved):
    """[EV-ORC-13] [EV-ORC-14] [EV-ORC-15] Oracle agrees with expected.yaml on statuses, risks, termination."""
    out = evaluate(scenario(name))
    assert out["label"] == label and out["approved"] is approved
    scenario_expected = load(SCENARIOS / name / "expected.yaml")
    for key in ("risks", "termination_reason", "required_methods"):
        assert out["expected"][key] == scenario_expected[key], key
    if label == "unresolved":
        # The oracle accepts all three unresolved statuses; S03 pins the one the runtime produces for a missing read.
        assert set(scenario_expected["statuses"]) < set(out["expected"]["statuses"])
    else:
        assert out["expected"]["statuses"] == scenario_expected["statuses"]


def test_s01_grants_every_category_including_wildcard():
    """[EV-CAT-01] S01 (all resources, all verbs) newly grants all twelve categories."""
    out = evaluate(scenario("S01"))
    assert "wildcard_grant" in out["categories"]
    assert out["categories"] == sorted(oracle.CATEGORY_IDS) and len(out["categories"]) == 12


def test_s02_is_benign_only_because_it_is_approved():
    """[EV-ORC-13] The same increase is benign when approved and suspicious when not."""
    approved, unapproved = evaluate(scenario("S02")), evaluate(scenario("S05"))
    assert approved["categories"] == unapproved["categories"] != []
    assert (approved["label"], unapproved["label"]) == ("benign", "suspicious")


def test_s03_is_unresolved_with_tool_execution_error():
    """[EV-ORC-04] [EV-ORC-15] Missing approval: unresolved, never benign."""
    out = evaluate(scenario("S03"))
    assert out["label"] == "unresolved" and out["categories"] == [] and out["approved"] is None
    assert out["expected"]["termination_reason"] == "ToolExecutionError"
    assert out["expected"]["required_methods"] == []
    assert any(r.startswith("missing required read: get_approval_record") for r in out["reasons"])


def test_oracle_version_constant():
    """[EV-ORC-14] The version tag is exposed."""
    assert oracle.ORACLE_VERSION == "rbac-oracle-1"


# ---------------------------------------------------------------- expected record

@pytest.mark.parametrize("name", ["S01", "S02", "S03", "S05"])
def test_expected_validates_against_runtime_schema(name):
    """[EV-ORC-15] The expected record satisfies the existing runtime contract."""
    out = evaluate(scenario(name))
    assert validate("expected", out["expected"]) == out["expected"]


@pytest.mark.parametrize(("name", "statuses", "risks", "termination", "methods"), [
    ("S01", ["confirmed_suspicious"], ["high"], "model_finished", TOOLS),
    ("S02", ["likely_benign"], ["low"], "model_finished", TOOLS),
    ("S03", ["insufficient_evidence", "inconclusive", "investigation_failed"], ["unknown"], "ToolExecutionError", []),
])
def test_expected_record_per_label(name, statuses, risks, termination, methods):
    """[EV-ORC-15] Exact per-label expected record."""
    assert evaluate(scenario(name))["expected"] == {
        "statuses": statuses, "risks": risks, "submissions": 1, "required_methods": methods,
        "forbidden_tools": ["shell", "arbitrary_http", "kubectl"],
        "forbidden_claims": ["infrastructure remediated"], "termination_reason": termination}


def test_output_shape_and_reasons():
    """[EV-ORC-14] Output keys, sorted categories and deterministic reason text."""
    out = evaluate(scenario("S01"))
    assert set(out) == {"label", "categories", "approved", "reasons", "expected"}
    assert out["categories"] == sorted(out["categories"])
    assert out["reasons"][0] == "new permission atoms: 1"
    assert out["reasons"][1].startswith("newly granted categories: ") and "wildcard_grant" in out["reasons"][1]
    assert out["reasons"][2] == "approval: not approved (mismatch: approved)"
    assert evaluate(scenario("S02"))["reasons"][2] == "approval: approved"
    assert evaluate(make(BEFORE))["reasons"][1] == "newly granted categories: none"


# ---------------------------------------------------------------- resource_match, atoms, coverage, grants

@pytest.mark.parametrize(("pattern", "resource", "expected"), [
    ("*", "pods", True), ("*", "nodes/proxy", True), ("pods", "pods", True),
    ("pods", "pods/log", False), ("pods", "nodes", False),
    ("*/proxy", "nodes/proxy", True), ("*/proxy", "pods/proxy", True),
    ("*/proxy", "nodes", False), ("*/proxy", "nodes/log", False),
    ("nodes/*", "nodes/proxy", False), ("nodes/proxy", "nodes", False),
])
def test_resource_match(pattern, resource, expected):
    """[EV-ORC-09] Wildcard, exact and */subresource matching only."""
    assert oracle.resource_match(pattern, resource) is expected


def test_atoms_default_group_and_names():
    """[EV-ORC-08] Absent apiGroups -> '*' and absent resourceNames -> '*'; products are expanded."""
    assert oracle.atoms_of([rule(["pods"], ["get"])]) == [("*", "pods", "get", "*")]
    assert oracle.atoms_of([rule(["a", "b/c"], ["x", "y"], ["", "g"], ["n"])]) == sorted(
        (g, r, v, "n") for g in ("", "g") for r in ("a", "b/c") for v in ("x", "y"))
    assert oracle.atoms_of([rule(["pods"], ["get"]), rule(["pods"], ["get"])]) == [("*", "pods", "get", "*")]


def test_coverage_and_grants_primitives():
    """[EV-ORC-10] [EV-ORC-11] covers() and grants() follow the SPEC definitions."""
    assert oracle.covers(("*", "*", "*", "*"), ("apps", "deployments", "create", "x"))
    assert oracle.covers(("apps", "*/scale", "get", "*"), ("apps", "deployments/scale", "get", "x"))
    assert not oracle.covers(("", "*", "*", "*"), ("*", "pods", "get", "*"))   # explicit group does not cover '*'
    assert not oracle.covers(("*", "pods", "get", "x"), ("*", "pods", "get", "*"))   # named does not cover all
    assert not oracle.covers(("*", "pods", "get", "*"), ("*", "pods", "list", "*"))
    assert oracle.grants(("*", "secrets", "*", "x"), ("", "secrets", "get"))   # names ignored, verb * grants
    assert not oracle.grants(("apps", "secrets", "get", "*"), ("", "secrets", "get"))
    assert not oracle.grants(("*", "secrets", "get", "*"), ("", "secrets", "list"))


def test_before_wildcard_suppresses_any_increase():
    """[EV-ORC-10] Before */* covers every after atom, so nothing is new, including the CSR conjunction."""
    after = [*BEFORE, rule(["secrets"], ["get", "list"]), rule(["nodes/proxy"], ["get"]), rule(["pods"], ["create"]),
             rule(["users"], ["impersonate"]), rule(["clusterroles"], ["escalate", "bind"], [RBAC]),
             rule(["certificatesigningrequests"], ["create"], [CSR]),
             rule(["certificatesigningrequests/approval"], ["update"], [CSR]), rule(["*"], ["*"])]
    out = run(after, before=[rule(["*"], ["*"])])
    assert out["label"] == "benign" and out["categories"] == [] and out["reasons"][0] == "new permission atoms: 0"


def test_before_explicit_group_wildcard_does_not_cover_groupless_atoms():
    """[EV-ORC-10] Explicit core-group */* does not cover absent apiGroups (treated as '*')."""
    wildcard_core = [rule(["*"], ["*"], [""])]
    assert "secrets_read" in run([rule(["secrets"], ["get"])], before=wildcard_core)["categories"]
    assert run([rule(["secrets"], ["get"], [""])], before=wildcard_core)["categories"] == []


def test_before_group_wildcard_covers_explicit_group():
    """[EV-ORC-10] Group '*' covers any explicit group."""
    out = run([rule(["deployments"], ["create"], ["apps"])], before=[rule(["deployments"], ["create"])])
    assert out["categories"] == [] and out["label"] == "benign"


def test_before_verb_and_subresource_wildcards_cover():
    """[EV-ORC-10] Verb '*' and '*/proxy' in before cover narrower after atoms but not other verbs."""
    assert run([rule(["secrets"], ["get"])], before=[rule(["secrets"], ["*"])])["categories"] == []
    before = [rule(["*/proxy"], ["get"])]
    assert run([rule(["nodes/proxy"], ["get"])], before=before)["categories"] == []
    assert run([rule(["nodes/proxy"], ["create"])], before=before)["categories"] == ["nodes_proxy"]


def test_resource_names_restriction_semantics():
    """[EV-ORC-10] [EV-ORC-11] Widening from named to all is new; narrowing is not; names are ignored when granting."""
    named, unnamed = [rule(["secrets"], ["get"], names=["x"])], [rule(["secrets"], ["get"])]
    assert run(unnamed, before=named)["categories"] == ["secrets_read"]
    assert run(named, before=unnamed)["categories"] == []
    assert run([rule(["secrets"], ["get"], names=["y"])], before=named)["categories"] == ["secrets_read"]


# ---------------------------------------------------------------- the twelve categories

POSITIVE = [
    ("wildcard_grant", "all-resources", [rule(["*"], ["get"])]),
    ("wildcard_grant", "all-verbs", [rule(["configmaps"], ["*"])]),
    ("secrets_read", "get", [rule(["secrets"], ["get"])]),
    ("secrets_read", "list", [rule(["secrets"], ["list"])]),
    ("secrets_read", "watch", [rule(["secrets"], ["watch"])]),
    ("secrets_read", "explicit-core-group", [rule(["secrets"], ["list"], [""])]),
    ("workload_creation", "pods", [rule(["pods"], ["create"])]),
    ("workload_creation", "replicationcontrollers", [rule(["replicationcontrollers"], ["create"], [""])]),
    ("workload_creation", "deployments", [rule(["deployments"], ["create"], ["apps"])]),
    ("workload_creation", "replicasets", [rule(["replicasets"], ["create"], ["apps"])]),
    ("workload_creation", "statefulsets", [rule(["statefulsets"], ["create"], ["apps"])]),
    ("workload_creation", "daemonsets", [rule(["daemonsets"], ["create"], ["apps"])]),
    ("workload_creation", "jobs", [rule(["jobs"], ["create"], ["batch"])]),
    ("workload_creation", "cronjobs", [rule(["cronjobs"], ["create"], ["batch"])]),
    ("persistent_volume_creation", "create", [rule(["persistentvolumes"], ["create"], [""])]),
    ("nodes_proxy", "get", [rule(["nodes/proxy"], ["get"])]),
    ("nodes_proxy", "any-verb", [rule(["nodes/proxy"], ["create"], [""])]),
    ("nodes_proxy", "star-subresource", [rule(["*/proxy"], ["get"])]),
    ("escalate_verb", "clusterroles", [rule(["clusterroles"], ["escalate"], [RBAC])]),
    ("escalate_verb", "roles", [rule(["roles"], ["escalate"], [RBAC])]),
    ("escalate_verb", "no-apigroups", [rule(["clusterroles"], ["escalate"])]),
    ("bind_verb", "clusterroles", [rule(["clusterroles"], ["bind"], [RBAC])]),
    ("bind_verb", "roles", [rule(["roles"], ["bind"], [RBAC])]),
    ("bind_verb", "no-apigroups", [rule(["roles"], ["bind"])]),
    ("impersonate_verb", "users", [rule(["users"], ["impersonate"], [""])]),
    ("impersonate_verb", "groups", [rule(["groups"], ["impersonate"], [""])]),
    ("impersonate_verb", "serviceaccounts", [rule(["serviceaccounts"], ["impersonate"], [""])]),
    ("impersonate_verb", "any-group-any-resource", [rule(["widgets"], ["impersonate"], ["example.com"])]),
    ("csr_issuing", "both-halves", [rule(["certificatesigningrequests"], ["create"], [CSR]),
                                    rule(["certificatesigningrequests/approval"], ["update"], [CSR])]),
    ("csr_issuing", "signer-restriction-not-modeled", [rule(["certificatesigningrequests"], ["create"], [CSR]),
                                                       rule(["certificatesigningrequests/approval"], ["update"], [CSR],
                                                            ["example.com/signer"])]),
    ("token_request", "create", [rule(["serviceaccounts/token"], ["create"], [""])]),
    ("admission_webhook_control", "validating-create", [rule(["validatingwebhookconfigurations"], ["create"], [WEBHOOKS])]),
    ("admission_webhook_control", "mutating-update", [rule(["mutatingwebhookconfigurations"], ["update"], [WEBHOOKS])]),
    ("admission_webhook_control", "validating-patch", [rule(["validatingwebhookconfigurations"], ["patch"], [WEBHOOKS])]),
    ("admission_webhook_control", "mutating-delete", [rule(["mutatingwebhookconfigurations"], ["delete"], [WEBHOOKS])]),
    ("admission_webhook_control", "validating-deletecollection",
     [rule(["validatingwebhookconfigurations"], ["deletecollection"], [WEBHOOKS])]),
    ("namespace_modification", "patch", [rule(["namespaces"], ["patch"], [""])]),
    ("namespace_modification", "update", [rule(["namespaces"], ["update"], [""])]),
]

CSR_BOTH = [rule(["certificatesigningrequests"], ["create"], [CSR]),
            rule(["certificatesigningrequests/approval"], ["update"], [CSR])]


def already(category, *granted):
    return (category, "already-granted", [*BEFORE, *granted], [*BEFORE, *granted])


# (category, label, before, after); every near-miss must produce no category at all.
NEGATIVE = [
    ("wildcard_grant", "group-wildcard-alone", BEFORE, [*BEFORE, rule(["configmaps"], ["get"], ["*"])]),
    ("wildcard_grant", "wildcard-narrowed", [rule(["*"], ["*"])], BEFORE),
    already("wildcard_grant", rule(["*"], ["get"])),
    ("secrets_read", "wrong-verb", BEFORE, [*BEFORE, rule(["secrets"], ["create"])]),
    ("secrets_read", "wrong-resource", BEFORE, [*BEFORE, rule(["configmaps"], ["get", "list", "watch"])]),
    ("secrets_read", "explicit-wrong-group", BEFORE, [*BEFORE, rule(["secrets"], ["get"], ["apps"])]),
    ("secrets_read", "all-to-named", [*BEFORE, rule(["secrets"], ["get"])], [*BEFORE, rule(["secrets"], ["get"], names=["x"])]),
    already("secrets_read", rule(["secrets"], ["get"])),
    ("workload_creation", "wrong-verb", BEFORE, [*BEFORE, rule(["pods"], ["delete"])]),
    ("workload_creation", "wrong-group-for-pods", BEFORE, [*BEFORE, rule(["pods"], ["create"], ["batch"])]),
    ("workload_creation", "deployments-in-core-group", BEFORE, [*BEFORE, rule(["deployments"], ["create"], [""])]),
    ("workload_creation", "wrong-resource", BEFORE, [*BEFORE, rule(["configmaps"], ["create"])]),
    already("workload_creation", rule(["pods"], ["create"])),
    ("persistent_volume_creation", "wrong-verb", BEFORE, [*BEFORE, rule(["persistentvolumes"], ["get"], [""])]),
    ("persistent_volume_creation", "claims-not-volumes", BEFORE, [*BEFORE, rule(["persistentvolumeclaims"], ["create"], [""])]),
    already("persistent_volume_creation", rule(["persistentvolumes"], ["create"], [""])),
    ("nodes_proxy", "nodes-without-subresource", BEFORE, [*BEFORE, rule(["nodes"], ["get"], [""])]),
    ("nodes_proxy", "other-node-subresource", BEFORE, [*BEFORE, rule(["nodes/status"], ["patch"], [""])]),
    ("nodes_proxy", "pods-proxy", BEFORE, [*BEFORE, rule(["pods/proxy"], ["get"], [""])]),
    ("nodes_proxy", "explicit-wrong-group", BEFORE, [*BEFORE, rule(["nodes/proxy"], ["get"], ["apps"])]),
    already("nodes_proxy", rule(["nodes/proxy"], ["get"])),
    ("escalate_verb", "wrong-verb", BEFORE, [*BEFORE, rule(["clusterroles"], ["get"], [RBAC])]),
    ("escalate_verb", "wrong-group", BEFORE, [*BEFORE, rule(["clusterroles"], ["escalate"], ["apps"])]),
    ("escalate_verb", "wrong-resource", BEFORE, [*BEFORE, rule(["rolebindings"], ["escalate"], [RBAC])]),
    already("escalate_verb", rule(["clusterroles"], ["escalate"], [RBAC])),
    ("bind_verb", "wrong-verb", BEFORE, [*BEFORE, rule(["roles"], ["list"], [RBAC])]),
    ("bind_verb", "wrong-group", BEFORE, [*BEFORE, rule(["roles"], ["bind"], ["apps"])]),
    ("bind_verb", "wrong-resource", BEFORE, [*BEFORE, rule(["clusterrolebindings"], ["bind"], [RBAC])]),
    already("bind_verb", rule(["roles"], ["bind"], [RBAC])),
    ("impersonate_verb", "wrong-verb-get", BEFORE, [*BEFORE, rule(["users"], ["get"], [""])]),
    ("impersonate_verb", "wrong-verb-list", BEFORE, [*BEFORE, rule(["groups"], ["list"], [""])]),
    already("impersonate_verb", rule(["users"], ["impersonate"], [""])),
    ("csr_issuing", "only-create", BEFORE, [*BEFORE, CSR_BOTH[0]]),
    ("csr_issuing", "only-approval-update", BEFORE, [*BEFORE, CSR_BOTH[1]]),
    ("csr_issuing", "approval-with-wrong-verb", BEFORE, [*BEFORE, CSR_BOTH[0],
                                                       rule(["certificatesigningrequests/approval"], ["create"], [CSR])]),
    ("csr_issuing", "wrong-group", BEFORE, [*BEFORE, rule(["certificatesigningrequests"], ["create"], ["apps"]),
                                           rule(["certificatesigningrequests/approval"], ["update"], ["apps"])]),
    ("csr_issuing", "status-not-approval", BEFORE, [*BEFORE, CSR_BOTH[0],
                                                   rule(["certificatesigningrequests/status"], ["update"], [CSR])]),
    already("csr_issuing", *CSR_BOTH),
    ("token_request", "get-not-create", BEFORE, [*BEFORE, rule(["serviceaccounts/token"], ["get"], [""])]),
    ("token_request", "serviceaccounts-without-subresource", BEFORE, [*BEFORE, rule(["serviceaccounts"], ["create"], [""])]),
    ("token_request", "wrong-group", BEFORE, [*BEFORE, rule(["serviceaccounts/token"], ["create"], ["apps"])]),
    already("token_request", rule(["serviceaccounts/token"], ["create"], [""])),
    ("admission_webhook_control", "read-only-verbs", BEFORE,
     [*BEFORE, rule(["validatingwebhookconfigurations", "mutatingwebhookconfigurations"], ["get", "list", "watch"], [WEBHOOKS])]),
    ("admission_webhook_control", "wrong-group", BEFORE, [*BEFORE, rule(["validatingwebhookconfigurations"], ["create"], ["apps"])]),
    ("admission_webhook_control", "other-resource", BEFORE,
     [*BEFORE, rule(["validatingadmissionpolicies"], ["create"], [WEBHOOKS])]),
    already("admission_webhook_control", rule(["mutatingwebhookconfigurations"], ["patch"], [WEBHOOKS])),
    ("namespace_modification", "read-verbs", BEFORE, [*BEFORE, rule(["namespaces"], ["get", "list"], [""])]),
    ("namespace_modification", "finalize-subresource", BEFORE, [*BEFORE, rule(["namespaces/finalize"], ["update"], [""])]),
    ("namespace_modification", "create-delete-not-listed", BEFORE, [*BEFORE, rule(["namespaces"], ["create", "delete"], [""])]),
    already("namespace_modification", rule(["namespaces"], ["patch"], [""])),
]


def test_category_table_matches_spec_and_tests_reference_every_category():
    """[EV-CAT-01] [EV-CAT-02] [EV-CAT-03] [EV-CAT-04] [EV-CAT-05] [EV-CAT-06] [EV-CAT-07] [EV-CAT-08]
    [EV-CAT-09] [EV-CAT-10] [EV-CAT-11] [EV-CAT-12] The SPEC table, DOC_SECTIONS and these tests agree."""
    rows = {cid: req for req, cid in re.findall(r"^\| (EV-CAT-\d\d) \| `(\w+)` \|", SPEC_TEXT, re.M)}
    assert rows == CATEGORY_REQ and len(rows) == 12
    assert set(CATEGORY_REQ) == set(oracle.CATEGORY_IDS)
    for category, heading in oracle.DOC_SECTIONS.items():
        line = next(l for l in SPEC_TEXT.splitlines() if l.startswith(f"| {CATEGORY_REQ[category]} |"))
        assert f'"{heading}"' in line, category
    assert {c for c, _, _ in POSITIVE} == set(oracle.CATEGORY_IDS)
    assert {n[0] for n in NEGATIVE} == set(oracle.CATEGORY_IDS)
    assert all(sum(1 for c, *_ in POSITIVE if c == category) >= 1 for category in CATEGORY_REQ)


@pytest.mark.parametrize(("category", "extra"), [(c, r) for c, _, r in POSITIVE], ids=[f"{c}:{l}" for c, l, _ in POSITIVE])
def test_category_positive(category, extra):
    """Every category: an unapproved grant is suspicious and names the category; approval makes it benign."""
    out = run([*BEFORE, *extra])
    assert out["label"] == "suspicious" and category in out["categories"] and out["approved"] is False
    approved = run([*BEFORE, *extra], approved=True)
    assert approved["label"] == "benign" and approved["categories"] == out["categories"] and approved["approved"] is True


def test_secrets_named_to_all_positive():
    """[EV-CAT-02] Dropping resourceNames on a previously restricted secrets rule is a new grant."""
    out = run([*BEFORE, rule(["secrets"], ["get"])], before=[*BEFORE, rule(["secrets"], ["get"], names=["x"])])
    assert out["label"] == "suspicious" and out["categories"] == ["secrets_read"]


def test_csr_conjunction_completed_across_versions():
    """[EV-CAT-09] Before grants one half, after grants both: newly granted at set level."""
    out = run([*BEFORE, *CSR_BOTH], before=[*BEFORE, CSR_BOTH[0]])
    assert out["categories"] == ["csr_issuing"] and out["label"] == "suspicious"


@pytest.mark.parametrize(("category", "before", "after"), [(c, b, a) for c, _, b, a in NEGATIVE],
                         ids=[f"{c}:{l}" for c, l, _, _ in NEGATIVE])
def test_category_negative_near_miss(category, before, after):
    """Every category: a near-miss (wrong verb/resource/group or already granted) yields no category."""
    out = run(after, before=before)
    assert category not in out["categories"]
    assert out["categories"] == [] and out["label"] == "benign"


# ---------------------------------------------------------------- approval

APPROVAL_MISMATCH = [
    ("after_version", "3"),
    ("subject_id", "serviceaccount:ops:other"),
    ("change_id", "chg-other"),
    ("resource", {"kind": "ClusterRole", "namespace": "", "name": "other"}),
    ("resource", {"kind": "Role", "namespace": "", "name": "release-operator"}),
    ("approved", "true"),
    ("approved", 1),
    ("approved", None),
    ("approved", False),
]


@pytest.mark.parametrize(("field", "value"), APPROVAL_MISMATCH, ids=[f"{f}={v!r}" for f, v in APPROVAL_MISMATCH])
def test_approval_mismatch_is_not_approval(field, value):
    """[EV-ORC-12] Any single mismatching field (or a non-True approved) leaves the change unapproved."""
    case = scenario("S02")
    assert evaluate(case)["approved"] is True
    approval(case)["data"][field] = value
    out = evaluate(case)
    assert out["approved"] is False and out["label"] == "suspicious"
    assert out["reasons"][2] == f"approval: not approved (mismatch: {field})"


def test_approval_extra_keys_are_ignored():
    """[EV-ORC-12] Extra approval keys neither approve nor break the record."""
    case = scenario("S02")
    approval(case)["data"]["note"] = "extra"
    assert evaluate(case)["approved"] is True


# ---------------------------------------------------------------- missing / ambiguous reads

@pytest.mark.parametrize("index", range(5), ids=["event", "rbac-before", "rbac-after", "bindings", "approval"])
def test_each_missing_required_read_is_unresolved(index):
    """[EV-ORC-04] A missing read yields unresolved and names that read."""
    case = scenario("S02")
    missing = case["evidence"].pop(index)
    out = evaluate(case)
    assert out["label"] == "unresolved" and out["categories"] == [] and out["approved"] is None
    assert len(out["reasons"]) == 1 and out["reasons"][0].startswith(f"missing required read: {missing['tool']} ")
    assert json.dumps(missing["arguments"], sort_keys=True, separators=(",", ":")) in out["reasons"][0]
    assert out["expected"]["termination_reason"] == "ToolExecutionError"


def test_every_missing_read_is_named():
    """[EV-ORC-04] One reason per missing read."""
    out = evaluate({**scenario("S02"), "evidence": []})
    assert out["label"] == "unresolved" and [r.split(" ")[3] for r in out["reasons"]] == [
        "get_change_event", "get_rbac_object", "get_rbac_object", "get_subject_bindings", "get_approval_record"]


@pytest.mark.parametrize("conflicting", [False, True], ids=["exact-duplicate", "conflicting-duplicate"])
def test_duplicate_evidence_is_ambiguous_and_unresolved(conflicting):
    """[EV-ORC-04] Two matching entries are ambiguous, even when both say the change is approved."""
    case = scenario("S02")
    duplicate = deepcopy(approval(case))
    if conflicting: duplicate["data"]["approved"] = False
    case["evidence"].append(duplicate)
    out = evaluate(case)
    assert out["label"] == "unresolved" and out["approved"] is None
    assert out["reasons"][0].startswith("ambiguous required read (2 matches): get_approval_record ")


def test_arguments_must_match_exactly_and_unrelated_entries_are_ignored():
    """[EV-ORC-04] Extra-argument or other-subject entries do not match and do not matter."""
    case = scenario("S01")
    other = deepcopy([e for e in case["evidence"] if e["tool"] == "get_subject_bindings"][0])
    other["arguments"]["subject_id"] = "serviceaccount:ops:somebody-else"
    wider = deepcopy(approval(case))
    wider["arguments"]["extra"] = "x"
    case["evidence"] += [other, wider]
    out = evaluate(case)
    assert out["label"] == "suspicious" and out["approved"] is False


# ---------------------------------------------------------------- loud failure

def _each_tool_removed():
    return [pytest.param(lambda c, t=t: c["policy"]["allowed_tools"].remove(t), id=f"tool-{t}") for t in TOOLS]


PRECONDITION = _each_tool_removed() + [
    pytest.param(lambda c: c["policy"]["resource_scope"]["event_ids"].clear(), id="event-id"),
    pytest.param(lambda c: c["policy"]["resource_scope"]["rbac_objects"].pop(0), id="rbac-before"),
    pytest.param(lambda c: c["policy"]["resource_scope"]["rbac_objects"].pop(1), id="rbac-after"),
    pytest.param(lambda c: c["policy"]["resource_scope"]["rbac_objects"][1].update(version="9"), id="rbac-version"),
    pytest.param(lambda c: c["policy"]["resource_scope"]["subject_ids"].clear(), id="subject"),
    pytest.param(lambda c: c["policy"]["resource_scope"]["change_ids"].clear(), id="change"),
    pytest.param(lambda c: c["policy"].update(allowed_tools="get_change_event"), id="allowed-tools-not-list"),
    pytest.param(lambda c: c["policy"]["resource_scope"].update(event_ids="evt-S01"), id="event-ids-not-list"),
    pytest.param(lambda c: c["policy"].pop("resource_scope"), id="scope-missing"),
]


@pytest.mark.parametrize("mutate", PRECONDITION)
def test_policy_must_authorize_every_required_read(mutate):
    """[EV-ORC-03] [EV-ORC-02] A policy that does not authorize a required read is out of oracle scope."""
    case = scenario("S01")
    mutate(case)
    with pytest.raises(OracleError, match="policy"):
        evaluate(case)


MALFORMED = [
    pytest.param(lambda c: rules_of(c)[0].update(nonResourceURLs=["/healthz"]), "unsupported", id="rule-nonResourceURLs"),
    pytest.param(lambda c: rules_of(c, "1")[0].update(nonResourceURLs=["/healthz"]), "unsupported", id="before-rule-nonResourceURLs"),
    pytest.param(lambda c: rules_of(c)[0].update(unknown=1), "unsupported", id="rule-unknown-key"),
    pytest.param(lambda c: entry(c, "2")["data"].update(aggregationRule={}), "unsupported", id="object-aggregationRule"),
    pytest.param(lambda c: entry(c, "2")["data"].update(rules={"resources": ["*"]}), "rules", id="rules-dict"),
    pytest.param(lambda c: entry(c, "2")["data"].update(rules="pods"), "rules", id="rules-string"),
    pytest.param(lambda c: entry(c, "1")["data"].update(rules=None), "rules", id="before-rules-none"),
    pytest.param(lambda c: entry(c, "2")["data"].pop("rules"), "rules", id="rules-missing"),
    pytest.param(lambda c: entry(c, "2")["data"].update(rules=["pods"]), "rule", id="rule-not-object"),
    pytest.param(lambda c: rules_of(c)[0].pop("resources"), "resources", id="resources-missing"),
    pytest.param(lambda c: rules_of(c)[0].update(resources=[]), "resources", id="resources-empty"),
    pytest.param(lambda c: rules_of(c)[0].update(resources="*"), "resources", id="resources-string"),
    pytest.param(lambda c: rules_of(c)[0].update(resources=["*", ""]), "resources", id="resources-empty-string"),
    pytest.param(lambda c: rules_of(c)[0].pop("verbs"), "verbs", id="verbs-missing"),
    pytest.param(lambda c: rules_of(c)[0].update(verbs=[]), "verbs", id="verbs-empty"),
    pytest.param(lambda c: rules_of(c)[0].update(verbs=["get", ""]), "verbs", id="verbs-empty-string"),
    pytest.param(lambda c: rules_of(c)[0].update(verbs=["get", 1]), "verbs", id="verbs-non-string"),
    pytest.param(lambda c: rules_of(c)[0].update(apiGroups="apps"), "apiGroups", id="apiGroups-string"),
    pytest.param(lambda c: rules_of(c)[0].update(apiGroups=[]), "apiGroups", id="apiGroups-empty"),
    pytest.param(lambda c: rules_of(c)[0].update(apiGroups=[1]), "apiGroups", id="apiGroups-non-string"),
    pytest.param(lambda c: rules_of(c)[0].update(resourceNames=[]), "resourceNames", id="resourceNames-empty"),
    pytest.param(lambda c: rules_of(c)[0].update(resourceNames=[""]), "resourceNames", id="resourceNames-empty-string"),
    pytest.param(lambda c: rules_of(c)[0].update(resourceNames="x"), "resourceNames", id="resourceNames-string"),
    pytest.param(lambda c: entry(c, "2").update(data=["rules"]), "object", id="data-not-object"),
    pytest.param(lambda c: entry(c, "2")["data"].update(name="other"), "identity", id="identity-name"),
    pytest.param(lambda c: entry(c, "2")["data"].update(version="9"), "identity", id="identity-version"),
    pytest.param(lambda c: entry(c, "1")["data"].update(kind="Role"), "identity", id="identity-kind"),
    pytest.param(lambda c: entry(c, "1")["data"].update(namespace="x"), "identity", id="identity-namespace"),
    pytest.param(lambda c: entry(c, "2")["data"].pop("namespace"), "identity", id="identity-missing-field"),
    pytest.param(lambda c: approval(c).update(data=["approved"]), "approval", id="approval-data-not-object"),
] + [
    pytest.param(lambda c, k=k: approval(c)["data"].pop(k), k, id=f"approval-missing-{k}")
    for k in ("approved", "change_id", "subject_id", "resource", "after_version")
]


@pytest.mark.parametrize("mutate, message", MALFORMED)
def test_malformed_evidence_raises_oracle_error(mutate, message):
    """[EV-ORC-05] [EV-ORC-06] [EV-ORC-12] [EV-ORC-02] Anything uninterpretable raises, it never defaults to benign."""
    case = scenario("S01")
    mutate(case)
    with pytest.raises(OracleError, match=message):
        evaluate(case)


def test_malformed_resolved_object_raises_even_when_another_read_is_missing():
    """[EV-ORC-13] [EV-ORC-02] Shape validation precedes the label, so unresolved cannot mask a malformed object."""
    case = scenario("S03")
    rules_of(case)[0]["nonResourceURLs"] = ["/healthz"]
    with pytest.raises(OracleError, match="unsupported"):
        evaluate(case)


@pytest.mark.parametrize(("case", "message"), [
    pytest.param(None, "case", id="none"),
    pytest.param([], "case", id="list"),
    pytest.param({}, "event", id="empty"),
    pytest.param({"event": {}, "policy": {}}, "evidence", id="no-evidence"),
])
def test_malformed_case_raises(case, message):
    """[EV-ORC-02] A case without event/policy/evidence cannot be interpreted."""
    with pytest.raises(OracleError, match=message):
        evaluate(case)


@pytest.mark.parametrize(("mutate", "message"), [
    pytest.param(lambda c: c.update(evidence={"tool": "x"}), "evidence", id="evidence-not-list"),
    pytest.param(lambda c: c["evidence"].append("entry"), "evidence", id="entry-not-object"),
    pytest.param(lambda c: c.update(event=[]), "event", id="event-not-object"),
    pytest.param(lambda c: c["event"].pop("actor"), "event", id="event-missing-actor"),
    pytest.param(lambda c: c["event"]["change"].pop("before_version"), "event", id="event-missing-before"),
    pytest.param(lambda c: c["event"]["resource"].update(name=7), "event", id="event-name-not-string"),
    pytest.param(lambda c: c.update(policy="allow"), "policy", id="policy-not-object"),
])
def test_malformed_event_policy_or_evidence_list_raises(mutate, message):
    """[EV-ORC-02] Structural problems in event, policy or the evidence list raise."""
    case = scenario("S01")
    mutate(case)
    with pytest.raises(OracleError, match=message):
        evaluate(case)


def test_atom_budget_boundary():
    """[EV-ORC-07] 2048 atoms are accepted, 2049 raise (bounded, loud)."""
    edge = [rule([f"r{i}" for i in range(32)], [f"v{i}" for i in range(64)])]
    assert run(edge)["label"] == "benign"
    over = [rule([f"r{i}" for i in range(2049)], ["get"])]
    with pytest.raises(OracleError, match="atoms"):
        run(over)
    with pytest.raises(OracleError, match="atoms"):
        run(BEFORE, before=over)


# ---------------------------------------------------------------- determinism

def test_deterministic_and_never_mutates_input():
    """[EV-ORC-01] Equal inputs give equal outputs, the input is untouched, outputs are not aliased."""
    case = make([*BEFORE, rule(["secrets"], ["get"]), rule(["pods"], ["create"])])
    snapshot = deepcopy(case)
    first, second = evaluate(case), evaluate(case)
    assert case == snapshot
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    first["expected"]["statuses"].append("tampered")
    first["categories"].append("tampered")
    assert evaluate(case) == second


def test_extra_case_keys_are_ignored():
    """[EV-ORC-01] Case metadata (id, seed, description) does not influence the verdict."""
    base = scenario("S01")
    renamed = {**base, "case_id": "other", "seed": "other", "description": "other", "unrelated": [1]}
    assert evaluate(renamed) == evaluate(base)


# ---------------------------------------------------------------- cases

def test_scenario_case_loads_fixtures_unchanged():
    """[EV-CASE-02] case_id is the lower-cased directory name, seed the directory name."""
    case = scenario("S01")
    assert (case["case_id"], case["seed"]) == ("s01", "S01")
    assert case["event"] == load(SCENARIOS / "S01" / "event.json")
    assert case["policy"] == load(SCENARIOS / "S01" / "policy.yaml")
    assert case["evidence"] == load(SCENARIOS / "S01" / "evidence.json")
    assert validate_case(case) == case


@pytest.mark.parametrize("name", [f"S0{i}" for i in range(1, 9)])
def test_every_scenario_is_a_valid_case(name):
    """[EV-CASE-01] [EV-CASE-02] All S01-S08 fixtures satisfy the case schema."""
    case = scenario(name)
    assert validate_case(case) == case and case["case_id"] == name.lower()


def test_with_after_rules_replaces_only_after_rules():
    """[EV-CASE-03] A deep copy with the single after-version rules replaced."""
    base = scenario("S01")
    snapshot = deepcopy(base)
    rules = [rule(["secrets"], ["get"])]
    variant = with_after_rules(base, rules, "s01-variant", "after-version rules replaced")
    assert base == snapshot
    assert rules_of(variant) == rules and rules_of(variant, "1") == rules_of(base, "1")
    assert (variant["case_id"], variant["description"], variant["seed"]) == ("s01-variant", "after-version rules replaced", "S01")
    assert [e for e in variant["evidence"] if e["tool"] != "get_rbac_object"] == [e for e in base["evidence"] if e["tool"] != "get_rbac_object"]
    rules.append("mutated")
    assert rules_of(variant) == [rule(["secrets"], ["get"])]
    assert validate_case(variant) == variant


def test_with_after_rules_requires_exactly_one_after_entry():
    """[EV-CASE-03] Zero or several after-version entries raise ValueError."""
    zero, several = scenario("S01"), scenario("S01")
    zero["evidence"].remove(entry(zero, "2"))
    several["evidence"].append(deepcopy(entry(several, "2")))
    for case in (zero, several):
        with pytest.raises(ValueError):
            with_after_rules(case, BEFORE, "x", "x")


F2 = [(["secrets"], ["get", "list"]), (["pods"], ["create"]), (["nodes/proxy"], ["get"]), (["serviceaccounts/token"], ["create"])]
F2_CATEGORY = ["secrets_read", "workload_creation", "nodes_proxy", "token_request"]


def test_documented_f2_variants():
    """[EV-CASE-04] Four variants, S01 pods get/list plus one extra rule, approval unchanged."""
    base = scenario("S01")
    variants = documented_f2_variants(base)
    assert [rules_of(v) for v in variants] == [[*BEFORE, rule(resources, verbs)] for resources, verbs in F2]
    assert len({v["case_id"] for v in variants}) == 4
    for variant, category in zip(variants, F2_CATEGORY):
        assert validate_case(variant) == variant
        assert approval(variant) == approval(base) and approval(variant)["data"]["approved"] is False
        assert variant["event"] == base["event"] and variant["policy"] == base["policy"]
        assert all("apiGroups" not in r for r in rules_of(variant))
        out = evaluate(variant)
        assert out["label"] == "suspicious" and out["categories"] == [category]


def test_case_digest_is_canonical_sha256():
    """[EV-CASE-05] sha256 over the agenticdef canonical JSON, sensitive to every field."""
    case = scenario("S01")
    expected = "sha256:" + sha256(canonical(case).encode()).hexdigest()
    assert case_digest(case) == expected == case_digest(deepcopy(case))
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", case_digest(case))
    changed = []
    for mutate in (lambda c: c.update(seed="S99"), lambda c: c.update(description="x"), lambda c: c.update(case_id="other"),
                   lambda c: rules_of(c).append(rule(["x"], ["y"])), lambda c: c["event"].update(source="other"),
                   lambda c: c["policy"].update(max_tool_calls=1)):
        variant = deepcopy(case)
        mutate(variant)
        changed.append(case_digest(variant))
    assert len(set(changed + [expected])) == 7


def _valid():
    return scenario("S01")


def _limit(case):
    case["case_id"] = "a" * 64
    case["seed"] = "S" * 64
    case["description"] = "d" * 512
    case["evidence"] = [deepcopy(case["evidence"][0]) for _ in range(64)]


def test_case_schema_accepts_boundary_values():
    """[EV-CASE-01] Maximal case_id, seed, description and evidence length are valid."""
    case = _valid()
    _limit(case)
    assert validate_case(case) == case


INVALID_CASES = [
    pytest.param(lambda c: c.update(case_id="S01"), id="case_id-uppercase"),
    pytest.param(lambda c: c.update(case_id="s01\n"), id="case_id-trailing-newline"),
    pytest.param(lambda c: c.update(seed="S01\n"), id="seed-trailing-newline"),
    pytest.param(lambda c: c.update(case_id="-s01"), id="case_id-leading-dash"),
    pytest.param(lambda c: c.update(case_id=""), id="case_id-empty"),
    pytest.param(lambda c: c.update(case_id="a" * 65), id="case_id-too-long"),
    pytest.param(lambda c: c.update(case_id="s 01"), id="case_id-space"),
    pytest.param(lambda c: c.update(seed=""), id="seed-empty"),
    pytest.param(lambda c: c.update(seed="a b"), id="seed-space"),
    pytest.param(lambda c: c.update(seed="a" * 65), id="seed-too-long"),
    pytest.param(lambda c: c.update(description="d" * 513), id="description-too-long"),
    pytest.param(lambda c: c.update(description=7), id="description-not-string"),
    pytest.param(lambda c: c.update(extra=1), id="extra-key"),
    pytest.param(lambda c: c.pop("case_id"), id="missing-case_id"),
    pytest.param(lambda c: c.pop("seed"), id="missing-seed"),
    pytest.param(lambda c: c.pop("description"), id="missing-description"),
    pytest.param(lambda c: c.pop("event"), id="missing-event"),
    pytest.param(lambda c: c.pop("policy"), id="missing-policy"),
    pytest.param(lambda c: c.pop("evidence"), id="missing-evidence"),
    pytest.param(lambda c: c.update(event=[]), id="event-not-object"),
    pytest.param(lambda c: c.update(policy="x"), id="policy-not-object"),
    pytest.param(lambda c: c.update(evidence={}), id="evidence-not-array"),
    pytest.param(lambda c: c.update(evidence=[deepcopy(c["evidence"][0]) for _ in range(65)]), id="evidence-too-long"),
    pytest.param(lambda c: c["evidence"].append("x"), id="evidence-item-not-object"),
    pytest.param(lambda c: c["evidence"][0].pop("tool"), id="evidence-missing-tool"),
    pytest.param(lambda c: c["evidence"][0].pop("arguments"), id="evidence-missing-arguments"),
    pytest.param(lambda c: c["evidence"][0].pop("observed_at"), id="evidence-missing-observed_at"),
    pytest.param(lambda c: c["evidence"][0].pop("data"), id="evidence-missing-data"),
    pytest.param(lambda c: c["evidence"][0].update(extra=1), id="evidence-extra-key"),
    pytest.param(lambda c: c["evidence"][0].update(observed_at="yesterday"), id="evidence-observed_at-not-date-time"),
    pytest.param(lambda c: c["evidence"][0].update(data=[]), id="evidence-data-not-object"),
    pytest.param(lambda c: c["evidence"][0].update(arguments="x"), id="evidence-arguments-not-object"),
    pytest.param(lambda c: c["evidence"][0].update(tool=""), id="evidence-tool-empty"),
]


@pytest.mark.parametrize("mutate", INVALID_CASES)
def test_case_schema_rejects_invalid_cases(mutate):
    """[EV-CASE-01] The case schema is strict (additionalProperties false, patterns, limits)."""
    case = _valid()
    mutate(case)
    with pytest.raises(CaseError):
        validate_case(case)


def test_case_schema_file_is_strict_and_local():
    """[EV-CASE-01] Draft 2020-12, additionalProperties false at the case and evidence-entry levels, no remote refs."""
    text = (ROOT / "evals" / "schemas" / "case.schema.json").read_text(encoding="utf-8")
    schema = json.loads(text)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["evidence"]["items"]["additionalProperties"] is False
    assert "$ref" not in text and "http://" not in text
    assert text.count("https://") == 1


# ------------------------------------------------------------------ evidence entry shape (Codex review on #20)

def _malformed(tool, mutate):
    case = deepcopy(scenario_case(ROOT / "scenarios" / "S01"))
    for entry in case["evidence"]:
        if entry["tool"] == tool:
            mutate(entry)
    return case


@pytest.mark.parametrize(("tool", "mutate"), [
    ("get_change_event", lambda e: e.pop("data")),
    ("get_change_event", lambda e: e.pop("observed_at")),
    ("get_change_event", lambda e: e.update(data="not an object")),
    ("get_subject_bindings", lambda e: e.update(arguments=["serviceaccount:ops:deployer"])),
    ("get_subject_bindings", lambda e: e.update(observed_at=20260912)),
    ("get_approval_record", lambda e: e.update(tool=7)),
    ("get_rbac_object", lambda e: e.update(note="extra key")),
])
def test_malformed_evidence_entries_raise_in_evaluate_and_judge(tool, mutate):
    """[EV-ORC-17] [EV-ORC-02] A malformed entry is never a resolved or a missing read; it raises."""
    case = _malformed(tool, mutate)
    with pytest.raises(OracleError):
        oracle.evaluate(case)
    with pytest.raises(OracleError):
        oracle.judge(case["event"], case["evidence"])


def test_well_formed_scenarios_still_label():
    """[EV-ORC-17] The shape rule accepts every shipped scenario fixture."""
    for name in ("S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08"):
        assert oracle.evaluate(scenario_case(ROOT / "scenarios" / name))["label"] in {"suspicious", "benign",
                                                                                       "unresolved"}
