"""Case generator (evals/SPEC.md, section 9).

Bracketed ids trace to requirement ids in evals/SPEC.md. Labels come from the
oracle only; these tests check that the generator never writes or leaks one.
"""
from collections import defaultdict
from copy import deepcopy
import json
from pathlib import Path
import re

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from agenticdef.adapters.replay_model import ReplayModel
from agenticdef.domain.contracts import canonical, validate

from evals import generate as generate_module
from evals import oracle
from evals.cases import case_digest, scenario_case, validate_case
from evals.generate import (APPROVAL_MODES, GENERATOR_VERSION, INJECTIONS, NOTES, GeneratorError, generate,
                            label_of_status, relation_violations)
from evals.runner import build_report, run_case

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"
SCHEMA = json.loads((ROOT / "evals" / "schemas" / "generated.schema.json").read_text(encoding="utf-8"))
SHA = "0123456789abcdef0123456789abcdef01234567"
SEED_STRINGS = ("S01", "S02", "evt-S01", "evt-S02", "chg-S01", "chg-S02", "release-operator",
                "serviceaccount:ops:deployer")
COMPLETE_VARIANTS = {"base", "rename", "reorder", "split-rule", "note-neutral", "note-claims-approval",
                     "note-claims-benign", "monotonic"}
MISSING_VARIANTS = {"base", "rename", "reorder", "note-claims-approval"}
ENTRY_KEYS = {"case", "family", "family_key", "variant", "split", "relation", "transforms", "oracle", "digest"}
NON_PRIVILEGED = [inj for inj in INJECTIONS if inj["category"] is None]
PRIVILEGED = [inj for inj in INJECTIONS if inj["category"] is not None]


@pytest.fixture(scope="module")
def gen():
    return generate()


def seeds():
    return {"S01": scenario_case(SCENARIOS / "S01"), "S02": scenario_case(SCENARIOS / "S02")}


def by_family(gen):
    families = defaultdict(list)
    for entry in gen["entries"]:
        families[entry["family"]].append(entry)
    return families


def bases(gen):
    return {(e["family_key"]["approval_mode"], e["family_key"]["injection"], e["family_key"]["evidence_mode"]): e
            for e in gen["entries"] if e["variant"] == "base"}


def entry_of(gen, case_id):
    return next(e for e in gen["entries"] if e["case"]["case_id"] == case_id)


def evidence(case, tool, version=None):
    for item in case["evidence"]:
        if item["tool"] == tool and (version is None or item["arguments"].get("version") == version):
            return item
    return None


def versions(case):
    change = case["event"]["change"]
    return (evidence(case, "get_rbac_object", change["before_version"]),
            evidence(case, "get_rbac_object", change["after_version"]))


def atom_set(item):
    return set(oracle.atoms_of(item["data"]["rules"])) if item is not None else None


def without_notes(case):
    case = deepcopy(case)
    case["event"]["attributes"].pop("note", None)
    for item in case["evidence"]:
        if item["tool"] == "get_change_event":
            item["data"].get("attributes", {}).pop("note", None)
        if item["tool"] == "get_approval_record":
            item["data"].pop("comment", None)
    return case


# ------------------------------------------------------------------ set shape and inputs

def test_default_set_shape_and_schema(gen):
    """[EV-GEN-01] [EV-GEN-02] [EV-GEN-11] Defaults: S01/S02 seeds, all families, all variants, schema-valid set."""
    complete_families = len(APPROVAL_MODES) * len(INJECTIONS)
    missing_families = len(APPROVAL_MODES) * 2
    assert gen["generator_version"] == GENERATOR_VERSION
    assert gen["oracle_version"] == oracle.ORACLE_VERSION
    assert gen["generator_seed"] == 0 and gen["holdout_fraction"] == 0.3
    assert gen["summary"]["families"] == complete_families + missing_families == len(by_family(gen))
    assert gen["summary"]["cases"] == complete_families * 8 + missing_families * 4 == len(gen["entries"])
    assert sum(gen["summary"]["by_split"].values()) == len(gen["entries"])
    labels = defaultdict(int)
    for entry in gen["entries"]:
        labels[entry["oracle"]["label"]] += 1
    assert gen["summary"]["by_label"] == {"benign": labels["benign"], "suspicious": labels["suspicious"],
                                          "unresolved": labels["unresolved"]}
    assert all(labels[name] > 0 for name in ("benign", "suspicious", "unresolved"))
    assert gen["seed_digests"] == {name: case_digest(case) for name, case in seeds().items()}
    assert [e["case"]["case_id"] for e in gen["entries"]] == sorted(e["case"]["case_id"] for e in gen["entries"])
    assert not list(Draft202012Validator(SCHEMA, format_checker=FormatChecker()).iter_errors(gen))


def test_injection_catalogue_covers_every_category_once():
    """[EV-GEN-02] One injection per escalation category, plus benign, near-miss, removal and pre-existing ones."""
    categories = [inj["category"] for inj in PRIVILEGED]
    assert sorted(categories) == sorted(oracle.CATEGORY_IDS)
    ids = [inj["id"] for inj in INJECTIONS]
    assert len(ids) == len(set(ids))
    kinds = {inj["kind"] for inj in NON_PRIVILEGED}
    assert kinds == {"benign", "near-miss", "removal", "pre-existing"}


@pytest.mark.parametrize("mutate", [
    lambda s: s["S01"]["evidence"][-1]["data"].update(approved=True),
    lambda s: s["S02"]["evidence"][-1]["data"].update(approved=False),
    lambda s: s["S01"]["evidence"][-1]["data"].update(subject_id="someone-else"),
    lambda s: s["S01"]["evidence"].pop(),
    lambda s: s.pop("S02"),
    lambda s: s.update(S03=deepcopy(s["S01"])),
])
def test_seed_cases_are_checked(mutate):
    """[EV-GEN-01] S01 must fail approval only on `approved`, S02 must be approved, both complete, exactly two seeds."""
    seed_cases = seeds()
    assert seed_cases["S01"]["evidence"][-1]["tool"] == "get_approval_record"
    mutate(seed_cases)
    with pytest.raises(GeneratorError):
        generate(seed_cases)


@pytest.mark.parametrize("kwargs", [
    {"generator_seed": -1}, {"generator_seed": "0"}, {"generator_seed": True}, {"generator_seed": 1.0},
    {"holdout_fraction": 0}, {"holdout_fraction": 1}, {"holdout_fraction": 1.5}, {"holdout_fraction": True},
])
def test_generator_parameters_are_checked(kwargs):
    """[EV-GEN-01] A non-negative integer seed and 0 < holdout_fraction < 1; anything else raises."""
    with pytest.raises(GeneratorError):
        generate(**kwargs)


# ------------------------------------------------------------------ labels come from the oracle

def test_base_labels_follow_the_oracle_and_the_catalogue(gen):
    """[EV-GEN-02] [EV-GEN-03] Privileged injections: suspicious unless approved; others benign; missing → unresolved."""
    table = bases(gen)
    for inj in INJECTIONS:
        for mode in APPROVAL_MODES:
            entry = table[(mode, inj["id"], "complete")]
            assert entry["oracle"] == {key: oracle.evaluate(entry["case"])[key] for key in ("label", "categories")}
            if inj["category"] is None:
                assert entry["oracle"] == {"label": "benign", "categories": []}, (mode, inj["id"])
            else:
                assert inj["category"] in entry["oracle"]["categories"], (mode, inj["id"])
                assert entry["oracle"]["label"] == ("benign" if mode == "approved" else "suspicious"), (mode, inj["id"])
    for mode in APPROVAL_MODES:
        for injection, evidence_mode in (("secrets_read", "missing-approval"), ("wildcard_grant", "missing-before")):
            assert table[(mode, injection, evidence_mode)]["oracle"]["label"] == "unresolved"


def test_stale_approval_no_longer_matches(gen):
    """[EV-GEN-02] `stale` keeps approved: true but points at the before version, so it is not approval."""
    entry = bases(gen)[("stale", "secrets_read", "complete")]
    approval = evidence(entry["case"], "get_approval_record")["data"]
    change = entry["case"]["event"]["change"]
    assert approval["approved"] is True and approval["after_version"] == change["before_version"]
    assert oracle.evaluate(entry["case"])["approved"] is False


def test_removal_and_pre_existing_injections_add_nothing(gen):
    """[EV-GEN-02] Removal empties the after rules; pre-existing grants appear in both versions."""
    table = bases(gen)
    removal = next(inj for inj in INJECTIONS if inj["kind"] == "removal")
    before, after = versions(table[("unapproved", removal["id"], "complete")]["case"])
    assert after["data"]["rules"] == [] and before["data"]["rules"]
    for inj in (i for i in INJECTIONS if i["kind"] == "pre-existing"):
        before, after = versions(table[("unapproved", inj["id"], "complete")]["case"])
        assert atom_set(after) <= atom_set(before)


def test_catalogue_drift_raises(monkeypatch):
    """[EV-GEN-03] An injection whose intended category the oracle does not produce is catalogue drift."""
    drifted = deepcopy(INJECTIONS)
    target = next(inj for inj in drifted if inj["category"] == "secrets_read")
    target["category"] = "token_request"
    monkeypatch.setattr(generate_module, "INJECTIONS", drifted)
    with pytest.raises(GeneratorError, match="catalogue"):
        generate()


def test_non_privileged_injection_that_grants_a_category_raises(monkeypatch):
    """[EV-GEN-03] A benign or near-miss injection that newly grants a category is catalogue drift."""
    drifted = deepcopy(INJECTIONS)
    target = next(inj for inj in drifted if inj["kind"] == "benign")
    target["after_add"] = [{"resources": ["secrets"], "verbs": ["get"]}]
    monkeypatch.setattr(generate_module, "INJECTIONS", drifted)
    with pytest.raises(GeneratorError, match="catalogue"):
        generate()


# ------------------------------------------------------------------ neutrality

def test_cases_carry_neutral_identifiers_and_no_label(gen):
    """[EV-GEN-04] Hash-derived ids; no seed identifier, label word or category id outside note text."""
    words = ("suspicious", "benign") + oracle.CATEGORY_IDS
    for entry in gen["entries"]:
        case = entry["case"]
        assert re.fullmatch(r"g-[0-9a-f]{12}", case["case_id"])
        assert case["description"] == "generated case"
        event = case["event"]
        assert re.fullmatch(r"evt-[0-9a-f]{12}", event["event_id"])
        assert re.fullmatch(r"chg-[0-9a-f]{12}", event["change"]["change_id"])
        assert re.fullmatch(r"serviceaccount:ns-[0-9a-f]{6}:sa-[0-9a-f]{6}", event["actor"]["subject_id"])
        assert re.fullmatch(r"role-[0-9a-f]{10}", event["resource"]["name"])
        text = canonical(without_notes({k: v for k, v in case.items() if k != "seed"}))
        for word in SEED_STRINGS + words:
            assert word not in text, (case["case_id"], word)


def test_rename_variant_uses_other_identifiers(gen):
    """[EV-GEN-04] [EV-GEN-05] The rename variant differs from its base only in the renamed identifiers."""
    for members in by_family(gen).values():
        base = next(e for e in members if e["variant"] == "base")["case"]
        rename = next(e for e in members if e["variant"] == "rename")["case"]
        old = [base["event"]["event_id"], base["event"]["change"]["change_id"],
               base["event"]["actor"]["subject_id"], base["event"]["resource"]["name"]]
        new = [rename["event"]["event_id"], rename["event"]["change"]["change_id"],
               rename["event"]["actor"]["subject_id"], rename["event"]["resource"]["name"]]
        assert all(a != b for a, b in zip(old, new))
        text = canonical({k: v for k, v in rename.items() if k != "case_id"})
        for a, b in zip(old, new):
            text = text.replace(b, a)
        assert text == canonical({k: v for k, v in base.items() if k != "case_id"})


def test_identifier_collision_raises(monkeypatch):
    """[EV-GEN-04] A new identifier equal to an existing string would merge two meanings; it raises."""
    monkeypatch.setattr(generate_module, "_neutral_ids", lambda *parts: {
        "event_id": "rbac_change", "change_id": "chg-x", "subject_id": "serviceaccount:a:b", "name": "role-x"})
    with pytest.raises(GeneratorError, match="collision"):
        generate()


# ------------------------------------------------------------------ variants

def test_variant_sets_per_family(gen):
    """[EV-GEN-05] Complete families have eight variants, missing-evidence families four."""
    for members in by_family(gen).values():
        variants = {e["variant"] for e in members}
        mode = members[0]["family_key"]["evidence_mode"]
        assert variants == (COMPLETE_VARIANTS if mode == "complete" else MISSING_VARIANTS)
        assert len(members) == len(variants)
        assert len({e["split"] for e in members}) == 1
        assert len({e["case"]["seed"] for e in members}) == 1
        assert {json.dumps(e["family_key"], sort_keys=True) for e in members} == {
            json.dumps(members[0]["family_key"], sort_keys=True)}


def test_seed_cluster_is_the_source_scenario(gen):
    """[EV-GEN-02] The case `seed` (cluster) is S01 for unapproved families and S02 otherwise."""
    for entry in gen["entries"]:
        expected = "S01" if entry["family_key"]["approval_mode"] == "unapproved" else "S02"
        assert entry["case"]["seed"] == expected


def test_reorder_changes_order_not_permissions(gen):
    """[EV-GEN-05] Reorder permutes rules, rule lists and evidence; the permission atoms are unchanged."""
    for members in by_family(gen).values():
        base = next(e for e in members if e["variant"] == "base")["case"]
        reorder = next(e for e in members if e["variant"] == "reorder")["case"]
        assert canonical(reorder["evidence"]) != canonical(base["evidence"])
        assert sorted(map(canonical, reorder["evidence"])) != sorted(map(canonical, base["evidence"])) or \
            all(len(item["data"].get("rules", [])) < 2 for item in base["evidence"] if item["tool"] == "get_rbac_object")
        for b, r in zip(versions(base), versions(reorder)):
            assert atom_set(b) == atom_set(r)


def test_split_rule_adds_one_rule_per_version_with_the_same_atoms(gen):
    """[EV-GEN-05] Split-rule turns one multi-verb (or multi-resource) rule into two equivalent rules."""
    for members in by_family(gen).values():
        if members[0]["family_key"]["evidence_mode"] != "complete":
            continue
        base = next(e for e in members if e["variant"] == "base")["case"]
        split = next(e for e in members if e["variant"] == "split-rule")["case"]
        for b, s in zip(versions(base), versions(split)):
            assert atom_set(b) == atom_set(s)
            if b["data"]["rules"]:
                assert len(s["data"]["rules"]) == len(b["data"]["rules"]) + 1


def test_monotonic_variant_only_adds_a_grant(gen):
    """[EV-GEN-05] [EV-GEN-07] Monotonic: after atoms grow, categories are a superset, label never turns benign."""
    rank = {"benign": 0, "suspicious": 1}
    for members in by_family(gen).values():
        if members[0]["family_key"]["evidence_mode"] != "complete":
            continue
        base = next(e for e in members if e["variant"] == "base")
        mono = next(e for e in members if e["variant"] == "monotonic")
        assert mono["relation"] == {"kind": "monotonic", "base_case_id": base["case"]["case_id"]}
        assert atom_set(versions(base["case"])[1]) < atom_set(versions(mono["case"])[1])
        assert set(base["oracle"]["categories"]) <= set(mono["oracle"]["categories"])
        assert rank[mono["oracle"]["label"]] >= rank[base["oracle"]["label"]]
        if base["family_key"]["approval_mode"] != "approved":
            assert mono["oracle"]["label"] == "suspicious"


def test_notes_are_consistent_and_do_not_change_the_label(gen):
    """[EV-GEN-06] Notes go to event attributes and the change-event evidence; claims-approval also comments."""
    for entry in gen["entries"]:
        if not entry["variant"].startswith("note-"):
            continue
        case, text = entry["case"], NOTES[entry["variant"]]
        assert case["event"]["attributes"]["note"] == text
        change = evidence(case, "get_change_event")
        assert change["data"]["attributes"]["note"] == text
        approval = evidence(case, "get_approval_record")
        if approval is not None:
            assert (approval["data"].get("comment") == text) == (entry["variant"] == "note-claims-approval")
        base = entry_of(gen, entry["relation"]["base_case_id"])
        assert entry["oracle"] == base["oracle"]


# ------------------------------------------------------------------ relations

def test_relations_point_at_the_family_base(gen):
    """[EV-GEN-07] base → base; structure and notes → invariant; monotonic → monotonic; same family."""
    kinds = {"base": "base", "monotonic": "monotonic"}
    for members in by_family(gen).values():
        base = next(e for e in members if e["variant"] == "base")
        for entry in members:
            kind = kinds.get(entry["variant"], "invariant")
            expected_base = None if kind == "base" else base["case"]["case_id"]
            assert entry["relation"] == {"kind": kind, "base_case_id": expected_base}
            if kind == "invariant":
                assert entry["oracle"] == base["oracle"]


def test_oracle_labels_satisfy_every_relation(gen):
    """[EV-GEN-07] [EV-GEN-08] The generator's own labels violate no relation."""
    labels = {e["case"]["case_id"]: e["oracle"]["label"] for e in gen["entries"]}
    assert relation_violations(gen["entries"], labels.__getitem__) == []


def test_relation_checker_reports_violations(gen):
    """[EV-GEN-08] A flipped invariant and a monotonic variant that turned benign are both reported."""
    labels = {e["case"]["case_id"]: e["oracle"]["label"] for e in gen["entries"]}
    table = bases(gen)
    family = by_family(gen)[table[("unapproved", "secrets_read", "complete")]["family"]]
    reorder = next(e for e in family if e["variant"] == "reorder")["case"]["case_id"]
    mono = next(e for e in family if e["variant"] == "monotonic")["case"]["case_id"]
    base = table[("unapproved", "secrets_read", "complete")]["case"]["case_id"]
    labels[reorder] = "benign"
    labels[mono] = "benign"
    found = relation_violations(gen["entries"], labels.__getitem__)
    assert found == sorted([
        {"case_id": reorder, "base_case_id": base, "relation": "invariant", "label": "benign", "base_label": "suspicious"},
        {"case_id": mono, "base_case_id": base, "relation": "monotonic", "label": "benign", "base_label": "suspicious"},
    ], key=lambda v: v["case_id"])


def test_monotonic_benign_to_benign_and_abstention_are_not_violations(gen):
    """[EV-GEN-08] Monotonic allows benign→benign and any move to unresolved; only a move to benign is wrong."""
    labels = {e["case"]["case_id"]: e["oracle"]["label"] for e in gen["entries"]}
    family = by_family(gen)[bases(gen)[("unapproved", "secrets_read", "complete")]["family"]]
    mono = next(e for e in family if e["variant"] == "monotonic")["case"]["case_id"]
    labels[mono] = "unresolved"
    assert relation_violations(family, labels.__getitem__) == []
    approved = by_family(gen)[bases(gen)[("approved", "configmaps-read", "complete")]["family"]]
    assert {e["oracle"]["label"] for e in approved} == {"benign"}
    assert relation_violations(approved, labels.__getitem__) == []


@pytest.mark.parametrize("label_of", [
    lambda case_id: None,
    lambda case_id: "maybe",
    lambda case_id: {}[case_id],
])
def test_relation_checker_fails_closed_on_missing_labels(gen, label_of):
    """[EV-GEN-08] An absent or unknown outcome raises instead of passing silently."""
    with pytest.raises(GeneratorError):
        relation_violations(gen["entries"], label_of)


def test_relation_checker_requires_the_base_in_the_given_entries(gen):
    """[EV-GEN-08] A relation whose base is not among the given entries cannot be checked; it raises."""
    labels = {e["case"]["case_id"]: e["oracle"]["label"] for e in gen["entries"]}
    without_bases = [e for e in gen["entries"] if e["variant"] != "base"]
    with pytest.raises(GeneratorError, match="base"):
        relation_violations(without_bases, labels.__getitem__)


@pytest.mark.parametrize(("status", "label"), [
    ("confirmed_suspicious", "suspicious"), ("likely_benign", "benign"), ("insufficient_evidence", "unresolved"),
    ("inconclusive", "unresolved"), ("investigation_failed", "unresolved"),
])
def test_label_of_status(status, label):
    """[EV-GEN-08] Runtime statuses map onto oracle labels."""
    assert label_of_status(status) == label


@pytest.mark.parametrize("status", ["", "benign", None, "COMPLETED"])
def test_label_of_status_rejects_unknown_values(status):
    """[EV-GEN-08] Anything that is not a runtime status raises."""
    with pytest.raises(GeneratorError):
        label_of_status(status)


# ------------------------------------------------------------------ split

def stratum(base):
    label, key = base["oracle"]["label"], base["family_key"]
    if label == "suspicious":
        return label, next(i["category"] for i in INJECTIONS if i["id"] == key["injection"])
    if label == "benign":
        return label, next(i["kind"] for i in INJECTIONS if i["id"] == key["injection"])
    return label, key["evidence_mode"]


def test_split_is_by_family_and_stratified_by_label_and_category(gen):
    """[EV-GEN-09] Variants share their family's split; each (label, category or kind) stratum has round(n*f)."""
    strata = defaultdict(list)
    for members in by_family(gen).values():
        base = next(e for e in members if e["variant"] == "base")
        strata[stratum(base)].append(base["split"])
    assert len(strata) == len(oracle.CATEGORY_IDS) + 5 + 2
    for key, splits in strata.items():
        n = len(splits)
        expected = round(n * 0.3)
        if n >= 2:
            expected = min(max(expected, 1), n - 1)
        assert splits.count("holdout") == expected, key
        assert splits.count("dev") == n - expected, key


def test_every_category_has_suspicious_families_in_both_splits(gen):
    """[EV-GEN-09] No escalation category is missing from dev or holdout, so per-category gaps show in both."""
    seen = defaultdict(set)
    for entry in gen["entries"]:
        if entry["variant"] == "base" and entry["oracle"]["label"] == "suspicious":
            seen[stratum(entry)[1]].add(entry["split"])
    assert seen == {category: {"dev", "holdout"} for category in oracle.CATEGORY_IDS}


def test_generator_version_names_the_split_rule():
    """[EV-GEN-09] The category-aware split is rbac-gen-2; the label-only split was rbac-gen-1."""
    assert GENERATOR_VERSION == "rbac-gen-2"


def test_holdout_fraction_changes_the_split_only(gen):
    """[EV-GEN-09] [EV-GEN-11] Another fraction moves families between splits; cases and labels are unchanged."""
    other = generate(holdout_fraction=0.5)
    assert [e["case"] for e in other["entries"]] == [e["case"] for e in gen["entries"]]
    assert [e["oracle"] for e in other["entries"]] == [e["oracle"] for e in gen["entries"]]
    assert other["summary"]["by_split"]["holdout"] > gen["summary"]["by_split"]["holdout"]


# ------------------------------------------------------------------ entries and runtime validity

def test_entries_are_valid_runtime_inputs(gen):
    """[EV-GEN-10] Each case is schema-valid for evals and for the runtime contracts and fixture limits."""
    for entry in gen["entries"]:
        assert set(entry) == ENTRY_KEYS
        case = entry["case"]
        assert set(case) == {"case_id", "seed", "description", "event", "policy", "evidence"}
        validate_case(case)
        validate("event", case["event"])
        validate("policy", case["policy"])
        assert len(case["evidence"]) <= 64
        assert all(len(canonical(item).encode()) <= 8192 for item in case["evidence"])
        assert entry["digest"] == case_digest(case)
        assert entry["transforms"][:3] == [f"inject:{entry['family_key']['injection']}",
                                           f"approval:{entry['family_key']['approval_mode']}",
                                           f"evidence:{entry['family_key']['evidence_mode']}"]


def test_case_ids_are_unique(gen):
    """[EV-GEN-10] Case ids are unique across the set."""
    ids = [e["case"]["case_id"] for e in gen["entries"]]
    assert len(ids) == len(set(ids))


def test_set_is_deterministic(gen):
    """[EV-GEN-11] Equal inputs give an equal set."""
    assert generate() == gen


def test_another_seed_changes_identifiers_not_labels(gen):
    """[EV-GEN-11] A different generator_seed renames everything but keeps each (family key, variant) label."""
    other = generate(generator_seed=7)
    key = lambda e: (json.dumps(e["family_key"], sort_keys=True), e["variant"])  # noqa: E731
    assert {key(e): e["oracle"] for e in other["entries"]} == {key(e): e["oracle"] for e in gen["entries"]}
    assert not {e["case"]["case_id"] for e in other["entries"]} & {e["case"]["case_id"] for e in gen["entries"]}


@pytest.mark.parametrize("mutate", [
    lambda s: s["entries"][0].update(extra=1),
    lambda s: s["entries"][0]["oracle"].update(label="maybe"),
    lambda s: s["entries"][0].update(split="test"),
    lambda s: s["summary"].update(extra=1),
    lambda s: s.update(generator_seed=-1),
])
def test_generated_schema_is_strict(gen, mutate):
    """[EV-GEN-11] The set schema is closed and typed."""
    broken = deepcopy(gen)
    mutate(broken)
    assert list(Draft202012Validator(SCHEMA, format_checker=FormatChecker()).iter_errors(broken))


def test_generator_imports_no_network_model_or_shell_module():
    """[EV-GEN-12] The generator stays an offline, label-free data tool."""
    text = (ROOT / "evals" / "generate.py").read_text(encoding="utf-8")
    for module in ("socket", "urllib", "http", "httpx", "subprocess", "anthropic", "random"):
        assert not re.search(rf"^\s*(import|from)\s+{module}\b", text, re.M), module


def test_generated_bases_run_through_the_runtime(gen, tmp_path):
    """[EV-GEN-12] Every family base runs unchanged through run_case in replay mode and reaches a terminal record."""
    results = []
    for entry in gen["entries"]:
        if entry["variant"] != "base":
            continue
        result = run_case(entry["case"], mode="replay", model=ReplayModel(),
                          output_dir=tmp_path / entry["case"]["case_id"])
        assert result["error"] is None and result["result"] is not None, entry["case"]["case_id"]
        assert result["oracle"]["label"] == entry["oracle"]["label"]
        results.append(result)
    report = build_report(results, repo_sha=SHA)
    assert report["summary"]["cases"] == len(by_family(gen))
    missing = [r for r in results if r["oracle"]["label"] == "unresolved"]
    assert missing and all(r["result"]["status"] == "insufficient_evidence" for r in missing)


def test_replay_outcomes_on_whole_families_obey_the_relations(gen, tmp_path):
    """[EV-GEN-08] [EV-GEN-12] Runtime labels feed relation_violations; the replay double is name- and order-blind."""
    table = bases(gen)
    families = by_family(gen)
    chosen = [families[table[key]["family"]] for key in (
        ("unapproved", "wildcard_grant", "complete"), ("approved", "bind_verb", "complete"),
        ("unapproved", "secrets_read", "missing-approval"))]
    labels = {}
    for members in chosen:
        for entry in members:
            result = run_case(entry["case"], mode="replay", model=ReplayModel(),
                              output_dir=tmp_path / entry["case"]["case_id"])
            labels[entry["case"]["case_id"]] = label_of_status(result["result"]["status"])
    entries = [e for members in chosen for e in members]
    assert relation_violations(entries, labels.__getitem__) == []
