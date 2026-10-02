"""Baselines, metrics and the evaluation harness (evals/SPEC.md, section 10; EV-ORC-16; EV-RUN-09).

Bracketed ids trace to requirement ids in evals/SPEC.md. Every provider here is
deterministic or scripted; the numbers describe the harness, not a real model.
"""
import ast
import asyncio
from copy import deepcopy
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

import httpx
import pytest
from jsonschema import Draft202012Validator, FormatChecker

from agenticdef.adapters.anthropic_model import AnthropicModel
from agenticdef.adapters.replay_model import ReplayModel

from evals import oracle
from evals.baselines import (BASELINE_PROVENANCES, AlwaysBenign, AlwaysSuspicious, AlwaysUnresolved,
                             DeterministicOracle)
from evals.cases import documented_f2_variants, scenario_case
from evals.generate import generate
from evals.harness import evaluate
from evals.generate import relation_violations
from evals.metrics import clustered_rate, pass_hat_k, summarize, wilson_interval
from evals.runner import EvalError, StepClock, execute_case, run_case
from test_anthropic_model import message

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"
SHA = "0123456789abcdef0123456789abcdef01234567"
SCHEMA = json.loads((ROOT / "evals" / "schemas" / "metrics.schema.json").read_text(encoding="utf-8"))
RATES = ("wrong_benign", "false_alarm", "abstention", "coverage", "selective_accuracy", "verdict_accuracy",
         "unresolved_kept", "adapter_or_format_failure", "policy_rejection", "grounding_failure", "run_error",
         "metamorphic_violation")


def scenario(name):
    return scenario_case(SCENARIOS / name)


def baseline_providers():
    return [
        {"name": "always-suspicious", "mode": "baseline", "factory": lambda case, trial: AlwaysSuspicious()},
        {"name": "always-benign", "mode": "baseline", "factory": lambda case, trial: AlwaysBenign()},
        {"name": "always-unresolved", "mode": "baseline", "factory": lambda case, trial: AlwaysUnresolved()},
        {"name": "deterministic", "mode": "baseline", "factory": lambda case, trial: DeterministicOracle()},
        {"name": "replay", "mode": "replay", "factory": lambda case, trial: ReplayModel()},
    ]


@pytest.fixture(scope="module")
def gen():
    return generate()


def family(gen, mode, injection, evidence="complete"):
    return next(e["family"] for e in gen["entries"] if e["variant"] == "base" and e["family_key"] == {
        "approval_mode": mode, "injection": injection, "evidence_mode": evidence})


@pytest.fixture(scope="module")
def three_families(gen):
    return [family(gen, "unapproved", "secrets_read"), family(gen, "approved", "bind_verb"),
            family(gen, "unapproved", "secrets_read", "missing-approval")]


@pytest.fixture(scope="module")
def report(gen, three_families, tmp_path_factory):
    out = tmp_path_factory.mktemp("metrics") / "out"
    return evaluate(gen, baseline_providers(), k=1, output_dir=out, repo_sha=SHA, families=three_families)


def split(report, name, which="all"):
    return next(p for p in report["providers"] if p["name"] == name)["splits"][which]


def rate(report, name, metric, which="all"):
    value = split(report, name, which)[metric]
    return value["k"], value["n"]


# ------------------------------------------------------------------ statistics

@pytest.mark.parametrize(("k", "n", "expected"), [
    (0, 10, [0.0, 0.277533]), (5, 10, [0.236593, 0.763407]), (10, 10, [0.722467, 1.0]),
])
def test_wilson_interval_reference_values(k, n, expected):
    """[EV-MET-01] Wilson score interval at 95% as a JSON-native [low, high] list, clamped and rounded."""
    assert wilson_interval(k, n) == expected


def test_wilson_interval_edges():
    """[EV-MET-01] n == 0 has no interval; impossible counts raise."""
    assert wilson_interval(0, 0) is None
    for k, n in ((11, 10), (-1, 10), (1, -2)):
        with pytest.raises(ValueError):
            wilson_interval(k, n)


def test_clustered_rate_perfectly_correlated_clusters():
    """[EV-MET-02] Four all-or-nothing clusters of five: deff = 20/3, n_eff = 3, CI = Wilson at n = 3."""
    pairs = [(f"c{j}", j < 2) for j in range(4) for _ in range(5)]
    result = clustered_rate(pairs)
    assert (result["k"], result["n"], result["clusters"], result["rate"]) == (10, 20, 4, 0.5)
    assert result["ci_naive"] == wilson_interval(10, 20)
    assert result["deff"] == round(20 / 3, 6)
    assert result["n_eff"] == 3.0
    assert result["ci"] == [0.125334, 0.874666]


def test_clustered_rate_singleton_clusters_have_deff_near_one():
    """[EV-MET-02] Independent singleton clusters: deff = m/(m-1) from the small-sample correction."""
    pairs = [(f"c{j}", j < 3) for j in range(10)]
    result = clustered_rate(pairs)
    assert result["rate"] == 0.3 and result["deff"] == round(10 / 9, 6)
    assert result["n_eff"] == 9.0


@pytest.mark.parametrize("pairs", [
    [("a", False)] * 5 + [("b", False)] * 5,
    [("a", True)] * 4 + [("b", True)] * 4,
    [("only", True), ("only", False), ("only", True)],
])
def test_clustered_rate_without_cluster_variance_uses_n(pairs):
    """[EV-MET-02] Rate 0 or 1, or a single cluster: deff is null and the CI is the naive Wilson interval."""
    result = clustered_rate(pairs)
    assert result["deff"] is None and result["n_eff"] == float(result["n"])
    assert result["ci"] == result["ci_naive"]


def test_clustered_rate_empty():
    """[EV-MET-02] No runs: counts are zero and every derived value is null."""
    assert clustered_rate([]) == {"k": 0, "n": 0, "clusters": 0, "rate": None, "ci_naive": None, "deff": None,
                                  "n_eff": None, "ci": None}


@pytest.mark.parametrize(("trials", "k", "expected"), [
    ({"a": [True, True, True, False]}, 2, 0.5),
    ({"a": [True, True], "b": [True, False]}, 1, 0.75),
    ({"a": [True, True], "b": [True, False]}, 2, 0.5),
    ({"a": [False, False, False]}, 1, 0.0),
])
def test_pass_hat_k_exact_values(trials, k, expected):
    """[EV-MET-03] Mean over cases of C(c, k) / C(n, k)."""
    assert pass_hat_k(trials, k) == expected


def test_pass_hat_k_rejects_bad_input():
    """[EV-MET-03] k must be a positive integer not above any case's trial count; no cases gives None."""
    assert pass_hat_k({}, 1) is None
    for trials, k in (({"a": [True]}, 2), ({"a": [True]}, 0), ({"a": [True]}, True), ({"a": [True]}, 1.0)):
        with pytest.raises(ValueError):
            pass_hat_k(trials, k)


def _uniform(*parts):
    return int(sha256(json.dumps(parts).encode()).hexdigest()[:13], 16) / 16 ** 13


def test_pass_hat_k_matches_q_to_the_k_on_seeded_bernoulli_trials():
    """[EV-MET-03] On seeded i.i.d. trials with success q, pass^k estimates q^k (4000 tasks, 6 trials)."""
    q = 0.8
    trials = {f"t{i}": [_uniform("bernoulli", i, j) < q for j in range(6)] for i in range(4000)}
    for k in (1, 2, 3):
        assert abs(pass_hat_k(trials, k) - q ** k) < 0.02


# ------------------------------------------------------------------ oracle helpers and the step clock

def test_required_reads_lists_the_five_reads():
    """[EV-ORC-16] The five reads of EV-ORC-04, in order, as (tool, arguments) pairs."""
    event = scenario("S01")["event"]
    assert oracle.required_reads(event) == [
        ("get_change_event", {"event_id": "evt-S01"}),
        ("get_rbac_object", {"kind": "ClusterRole", "namespace": "", "name": "release-operator", "version": "1"}),
        ("get_rbac_object", {"kind": "ClusterRole", "namespace": "", "name": "release-operator", "version": "2"}),
        ("get_subject_bindings", {"subject_id": "serviceaccount:ops:deployer"}),
        ("get_approval_record", {"change_id": "chg-S01"}),
    ]


def test_judge_equals_evaluate_without_the_policy():
    """[EV-ORC-16] judge(event, evidence) gives evaluate's output and needs no policy; inputs are not mutated."""
    cases = [scenario(name) for name in ("S01", "S02", "S03", "S05")]
    cases += documented_f2_variants(scenario("S01"))
    for case in cases:
        frozen = deepcopy(case)
        assert oracle.judge(case["event"], case["evidence"]) == oracle.evaluate(case)
        assert case == frozen
    unscoped = scenario("S01")
    unscoped["policy"]["resource_scope"]["change_ids"] = []
    with pytest.raises(oracle.OracleError):
        oracle.evaluate(unscoped)
    assert oracle.judge(unscoped["event"], unscoped["evidence"])["label"] == "suspicious"


def test_step_clock_is_deterministic():
    """[EV-RUN-09] Each monotonic() read advances by the step; utcnow() is a parseable, advancing timestamp."""
    clock = StepClock()
    first, second = clock.monotonic(), clock.monotonic()
    assert second - first == pytest.approx(clock.step)
    t1, t2 = clock.utcnow(), clock.utcnow()
    assert datetime.fromisoformat(t2) > datetime.fromisoformat(t1)
    again = StepClock()
    assert [again.monotonic(), again.monotonic(), again.utcnow()] == [first, second, t1]


def test_step_clock_makes_records_reproducible(tmp_path):
    """[EV-RUN-09] Two runs of one case with a StepClock persist identical records, timestamps included."""
    records = []
    for tag in ("a", "b"):
        entry, record = execute_case(scenario("S01"), mode="replay", model=ReplayModel(),
                                     output_dir=tmp_path / tag, clock=StepClock())
        assert entry["passed"]
        records.append(record)
    assert records[0] == records[1]
    assert records[0]["result"]["budget_usage"]["runtime_seconds"] > 0


def test_execute_case_returns_the_persisted_record(tmp_path):
    """[EV-RUN-09] execute_case is run_case plus the record the repository persisted."""
    entry, record = execute_case(scenario("S02"), mode="replay", model=ReplayModel(), output_dir=tmp_path / "x")
    persisted = json.loads(next((tmp_path / "x" / "s02").glob("inv-*/record.json")).read_text(encoding="utf-8"))
    assert record == persisted and entry["result"]["status"] == record["result"]["status"]


# ------------------------------------------------------------------ baselines

@pytest.mark.parametrize(("model", "name", "status"), [
    (AlwaysSuspicious, "S02", "confirmed_suspicious"),
    (AlwaysBenign, "S01", "likely_benign"),
    (AlwaysUnresolved, "S01", "inconclusive"),
    (DeterministicOracle, "S01", "confirmed_suspicious"),
    (DeterministicOracle, "S02", "likely_benign"),
    (DeterministicOracle, "S03", "insufficient_evidence"),
])
def test_baselines_run_through_the_runtime(tmp_path, model, name, status):
    """[EV-BASE-01] [EV-RUN-01] [EV-RUN-05] Baselines are model ports with fixed verdict policies in baseline mode."""
    entry, record = execute_case(scenario(name), mode="baseline", model=model(), output_dir=tmp_path / "x")
    assert record["result"]["status"] == status
    assert record["metadata"]["model_provider"] == model.provenance
    if model is AlwaysUnresolved:
        assert record["result"]["budget_usage"]["tool_calls"] == 0
        assert record["result"]["termination_reason"] == "model_finished"


def test_deterministic_baseline_catches_what_the_replay_double_misses(tmp_path):
    """[EV-BASE-01] On the four F2 variants the deterministic baseline agrees with the oracle; replay does not."""
    for case in documented_f2_variants(scenario("S01")):
        entry = run_case(case, mode="baseline", model=DeterministicOracle(), output_dir=tmp_path / case["case_id"])
        assert entry["passed"] and entry["result"]["status"] == "confirmed_suspicious"


def test_baseline_provenances_are_fixed_and_distinct():
    """[EV-BASE-01] Each baseline has one fixed provenance and the set lists exactly them."""
    models = (AlwaysSuspicious, AlwaysBenign, AlwaysUnresolved, DeterministicOracle)
    assert set(BASELINE_PROVENANCES) == {m.provenance for m in models} and len(BASELINE_PROVENANCES) == 4
    assert all(p.startswith("baseline_") for p in BASELINE_PROVENANCES)


class RecordingContext(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.read = set()

    def __getitem__(self, key):
        self.read.add(key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        self.read.add(key)
        return super().get(key, default)


@pytest.mark.parametrize("model", [AlwaysSuspicious, AlwaysBenign, AlwaysUnresolved, DeterministicOracle])
def test_baselines_read_only_the_investigation_context(model):
    """[EV-BASE-02] A baseline touches only the event, evidence and missing-evidence copies the runtime passes."""
    case = scenario("S01")
    evidence = [{"evidence": {"evidence_id": "ev-" + "a" * 63 + str(i)},
                 "untrusted_data": {"source": "synthetic-fixture", **item}} for i, item in enumerate(case["evidence"])]
    context = RecordingContext(event=case["event"], evidence=evidence, missing_evidence=[])
    action = asyncio.run(model().choose_action(context, tuple(oracle.REQUIRED_TOOLS)))
    assert action["type"] in {"finish", "tool_request"}
    draft = asyncio.run(model().produce_result(context))
    assert draft["status"] in {"confirmed_suspicious", "likely_benign", "inconclusive"}
    assert context.read <= {"event", "evidence", "missing_evidence"}


def test_modes_and_provenances_must_match(tmp_path):
    """[EV-RUN-05] baseline mode refuses the replay double; replay mode refuses a baseline."""
    with pytest.raises(EvalError, match="provenance"):
        run_case(scenario("S01"), mode="baseline", model=ReplayModel(), output_dir=tmp_path / "a")
    with pytest.raises(EvalError, match="provenance"):
        run_case(scenario("S01"), mode="replay", model=DeterministicOracle(), output_dir=tmp_path / "b")


# ------------------------------------------------------------------ the harness and its report

def test_report_is_schema_valid_and_sorted(report, gen, three_families):
    """[EV-MET-07] Schema-valid, providers sorted, set digest over the evaluated case digests."""
    assert not list(Draft202012Validator(SCHEMA, format_checker=FormatChecker()).iter_errors(report))
    assert [p["name"] for p in report["providers"]] == sorted(p["name"] for p in baseline_providers())
    entries = [e for e in gen["entries"] if e["family"] in three_families]
    expected_digest = "sha256:" + sha256("\n".join(sorted(e["digest"] for e in entries)).encode()).hexdigest()
    assert report["set_digest"] == expected_digest
    assert (report["families"], report["cases"], report["k"], report["clock"]) == (3, 20, 1, "step")
    assert (report["metrics_version"], report["repo_sha"]) == ("1", SHA)
    assert report["generator_version"] == gen["generator_version"]
    assert report["oracle_version"] == oracle.ORACLE_VERSION


def test_trivial_baselines_anchor_the_safety_metrics(report):
    """[EV-MET-05] always-benign misses every escalation; always-suspicious alarms on every benign change."""
    assert rate(report, "always-benign", "wrong_benign") == (8, 8)
    assert rate(report, "always-benign", "false_alarm") == (0, 8)
    assert rate(report, "always-suspicious", "wrong_benign") == (0, 8)
    assert rate(report, "always-suspicious", "false_alarm") == (8, 8)
    for name in ("always-benign", "always-suspicious"):
        assert rate(report, name, "verdict_accuracy") == (12, 20)
        assert rate(report, name, "selective_accuracy") == (8, 16)
        assert rate(report, name, "unresolved_kept") == (4, 4)


def test_always_unresolved_has_no_coverage(report):
    """[EV-MET-05] Abstaining everywhere scores zero wrong-benign and zero coverage; both must be read together."""
    assert rate(report, "always-unresolved", "wrong_benign") == (0, 8)
    assert rate(report, "always-unresolved", "abstention") == (16, 16)
    assert rate(report, "always-unresolved", "coverage") == (0, 16)
    assert split(report, "always-unresolved", "all")["selective_accuracy"]["rate"] is None
    usage = split(report, "always-unresolved", "all")["usage"]
    assert usage["tool_calls"] == {"mean": 0.0, "max": 0}


def test_deterministic_baseline_is_the_ceiling(report):
    """[EV-MET-05] [EV-BASE-01] The fixed-reads deterministic baseline matches every oracle label by construction."""
    assert rate(report, "deterministic", "verdict_accuracy") == (20, 20)
    assert rate(report, "deterministic", "wrong_benign") == (0, 8)
    assert rate(report, "deterministic", "false_alarm") == (0, 8)
    assert split(report, "deterministic", "all")["pass_hat_k"] == {"k": 1, "value": 1.0, "cases": 20}
    usage = split(report, "deterministic", "all")["usage"]
    assert usage["tool_calls"]["max"] == 5 and usage["model_calls"]["max"] == 7


def test_replay_double_misses_the_secrets_family(report):
    """[EV-MET-05] The replay double calls every unapproved secrets_read case benign, consistently."""
    assert rate(report, "replay", "wrong_benign") == (8, 8)
    assert rate(report, "replay", "false_alarm") == (0, 8)
    assert rate(report, "replay", "metamorphic_violation") == (0, 17)


def test_no_baseline_violates_a_relation_and_none_fails_to_run(report):
    """[EV-MET-05] Deterministic providers are consistent; no run errors, no format or policy failures."""
    for provider in report["providers"]:
        stats = provider["splits"]["all"]
        assert (stats["metamorphic_violation"]["k"], stats["metamorphic_violation"]["n"]) == (0, 17)
        for metric in ("run_error", "adapter_or_format_failure", "policy_rejection", "grounding_failure"):
            assert stats[metric]["k"] == 0, (provider["name"], metric)


def test_splits_partition_the_runs(report, gen, three_families):
    """[EV-MET-05] dev and holdout hold exactly their families' runs and partition `all`."""
    members = [e for e in gen["entries"] if e["family"] in three_families]
    expected = {name: (sum(e["split"] == name for e in members), len({e["family"] for e in members if e["split"] == name}))
                for name in ("dev", "holdout")}
    for provider in report["providers"]:
        splits = provider["splits"]
        for name in ("dev", "holdout"):
            assert (splits[name]["cases"], splits[name]["families"]) == expected[name], (provider["name"], name)
        assert splits["dev"]["cases"] + splits["holdout"]["cases"] == splits["all"]["cases"] == 20
        assert splits["dev"]["families"] + splits["holdout"]["families"] == splits["all"]["families"] == 3
        for metric in RATES:
            assert splits["dev"][metric]["n"] + splits["holdout"][metric]["n"] == splits["all"][metric]["n"]


def test_termination_reasons_are_counted(report):
    """[EV-MET-05] The histogram counts every run once."""
    reasons = split(report, "always-suspicious", "all")["termination_reasons"]
    assert reasons == {"model_finished": 16, "ToolExecutionError": 4}


def test_reports_are_reproducible_with_the_step_clock(gen, tmp_path):
    """[EV-MET-07] [EV-RUN-09] Equal inputs give an equal report."""
    chosen = [family(gen, "stale", "token_request")]
    providers = baseline_providers()[3:]
    first = evaluate(gen, providers, k=1, output_dir=tmp_path / "a", repo_sha=SHA, families=chosen)
    second = evaluate(gen, providers, k=1, output_dir=tmp_path / "b", repo_sha=SHA, families=chosen)
    assert first == second


@pytest.mark.parametrize(("change", "match"), [
    ({"k": 0}, "k"), ({"k": True}, "k"), ({"k": "1"}, "k"),
    ({"providers": []}, "provider"),
    ({"providers": baseline_providers()[:1] * 2}, "unique"),
    ({"providers": [{"name": "Bad Name", "mode": "baseline", "factory": lambda c, t: AlwaysBenign()}]}, "name"),
    ({"providers": [{"name": "x", "mode": "live", "factory": lambda c, t: AlwaysBenign()}]}, "mode"),
    ({"providers": [{"name": "x", "mode": "baseline", "factory": None}]}, "factory"),
    ({"providers": [{"name": "x", "mode": "baseline"}]}, "provider"),
    ({"families": []}, "famil"), ({"families": ["f-0000000000"]}, "famil"),
    ({"clock": "wall"}, "clock"), ({"repo_sha": "abc"}, "repo_sha"),
    ({"clock": ["step"]}, "clock"), ({"families": [["x"]]}, "famil"), ({"output_dir": None}, "output_dir"),
    ({"providers": [{"name": "x", "mode": ["baseline"], "factory": lambda c, t: AlwaysBenign()}]}, "mode"),
])
def test_evaluate_rejects_bad_requests(gen, three_families, tmp_path, change, match):
    """[EV-MET-06] Invalid k, providers, families, clock, output_dir or sha raise EvalError before any run, even
    when the value is of a type the check cannot hash or open."""
    kwargs = {"providers": baseline_providers()[:1], "k": 1, "output_dir": tmp_path / "out", "repo_sha": SHA,
              "families": three_families[:1], "clock": "step", **change}
    with pytest.raises(EvalError, match=match):
        evaluate(gen, **kwargs)
    assert not (tmp_path / "out").exists()


def test_evaluate_refuses_an_existing_output_dir(gen, three_families, tmp_path):
    """[EV-MET-06] A used output directory would mix cached records into a new evaluation."""
    (tmp_path / "out").mkdir()
    with pytest.raises(EvalError, match="output_dir"):
        evaluate(gen, baseline_providers()[:1], k=1, output_dir=tmp_path / "out", repo_sha=SHA,
                 families=three_families[:1])


def test_a_fail_closed_run_is_counted_not_crashed(gen, tmp_path, monkeypatch):
    """[EV-MET-04] [EV-MET-05] A run that grades fail-closed is outcome `error`: a run error, an abstention, and
    `unresolved` for relation checks, so its family's invariant variants show as violations."""
    from agenticdef.adapters.fixture_tools import FixtureTools
    from evals import harness
    from evals.runner import grade_case

    chosen = [family(gen, "unapproved", "secrets_read")]
    base_id = next(e["case"]["case_id"] for e in gen["entries"] if e["family"] in chosen and e["variant"] == "base")
    real = harness.execute_case

    def damaged(case, **kwargs):
        entry, record = real(case, **kwargs)
        if case["case_id"] == base_id:
            entry = grade_case(case, mode=kwargs["mode"], record=None, tools=FixtureTools(case["evidence"]),
                               provenance=entry["provenance"])
        return entry, record

    monkeypatch.setattr(harness, "execute_case", damaged)
    out = evaluate(gen, baseline_providers()[:1], k=1, output_dir=tmp_path / "out", repo_sha=SHA, families=chosen)
    stats = out["providers"][0]["splits"]["all"]
    assert (stats["run_error"]["k"], stats["abstention"]["k"], stats["wrong_benign"]["k"]) == (1, 1, 0)
    assert stats["termination_reasons"]["none"] == 1
    assert (stats["metamorphic_violation"]["k"], stats["metamorphic_violation"]["n"]) == (6, 7)


@pytest.mark.parametrize("tamper", [
    lambda s, fam: s.update(oracle_version="rbac-oracle-0"),
    lambda s, fam: next(e for e in s["entries"] if e["family"] == fam)["oracle"].update(label="benign"),
    lambda s, fam: next(e for e in s["entries"] if e["family"] == fam)["oracle"].update(categories=[]),
])
def test_stale_or_edited_sets_are_rejected_before_any_run(gen, tmp_path, tamper):
    """[EV-MET-09] A set whose oracle version or stored oracle output disagrees with the oracle now never runs."""
    chosen = family(gen, "unapproved", "secrets_read")
    edited = deepcopy(gen)
    tamper(edited, chosen)
    with pytest.raises(EvalError, match="oracle"):
        evaluate(edited, baseline_providers()[:1], k=1, output_dir=tmp_path / "out", repo_sha=SHA, families=[chosen])
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("tamper, cause", [
    (lambda case: next(e for e in case["evidence"] if e["tool"] == "get_approval_record")["data"].pop("approved"),
     "approval data missing"),
    (lambda case: case.update(extra=1), "additionalProperties"),
])
def test_uninterpretable_edited_cases_raise_eval_error_before_any_run(gen, tmp_path, tamper, cause):
    """[EV-MET-09] An edited case the oracle or the case schema rejects fails the pre-run check with EvalError,
    even when it is not the family's first case."""
    chosen = family(gen, "approved", "bind_verb")
    edited = deepcopy(gen)
    tamper([e for e in edited["entries"] if e["family"] == chosen][-1]["case"])
    with pytest.raises(EvalError, match=cause):
        evaluate(edited, baseline_providers()[:1], k=1, output_dir=tmp_path / "out", repo_sha=SHA, families=[chosen])
    assert not (tmp_path / "out").exists()


def test_edited_cases_whose_digest_no_longer_matches_are_rejected_before_any_run(gen, tmp_path):
    """[EV-MET-09] An edit that keeps the case valid and its oracle output unchanged still changes what runs, so a
    stored digest that no longer matches the case fails the pre-run check; set_digest never names another set."""
    chosen = family(gen, "approved", "bind_verb")
    edited = deepcopy(gen)
    case = [e for e in edited["entries"] if e["family"] == chosen][-1]["case"]
    case["policy"]["max_tool_calls"] -= 1
    assert oracle.evaluate(case)["label"] == oracle.evaluate(
        [e for e in gen["entries"] if e["case"]["case_id"] == case["case_id"]][0]["case"])["label"]
    with pytest.raises(EvalError, match="digest"):
        evaluate(edited, baseline_providers()[:1], k=1, output_dir=tmp_path / "out", repo_sha=SHA, families=[chosen])
    assert not (tmp_path / "out").exists()


def _without(mapping, key):
    mapping = deepcopy(mapping)
    del mapping[key]
    return mapping


@pytest.mark.parametrize("malformed", [
    lambda s: [],
    lambda s: _without(s, "entries"),
    lambda s: {**s, "entries": [_without(s["entries"][0], "family"), *s["entries"][1:]]},
    lambda s: {**s, "entries": ["not an entry", *s["entries"][1:]]},
])
def test_malformed_sets_raise_eval_error_before_any_field_is_read(gen, tmp_path, malformed):
    """[EV-MET-09] A set that is not shaped like generated.schema.json raises EvalError, not KeyError, TypeError
    or AttributeError."""
    with pytest.raises(EvalError, match="schema"):
        evaluate(malformed(gen), baseline_providers()[:1], k=1, output_dir=tmp_path / "out", repo_sha=SHA)
    assert not (tmp_path / "out").exists()


def _family_entries(generated_set, family_id):
    return [e for e in generated_set["entries"] if e["family"] == family_id]


@pytest.mark.parametrize("tamper", [
    lambda s, fam: [e.update(split="holdout" if e["split"] == "dev" else "dev") for e in _family_entries(s, fam)],
    lambda s, fam: _family_entries(s, fam)[-1]["relation"].update(
        kind="monotonic" if _family_entries(s, fam)[-1]["relation"]["kind"] == "invariant" else "invariant"),
    lambda s, fam: _family_entries(s, fam)[-1].update(
        family=next(e["family"] for e in s["entries"] if e["family"] != fam)),
    lambda s, fam: _family_entries(s, fam)[-1]["transforms"].append("edited"),
])
def test_edited_entry_metadata_is_rejected_before_any_run(gen, tmp_path, tamper):
    """[EV-MET-09] split, relation, family and other entry fields feed the metrics, so the whole set must equal
    what generate() produces from its recorded parameters; an edit to any of them never runs."""
    chosen = family(gen, "approved", "bind_verb")
    edited = deepcopy(gen)
    tamper(edited, chosen)
    with pytest.raises(EvalError, match="generate"):
        evaluate(edited, baseline_providers()[:1], k=1, output_dir=tmp_path / "out", repo_sha=SHA, families=[chosen])
    assert not (tmp_path / "out").exists()


def test_a_set_saved_as_json_and_reloaded_still_runs(gen, tmp_path):
    """[EV-MET-09] The reproducibility check compares values, so a set round-tripped through JSON is accepted."""
    reloaded = json.loads(json.dumps(gen))
    out = evaluate(reloaded, baseline_providers()[3:4], k=1, output_dir=tmp_path / "out", repo_sha=SHA,
                   families=[family(gen, "approved", "bind_verb")])
    assert out["providers"][0]["splits"]["all"]["verdict_accuracy"]["rate"] == 1.0


def test_factories_get_their_own_copy_of_the_case(gen, tmp_path):
    """[EV-MET-06] A factory that mutates the case it is given cannot change the case that runs."""
    def factory(case, trial):
        case["policy"]["max_tool_calls"] = 1
        return DeterministicOracle()

    out = evaluate(gen, [{"name": "mutating", "mode": "baseline", "factory": factory}], k=1,
                   output_dir=tmp_path / "out", repo_sha=SHA, families=[family(gen, "approved", "bind_verb")])
    stats = out["providers"][0]["splits"]["all"]
    assert stats["verdict_accuracy"]["k"] == stats["verdict_accuracy"]["n"]
    assert set(stats["termination_reasons"]) == {"model_finished"}


def test_factories_cannot_change_the_checked_set_or_providers(gen, tmp_path):
    """[EV-MET-06] A factory that closes over the caller's set or provider list cannot change the report's
    provenance or move another provider's records outside output_dir: evaluate works on private snapshots."""
    original = deepcopy(gen)
    providers = [{"name": "a", "mode": "baseline", "factory": None},
                 {"name": "b", "mode": "baseline", "factory": lambda case, trial: DeterministicOracle()}]

    def meddling(case, trial):
        original.update(generator_seed=7, generator_version="rbac-gen-edited")
        providers[1]["name"] = "../escaped"
        return DeterministicOracle()

    providers[0]["factory"] = meddling
    out = evaluate(original, providers, k=1, output_dir=tmp_path / "out", repo_sha=SHA,
                   families=[family(gen, "approved", "bind_verb")])
    assert (out["generator_seed"], out["generator_version"]) == (gen["generator_seed"], gen["generator_version"])
    assert [p["name"] for p in out["providers"]] == ["a", "b"]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["out"]
    assert sorted(path.name for path in (tmp_path / "out").iterdir()) == ["a", "b"]


def test_a_factory_that_changes_directory_cannot_move_the_records(gen, tmp_path, monkeypatch):
    """[EV-MET-06] A relative output_dir is anchored when it is snapshotted, so os.chdir in a factory does not
    change where records are written."""
    (tmp_path / "home").mkdir()
    (tmp_path / "elsewhere").mkdir()
    monkeypatch.chdir(tmp_path / "home")

    def wandering(case, trial):
        os.chdir(tmp_path / "elsewhere")
        return DeterministicOracle()

    evaluate(gen, [{"name": "w", "mode": "baseline", "factory": wandering}], k=1, output_dir="out", repo_sha=SHA,
             families=[family(gen, "approved", "bind_verb")])
    assert sorted(path.name for path in (tmp_path / "home" / "out" / "w" / "t0").iterdir())
    assert list((tmp_path / "elsewhere").iterdir()) == []


@pytest.mark.parametrize("poison", [object(), float("nan")])
def test_a_set_that_is_not_json_raises_eval_error(gen, tmp_path, poison):
    """[EV-MET-06] The set snapshot is a JSON round trip, so a value JSON cannot hold raises EvalError."""
    entry = deepcopy(gen["entries"][0])
    entry["case"]["description"] = poison
    with pytest.raises(EvalError, match="JSON"):
        evaluate({**gen, "entries": [entry, *gen["entries"][1:]]}, baseline_providers()[:1], k=1,
                 output_dir=tmp_path / "out", repo_sha=SHA)
    assert not (tmp_path / "out").exists()


def test_a_run_whose_case_differs_from_its_stored_digest_raises(gen, tmp_path, monkeypatch):
    """[EV-MET-09] If the case that was graded no longer matches the stored digest, the harness raises instead of
    reporting a set_digest that names another set."""
    from evals import harness

    real = harness.execute_case

    def mutated(case, **kwargs):
        case["policy"]["max_runtime_seconds"] += 1
        return real(case, **kwargs)

    monkeypatch.setattr(harness, "execute_case", mutated)
    with pytest.raises(EvalError, match="digest"):
        evaluate(gen, baseline_providers()[3:4], k=1, output_dir=tmp_path / "out", repo_sha=SHA,
                 families=[family(gen, "approved", "bind_verb")])


def test_runs_are_scored_against_the_oracle_they_computed(gen, tmp_path, monkeypatch):
    """[EV-MET-09] If a run's own oracle result differed from the stored label, the harness raises instead of
    scoring against the stored one."""
    from evals import harness

    chosen = [family(gen, "approved", "bind_verb")]
    real = harness.execute_case

    def drifted(case, **kwargs):
        entry, record = real(case, **kwargs)
        entry = deepcopy(entry)
        entry["oracle"]["label"] = "suspicious"
        return entry, record

    monkeypatch.setattr(harness, "execute_case", drifted)
    with pytest.raises(EvalError, match="oracle"):
        evaluate(gen, baseline_providers()[:1], k=1, output_dir=tmp_path / "out", repo_sha=SHA, families=chosen)


# ------------------------------------------------------------------ seeded stochastic mock over HTTP

class StochasticProvider:
    """Seeded mock provider: the five reads, then a malformed reply with probability f, else a verdict that is
    correct with probability q. Every decision is logged so the test can recompute the metrics."""

    def __init__(self, case, label, trial, q, f, log):
        self.actions = [{"type": "tool_request", "tool": t, "arguments": a}
                        for t, a in oracle.required_reads(case["event"])] + [{"type": "finish"}]
        self.case_id, self.label, self.trial, self.q, self.f, self.log = case["case_id"], label, trial, q, f, log

    def __call__(self, request):
        envelope = json.loads(json.loads(request.content)["messages"][0]["content"])
        evidence = envelope["untrusted_investigation_data"]["evidence"]
        if envelope["task"] == "choose_action":
            return httpx.Response(200, json=message(self.actions[len(evidence)]))
        u = _uniform("stochastic", self.case_id, self.trial)
        if u < self.f:
            self.log[(self.case_id, self.trial)] = "malformed"
            return httpx.Response(200, json={"type": "message", "stop_reason": "end_turn",
                                             "content": [{"type": "text", "text": "not json"}]})
        correct = u < self.f + (1 - self.f) * self.q
        verdict = self.label if correct else {"suspicious": "benign", "benign": "suspicious"}[self.label]
        self.log[(self.case_id, self.trial)] = "correct" if correct else "wrong"
        status, risk = {"suspicious": ("confirmed_suspicious", "high"), "benign": ("likely_benign", "low")}[verdict]
        return httpx.Response(200, json=message(dict(
            status=status, risk=risk, summary="Seeded mock verdict",
            findings=[dict(claim="Seeded mock claim", evidence_ids=[e["evidence"]["evidence_id"] for e in evidence])],
            missing_evidence=[], recommended_next_actions=["Human review"])))


def test_seeded_stochastic_mock_validates_pass_hat_k_and_failure_counts(gen, tmp_path):
    """[EV-MET-03] [EV-MET-04] [EV-MET-05] Over HTTP, the report's pass^k and failure counts match the seeded log."""
    chosen = [family(gen, "unapproved", "secrets_read"), family(gen, "approved", "bind_verb")]
    labels = {e["case"]["case_id"]: e["oracle"]["label"] for e in gen["entries"] if e["family"] in chosen}
    log = {}

    def factory(case, trial):
        provider = StochasticProvider(case, labels[case["case_id"]], trial, q=0.7, f=0.15, log=log)
        return AnthropicModel(model="operator-selected-model", api_key="test-placeholder",
                              transport=httpx.MockTransport(provider))

    k = 3
    out = evaluate(gen, [{"name": "stochastic", "mode": "mock", "factory": factory}], k=k,
                   output_dir=tmp_path / "out", repo_sha=SHA, families=chosen)
    stats = out["providers"][0]["splits"]["all"]
    assert len(log) == len(labels) * k
    successes = {case_id: [log[(case_id, t)] == "correct" for t in range(k)] for case_id in labels}
    assert stats["pass_hat_k"] == {"k": k, "value": round(pass_hat_k(successes, k), 6), "cases": len(labels)}
    malformed = sum(v == "malformed" for v in log.values())
    assert 0 < malformed < len(log)
    assert (stats["adapter_or_format_failure"]["k"], stats["adapter_or_format_failure"]["n"]) == (malformed, len(log))
    assert stats["termination_reasons"].get("ModelError", 0) == malformed
    assert stats["verdict_accuracy"]["k"] == sum(v == "correct" for v in log.values())
    wrong_benign = sum(v == "wrong" for (case_id, _), v in log.items() if labels[case_id] == "suspicious")
    assert stats["wrong_benign"]["k"] == wrong_benign
    assert out["providers"][0]["model_provider"] == "anthropic_api" and out["providers"][0]["mode"] == "mock"
    entries = [e for e in gen["entries"] if e["family"] in chosen]
    flip = {"suspicious": "benign", "benign": "suspicious"}
    expected_violations = 0
    for trial in range(k):
        outcome = {case_id: {"correct": labels[case_id], "wrong": flip[labels[case_id]], "malformed": "unresolved"}[
            log[(case_id, trial)]] for case_id in labels}
        expected_violations += len(relation_violations(entries, outcome.__getitem__))
    assert expected_violations > 0
    assert stats["metamorphic_violation"]["k"] == expected_violations
    assert stats["metamorphic_violation"]["n"] == k * sum(e["relation"]["kind"] != "base" for e in entries)


# ------------------------------------------------------------------ summarize on synthetic observations

def _obs(case_id, family, label, outcome, reason, trial=0, kind="base"):
    return {"case_id": case_id, "family": family, "oracle_label": label, "outcome": outcome, "trial": trial,
            "termination_reason": reason, "relation_kind": kind,
            "usage": {"model_calls": 1, "tool_calls": 0, "evidence_items": 0, "runtime_seconds": 0.5}}


def test_summarize_counts_errors_failures_and_per_trial_violations():
    """[EV-MET-04] [EV-MET-05] Errors abstain and count as run errors; failure kinds and violations are counted per run."""
    observations = [
        _obs("a", "f1", "suspicious", "error", None),
        _obs("b", "f1", "suspicious", "unresolved", "ContractError", kind="invariant"),
        _obs("c", "f2", "benign", "unresolved", "ModelError"),
        _obs("d", "f2", "benign", "unresolved", "ScopeError", kind="monotonic"),
        _obs("e", "f3", "benign", "unresolved", "PolicyError"),
        _obs("f", "f3", "suspicious", "unresolved", "GroundingError"),
        _obs("g", "f4", "unresolved", "unresolved", "ToolNotAllowedError"),
        _obs("b", "f1", "suspicious", "suspicious", "model_finished", trial=1, kind="invariant"),
    ]
    stats = summarize(observations, {("b", 0), ("d", 0)}, 1)
    count = lambda metric: (stats[metric]["k"], stats[metric]["n"])  # noqa: E731
    assert count("abstention") == (6, 7) and count("coverage") == (1, 7)
    assert count("run_error") == (1, 8)
    assert count("adapter_or_format_failure") == (2, 8)
    assert count("policy_rejection") == (3, 8)
    assert count("grounding_failure") == (1, 8)
    assert count("metamorphic_violation") == (2, 3)
    assert count("unresolved_kept") == (1, 1)
    assert count("selective_accuracy") == (1, 1)
    assert stats["termination_reasons"] == {"ContractError": 1, "GroundingError": 1, "ModelError": 1,
                                            "PolicyError": 1, "ScopeError": 1, "ToolNotAllowedError": 1,
                                            "model_finished": 1, "none": 1}
    assert stats["usage"]["runtime_seconds"] == {"mean": 0.5, "max": 0.5}
    assert (stats["cases"], stats["families"]) == (7, 4)


# ------------------------------------------------------------------ boundaries

def _imports(path):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            yield from (alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            yield ("." if node.level else "") + (node.module or "").split(".")[0]


def test_metrics_module_is_standard_library_only():
    """[EV-MET-08] metrics.py is pure: standard-library imports only."""
    for module in _imports(ROOT / "evals" / "metrics.py"):
        assert module in sys.stdlib_module_names, module


def test_baselines_and_harness_import_no_network_shell_or_randomness():
    """[EV-MET-08] No network, model client, shell or random module in baselines.py or harness.py."""
    forbidden = {"socket", "urllib", "http", "httpx", "requests", "anthropic", "subprocess", "random", "secrets"}
    for name in ("baselines.py", "harness.py"):
        assert not set(_imports(ROOT / "evals" / name)) & forbidden, name
