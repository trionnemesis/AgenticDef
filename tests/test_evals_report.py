"""Runner, grading and report (evals/SPEC.md, sections 5 and 6).

Bracketed ids trace to requirement ids in evals/SPEC.md. Everything is offline:
replay uses ReplayModel, mock uses AnthropicModel over httpx.MockTransport with
the scripted provider that the existing M6 evaluation already uses.
"""
import asyncio
from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess

import httpx
import pytest
from jsonschema import Draft202012Validator, FormatChecker

from agenticdef.adapters.anthropic_model import AnthropicModel
from agenticdef.adapters.clock import SystemClock
from agenticdef.adapters.fixture_tools import FixtureTools
from agenticdef.adapters.replay_model import ReplayModel
from agenticdef.adapters.repository import JsonRepository
from agenticdef.application.investigate import Investigator
from agenticdef.cli import load
from agenticdef.domain.errors import ContractError

from evals import oracle, runner
from evals.cases import case_digest, documented_f2_variants, scenario_case
from evals.oracle import OracleError
from evals.runner import EvalError, build_report, grade_case, report_json, run_case
from test_anthropic_evaluation import ScriptedProvider

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"
SHA = "0123456789abcdef0123456789abcdef01234567"
REPLAY = {"model_provider": "deterministic_replay", "evidence_provider": "synthetic_fixture"}
CHECKS = {"status", "risk", "termination_reason", "terminal", "forbidden_tools", "required_methods",
          "grounding", "forbidden_claims"}
SCHEMA = json.loads((ROOT / "evals" / "schemas" / "report.schema.json").read_text(encoding="utf-8"))


def schema_errors(report):
    return list(Draft202012Validator(SCHEMA, format_checker=FormatChecker()).iter_errors(report))


def scenario(name):
    return scenario_case(SCENARIOS / name)


def replay(case, tmp_path, tag="run", model=None):
    return run_case(case, mode="replay", model=model or ReplayModel(), output_dir=tmp_path / f"{tag}-{case['case_id']}")


def replay_scenarios(tmp_path, tag="run"):
    return [replay(scenario(name), tmp_path, tag) for name in ("S01", "S02", "S03", "S05")]


def mock_model(event, status, risk):
    provider = ScriptedProvider(event, status, risk)
    model = AnthropicModel(model="operator-selected-model", api_key="test-placeholder",
                           transport=httpx.MockTransport(provider))
    return model, provider


def s01_record(tmp_path):
    path = SCENARIOS / "S01"
    tools = FixtureTools(load(path / "evidence.json"))
    investigator = Investigator(policy=load(path / "policy.yaml"), model=ReplayModel(), tools=tools,
                                repository=JsonRepository(tmp_path), clock=SystemClock())
    return asyncio.run(investigator.run(load(path / "event.json"))), tools


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    return replay(scenario("S01"), tmp_path_factory.mktemp("sample"))


# ---------------------------------------------------------------- replay over scenarios

def test_replay_scenarios_pass_and_report_is_valid(tmp_path):
    """[EV-RUN-04] [EV-RUN-06] [EV-REP-01] S01/S02/S03/S05 pass against the oracle in replay mode."""
    results = replay_scenarios(tmp_path)
    for entry in results:
        assert entry["passed"] is True and entry["verdict_pass"] is True and entry["error"] is None
        assert set(entry["checks"]) == CHECKS and all(entry["checks"].values())
        assert entry["mode"] == "replay" and entry["provenance"] == REPLAY
    report = build_report(results, repo_sha=SHA)
    assert schema_errors(report) == []
    assert report["report_version"] == "1" and report["repo_sha"] == SHA
    assert report["oracle_version"] == oracle.ORACLE_VERSION == "rbac-oracle-1"
    assert report["summary"] == {"cases": 4, "passed": 4, "failed": 0}
    cases = {c["case_id"]: c for c in report["cases"]}
    assert list(cases) == ["s01", "s02", "s03", "s05"]
    assert {k: c["oracle"]["label"] for k, c in cases.items()} == {
        "s01": "suspicious", "s02": "benign", "s03": "unresolved", "s05": "suspicious"}
    assert {k: c["oracle"]["approved"] for k, c in cases.items()} == {"s01": False, "s02": True, "s03": None, "s05": False}
    assert {k: (c["result"]["state"], c["result"]["status"], c["result"]["risk"], c["result"]["termination_reason"])
            for k, c in cases.items()} == {
        "s01": ("COMPLETED", "confirmed_suspicious", "high", "model_finished"),
        "s02": ("COMPLETED", "likely_benign", "low", "model_finished"),
        "s03": ("INSUFFICIENT_EVIDENCE", "insufficient_evidence", "unknown", "ToolExecutionError"),
        "s05": ("COMPLETED", "confirmed_suspicious", "high", "model_finished")}
    assert cases["s01"]["result"]["budget_usage"] == {"model_calls": 7, "tool_calls": 5, "evidence_items": 5}
    for name in ("S01", "S02", "S03", "S05"):
        entry = cases[name.lower()]
        assert entry["seed"] == name and entry["case_digest"] == case_digest(scenario(name))
        assert entry["oracle"] == oracle.evaluate(scenario(name))


def test_runner_uses_the_same_runtime_and_persists_a_record(tmp_path):
    """[EV-RUN-04] The persisted record is the Investigator's own, under output_dir/<case_id>."""
    replay(scenario("S01"), tmp_path)
    records = list((tmp_path / "run-s01" / "s01").glob("inv-*/record.json"))
    assert len(records) == 1
    record = json.loads(records[0].read_text(encoding="utf-8"))
    assert record["state"] == "COMPLETED" and len(record["evidence"]) == 5
    assert record["metadata"]["model_provider"] == "deterministic_replay"
    assert record["metadata"]["evidence_provider"] == "synthetic_fixture"
    assert [a["kind"] for a in record["audit"]][-1] == "terminal"


F2_CATEGORIES = ["secrets_read", "workload_creation", "nodes_proxy", "token_request"]


def test_f2_variants_characterize_the_replay_model_limitation(tmp_path):
    """[EV-CASE-04] [EV-RUN-06] The double completes the documented variants as benign; the oracle says suspicious."""
    variants = documented_f2_variants(scenario("S01"))
    assert len(variants) == 4
    for variant, category in zip(variants, F2_CATEGORIES):
        entry = replay(variant, tmp_path)
        assert entry["oracle"]["label"] == "suspicious" and entry["oracle"]["categories"] == [category]
        assert entry["result"]["state"] == "COMPLETED"
        assert (entry["result"]["status"], entry["result"]["risk"]) == ("likely_benign", "low")
        assert entry["verdict_pass"] is False and entry["passed"] is False and entry["error"] is None
        assert {k for k, ok in entry["checks"].items() if not ok} == {"status", "risk"}, entry["checks"]


def test_failing_cases_are_counted_in_the_summary(tmp_path):
    """[EV-REP-01] Summary is computed from the cases, so a failing case cannot hide."""
    variants = documented_f2_variants(scenario("S01"))
    results = [replay(scenario("S01"), tmp_path), replay(variants[0], tmp_path)]
    report = build_report(results, repo_sha=SHA)
    assert report["summary"] == {"cases": 2, "passed": 1, "failed": 1}
    assert schema_errors(report) == []


# ---------------------------------------------------------------- mock mode

@pytest.mark.parametrize(("name", "status", "risk"), [("S01", "confirmed_suspicious", "high"), ("S02", "likely_benign", "low")])
def test_mock_mode_correct_verdict_passes(tmp_path, name, status, risk):
    """[EV-RUN-05] [EV-RUN-06] The HTTP adapter over a mock transport passes when its verdict matches the oracle."""
    case = scenario(name)
    model, provider = mock_model(case["event"], status, risk)
    entry = run_case(case, mode="mock", model=model, output_dir=tmp_path / "out")
    assert [e["task"] for e in provider.envelopes] == ["choose_action"] * 6 + ["produce_result"]
    assert entry["mode"] == "mock"
    assert entry["provenance"] == {"model_provider": "anthropic_api", "evidence_provider": "synthetic_fixture"}
    assert entry["passed"] is True and entry["verdict_pass"] is True and entry["error"] is None
    assert (entry["result"]["status"], entry["result"]["risk"]) == (status, risk)
    report = build_report([entry], repo_sha=SHA)
    assert schema_errors(report) == [] and report["cases"][0]["mode"] == "mock"


def test_mock_mode_inverted_verdict_fails(tmp_path):
    """[EV-RUN-06] A grounded but inverted verdict is accepted by the runtime and fails the oracle grade."""
    case = scenario("S01")
    model, _ = mock_model(case["event"], "likely_benign", "low")
    entry = run_case(case, mode="mock", model=model, output_dir=tmp_path / "out")
    assert entry["result"]["state"] == "COMPLETED" and entry["verdict_pass"] is False and entry["passed"] is False
    assert {k for k, ok in entry["checks"].items() if not ok} == {"status", "risk"}
    assert build_report([entry], repo_sha=SHA)["summary"] == {"cases": 1, "passed": 0, "failed": 1}


# ---------------------------------------------------------------- run_case errors

@pytest.mark.parametrize("mode", ["Live", "Replay", "", None, "replay,mock", ["live"]])
def test_only_the_four_modes_exist(tmp_path, mode):
    """[EV-RUN-01] Anything but replay, mock, baseline and live raises before any work."""
    out = tmp_path / "out"
    with pytest.raises(EvalError, match="mode"):
        run_case(scenario("S01"), mode=mode, model=ReplayModel(), output_dir=out)
    assert not out.exists()


def _metered(handler):
    from evals.live import load_protocol
    from evals.metering import MeteredTransport
    return MeteredTransport(load_protocol(ROOT / "evals" / "protocols" / "d8-smoke-sonnet-5-5.json"),
                            connect=lambda: httpx.MockTransport(handler))


def test_live_mode_runs_only_an_api_adapter_over_the_metered_transport(tmp_path):
    """[EV-RUN-01] [EV-RUN-08] live refuses the replay double and an adapter over a mock transport, before any
    call or directory."""
    out = tmp_path / "out"
    with pytest.raises(EvalError, match="live"):
        run_case(scenario("S01"), mode="live", model=ReplayModel(), output_dir=out)
    case = scenario("S01")
    model, provider = mock_model(case["event"], "confirmed_suspicious", "high")
    with pytest.raises(EvalError, match="MeteredTransport"):
        run_case(case, mode="live", model=model, output_dir=out)
    assert not out.exists() and provider.envelopes == []


def test_mock_mode_refuses_a_transport_that_could_reach_the_network(tmp_path):
    """[EV-RUN-08] [EV-ARCH-04] mock needs an httpx.MockTransport: the metered (network) transport or any other
    transport is refused before a request is sent, so a network run can never be labeled mock."""
    sent = []
    out = tmp_path / "out"
    for transport in (_metered(lambda request: sent.append(request)), httpx.AsyncBaseTransport()):
        model = AnthropicModel(model="claude-sonnet-5-5", api_key="test-placeholder", transport=transport)
        with pytest.raises(EvalError, match="MockTransport"):
            run_case(scenario("S01"), mode="mock", model=model, output_dir=out)
    assert sent == [] and not out.exists()


@pytest.mark.parametrize("mode", ["replay", "baseline"])
def test_offline_modes_refuse_an_api_adapter_before_any_call(tmp_path, mode):
    """[EV-RUN-05] [EV-RUN-08] replay and baseline never run an anthropic_api adapter, not even over a mock."""
    case = scenario("S01")
    model, provider = mock_model(case["event"], "confirmed_suspicious", "high")
    with pytest.raises(EvalError, match="provenance"):
        run_case(case, mode=mode, model=model, output_dir=tmp_path / "out")
    assert provider.envelopes == [] and not (tmp_path / "out").exists()


def test_replay_mode_rejects_a_real_model_adapter(tmp_path):
    """[EV-RUN-05] replay requires deterministic_replay provenance."""
    case = scenario("S01")
    model, _ = mock_model(case["event"], "confirmed_suspicious", "high")
    with pytest.raises(EvalError, match="provenance"):
        run_case(case, mode="replay", model=model, output_dir=tmp_path / "out")


def test_mock_mode_rejects_the_replay_double(tmp_path):
    """[EV-RUN-05] mock requires anthropic_api provenance."""
    with pytest.raises(EvalError, match="provenance"):
        run_case(scenario("S01"), mode="mock", model=ReplayModel(), output_dir=tmp_path / "out")


def test_provenance_requires_fixture_evidence(monkeypatch, tmp_path):
    """[EV-RUN-05] Evidence provenance other than synthetic_fixture raises, whatever the mode."""
    monkeypatch.setattr(FixtureTools, "provenance", "live_cluster")
    with pytest.raises(EvalError, match="provenance"):
        replay(scenario("S01"), tmp_path)


@pytest.mark.parametrize("mode", ["replay", "mock", "baseline", "live"])
def test_adapter_without_injected_transport_is_refused_before_any_call(monkeypatch, tmp_path, mode):
    """[EV-RUN-08] [EV-ARCH-04] An anthropic_api adapter that would use the network never runs."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: pytest.fail("network client constructed"))
    out = tmp_path / "out"
    model = AnthropicModel(model="operator-selected-model", api_key="test-placeholder")
    with pytest.raises(EvalError, match="network"):
        run_case(scenario("S01"), mode=mode, model=model, output_dir=out)
    assert not out.exists()


def test_existing_output_dir_is_refused_and_left_untouched(tmp_path):
    """[EV-RUN-03] A pre-existing directory raises, so a cached terminal record cannot count as a new execution."""
    out = tmp_path / "existing"
    out.mkdir()
    (out / "sentinel").write_text("keep", encoding="utf-8")
    with pytest.raises(EvalError, match="exist"):
        run_case(scenario("S01"), mode="replay", model=ReplayModel(), output_dir=out)
    assert [p.name for p in out.iterdir()] == ["sentinel"]


def test_rerunning_into_a_used_output_dir_is_refused(tmp_path):
    """[EV-RUN-03] The same directory cannot be reused for a second run."""
    case = scenario("S01")
    run_case(case, mode="replay", model=ReplayModel(), output_dir=tmp_path / "out")
    model = ReplayModel()
    with pytest.raises(EvalError, match="exist"):
        run_case(case, mode="replay", model=model, output_dir=tmp_path / "out")
    assert model.calls == 0


def test_output_dir_is_created_with_parents(tmp_path):
    """[EV-RUN-03] The runner creates the directory it requires to be absent."""
    out = tmp_path / "a" / "b"
    replay_entry = run_case(scenario("S01"), mode="replay", model=ReplayModel(), output_dir=out)
    assert out.is_dir() and replay_entry["passed"]


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda c: c.update(case_id="S01"), id="case_id"),
    pytest.param(lambda c: c.update(extra=1), id="extra-key"),
    pytest.param(lambda c: c["evidence"][0].pop("data"), id="evidence-entry"),
    pytest.param(lambda c: c.pop("event"), id="missing-event"),
])
def test_invalid_case_raises_before_any_directory_or_call(tmp_path, mutate):
    """[EV-RUN-02] The case schema gates the runner."""
    case = scenario("S01")
    mutate(case)
    model, out = ReplayModel(), tmp_path / "out"
    with pytest.raises(ValueError):
        run_case(case, mode="replay", model=model, output_dir=out)
    assert model.calls == 0 and not out.exists()


def test_out_of_oracle_scope_case_raises_before_running(tmp_path):
    """[EV-RUN-02] An uninterpretable case raises OracleError, never a pass; nothing is created or called."""
    case = scenario("S01")
    case["policy"]["allowed_tools"].remove("get_approval_record")
    model, out = ReplayModel(), tmp_path / "out"
    with pytest.raises(OracleError):
        run_case(case, mode="replay", model=model, output_dir=out)
    assert model.calls == 0 and not out.exists()


def test_runtime_validates_event_and_policy_itself(tmp_path):
    """[EV-CASE-01] [EV-RUN-02] event/policy are opaque to the case schema; the runtime rejects invalid ones."""
    bad_event = scenario("S01")
    bad_event["event"]["event_type"] = "shell"
    model = ReplayModel()
    with pytest.raises(ContractError):
        run_case(bad_event, mode="replay", model=model, output_dir=tmp_path / "event")
    bad_policy = scenario("S01")
    bad_policy["policy"]["max_model_calls"] = 10 ** 6
    with pytest.raises(ContractError):
        run_case(bad_policy, mode="replay", model=model, output_dir=tmp_path / "policy")
    assert model.calls == 0


# ---------------------------------------------------------------- fail-closed grading

def _grade(case, record, tools, **kw):
    return grade_case(case, mode="replay", record=record, tools=tools, provenance=REPLAY, **kw)


NO_RECORD = "no investigation record"
NO_RESULT = "terminal record has no result"
BAD_RESULT = "result violates the runtime result schema"
MALFORMED = "malformed record"
NOT_TERMINAL = "record is not in a terminal state"


def _assert_failed_closed(entry, error):
    """The entry carries exactly this error (or starts with it), so each guard is pinned to its own path."""
    assert entry["passed"] is False and entry["verdict_pass"] is False
    assert isinstance(entry["error"], str) and entry["error"].startswith(error), entry["error"]
    assert entry["result"] is None
    assert set(entry["checks"]) == CHECKS and not any(entry["checks"].values())
    assert build_report([entry], repo_sha=SHA)["summary"] == {"cases": 1, "passed": 0, "failed": 1}


def test_good_record_passes_grading(tmp_path):
    """[EV-RUN-06] Sanity: the unmodified S01 record passes grade_case."""
    record, tools = s01_record(tmp_path)
    entry = _grade(scenario("S01"), record, tools)
    assert entry["passed"] is True and entry["error"] is None and entry["verdict_pass"] is True


def test_record_none_fails_closed(tmp_path):
    """[EV-RUN-07] No record is a failure with an error, not a vacuous pass."""
    _, tools = s01_record(tmp_path)
    _assert_failed_closed(_grade(scenario("S01"), None, tools), NO_RECORD)


@pytest.mark.parametrize("state", ["RECEIVED", "VALIDATED", "POLICY_LOADED", "INVESTIGATING", "RUNNING", "UNKNOWN"])
def test_non_terminal_state_fails_closed(tmp_path, state):
    """[EV-RUN-07] A non-terminal record never passes, even when its result looks right."""
    record, tools = s01_record(tmp_path)
    record["state"] = state
    _assert_failed_closed(_grade(scenario("S01"), record, tools), NOT_TERMINAL)


def test_result_none_fails_closed(tmp_path):
    """[EV-RUN-07] A terminal record without a result fails; so does a claim record left RUNNING."""
    record, tools = s01_record(tmp_path)
    terminal_without_result = deepcopy(record)
    terminal_without_result["result"] = None
    _assert_failed_closed(_grade(scenario("S01"), terminal_without_result, tools), NO_RESULT)
    claim = {"investigation_id": record["investigation_id"], "state": "RUNNING", "result": None}
    _assert_failed_closed(_grade(scenario("S01"), claim, tools), NOT_TERMINAL)


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda r: r["result"].update(status="bogus"), id="status"),
    pytest.param(lambda r: r["result"].pop("summary"), id="missing-field"),
    pytest.param(lambda r: r["result"].update(extra=1), id="extra-field"),
    pytest.param(lambda r: r["result"].update(risk="critical"), id="risk"),
])
def test_schema_invalid_result_fails_closed(tmp_path, mutate):
    """[EV-RUN-07] A result that violates the runtime result schema fails closed."""
    record, tools = s01_record(tmp_path)
    mutate(record)
    _assert_failed_closed(_grade(scenario("S01"), record, tools), BAD_RESULT)


@pytest.mark.parametrize("record", [{}, {"state": "COMPLETED"}, {"result": {}}, "record", []], ids=repr)
def test_malformed_record_fails_closed_without_raising(tmp_path, record):
    """[EV-RUN-07] Missing keys or a non-mapping record are failures, not KeyError/TypeError."""
    _, tools = s01_record(tmp_path)
    _assert_failed_closed(_grade(scenario("S01"), record, tools), MALFORMED)


def test_verdict_pass_requires_both_status_and_risk(tmp_path):
    """[EV-RUN-06] verdict_pass is status AND risk: either one alone failing fails the verdict and the case."""
    record, tools = s01_record(tmp_path)
    wrong_risk = deepcopy(record)
    wrong_risk["result"]["risk"] = "low"
    entry = _grade(scenario("S01"), wrong_risk, tools)
    assert entry["checks"]["status"] is True and entry["checks"]["risk"] is False
    assert entry["verdict_pass"] is False and entry["passed"] is False and entry["error"] is None
    wrong_status = deepcopy(record)
    wrong_status["result"]["status"] = "likely_benign"
    entry = _grade(scenario("S01"), wrong_status, tools)
    assert entry["checks"]["status"] is False and entry["checks"]["risk"] is True
    assert entry["verdict_pass"] is False and entry["passed"] is False and entry["error"] is None


@pytest.mark.parametrize("damage", [
    pytest.param(lambda r: r.pop("evidence"), id="no-evidence-key"),
    pytest.param(lambda r: r.update(evidence=[{}]), id="evidence-without-method"),
    pytest.param(lambda r: r.update(evidence=None), id="evidence-not-a-list"),
])
def test_schema_valid_but_ungradable_record_fails_closed_instead_of_raising(tmp_path, damage):
    """[EV-RUN-07] A record that passes the state/result checks but cannot be graded is a failure, not a crash."""
    record, tools = s01_record(tmp_path)
    damage(record)
    _assert_failed_closed(_grade(scenario("S01"), record, tools), "record cannot be graded")


def test_grading_is_against_the_oracle_not_the_record(tmp_path):
    """[EV-RUN-06] An S01 record graded against an oracle that expects unresolved is a failure."""
    record, tools = s01_record(tmp_path)
    entry = _grade(scenario("S03"), record, tools)
    assert entry["passed"] is False and entry["verdict_pass"] is False
    assert not entry["checks"]["status"] and not entry["checks"]["risk"] and not entry["checks"]["termination_reason"]


def test_forbidden_tool_execution_fails_a_check(tmp_path):
    """[EV-RUN-06] assert_expected is reused unchanged, so forbidden tools still fail their check."""
    record, tools = s01_record(tmp_path)
    tools.executed.append({"tool": "shell", "arguments": {}})
    entry = _grade(scenario("S01"), record, tools)
    assert entry["checks"]["forbidden_tools"] is False and entry["passed"] is False and entry["verdict_pass"] is True


def test_grade_case_rejects_an_unsupported_mode(tmp_path):
    """[EV-RUN-01] The grading entry point has the same mode gate."""
    record, tools = s01_record(tmp_path)
    with pytest.raises(EvalError, match="mode"):
        grade_case(scenario("S01"), mode="Live", record=record, tools=tools, provenance=REPLAY)


# ---------------------------------------------------------------- report

def test_build_report_requires_a_full_hex_sha(sample):
    """[EV-REP-02] repo_sha must be exactly 40 lower-case hex characters."""
    for bad in ("", "abc", SHA[:-1], SHA + "0", SHA + "\n", SHA.upper(), "g" * 40, None, 7):
        with pytest.raises(EvalError, match="^repo_sha must be"):
            build_report([deepcopy(sample)], repo_sha=bad)


def test_build_report_requires_cases(sample):
    """[EV-REP-02] An empty case list is an error, never a vacuous pass."""
    for empty in ([], ()):
        with pytest.raises(EvalError, match="^no cases to report"):
            build_report(empty, repo_sha=SHA)


def test_build_report_rejects_a_case_counted_twice(sample):
    """[EV-REP-02] The same (case_id, mode) twice cannot inflate the summary."""
    with pytest.raises(EvalError, match="duplicate"):
        build_report([deepcopy(sample), deepcopy(sample)], repo_sha=SHA)
    other_mode = deepcopy(sample)
    other_mode["mode"] = "mock"
    other_mode["provenance"] = {"model_provider": "anthropic_api", "evidence_provider": "synthetic_fixture"}
    assert build_report([deepcopy(sample), other_mode], repo_sha=SHA)["summary"]["cases"] == 2


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda e: e.pop("case_digest"), id="missing-field"),
    pytest.param(lambda e: e.update(extra=1), id="extra-field"),
    pytest.param(lambda e: e["result"]["budget_usage"].update(runtime_seconds=0.1), id="runtime-seconds"),
    pytest.param(lambda e: e.update(mode="Live"), id="unknown-mode"),
])
def test_build_report_validates_before_returning(sample, mutate):
    """[EV-REP-01] A malformed case result raises instead of producing a report."""
    entry = deepcopy(sample)
    mutate(entry)
    with pytest.raises(EvalError, match="schema"):
        build_report([entry], repo_sha=SHA)


def _report(sample):
    return build_report([deepcopy(sample)], repo_sha=SHA)


SCHEMA_VIOLATIONS = [
    pytest.param(lambda r: r.update(extra=1), id="report-extra"),
    pytest.param(lambda r: r.pop("summary"), id="report-missing-summary"),
    pytest.param(lambda r: r.pop("repo_sha"), id="report-missing-repo_sha"),
    pytest.param(lambda r: r.update(report_version="2"), id="report_version"),
    pytest.param(lambda r: r.update(repo_sha=SHA.upper()), id="repo_sha-uppercase"),
    pytest.param(lambda r: r.update(repo_sha=SHA[:-1]), id="repo_sha-short"),
    pytest.param(lambda r: r.update(cases=[]), id="no-cases"),
    pytest.param(lambda r: r["summary"].update(extra=1), id="summary-extra"),
    pytest.param(lambda r: r["summary"].update(passed="1"), id="summary-type"),
    pytest.param(lambda r: r["cases"][0].update(extra=1), id="case-extra"),
    pytest.param(lambda r: r["cases"][0].update(case_digest="sha256:abc"), id="case_digest"),
    pytest.param(lambda r: r["cases"][0].update(case_id="S01"), id="case_id"),
    pytest.param(lambda r: r["cases"][0].update(mode="Live"), id="mode"),
    pytest.param(lambda r: r["cases"][0].update(passed=1), id="passed-type"),
    pytest.param(lambda r: r["cases"][0].update(error=5), id="error-type"),
    pytest.param(lambda r: r["cases"][0]["provenance"].update(model_provider="other"), id="model_provider"),
    pytest.param(lambda r: r["cases"][0]["provenance"].update(evidence_provider="live_cluster"), id="evidence_provider"),
    pytest.param(lambda r: r["cases"][0]["provenance"].update(extra=1), id="provenance-extra"),
    pytest.param(lambda r: r["cases"][0]["oracle"].update(label="maybe"), id="oracle-label"),
    pytest.param(lambda r: r["cases"][0]["oracle"].update(extra=1), id="oracle-extra"),
    pytest.param(lambda r: r["cases"][0]["oracle"]["categories"].append("Bad Id"), id="oracle-category"),
    pytest.param(lambda r: r["cases"][0]["oracle"]["expected"].update(extra=1), id="expected-extra"),
    pytest.param(lambda r: r["cases"][0]["oracle"]["expected"].pop("statuses"), id="expected-missing"),
    pytest.param(lambda r: r["cases"][0]["result"].update(extra=1), id="result-extra"),
    pytest.param(lambda r: r["cases"][0]["result"].update(status="bogus"), id="result-status"),
    pytest.param(lambda r: r["cases"][0]["result"]["budget_usage"].update(runtime_seconds=0.5), id="budget-runtime_seconds"),
    pytest.param(lambda r: r["cases"][0]["result"]["budget_usage"].pop("tool_calls"), id="budget-missing"),
    pytest.param(lambda r: r["cases"][0]["checks"].update(extra=True), id="checks-extra"),
    pytest.param(lambda r: r["cases"][0]["checks"].pop("status"), id="checks-missing"),
    pytest.param(lambda r: r["cases"][0]["checks"].update(status="yes"), id="checks-type"),
]


@pytest.mark.parametrize("mutate", SCHEMA_VIOLATIONS)
def test_report_schema_is_strict(sample, mutate):
    """[EV-REP-01] additionalProperties false everywhere; patterns, enums and types are enforced."""
    report = _report(sample)
    assert schema_errors(report) == []
    mutate(report)
    assert schema_errors(report) != []


def test_report_schema_file_is_draft_2020_12_closed_and_local():
    """[EV-REP-01] No remote references; every object the schema defines is closed."""
    text = (ROOT / "evals" / "schemas" / "report.schema.json").read_text(encoding="utf-8")
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(SCHEMA)
    assert "$ref" not in text and "http://" not in text and text.count("https://") == 1

    def objects(node):
        if isinstance(node, dict):
            if node.get("type") == "object": yield node
            for value in node.values(): yield from objects(value)
        elif isinstance(node, list):
            for value in node: yield from objects(value)
    found = list(objects(SCHEMA))
    assert len(found) >= 9 and all(node.get("additionalProperties") is False for node in found)


def test_two_replay_runs_give_byte_identical_reports(tmp_path):
    """[EV-REP-03] Identical inputs, different fresh directories: identical bytes."""
    first = report_json(build_report(replay_scenarios(tmp_path, "first"), repo_sha=SHA))
    second = report_json(build_report(replay_scenarios(tmp_path, "second"), repo_sha=SHA))
    assert first == second and first.endswith("\n")
    assert json.loads(first) == build_report(replay_scenarios(tmp_path, "third"), repo_sha=SHA)


def test_report_is_order_independent_and_excludes_volatile_fields(tmp_path):
    """[EV-REP-03] No timestamps, runtime, evidence ids or paths; cases sorted by (case_id, mode)."""
    results = replay_scenarios(tmp_path)
    forward = report_json(build_report(results, repo_sha=SHA))
    assert forward == report_json(build_report(list(reversed(results)), repo_sha=SHA))
    for fragment in ("runtime_seconds", "timestamps", "started_at", "finished_at", "acquired_at", "investigation_id",
                     "inv-", str(tmp_path)):
        assert fragment not in forward, fragment
    assert not re.search(r"ev-[0-9a-f]{64}", forward)
    assert [c["case_id"] for c in json.loads(forward)["cases"]] == ["s01", "s02", "s03", "s05"]


def test_report_does_not_alias_its_inputs(sample):
    """[EV-REP-01] Mutating a built report does not change the case results it was built from."""
    entry = deepcopy(sample)
    snapshot = deepcopy(entry)
    report = build_report([entry], repo_sha=SHA)
    report["cases"][0]["oracle"]["categories"].append("tampered")
    assert entry == snapshot


# ---------------------------------------------------------------- current_repo_sha

def test_current_repo_sha_runs_git_rev_parse_head(monkeypatch):
    """[EV-REP-04] Returns the trimmed sha from `git rev-parse HEAD` run at the repository root."""
    seen = {}

    def fake(args, **kwargs):
        seen.update(args=args, kwargs=kwargs)
        return subprocess.CompletedProcess(args, 0, SHA + "\n", "")
    monkeypatch.setattr(runner.subprocess, "run", fake)
    assert runner.current_repo_sha() == SHA
    assert seen["args"] == ["git", "rev-parse", "HEAD"]
    assert Path(seen["kwargs"]["cwd"]).resolve() == ROOT


@pytest.mark.parametrize("outcome", [
    pytest.param(lambda args: subprocess.CompletedProcess(args, 128, "", "fatal: not a git repository"), id="nonzero"),
    pytest.param(lambda args: subprocess.CompletedProcess(args, 0, "not-a-sha\n", ""), id="malformed"),
    pytest.param(lambda args: subprocess.CompletedProcess(args, 0, "", ""), id="empty"),
    pytest.param(lambda args: subprocess.CompletedProcess(args, 0, SHA.upper() + "\n", ""), id="uppercase"),
    pytest.param(lambda args: (_ for _ in ()).throw(FileNotFoundError("git")), id="git-missing"),
    pytest.param(lambda args: (_ for _ in ()).throw(subprocess.TimeoutExpired(args, 10)), id="timeout"),
])
def test_current_repo_sha_raises_on_any_failure(monkeypatch, outcome):
    """[EV-REP-04] Failure is loud; there is no fallback sha."""
    monkeypatch.setattr(runner.subprocess, "run", lambda args, **kwargs: outcome(args))
    with pytest.raises(EvalError):
        runner.current_repo_sha()
