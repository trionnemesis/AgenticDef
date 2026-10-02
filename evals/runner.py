"""Run and grade cases against the oracle, and build the fail-closed report.

Normative text: evals/SPEC.md, sections 5 and 6. The runner executes the SAME
runtime as replay (Investigator, FixtureTools, JsonRepository, SystemClock) with
a single submission and adds no capability: no network, no live mode, and git
(`rev-parse HEAD`) is the only subprocess.
"""
import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess

from jsonschema import Draft202012Validator, FormatChecker

from agenticdef.adapters.clock import SystemClock
from agenticdef.adapters.fixture_tools import FixtureTools
from agenticdef.adapters.repository import JsonRepository
from agenticdef.application.investigate import Investigator
from agenticdef.cli import assert_expected
from agenticdef.domain.contracts import validate
from agenticdef.domain.errors import ContractError
from agenticdef.domain.runtime import TERMINAL

from . import oracle
from .baselines import BASELINE_PROVENANCES
from .cases import case_digest, load_schema, validate_case

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1"
# Mode -> the model provenances the persisted record may carry. Evidence is always fixture evidence.
MODE_MODEL_PROVIDERS = {"replay": ("deterministic_replay",), "mock": ("anthropic_api",),
                        "baseline": tuple(sorted(BASELINE_PROVENANCES))}
EVIDENCE_PROVIDER = "synthetic_fixture"
CHECK_NAMES = ("status", "risk", "termination_reason", "terminal", "forbidden_tools",
               "required_methods", "grounding", "forbidden_claims")
SHA = re.compile(r"[0-9a-f]{40}")

_REPORT_VALIDATOR = Draft202012Validator(load_schema("report.schema.json"), format_checker=FormatChecker())


class EvalError(Exception):
    """An evaluation request that must not be silently accepted."""


class StepClock:
    """Deterministic clock for evaluation runs only: each monotonic() read advances by `step` seconds."""

    START = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __init__(self, step=0.001):
        self.step, self._reads = step, 0

    def monotonic(self):
        self._reads += 1
        return self._reads * self.step

    def utcnow(self):
        self._reads += 1
        return (self.START + timedelta(seconds=self._reads * self.step)).isoformat()


def _require_mode(mode):
    if mode == "live":
        raise EvalError("mode 'live' is not available: live runs need maintainer decision D8")
    if not isinstance(mode, str) or mode not in MODE_MODEL_PROVIDERS:
        raise EvalError(f"unsupported mode {mode!r}; expected 'replay', 'mock' or 'baseline'")


def _refuse_network_adapter(model):
    # An Anthropic adapter without an injected (mock) transport would call the real API.
    if getattr(model, "provenance", None) == "anthropic_api" and getattr(model, "_transport", None) is None:
        raise EvalError("refusing an anthropic_api adapter without an injected transport: it would use the network")


def _provenance(record, model, tools):
    metadata = record.get("metadata") if isinstance(record, dict) else None
    if isinstance(metadata, dict) and {"model_provider", "evidence_provider"} <= set(metadata):
        return {"model_provider": metadata["model_provider"], "evidence_provider": metadata["evidence_provider"]}
    return {"model_provider": getattr(model, "provenance", "test_double"),
            "evidence_provider": getattr(tools, "provenance", "test_double")}


def _require_provenance(mode, provenance):
    if (provenance["model_provider"] not in MODE_MODEL_PROVIDERS[mode]
            or provenance["evidence_provider"] != EVIDENCE_PROVIDER):
        raise EvalError(f"provenance mismatch: mode {mode!r} requires one of {MODE_MODEL_PROVIDERS[mode]!r} with "
                        f"{EVIDENCE_PROVIDER!r} evidence, record has {provenance!r}")


def _record_error(record):
    """Return why a record cannot be graded, or None. Never raises."""
    if record is None:
        return "no investigation record"
    if not isinstance(record, dict) or "state" not in record or "result" not in record:
        return "malformed record: expected a mapping with 'state' and 'result'"
    state = record["state"]
    if not isinstance(state, str) or state not in TERMINAL:
        return f"record is not in a terminal state ({state!r})"
    if record["result"] is None:
        return "terminal record has no result"
    try:
        validate("result", record["result"])
    except ContractError:
        return "result violates the runtime result schema"
    return None


def grade_case(case, *, mode, record, tools, provenance, oracle_result=None):
    """Grade one persisted record against the oracle. Fail closed; return a report case entry."""
    _require_mode(mode)
    validate_case(case)
    oracle_result = oracle.evaluate(case) if oracle_result is None else oracle_result
    error = _record_error(record)
    checks = result = None
    if error is None:
        try:
            checks = assert_expected(record, oracle_result["expected"], tools)
        except (KeyError, TypeError, AttributeError) as exc:
            error = f"record cannot be graded ({type(exc).__name__})"
    if error is None:
        usage = record["result"]["budget_usage"]
        result = {"state": record["state"], "status": record["result"]["status"],
                  "risk": record["result"]["risk"], "termination_reason": record["result"]["termination_reason"],
                  "budget_usage": {key: usage[key] for key in ("model_calls", "tool_calls", "evidence_items")}}
    else:
        checks = {name: False for name in CHECK_NAMES}
    return {
        "case_id": case["case_id"], "seed": case["seed"], "case_digest": case_digest(case), "mode": mode,
        "provenance": dict(provenance), "oracle": deepcopy(oracle_result), "result": result, "checks": checks,
        "verdict_pass": error is None and checks["status"] and checks["risk"],
        "passed": error is None and all(checks.values()), "error": error,
    }


def run_case(case, *, mode, model, output_dir, clock=None):
    """Run one case through the shared runtime in `replay`, `mock` or `baseline` mode and grade it."""
    return execute_case(case, mode=mode, model=model, output_dir=output_dir, clock=clock)[0]


def execute_case(case, *, mode, model, output_dir, clock=None):
    """`run_case` that also returns the persisted record: (report entry, record)."""
    _require_mode(mode)
    validate_case(case)
    oracle_result = oracle.evaluate(case)
    _refuse_network_adapter(model)
    output_dir = Path(output_dir)
    try:
        output_dir.mkdir(parents=True)
    except FileExistsError as exc:
        raise EvalError("output_dir already exists; a cached record must not count as a new execution") from exc
    tools = FixtureTools(case["evidence"])
    investigator = Investigator(policy=case["policy"], model=model, tools=tools,
                                repository=JsonRepository(output_dir / case["case_id"]),
                                clock=SystemClock() if clock is None else clock)
    record = asyncio.run(investigator.run(case["event"]))
    provenance = _provenance(record, model, tools)
    _require_provenance(mode, provenance)
    entry = grade_case(case, mode=mode, record=record, tools=tools, provenance=provenance, oracle_result=oracle_result)
    return entry, record


def _assemble(cases, repo_sha):
    passed = sum(1 for case in cases if isinstance(case, dict) and case.get("passed") is True)
    return {"report_version": REPORT_VERSION, "repo_sha": repo_sha, "oracle_version": oracle.ORACLE_VERSION,
            "cases": cases, "summary": {"cases": len(cases), "passed": passed, "failed": len(cases) - passed}}


def _validate_report(report):
    errors = list(_REPORT_VALIDATOR.iter_errors(report))
    if errors:
        first = min(errors, key=lambda e: (len(e.absolute_path), [str(p) for p in e.absolute_path]))
        raise EvalError(f"report violates schema at {[str(p) for p in first.absolute_path]} ({first.validator})")


def build_report(case_results, *, repo_sha):
    """Assemble and validate the deterministic report; raise rather than return anything unverifiable."""
    if not isinstance(repo_sha, str) or not SHA.fullmatch(repo_sha):
        raise EvalError("repo_sha must be 40 lowercase hexadecimal characters")
    if not isinstance(case_results, (list, tuple)) or not case_results:
        raise EvalError("no cases to report")
    cases = deepcopy(list(case_results))
    _validate_report(_assemble(cases, repo_sha))   # entry-level schema failures surface before any key access
    keys = [(case["case_id"], case["mode"]) for case in cases]
    if len(set(keys)) != len(keys):
        raise EvalError("duplicate case in report: each (case_id, mode) may appear once")
    cases.sort(key=lambda case: (case["case_id"], case["mode"]))
    report = _assemble(cases, repo_sha)
    _validate_report(report)
    return report


def report_json(report):
    """Canonical text of a report: sorted keys, no volatile fields, so equal inputs give equal bytes."""
    return json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def current_repo_sha():
    """`git rev-parse HEAD` at the repository root. HEAD only: a dirty working tree is not detected."""
    try:
        done = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), capture_output=True,
                              text=True, check=False, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvalError("cannot run git rev-parse HEAD") from exc
    sha = done.stdout.strip()
    if done.returncode != 0 or not SHA.fullmatch(sha):
        raise EvalError("git rev-parse HEAD did not return a commit sha")
    return sha
