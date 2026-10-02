"""Run providers over a generated set and build the metrics report. Normative text: evals/SPEC.md, section 10
(EV-MET-04..07).

Every run goes through `execute_case`, so every number comes from a persisted
record graded against the oracle. Requests are validated before any run.
"""
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import re

from jsonschema import Draft202012Validator, FormatChecker

from agenticdef.adapters.clock import SystemClock

from . import oracle
from .cases import CaseError, case_digest, load_schema, validate_case
from .generate import GeneratorError, generate, label_of_status, relation_violations
from .metrics import summarize
from .runner import MODE_MODEL_PROVIDERS, SHA, EvalError, StepClock, execute_case

METRICS_VERSION = "1"
PROVIDER_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
SPLITS = ("all", "dev", "holdout")
CLOCKS = {"step": StepClock, "system": SystemClock}

_METRICS_VALIDATOR = Draft202012Validator(load_schema("metrics.schema.json"), format_checker=FormatChecker())
_SET_VALIDATOR = Draft202012Validator(load_schema("generated.schema.json"), format_checker=FormatChecker())


def _check_request(generated_set, providers, k, output_dir, repo_sha, families, clock):
    if type(k) is not int or k < 1:
        raise EvalError("k must be an integer of at least 1")
    if not isinstance(repo_sha, str) or not SHA.fullmatch(repo_sha):
        raise EvalError("repo_sha must be 40 lowercase hexadecimal characters")
    if not isinstance(clock, str) or clock not in CLOCKS:
        raise EvalError(f"clock must be one of {sorted(CLOCKS)}")
    if not isinstance(providers, (list, tuple)) or not providers:
        raise EvalError("at least one provider is required")
    names = []
    for provider in providers:
        if not isinstance(provider, dict) or set(provider) != {"name", "mode", "factory"}:
            raise EvalError("each provider is {name, mode, factory}")
        if not isinstance(provider["name"], str) or not PROVIDER_NAME.fullmatch(provider["name"]):
            raise EvalError(f"invalid provider name {provider['name']!r}")
        if not isinstance(provider["mode"], str) or provider["mode"] not in MODE_MODEL_PROVIDERS:
            raise EvalError(f"unsupported mode {provider['mode']!r} for provider {provider['name']!r}")
        if not callable(provider["factory"]):
            raise EvalError(f"provider {provider['name']!r} needs a callable factory")
        names.append(provider["name"])
    if len(set(names)) != len(names):
        raise EvalError("provider names must be unique")
    errors = list(_SET_VALIDATOR.iter_errors(generated_set))
    if errors:
        first = min(errors, key=lambda e: (len(e.absolute_path), [str(p) for p in e.absolute_path]))
        raise EvalError(f"generated set violates its schema at {[str(p) for p in first.absolute_path]} "
                        f"({first.validator})")
    if generated_set["oracle_version"] != oracle.ORACLE_VERSION:
        raise EvalError(f"generated set was labeled by oracle {generated_set['oracle_version']!r}, "
                        f"not {oracle.ORACLE_VERSION!r}; regenerate it")
    known = {entry["family"] for entry in generated_set["entries"]}
    if families is not None:
        if not isinstance(families, (list, tuple)) or not families \
                or not all(isinstance(family, str) for family in families) or not set(families) <= known:
            raise EvalError("families must be None or a non-empty list of known family ids")
    if not isinstance(output_dir, (str, os.PathLike)):
        raise EvalError("output_dir must be a path")
    if Path(output_dir).exists():
        raise EvalError("output_dir already exists; cached records must not count as new runs")


def _check_stored_entries(entries):
    """Stale or edited sets never run: each case must be valid, match its stored digest, and its stored oracle
    output must equal the oracle's output now."""
    for entry in entries:
        case = entry["case"]
        try:
            result = oracle.evaluate(validate_case(case))
        except (CaseError, oracle.OracleError) as exc:
            raise EvalError(f"case {case.get('case_id')!r} of the set is uninterpretable: {exc}") from exc
        if entry["digest"] != case_digest(case):
            raise EvalError(f"stored digest of {case['case_id']!r} no longer matches the case")
        if entry["oracle"] != {"label": result["label"], "categories": result["categories"]}:
            raise EvalError(f"stored oracle output of {entry['case']['case_id']!r} differs from the oracle now")


def _check_reproducible(generated_set):
    """Every entry field feeds the metrics, so the set must be exactly what generate() produces from its recorded
    parameters and the shipped seeds."""
    try:
        expected = generate(generator_seed=generated_set["generator_seed"],
                            holdout_fraction=generated_set["holdout_fraction"])
    except GeneratorError as exc:
        raise EvalError(f"generated set cannot be regenerated: {exc}") from exc
    if generated_set != expected:
        raise EvalError("generated set differs from what generate() produces from its recorded parameters and the "
                        "shipped seeds; regenerate it")


def _observation(entry, trial, report_entry, record):
    computed = report_entry["oracle"]["label"]
    if computed != entry["oracle"]["label"]:
        raise EvalError(f"run of {entry['case']['case_id']!r} computed oracle label {computed!r}, "
                        f"stored {entry['oracle']['label']!r}")
    if report_entry["case_digest"] != entry["digest"]:
        raise EvalError(f"run of {entry['case']['case_id']!r} graded a case whose digest differs from the stored one")
    if report_entry["error"] is None:
        result = record["result"]
        outcome = label_of_status(result["status"])
        termination, usage = result["termination_reason"], dict(result["budget_usage"])
    else:
        outcome, termination = "error", None
        usage = {"model_calls": 0, "tool_calls": 0, "evidence_items": 0, "runtime_seconds": 0}
    return {"case_id": entry["case"]["case_id"], "family": entry["family"], "split": entry["split"],
            "oracle_label": computed, "relation_kind": entry["relation"]["kind"], "trial": trial,
            "outcome": outcome, "termination_reason": termination,
            "usage": {key: usage[key] for key in ("model_calls", "tool_calls", "evidence_items", "runtime_seconds")},
            "model_provider": report_entry["provenance"]["model_provider"]}


def _violations(entries, observations, k):
    """(case_id, trial) pairs whose relation the outcomes violate; an error outcome counts as unresolved."""
    violated = set()
    for trial in range(k):
        labels = {obs["case_id"]: ("unresolved" if obs["outcome"] == "error" else obs["outcome"])
                  for obs in observations if obs["trial"] == trial}
        for violation in relation_violations(entries, labels.__getitem__):
            violated.add((violation["case_id"], trial))
    return violated


def evaluate(generated_set, providers, *, k=1, output_dir, repo_sha, families=None, clock="step"):
    """Run every provider k times over the chosen families and return the validated metrics report."""
    _check_request(generated_set, providers, k, output_dir, repo_sha, families, clock)
    chosen = set(families) if families is not None else {entry["family"] for entry in generated_set["entries"]}
    entries = [deepcopy(entry) for entry in generated_set["entries"] if entry["family"] in chosen]
    _check_stored_entries(entries)
    _check_reproducible(generated_set)
    output_dir = Path(output_dir)
    summaries = []
    for provider in sorted(providers, key=lambda p: p["name"]):
        observations = []
        for trial in range(k):
            for entry in entries:
                report_entry, record = execute_case(
                    entry["case"], mode=provider["mode"], model=provider["factory"](deepcopy(entry["case"]), trial),
                    output_dir=output_dir / provider["name"] / f"t{trial}" / entry["case"]["case_id"],
                    clock=CLOCKS[clock]())
                observations.append(_observation(entry, trial, report_entry, record))
        violated = _violations(entries, observations, k)
        model_providers = {obs["model_provider"] for obs in observations}
        if len(model_providers) != 1:
            raise EvalError(f"provider {provider['name']!r} produced several model provenances {sorted(model_providers)}")
        splits = {name: summarize([obs for obs in observations if name == "all" or obs["split"] == name],
                                  violated, k) for name in SPLITS}
        summaries.append({"name": provider["name"], "mode": provider["mode"],
                          "model_provider": model_providers.pop(), "splits": splits})
    digests = sorted(entry["digest"] for entry in entries)
    report = {"metrics_version": METRICS_VERSION, "repo_sha": repo_sha, "oracle_version": oracle.ORACLE_VERSION,
              "generator_version": generated_set["generator_version"],
              "generator_seed": generated_set["generator_seed"],
              "set_digest": "sha256:" + sha256("\n".join(digests).encode()).hexdigest(),
              "families": len(chosen), "cases": len(entries), "k": k, "clock": clock, "providers": summaries}
    errors = list(_METRICS_VALIDATOR.iter_errors(report))
    if errors:
        raise EvalError(f"metrics report violates its schema at {list(errors[0].absolute_path)}")
    return report
