"""Opt-in live runs under a committed protocol. Normative text: evals/SPEC.md, section 11 (EV-LIVE-01..07).

This is the only evals module that builds a network transport or imports the
runtime's provider adapter (EV-ARCH-04), and nothing here runs unless the
operator opts in, in the environment and on the command line (EV-LIVE-03):

    AGENTICDEF_LIVE_EVAL=1 ANTHROPIC_API_KEY=... python -m evals.live \\
        --protocol evals/protocols/d8-smoke-sonnet-5-5.json --output-dir <new dir> --confirm-spend 10

Every request goes through `MeteredTransport` (evals/metering.py), so the
protocol's caps and stop conditions hold for every call.
"""
import argparse
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time

# Taken before this module imports the runtime: a runtime source file written after this may differ from the code
# already loaded, so a live run refuses it (EV-LIVE-03). `python -m evals.live` imports nothing earlier.
IMPORTED_NS = time.time_ns()

import httpx
from jsonschema import Draft202012Validator, FormatChecker

from agenticdef.adapters.anthropic_model import ANTHROPIC_VERSION, ENDPOINT, MAX_TOKENS, AnthropicModel

from . import oracle
from .cases import load_schema
from .generate import GENERATOR_VERSION, generate
from .harness import evaluate
from .metering import MeteredTransport
from .runner import REPO_ROOT, EvalError, current_repo_sha

LIVE_RUN_VERSION = "1"

# The key goes out as a header that the HTTP client builds before the metered transport sees the request.
_HEADER_SAFE_KEY = re.compile(r"[\x21-\x7e]+")
_PROTOCOL_VALIDATOR = Draft202012Validator(load_schema("protocol.schema.json"), format_checker=FormatChecker())
_LIVE_RUN_VALIDATOR = Draft202012Validator(load_schema("live-run.schema.json"), format_checker=FormatChecker())


def _require_valid(validator, value, what):
    errors = list(validator.iter_errors(value))
    if errors:
        first = min(errors, key=lambda e: (len(e.absolute_path), [str(p) for p in e.absolute_path]))
        raise EvalError(f"{what} violates its schema at {[str(p) for p in first.absolute_path]} ({first.validator})")


def _require_finite(value, where):
    """JSON Schema bounds cannot reject NaN (every comparison with it is false), so check before the schema."""
    if isinstance(value, float) and not math.isfinite(value):
        raise EvalError(f"{where} is not a finite number")
    if isinstance(value, dict):
        for key, item in value.items():
            _require_finite(item, f"{where}.{key}" if where != "protocol" else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _require_finite(item, f"{where}[{index}]")


def _check(protocol):
    """Finiteness, schema, then the code the protocol describes (EV-LIVE-01, EV-LIVE-02).

    Returns (digest, generated set)."""
    _require_finite(protocol, "protocol")
    _require_valid(_PROTOCOL_VALIDATOR, protocol, "protocol")
    provider, chosen = protocol["provider"], protocol["set"]
    for key, sent in (("endpoint", ENDPOINT), ("anthropic_version", ANTHROPIC_VERSION), ("max_tokens", MAX_TOKENS)):
        if provider[key] != sent:
            raise EvalError(f"protocol provider.{key} is {provider[key]!r}, the adapter sends {sent!r}")
    for key, current in (("generator_version", GENERATOR_VERSION), ("oracle_version", oracle.ORACLE_VERSION)):
        if chosen[key] != current:
            raise EvalError(f"protocol set.{key} is {chosen[key]!r}, the current one is {current!r}")
    generated = generate(generator_seed=chosen["generator_seed"], holdout_fraction=chosen["holdout_fraction"])
    split_of = {entry["family"]: entry["split"] for entry in generated["entries"]}
    unknown = sorted(set(chosen["families"]) - set(split_of))
    if unknown:
        raise EvalError(f"protocol names unknown families {unknown}")
    outside = sorted(family for family in chosen["families"] if split_of[family] != chosen["split"])
    if outside:
        raise EvalError(f"protocol families {outside} are not in split {chosen['split']!r}")
    entries = [entry for entry in generated["entries"] if entry["family"] in chosen["families"]]
    if len(entries) != chosen["cases"]:
        raise EvalError(f"protocol set.cases is {chosen['cases']}, its families hold {len(entries)} cases")
    ceiling = protocol["k"] * sum(entry["case"]["policy"]["max_model_calls"] for entry in entries)
    if protocol["caps"]["max_model_calls"] > ceiling:
        raise EvalError(f"protocol caps.max_model_calls {protocol['caps']['max_model_calls']} exceeds the "
                        f"{ceiling} calls the cases' policies allow, so it could never bind")
    canonical = json.dumps(protocol, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + sha256(canonical.encode("utf-8")).hexdigest(), generated


def check_protocol(protocol):
    """Validate a protocol against its schema and the code it describes; return its digest."""
    return _check(protocol)[0]


def _parse_protocol(data, source):
    try:
        protocol = json.loads(data)
    except ValueError as exc:
        raise EvalError(f"protocol {source} is not a readable JSON file ({type(exc).__name__})") from exc
    check_protocol(protocol)
    return protocol


def load_protocol(path):
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise EvalError(f"protocol {path} is not a readable JSON file ({type(exc).__name__})") from exc
    return _parse_protocol(data, path)


def check_api_key(key):
    """A key the HTTP client cannot put in a header would fail every case before the meter sees a request, so only
    visible ASCII is accepted. The message never repeats the key."""
    if not isinstance(key, str) or not _HEADER_SAFE_KEY.fullmatch(key):
        raise EvalError("ANTHROPIC_API_KEY must be visible ASCII with no whitespace")


def run_live(protocol, *, output_dir, api_key, repo_sha, connect):
    """Run one protocol through the metered transport and write live-run.json (EV-LIVE-05, EV-LIVE-06)."""
    digest, generated = _check(protocol)
    check_api_key(api_key)
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise EvalError("output_dir already exists; a live run never reuses a directory")
    transport = MeteredTransport(protocol, connect=connect)
    model_id = protocol["provider"]["model"]

    def factory(case, trial):
        if transport.stop is not None:
            raise EvalError(f"live run stopped: {transport.stop['condition']}")
        return AnthropicModel(model=model_id, api_key=api_key, transport=transport)

    output_dir.mkdir(parents=True)
    metrics = None
    try:
        metrics = evaluate(generated, [{"name": protocol["protocol_id"], "mode": "live", "factory": factory}],
                           k=protocol["k"], output_dir=output_dir / "runs", repo_sha=repo_sha,
                           families=list(protocol["set"]["families"]), clock="system")
    except EvalError:
        if transport.stop is None:
            raise
    stop, ledger = transport.stop, transport.ledger()
    if stop is None and ledger["calls"] == 0:
        # Every case ended before a request reached the transport, so nothing about the model was measured.
        stop = {"condition": "no_model_calls", "detail": "no request reached the API, so the run measured nothing"}
    stopped = stop is not None
    result = {"live_run_version": LIVE_RUN_VERSION, "protocol_id": protocol["protocol_id"], "protocol_digest": digest,
              "protocol": protocol, "repo_sha": repo_sha, "status": "stopped" if stopped else "completed",
              "stop": stop, "ledger": ledger, "metrics": None if stopped else metrics}
    _require_finite(result, "live run")
    _require_valid(_LIVE_RUN_VALIDATOR, result, "live run")
    (output_dir / "live-run.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def network_transport():
    """The real network transport. Built only after every opt-in, once per request (EV-LIVE-03, EV-LIVE-04)."""
    return httpx.AsyncHTTPTransport()


def git_status():
    """`git status --porcelain` of the repository; raises if git fails."""
    try:
        done = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT, capture_output=True, text=True,
                              check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvalError("cannot run git status") from exc
    return done.stdout


def _committed(path, root, rev, what):
    root, resolved = Path(root).resolve(), Path(path).resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError:
        raise EvalError(f"{what} {path} is outside the repository; commit it first") from None
    try:
        committed = subprocess.run(["git", "show", f"{rev}:{relative}"], cwd=root, capture_output=True, check=True,
                                   timeout=30).stdout
    except subprocess.CalledProcessError:
        raise EvalError(f"{what} {relative or path} is not committed at {rev}") from None
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvalError("cannot run git show") from exc
    try:
        on_disk = resolved.read_bytes()
    except OSError as exc:
        raise EvalError(f"{what} {path} is not a readable file ({type(exc).__name__})") from exc
    if on_disk != committed:
        raise EvalError(f"{what} {relative} differs from its committed version at {rev}")
    return committed


def committed_bytes(path, root=REPO_ROOT, rev="HEAD"):
    """The protocol's bytes at `rev`. Raises unless the file (symlinks followed) is inside the repository and
    identical to its version at `rev`, so a run can only use a protocol that `repo_sha` reproduces."""
    return _committed(path, root, rev, "protocol")


def check_runtime_sources(root=REPO_ROOT, modules=None, rev=None, loaded_after_ns=None):
    """Every loaded agenticdef and evals module must come from this checkout, or repo_sha would not name the code
    that ran (an installed wheel or another path can shadow it).

    With `rev`, each module's file must also equal its blob at that revision and must not have been written since
    this module began importing the runtime, so the code already loaded is the code at `rev` even if the checkout
    moved after the imports."""
    root = Path(root).resolve()
    homes = {"agenticdef": root / "src" / "agenticdef", "evals": root / "evals"}
    if rev is not None and loaded_after_ns is None:
        loaded_after_ns = IMPORTED_NS
    for name, module in list((sys.modules if modules is None else modules).items()):
        # `python -m evals.live` runs this module as __main__; judge it by its real name.
        name = getattr(getattr(module, "__spec__", None), "name", None) or name
        home, file = homes.get(name.split(".")[0]), getattr(module, "__file__", None)
        if home is None or file is None:
            continue
        path = Path(file).resolve()
        if not path.is_relative_to(home):
            raise EvalError(f"module {name} is loaded from {file}, not from this checkout ({home})")
        if rev is not None:
            _committed(path, root, rev, f"module {name}")
            if path.stat().st_mtime_ns >= loaded_after_ns:
                raise EvalError(f"module {name} changed on disk after the runtime was imported, so the loaded code "
                                f"may not be the code at {rev}")


def _refuse(message):
    print(f"refused: {message}", file=sys.stderr)
    return 2


def main(argv=None, env=None):
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(prog="python -m evals.live",
                                     description="Run one committed live protocol (evals/SPEC.md, section 11).")
    parser.add_argument("--protocol", required=True, help="committed protocol JSON file")
    parser.add_argument("--output-dir", required=True, help="new directory for records and live-run.json")
    parser.add_argument("--confirm-spend", required=True, help="must equal the protocol's caps.max_cost_usd")
    args = parser.parse_args(argv)
    if env.get("AGENTICDEF_LIVE_EVAL") != "1":
        return _refuse("set AGENTICDEF_LIVE_EVAL=1 to opt in to a paid live run")
    api_key = env.get("ANTHROPIC_API_KEY") or ""
    if not api_key:
        return _refuse("ANTHROPIC_API_KEY is not set")
    try:
        # One revision for every check, and the one recorded: a commit or checkout in between cannot split them.
        pinned = current_repo_sha()
        protocol = _parse_protocol(committed_bytes(args.protocol, rev=pinned), args.protocol)
        cap = protocol["caps"]["max_cost_usd"]
        try:
            confirmed = Decimal(args.confirm_spend)
        except InvalidOperation:
            return _refuse("--confirm-spend is not a number")
        if not confirmed.is_finite() or confirmed != Decimal(str(cap)):
            return _refuse(f"--confirm-spend must equal the protocol's caps.max_cost_usd ({cap})")
        if git_status():
            return _refuse("the working tree is not clean; commit the protocol and the code first")
        check_runtime_sources(rev=pinned)
        if current_repo_sha() != pinned:
            return _refuse("HEAD moved while the run was being checked; start it on a checkout nobody is changing")
        result = run_live(protocol, output_dir=args.output_dir, api_key=api_key, repo_sha=pinned,
                          connect=network_transport)
    except EvalError as exc:
        return _refuse(str(exc))
    print(json.dumps({"status": result["status"], "stop": result["stop"], "ledger": result["ledger"]}, indent=2,
                     sort_keys=True))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
