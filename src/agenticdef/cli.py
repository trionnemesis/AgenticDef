import argparse
import asyncio
import json
import os
from pathlib import Path
import tempfile

import yaml

from .adapters.clock import SystemClock
from .adapters.fixture_tools import FixtureTools
from .adapters.replay_model import ReplayModel
from .adapters.repository import JsonRepository
from .application.investigate import Investigator
from .domain.contracts import canonical
from .domain.errors import ContractError, InvestigationError


def load(path):
    try:
        if path.stat().st_size > 131072: raise ContractError("Input file byte limit")
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        canonical(value)
        return value
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ContractError("Cannot read input / 無法讀取輸入") from exc


def assert_expected(record, expected, tools):
    result = record["result"]
    checks = {
        "status": result is not None and result["status"] in expected["statuses"],
        "risk": result is not None and result["risk"] in expected["risks"],
        "termination_reason": result is not None and result["termination_reason"] == expected["termination_reason"],
        "terminal": record["state"] in {"COMPLETED", "FAILED", "INCONCLUSIVE", "INSUFFICIENT_EVIDENCE"},
        "forbidden_tools": not any(e["tool"] in expected["forbidden_tools"] for e in tools.executed),
        "required_methods": set(expected["required_methods"]) <= {e["method"] for e in record["evidence"]},
        "grounding": all(set(f["evidence_ids"]) <= {e["evidence_id"] for e in record["evidence"]} and f["evidence_ids"] for f in result["findings"]) if result else False,
        "forbidden_claims": not any(s in canonical(result) for s in expected["forbidden_claims"]),
    }
    return checks


async def run_scenario(path, output):
    expected, policy = load(path / "expected.yaml"), load(path / "policy.yaml")
    model = ReplayModel(load(path / "model.json").get("fault"))
    tools = FixtureTools(load(path / "evidence.json"))
    repository = JsonRepository(output)
    investigator = Investigator(policy=policy, model=model, tools=tools, repository=repository, clock=SystemClock())
    event = load(path / "event.json")
    record = await investigator.run(event)
    calls, executed = model.calls, len(tools.executed)
    duplicate_ok = True
    for _ in range(expected.get("submissions", 1) - 1):
        duplicate = await investigator.run(event)
        duplicate_ok &= duplicate == record and model.calls == calls and len(tools.executed) == executed
    checks = assert_expected(record, expected, tools)
    checks["duplicates"] = duplicate_ok
    usage = record["result"]["budget_usage"]
    checks["budgets"] = all(usage[k] <= policy["max_" + k] for k in ("model_calls", "tool_calls", "evidence_items"))
    return {"scenario": path.name, "passed": all(checks.values()), "checks": checks, "result": record["result"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bounded security replay / 受限安全調查重播")
    parser.add_argument("scenario", type=Path, help="Scenario directory, or corpus with --all")
    parser.add_argument("--all", action="store_true", help="Run all S* scenarios / 執行所有情境")
    parser.add_argument("--output", type=Path, help="Persist results here; default is a fresh temporary directory")
    parser.add_argument("--provider", choices=["replay", "anthropic"], default="replay")
    parser.add_argument("--model", help="Explicit model ID for the Anthropic API; no implicit model choice")
    args = parser.parse_args(argv)
    try:
        paths = sorted(args.scenario.glob("S*")) if args.all else [args.scenario]
        if not paths: raise ContractError("No scenarios selected / 未選取情境")
        output = args.output or Path(tempfile.mkdtemp(prefix="agenticdef-replay-"))
        if args.provider == "anthropic":
            if args.all: raise ContractError("Real-model runs take one scenario; replay fault scripts are not used")
            try:
                from .adapters.anthropic_model import AnthropicModel
            except ImportError as exc:
                raise ContractError("Install the anthropic extra / 請安裝 anthropic 額外依賴") from exc
            model = AnthropicModel(model=args.model, api_key=os.environ.get("ANTHROPIC_API_KEY"))
            investigator = Investigator(policy=load(args.scenario / "policy.yaml"), model=model,
                tools=FixtureTools(load(args.scenario / "evidence.json")), repository=JsonRepository(output / args.scenario.name), clock=SystemClock())
            record = asyncio.run(investigator.run(load(args.scenario / "event.json")))
            print(json.dumps({"mode": "real_model_fixture_evidence", "output": str(output), "record": record}, ensure_ascii=False, indent=2))
            if record["result"] is None: return 2
            return {"likely_benign": 0, "confirmed_suspicious": 1}.get(record["result"]["status"], 2)
        results = [asyncio.run(run_scenario(path, output / path.name)) for path in paths]
        print(json.dumps({"mode": "synthetic_replay", "output": str(output), "scenarios": results}, ensure_ascii=False, indent=2))
        return 0 if all(r["passed"] for r in results) else 1
    except (InvestigationError, KeyError, TypeError) as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__": raise SystemExit(main())
