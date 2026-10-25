"""Shared replay input and expectation helpers, independent of CLI orchestration."""
import yaml

from .domain.contracts import canonical
from .domain.errors import ContractError


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
