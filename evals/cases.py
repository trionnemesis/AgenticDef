"""Case builders and the case schema. Normative text: evals/SPEC.md, section 4.

May import the runtime for `load` (so fixtures are read exactly as replay reads
them) and `canonical` (so digests use the runtime's canonical JSON).
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator, FormatChecker

from agenticdef.cli import load
from agenticdef.domain.contracts import canonical

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
CASE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
SEED = re.compile(r"[A-Za-z0-9._-]{1,64}")

_BASE_RULE = {"resources": ["pods"], "verbs": ["get", "list"]}
# F2: documented ReplayModel limitation. Privileged grants outside {*, bind, escalate, impersonate}
# complete as likely_benign/low. Each tuple is (slug, resources, verbs) added to the S01 after-version rules.
_F2 = (
    ("secrets-read", ["secrets"], ["get", "list"]),
    ("pods-create", ["pods"], ["create"]),
    ("nodes-proxy", ["nodes/proxy"], ["get"]),
    ("token-request", ["serviceaccounts/token"], ["create"]),
)


class CaseError(ValueError):
    """The case violates evals/schemas/case.schema.json."""


def load_schema(name):
    """Load a schema that sits next to this module; never a remote reference."""
    schema = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


_CASE_VALIDATOR = Draft202012Validator(load_schema("case.schema.json"), format_checker=FormatChecker())


def validate_case(case):
    errors = list(_CASE_VALIDATOR.iter_errors(case))
    if errors:
        first = min(errors, key=lambda e: (len(e.absolute_path), [str(p) for p in e.absolute_path]))
        raise CaseError(f"case invalid at {[str(p) for p in first.absolute_path]} ({first.validator})")
    # JSON Schema `$` also matches before a trailing newline; require an exact match for path-like ids.
    if not CASE_ID.fullmatch(case["case_id"]) or not SEED.fullmatch(case["seed"]):
        raise CaseError("case invalid at ['case_id' or 'seed'] (exact pattern)")
    return case


def scenario_case(path):
    """Build a case from a scenario directory's event.json, policy.yaml and evidence.json."""
    path = Path(path)
    return {
        "case_id": path.name.lower(),
        "seed": path.name,
        "description": f"Scenario {path.name} fixtures, unchanged",
        "event": load(path / "event.json"),
        "policy": load(path / "policy.yaml"),
        "evidence": load(path / "evidence.json"),
    }


def with_after_rules(case, rules, case_id, description):
    """Deep copy of `case` with the rules of its single after-version get_rbac_object entry replaced."""
    variant = deepcopy(case)
    try:
        wanted = {**variant["event"]["resource"], "version": variant["event"]["change"]["after_version"]}
        matches = [e for e in variant["evidence"] if e.get("tool") == "get_rbac_object" and e.get("arguments") == wanted]
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("case has no readable event or evidence list") from exc
    if len(matches) != 1:
        raise ValueError(f"expected exactly one after-version get_rbac_object entry, found {len(matches)}")
    matches[0]["data"]["rules"] = deepcopy(rules)
    variant["case_id"], variant["description"] = case_id, description
    return variant


def documented_f2_variants(s01_case):
    """The four documented F2 variants of the S01 case; the approval stays `approved: false`."""
    variants = []
    for slug, resources, verbs in _F2:
        rules = [deepcopy(_BASE_RULE), {"resources": list(resources), "verbs": list(verbs)}]
        description = f"F2: S01 after-version rules add {'/'.join(resources)} {','.join(verbs)}; approval stays approved:false"
        variants.append(with_after_rules(s01_case, rules, f"{s01_case['case_id']}-f2-{slug}", description))
    return variants


def case_digest(case):
    return "sha256:" + sha256(canonical(case).encode()).hexdigest()
