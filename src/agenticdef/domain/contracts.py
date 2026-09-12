"""Load only bundled schemas; never retrieve remote schema references."""
import json
from importlib.resources import files

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .errors import ContractError

ROOT = files("agenticdef").joinpath("contracts")
SCHEMAS = {p.name: json.loads(p.read_text()) for p in ROOT.iterdir() if p.name.endswith(".json")}
REGISTRY = Registry().with_resources((name, Resource.from_contents(value)) for name, value in SCHEMAS.items())


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ContractError("Not finite JSON / 非有效 JSON") from exc


def validate(name, value):
    if len(canonical(value).encode()) > 131072:
        raise ContractError("Contract byte limit / 契約大小超限")
    schema = SCHEMAS[name + ".schema.json"]
    errors = list(Draft202012Validator(schema, registry=REGISTRY, format_checker=FormatChecker()).iter_errors(value))
    if errors:
        raise ContractError(f"{name}: invalid at {list(errors[0].absolute_path)} / 格式不符")
    return value
