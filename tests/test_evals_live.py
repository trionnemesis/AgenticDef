"""Live runs under a committed protocol (evals/SPEC.md, section 11; maintainer decision D8 in #2).

Bracketed ids trace to requirement ids in evals/SPEC.md. No test here opens a network connection: every
MeteredTransport gets an injected `connect` that returns an httpx.MockTransport, and the command tests replace
`live.network_transport` before it could build a real one.
"""
import asyncio
from collections import defaultdict
from copy import deepcopy
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import types

import httpx
import pytest
from jsonschema import Draft202012Validator, FormatChecker

from agenticdef.adapters.anthropic_model import ENDPOINT, AnthropicModel
from agenticdef.domain.errors import ModelError

from evals import live
from evals.baselines import DeterministicOracle
from evals.generate import generate
from evals.live import check_protocol, load_protocol, run_live
from evals.metering import LiveStopped, MeteredTransport
from evals.runner import EvalError

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "evals" / "protocols" / "d8-smoke-sonnet-5-5.json"
SHA = "0123456789abcdef0123456789abcdef01234567"
MODEL = "claude-sonnet-5-5"
LIVE_RUN = Draft202012Validator(json.loads((ROOT / "evals" / "schemas" / "live-run.schema.json").read_text(
    encoding="utf-8")), format_checker=FormatChecker())
OPT_IN = {"AGENTICDEF_LIVE_EVAL": "1", "ANTHROPIC_API_KEY": "test-placeholder"}


@pytest.fixture(scope="module")
def protocol():
    return load_protocol(SMOKE)


@pytest.fixture(scope="module")
def gen(protocol):
    return generate(generator_seed=protocol["set"]["generator_seed"],
                    holdout_fraction=protocol["set"]["holdout_fraction"])


def raw_protocol():
    return json.loads(SMOKE.read_text(encoding="utf-8"))


def envelope(request):
    return json.loads(json.loads(request.content)["messages"][0]["content"])


def sonnet_reply(value, request, *, model=MODEL, usage=None):
    """A Messages reply shaped like claude-sonnet-5-5 with adaptive thinking: an empty thinking block, then text."""
    if usage is None:
        usage = {"input_tokens": len(request.content) // 4, "output_tokens": 150,
                 "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    return {"type": "message", "model": model, "stop_reason": "end_turn", "usage": usage,
            "content": [{"type": "thinking", "thinking": "", "signature": "opaque"},
                        {"type": "text", "text": json.dumps(value)}]}


class OracleAPI:
    """Answers like a perfect model (the deterministic baseline), shaped as Sonnet replies; can fail on cue."""

    def __init__(self, fail=lambda number, request: False):
        self.calls, self.fail = [], fail

    async def __call__(self, request):
        self.calls.append(request)
        if self.fail(len(self.calls), request):
            return httpx.Response(529, json={"type": "error", "error": {"type": "overloaded_error"}})
        task, context = envelope(request)["task"], envelope(request)["untrusted_investigation_data"]
        baseline = DeterministicOracle()
        value = (await baseline.choose_action(context, ()) if task == "choose_action"
                 else await baseline.produce_result(context))
        return httpx.Response(200, json=sonnet_reply(value, request))


def metered(protocol, handler, **caps):
    changed = deepcopy(protocol)
    changed["caps"].update(caps)
    return MeteredTransport(changed, connect=lambda: httpx.MockTransport(handler))


def call(transport, model=MODEL):
    adapter = AnthropicModel(model=model, api_key="test-placeholder", transport=transport)
    return asyncio.run(adapter.choose_action({"evidence": []}, ("get_change_event",)))


def finish(request, **kwargs):
    return httpx.Response(200, json=sonnet_reply({"type": "finish"}, request, **kwargs))


# ------------------------------------------------------------------ protocol

def test_the_smoke_protocol_loads_with_a_canonical_digest(protocol):
    """[EV-LIVE-01] The committed protocol validates, and its digest is the SHA-256 of its canonical JSON."""
    assert protocol == raw_protocol()
    canonical = json.dumps(raw_protocol(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert check_protocol(protocol) == "sha256:" + sha256(canonical.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("breaker", [
    pytest.param(lambda p: p.update(extra=1), id="extra-key"),
    pytest.param(lambda p: p.pop("caps"), id="missing-caps"),
    pytest.param(lambda p: p["provider"].update(extra=1), id="provider-extra"),
    pytest.param(lambda p: p["provider"].update(retries=1), id="retries"),
    pytest.param(lambda p: p["provider"].update(fallbacks="default"), id="fallbacks"),
    pytest.param(lambda p: p["caps"].update(max_cost_usd=0), id="zero-cap"),
    pytest.param(lambda p: p["caps"].update(max_cost_usd="10"), id="string-cap"),
    pytest.param(lambda p: p["set"].update(families=[]), id="no-families"),
    pytest.param(lambda p: p["set"]["families"].append(p["set"]["families"][0]), id="duplicate-family"),
    pytest.param(lambda p: p.update(protocol_id="Bad Id"), id="protocol-id"),
    pytest.param(lambda p: p["prices"].update(as_of="25 Sep 2026"), id="as-of"),
    pytest.param(lambda p: p.update(k=0), id="k"),
])
def test_protocol_schema_violations_raise(tmp_path, breaker):
    """[EV-LIVE-01] Unknown, missing or out-of-range protocol fields raise, from a dict or from a file."""
    broken = raw_protocol()
    breaker(broken)
    with pytest.raises(EvalError, match="schema"):
        check_protocol(broken)
    path = tmp_path / "protocol.json"
    path.write_text(json.dumps(broken), encoding="utf-8")
    with pytest.raises(EvalError, match="schema"):
        load_protocol(path)


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_numbers_in_a_protocol_file_raise(tmp_path, token):
    """[EV-LIVE-01] Python's json accepts NaN and Infinity; a protocol file containing them is refused."""
    text = SMOKE.read_text(encoding="utf-8").replace('"cache_read_usd_per_mtok": 0.2',
                                                       f'"cache_read_usd_per_mtok": {token}')
    assert token in text
    path = tmp_path / "protocol.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(EvalError, match="finite"):
        load_protocol(path)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
@pytest.mark.parametrize("section, key", [("prices", "cache_read_usd_per_mtok"), ("caps", "max_cost_usd"),
                                          ("set", "holdout_fraction")])
def test_non_finite_numbers_in_a_protocol_dict_raise(value, section, key):
    """[EV-LIVE-01] The schema's numeric bounds cannot reject NaN, so non-finite numbers are refused first."""
    broken = raw_protocol()
    broken[section][key] = value
    with pytest.raises(EvalError, match=f"{section}.{key} is not a finite number"):
        check_protocol(broken)


def test_a_protocol_file_that_is_not_json_raises(tmp_path):
    """[EV-LIVE-01] A protocol file must be JSON."""
    path = tmp_path / "protocol.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(EvalError, match="JSON"):
        load_protocol(path)


def _holdout_family(gen):
    return next(e["family"] for e in gen["entries"] if e["split"] == "holdout")


@pytest.mark.parametrize("breaker, match", [
    pytest.param(lambda p, g: p["provider"].update(endpoint="https://example.invalid/v1/messages"), "endpoint",
                 id="endpoint"),
    pytest.param(lambda p, g: p["provider"].update(anthropic_version="2024-01-01"), "anthropic_version",
                 id="anthropic-version"),
    pytest.param(lambda p, g: p["provider"].update(max_tokens=8192), "max_tokens", id="max-tokens"),
    pytest.param(lambda p, g: p["set"].update(generator_version="rbac-gen-1"), "generator_version", id="generator"),
    pytest.param(lambda p, g: p["set"].update(oracle_version="rbac-oracle-0"), "oracle_version", id="oracle"),
    pytest.param(lambda p, g: p["set"]["families"].__setitem__(0, "f-0000000000"), "famil", id="unknown-family"),
    pytest.param(lambda p, g: p["set"]["families"].__setitem__(0, _holdout_family(g)), "split", id="wrong-split"),
    pytest.param(lambda p, g: p["set"].update(cases=24), "cases", id="case-count"),
    pytest.param(lambda p, g: p["caps"].update(max_model_calls=p["caps"]["max_model_calls"] + 1),
                 "max_model_calls", id="call-cap-above-the-policy-maximum"),
])
def test_a_protocol_that_does_not_describe_the_code_raises(gen, breaker, match):
    """[EV-LIVE-02] Schema-valid but untrue protocols raise: the provider fields must be what the adapter sends,
    and the set fields must regenerate to the named families and case count."""
    broken = raw_protocol()
    breaker(broken, gen)
    with pytest.raises(EvalError, match=match):
        check_protocol(broken)


def test_the_smoke_protocol_records_decision_d8(protocol, gen):
    """[EV-LIVE-07] Model, split, k, caps, prices and the fixed three-family rule of decision D8."""
    families = defaultdict(list)
    for entry in gen["entries"]:
        families[entry["family"]].append(entry)
    picks = {}
    for family_id, entries in sorted(families.items()):
        if entries[0]["split"] == "dev":
            label = next(e for e in entries if e["variant"] == "base")["oracle"]["label"]
            picks.setdefault(label, family_id)
    assert set(picks) == {"suspicious", "benign", "unresolved"}
    assert protocol["set"]["families"] == sorted(picks.values())
    cases = [entry for family_id in picks.values() for entry in families[family_id]]
    assert protocol["set"]["cases"] == len(cases) == 20
    assert protocol["caps"] == {"max_cost_usd": 10,
                                "max_model_calls": sum(e["case"]["policy"]["max_model_calls"] for e in cases)}
    assert protocol["provider"] == {"endpoint": ENDPOINT, "anthropic_version": "2023-06-01", "model": MODEL,
                                    "max_tokens": 4096, "thinking": "api_default", "effort": "api_default",
                                    "fallbacks": "none", "retries": 0}
    assert (protocol["set"]["split"], protocol["k"], protocol["purpose"]) == ("dev", 1, "smoke")
    prices = {key: value for key, value in protocol["prices"].items() if key.endswith("per_mtok")}
    assert prices == {"input_usd_per_mtok": 2.0, "output_usd_per_mtok": 10.0, "cache_write_usd_per_mtok": 2.5,
                      "cache_read_usd_per_mtok": 0.2}
    assert protocol["prices"]["as_of"] == "2026-09-25"


# ------------------------------------------------------------------ metering

def test_metering_charges_every_token_kind_at_the_protocol_price(protocol):
    """[EV-LIVE-04] A Sonnet-shaped reply (thinking block plus text) passes, and every token kind is charged."""
    usage = {"input_tokens": 1000, "output_tokens": 200, "cache_creation_input_tokens": 10,
             "cache_read_input_tokens": 20}
    transport = metered(protocol, lambda request: finish(request, usage=usage))
    assert call(transport) == {"type": "finish"} and call(transport) == {"type": "finish"}
    price = {key: Decimal(str(value)) for key, value in protocol["prices"].items() if key.endswith("per_mtok")}
    one = (1000 * price["input_usd_per_mtok"] + 200 * price["output_usd_per_mtok"]
           + 10 * price["cache_write_usd_per_mtok"] + 20 * price["cache_read_usd_per_mtok"]) / 10 ** 6
    assert transport.ledger() == {"calls": 2, "input_tokens": 2000, "output_tokens": 400, "cache_write_tokens": 20,
                                  "cache_read_tokens": 40, "cost_usd": float(2 * one), "worst_case_charged": 0,
                                  "http_statuses": {"200": 2}}
    assert transport.stop is None


def test_a_call_whose_worst_case_could_pass_the_cost_cap_is_never_sent(protocol):
    """[EV-LIVE-04] [EV-LIVE-05] The cap is checked against the worst case before sending, so it cannot be
    overrun; the refusal stops the run and fails the call closed."""
    sent = []
    transport = metered(protocol, lambda request: sent.append(request), max_cost_usd=0.01)
    with pytest.raises(ModelError):
        call(transport)
    assert sent == [] and transport.stop["condition"] == "max_cost_usd"
    assert transport.ledger()["calls"] == 0 and transport.ledger()["cost_usd"] == 0


def test_the_cost_cap_admits_a_call_whose_worst_case_fits(protocol):
    """[EV-LIVE-04] The worst case is (body bytes + overhead) at the larger input price plus max_tokens at the
    output price; a cap just above it lets the call through, a cap just below refuses it."""
    seen = []
    probe = metered(protocol, lambda request: seen.append(len(request.content)) or finish(request))
    call(probe)
    price = {key: Decimal(str(value)) for key, value in protocol["prices"].items() if key.endswith("per_mtok")}
    worst = ((seen[0] + protocol["input_overhead_tokens"])
             * max(price["input_usd_per_mtok"], price["cache_write_usd_per_mtok"])
             + protocol["provider"]["max_tokens"] * price["output_usd_per_mtok"]) / 10 ** 6
    admitted = metered(protocol, finish, max_cost_usd=float(worst) + 1e-9)
    assert call(admitted) == {"type": "finish"} and admitted.stop is None
    refused = metered(protocol, finish, max_cost_usd=float(worst) - 1e-9)
    with pytest.raises(ModelError):
        call(refused)
    assert refused.stop["condition"] == "max_cost_usd"


INPUT_SIDE = {"input_usd_per_mtok": "input_tokens", "cache_write_usd_per_mtok": "cache_creation_input_tokens",
              "cache_read_usd_per_mtok": "cache_read_input_tokens"}


@pytest.mark.parametrize("largest", sorted(INPUT_SIDE))
def test_the_worst_case_prices_input_at_the_largest_input_side_rate(protocol, largest):
    """[EV-LIVE-04] Whichever input-side price is largest, the preflight bound uses it: a cap just below that
    worst case refuses the call, and a reply billing every input token at that rate stays within a cap just
    above it."""
    changed = deepcopy(protocol)
    for key in INPUT_SIDE:
        changed["prices"][key] = 50.0 if key == largest else 1.0
    seen = []
    probe = MeteredTransport(changed, connect=lambda: httpx.MockTransport(
        lambda r: seen.append(len(r.content)) or finish(r, usage=_usage(input_tokens=0, output_tokens=0))))
    call(probe)
    bound = seen[0] + changed["input_overhead_tokens"]
    max_tokens = changed["provider"]["max_tokens"]
    worst = (bound * Decimal(50) + max_tokens * Decimal(str(changed["prices"]["output_usd_per_mtok"]))) / 10 ** 6
    dearest = {**_usage(input_tokens=0, output_tokens=max_tokens), INPUT_SIDE[largest]: bound}
    below = deepcopy(changed)
    below["caps"]["max_cost_usd"] = float(worst) - 1e-9
    refused = MeteredTransport(below, connect=lambda: httpx.MockTransport(lambda r: finish(r, usage=dearest)))
    with pytest.raises(ModelError):
        call(refused)
    assert refused.stop["condition"] == "max_cost_usd" and refused.ledger()["calls"] == 0
    above = deepcopy(changed)
    above["caps"]["max_cost_usd"] = float(worst) + 1e-9
    admitted = MeteredTransport(above, connect=lambda: httpx.MockTransport(lambda r: finish(r, usage=dearest)))
    assert call(admitted) == {"type": "finish"} and admitted.stop is None
    assert admitted.ledger()["cost_usd"] <= above["caps"]["max_cost_usd"]


def test_the_call_cap_stops_the_run_and_later_calls_never_reach_the_api(protocol):
    """[EV-LIVE-04] [EV-LIVE-05] One call over max_model_calls is refused; every later request is refused too."""
    sent = []
    transport = metered(protocol, lambda request: sent.append(request) or finish(request), max_model_calls=1)
    assert call(transport) == {"type": "finish"}
    for _ in range(2):
        with pytest.raises(ModelError):
            call(transport)
    assert len(sent) == 1 and transport.stop["condition"] == "max_model_calls"


def _raise_connect_error(request):
    raise httpx.ConnectError("connection refused", request=request)


def _usage(**changes):
    usage = {"input_tokens": 100, "output_tokens": 50, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    usage.update(changes)
    return usage


@pytest.mark.parametrize("handler, condition, statuses, charged", [
    pytest.param(lambda r: httpx.Response(429, json={"type": "error"}), "http_status", {"429": 1}, 1, id="429"),
    pytest.param(lambda r: httpx.Response(500, json={"type": "error"}), "http_status", {"500": 1}, 1, id="500"),
    pytest.param(_raise_connect_error, "transport_error", {}, 1, id="connect-error"),
    pytest.param(lambda r: httpx.Response(200, content=b"x" * 65537), "response_too_large", {"200": 1}, 1,
                 id="too-large"),
    pytest.param(lambda r: httpx.Response(200, content=b"not json"), "usage_missing", {"200": 1}, 1, id="not-json"),
    pytest.param(lambda r: httpx.Response(200, json={**sonnet_reply({"type": "finish"}, r), "usage": None}),
                 "usage_missing", {"200": 1}, 1, id="null-usage"),
    pytest.param(lambda r: finish(r, usage={"output_tokens": 5}), "usage_missing", {"200": 1}, 1,
                 id="no-input-tokens"),
    pytest.param(lambda r: finish(r, usage=_usage(output_tokens="50")), "usage_missing", {"200": 1}, 1,
                 id="string-tokens"),
    pytest.param(lambda r: finish(r, usage=_usage(input_tokens=-1)), "usage_missing", {"200": 1}, 1,
                 id="negative-tokens"),
    pytest.param(lambda r: finish(r, usage=_usage(cache_read_input_tokens=True)), "usage_missing", {"200": 1}, 1,
                 id="bool-tokens"),
    pytest.param(lambda r: finish(r, model="claude-opus-5-5"), "served_model_mismatch", {"200": 1}, 0,
                 id="other-model"),
    pytest.param(lambda r: httpx.Response(200, json={k: v for k, v in sonnet_reply({"type": "finish"}, r).items()
                                                     if k != "model"}), "served_model_mismatch", {"200": 1}, 0,
                 id="no-model"),
    pytest.param(lambda r: finish(r, usage=_usage(input_tokens=10 ** 6)), "worst_case_exceeded", {"200": 1}, 0,
                 id="input-above-bound"),
    pytest.param(lambda r: finish(r, usage=_usage(output_tokens=4097)), "worst_case_exceeded", {"200": 1}, 0,
                 id="output-above-max-tokens"),
])
def test_post_response_stop_conditions(protocol, handler, condition, statuses, charged):
    """[EV-LIVE-04] [EV-LIVE-05] Each post-response condition stops the run on the first call, charges spend
    conservatively, and later requests never reach the API."""
    sent = []
    transport = metered(protocol, lambda request: sent.append(request) or handler(request))
    for _ in range(2):
        with pytest.raises(ModelError):
            call(transport)
    ledger = transport.ledger()
    assert len(sent) == 1 and transport.stop["condition"] == condition
    assert (ledger["calls"], ledger["http_statuses"], ledger["worst_case_charged"]) == (1, statuses, charged)
    assert ledger["cost_usd"] > 0


def test_a_call_cancelled_by_the_runtime_deadline_is_charged_its_worst_case(protocol):
    """[EV-LIVE-04] A sent request cancelled mid-flight may still be billed: it is charged its worst case, and the
    run is not stopped, because a deadline is a run outcome rather than an anomaly."""
    async def slow(request):
        await asyncio.sleep(5)
        return finish(request)

    transport = metered(protocol, slow)
    adapter = AnthropicModel(model=MODEL, api_key="test-placeholder", transport=transport)
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(asyncio.wait_for(adapter.choose_action({"evidence": []}, ("get_change_event",)), timeout=0.05))
    ledger = transport.ledger()
    assert transport.stop is None and (ledger["calls"], ledger["worst_case_charged"]) == (1, 1)
    assert ledger["cost_usd"] > 0 and ledger["http_statuses"] == {}


@pytest.mark.parametrize("content", [b"not json", b"[1, 2]", b'"text"'])
def test_a_request_body_that_is_not_a_json_object_is_never_sent(protocol, content):
    """[EV-LIVE-04] Anything but the adapter's JSON object request stops the run before it is sent."""
    sent = []
    transport = metered(protocol, lambda request: sent.append(request))
    request = httpx.Request("POST", ENDPOINT, content=content, headers={"anthropic-version": "2023-06-01"})
    with pytest.raises(LiveStopped, match="request_mismatch"):
        asyncio.run(transport.handle_async_request(request))
    assert sent == [] and transport.stop["condition"] == "request_mismatch"


@pytest.mark.parametrize("field, value", [
    ("model", "claude-opus-5-5"), ("max_tokens", 8192), ("anthropic_version", "2024-01-01"),
    ("endpoint", "https://example.invalid/v1/messages"),
])
def test_a_request_that_differs_from_the_protocol_is_never_sent(protocol, field, value):
    """[EV-LIVE-04] The URL, model, max_tokens and anthropic-version the adapter sends must be the protocol's."""
    changed = deepcopy(protocol)
    changed["provider"][field] = value
    if field == "model":
        changed["provider"]["model"] = MODEL
    sent = []
    transport = MeteredTransport(changed, connect=lambda: httpx.MockTransport(lambda r: sent.append(r)))
    with pytest.raises(ModelError):
        call(transport, model=value if field == "model" else MODEL)
    assert sent == [] and transport.stop["condition"] == "request_mismatch"


# ------------------------------------------------------------------ driver

def _run(protocol, tmp_path, api):
    return run_live(protocol, output_dir=tmp_path / "live", api_key="test-placeholder", repo_sha=SHA,
                    connect=lambda: httpx.MockTransport(api))


@pytest.fixture(scope="module")
def completed(protocol, tmp_path_factory):
    api, tmp_path = OracleAPI(), tmp_path_factory.mktemp("completed")
    return api, tmp_path, _run(protocol, tmp_path, api)


def test_a_completed_run_writes_a_validated_live_run_with_metrics(protocol, completed):
    """[EV-LIVE-06] One live provider over the protocol's families, real clock, records under runs/, and a
    schema-valid live-run.json equal to the returned result."""
    api, tmp_path, result = completed
    assert result["status"] == "completed" and result["stop"] is None
    assert json.loads((tmp_path / "live" / "live-run.json").read_text(encoding="utf-8")) == result
    assert list(LIVE_RUN.iter_errors(result)) == []
    metrics = result["metrics"]
    provider = metrics["providers"][0]
    assert (provider["name"], provider["mode"], provider["model_provider"]) == (
        protocol["protocol_id"], "live", "anthropic_api")
    assert (metrics["cases"], metrics["families"], metrics["k"], metrics["clock"]) == (20, 3, 1, "system")
    assert provider["splits"]["all"]["verdict_accuracy"]["rate"] == 1.0
    assert provider["splits"]["holdout"]["cases"] == 0
    assert result["ledger"]["calls"] == len(api.calls) and result["ledger"]["http_statuses"] == {"200": len(api.calls)}
    assert (result["protocol"], result["protocol_digest"], result["repo_sha"]) == (
        protocol, check_protocol(protocol), SHA)
    assert sorted(path.name for path in (tmp_path / "live").iterdir()) == ["live-run.json", "runs"]


def test_a_stop_aborts_before_the_next_case_and_reports_no_metrics(protocol, tmp_path):
    """[EV-LIVE-05] [EV-LIVE-06] After the failing call nothing reaches the API, and no partial metrics appear."""
    api = OracleAPI(fail=lambda number, request: number == 10)
    result = _run(protocol, tmp_path, api)
    assert (result["status"], result["metrics"], result["stop"]["condition"]) == ("stopped", None, "http_status")
    assert len(api.calls) == 10 and result["ledger"]["http_statuses"] == {"200": 9, "529": 1}
    started = list((tmp_path / "live" / "runs" / protocol["protocol_id"] / "t0").iterdir())
    first_calls = [r for r in api.calls if envelope(r)["task"] == "choose_action"
                   and not envelope(r)["untrusted_investigation_data"]["evidence"]]
    assert len(started) == len(first_calls) < protocol["set"]["cases"], "no case may start after the stop"
    assert list(LIVE_RUN.iter_errors(result)) == []


def test_a_stop_on_the_last_call_still_withholds_metrics(protocol, completed, tmp_path):
    """[EV-LIVE-05] A stop with no later case to abort still makes the run stopped, never completed."""
    total = len(completed[0].calls)
    api = OracleAPI(fail=lambda number, request: number == total)
    result = _run(protocol, tmp_path, api)
    assert (result["status"], result["metrics"], result["stop"]["condition"]) == ("stopped", None, "http_status")
    assert len(api.calls) == total and envelope(api.calls[-1])["task"] == "produce_result"


def test_run_live_refuses_an_existing_output_dir_or_an_untrue_protocol(protocol, tmp_path):
    """[EV-LIVE-06] [EV-LIVE-02] Nothing is written or called for a used directory or a protocol that fails its
    checks."""
    api = OracleAPI()
    (tmp_path / "live").mkdir()
    with pytest.raises(EvalError, match="exist"):
        _run(protocol, tmp_path, api)
    assert list((tmp_path / "live").iterdir()) == []
    broken = deepcopy(protocol)
    broken["set"]["cases"] = 21
    with pytest.raises(EvalError, match="cases"):
        run_live(broken, output_dir=tmp_path / "other", api_key="test-placeholder", repo_sha=SHA,
                 connect=lambda: httpx.MockTransport(api))
    assert api.calls == [] and not (tmp_path / "other").exists()


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda r: r.update(metrics=None), id="completed-without-metrics"),
    pytest.param(lambda r: r.update(stop={"condition": "http_status", "detail": "x"}), id="completed-with-stop"),
    pytest.param(lambda r: r.update(status="stopped"), id="stopped-with-metrics"),
    pytest.param(lambda r: r.update(extra=1), id="extra"),
    pytest.param(lambda r: r["ledger"].update(cost_usd=-1), id="negative-cost"),
    pytest.param(lambda r: r["ledger"]["http_statuses"].update({"abc": 1}), id="status-key"),
])
def test_the_live_run_schema_ties_status_stop_and_metrics(completed, mutate):
    """[EV-LIVE-06] A completed run has metrics and no stop; a stopped run the reverse; no other shape passes."""
    result = deepcopy(completed[2])
    mutate(result)
    assert list(LIVE_RUN.iter_errors(result))


# ------------------------------------------------------------------ command (opt-in)

@pytest.fixture
def offline_git(monkeypatch):
    status = {"porcelain": ""}
    monkeypatch.setattr(live, "git_status", lambda: status["porcelain"])
    monkeypatch.setattr(live, "current_repo_sha", lambda: SHA)
    monkeypatch.setattr(live, "committed_bytes", lambda path: Path(path).read_bytes())
    monkeypatch.setattr(live, "check_runtime_sources", lambda: None)
    return status


def _module(name, file):
    module = types.ModuleType(name)
    if file is not None:
        module.__file__ = str(file)
    return module


def _checkout_modules():
    return {"agenticdef": _module("agenticdef", ROOT / "src" / "agenticdef" / "__init__.py"),
            "agenticdef.adapters.anthropic_model": _module("x", ROOT / "src" / "agenticdef" / "adapters" / "a.py"),
            "evals.live": _module("evals.live", ROOT / "evals" / "live.py"),
            "agenticdef._namespace": _module("agenticdef._namespace", None),
            "json": _module("json", "/usr/lib/python3/json/__init__.py"), "broken": None}


def test_runtime_modules_from_this_checkout_pass():
    """[EV-LIVE-03] agenticdef and evals modules under this checkout pass; other modules are not judged."""
    live.check_runtime_sources(modules=_checkout_modules())


@pytest.mark.parametrize("name, file", [
    ("agenticdef.application.investigate", "/usr/lib/python3/site-packages/agenticdef/application/investigate.py"),
    ("agenticdef", ROOT / "build" / "lib" / "agenticdef" / "__init__.py"),
    ("evals.metering", "/elsewhere/evals/metering.py"),
])
def test_a_runtime_module_loaded_from_elsewhere_refuses_the_run(name, file):
    """[EV-LIVE-03] If the runtime came from an installed wheel or another path, repo_sha would not name the
    code that ran, so the run is refused."""
    modules = {**_checkout_modules(), name: _module(name, file)}
    with pytest.raises(EvalError, match="not from this checkout"):
        live.check_runtime_sources(modules=modules)


def test_the_command_refuses_runtime_code_from_elsewhere(tmp_path, monkeypatch, offline_git):
    """[EV-LIVE-03] The command exits 2 before any transport exists when the runtime is not this checkout."""
    monkeypatch.setattr(live, "network_transport", lambda: pytest.fail("network transport constructed"))

    def elsewhere():
        raise EvalError("module agenticdef is loaded from /site-packages, not from this checkout")

    monkeypatch.setattr(live, "check_runtime_sources", elsewhere)
    assert live.main(_argv(tmp_path), env=OPT_IN) == 2
    assert not (tmp_path / "out").exists()


def _git(root, *args):
    subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                    *args], cwd=root, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "protocol.json").write_text("{}", encoding="utf-8")
    (root / ".gitignore").write_text("ignored.json\n", encoding="utf-8")
    (root / "nested").mkdir()
    (root / "nested" / "inner.json").write_text("{}", encoding="utf-8")
    _git(root, "add", "protocol.json", ".gitignore", "nested/inner.json")
    _git(root, "commit", "-q", "-m", "protocol")
    (tmp_path / "outside.json").write_text("{}", encoding="utf-8")
    return root


def test_a_protocol_committed_at_head_yields_its_committed_bytes(repo):
    """[EV-LIVE-03] A tracked, unchanged protocol inside the repository passes and its HEAD bytes are used."""
    assert live.committed_bytes(repo / "protocol.json", root=repo) == b"{}"
    assert live.committed_bytes(repo / "sub" / ".." / "protocol.json", root=repo) == b"{}"


def _write(root, name, text="{}"):
    (root / name).write_text(text, encoding="utf-8")
    return root / name


def _link(root):
    (root / "link.json").symlink_to(root.parent / "outside.json")
    return root / "link.json"


@pytest.mark.parametrize("make, match", [
    pytest.param(lambda root: _write(root, "untracked.json"), "not committed at HEAD", id="untracked"),
    pytest.param(lambda root: _write(root, "ignored.json"), "not committed at HEAD", id="ignored"),
    pytest.param(lambda root: _write(root, "protocol.json", '{"edited": true}'), "differs from its committed",
                 id="edited"),
    pytest.param(lambda root: root.parent / "outside.json", "outside the repository", id="outside"),
    pytest.param(_link, "outside the repository", id="symlink-to-outside"),
    pytest.param(lambda root: root, "not committed at HEAD", id="repository-root"),
    pytest.param(lambda root: root / "nested", "not a readable file", id="tracked-directory"),
])
def test_only_a_protocol_committed_at_head_can_start_a_run(repo, make, match):
    """[EV-LIVE-03] A clean tree is not enough: an untracked, ignored, edited, outside or symlinked-outside
    protocol has no committed version at HEAD and is refused."""
    with pytest.raises(EvalError, match=match):
        live.committed_bytes(make(repo), root=repo)


def _argv(tmp_path, spend="10", protocol_path=SMOKE):
    return ["--protocol", str(protocol_path), "--output-dir", str(tmp_path / "out"), "--confirm-spend", spend]


@pytest.mark.parametrize("env, spend, porcelain", [
    pytest.param({"ANTHROPIC_API_KEY": "test-placeholder"}, "10", "", id="no-opt-in"),
    pytest.param({**OPT_IN, "AGENTICDEF_LIVE_EVAL": "true"}, "10", "", id="opt-in-not-1"),
    pytest.param({"AGENTICDEF_LIVE_EVAL": "1"}, "10", "", id="no-key"),
    pytest.param({**OPT_IN, "ANTHROPIC_API_KEY": ""}, "10", "", id="empty-key"),
    pytest.param(OPT_IN, "9.99", "", id="spend-below-cap"),
    pytest.param(OPT_IN, "100", "", id="spend-above-cap"),
    pytest.param(OPT_IN, "ten", "", id="spend-not-a-number"),
    pytest.param(OPT_IN, "10", " M evals/live.py\n", id="dirty-tree"),
    pytest.param(OPT_IN, "10", "?? evals/protocols/new.json\n", id="untracked-file"),
])
def test_the_command_refuses_without_every_opt_in(tmp_path, monkeypatch, offline_git, env, spend, porcelain):
    """[EV-LIVE-03] Without the env opt-in, a key, the exact spend confirmation and a clean tree, the command
    exits 2 before building a network transport or creating the output directory."""
    monkeypatch.setattr(live, "network_transport", lambda: pytest.fail("network transport constructed"))
    offline_git["porcelain"] = porcelain
    assert live.main(_argv(tmp_path, spend), env=env) == 2
    assert not (tmp_path / "out").exists()


def test_the_command_refuses_an_uncommitted_protocol(tmp_path, monkeypatch, offline_git):
    """[EV-LIVE-03] A protocol without a committed version at HEAD exits 2 before any transport exists."""
    monkeypatch.setattr(live, "network_transport", lambda: pytest.fail("network transport constructed"))

    def uncommitted(path):
        raise EvalError(f"protocol {path} is not committed at HEAD")

    monkeypatch.setattr(live, "committed_bytes", uncommitted)
    assert live.main(_argv(tmp_path), env=OPT_IN) == 2
    assert not (tmp_path / "out").exists()


def test_the_command_refuses_an_untrue_protocol(tmp_path, monkeypatch, offline_git):
    """[EV-LIVE-03] [EV-LIVE-02] A protocol that fails its checks exits 2 before any transport exists."""
    monkeypatch.setattr(live, "network_transport", lambda: pytest.fail("network transport constructed"))
    broken = raw_protocol()
    broken["set"]["cases"] = 21
    path = tmp_path / "protocol.json"
    path.write_text(json.dumps(broken), encoding="utf-8")
    assert live.main(_argv(tmp_path, protocol_path=path), env=OPT_IN) == 2
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("fail, code, status", [
    pytest.param(lambda number, request: False, 0, "completed", id="completed"),
    pytest.param(lambda number, request: number == 3, 1, "stopped", id="stopped"),
])
def test_the_command_runs_with_every_opt_in(tmp_path, monkeypatch, offline_git, capsys, fail, code, status):
    """[EV-LIVE-03] [EV-LIVE-06] With every opt-in the command runs, prints status, stop and ledger, and exits 0
    only for a completed run."""
    api = OracleAPI(fail=fail)
    monkeypatch.setattr(live, "network_transport", lambda: httpx.MockTransport(api))
    assert live.main(_argv(tmp_path), env=OPT_IN) == code
    printed = json.loads(capsys.readouterr().out)
    assert set(printed) == {"status", "stop", "ledger"} and printed["status"] == status
    assert json.loads((tmp_path / "out" / "live-run.json").read_text(encoding="utf-8"))["status"] == status
