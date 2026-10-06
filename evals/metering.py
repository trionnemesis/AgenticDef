"""The metered transport of a live run. Normative text: evals/SPEC.md, section 11 (EV-LIVE-04, EV-LIVE-05).

Every request of a live run passes through `MeteredTransport`. It never retries,
checks each request against the protocol, refuses a call whose worst case could
overrun the caps, charges actual usage in exact decimal arithmetic, and stops
the run on the first anomaly: any exception after a call is sent stops the run,
not just the anticipated ones. Once stopped, no request reaches the inner
transport again. The protocol it receives has already been checked by
`evals.live.check_protocol`.
"""
import asyncio
from decimal import Decimal
from hashlib import sha256
import json

import httpx

MAX_RESPONSE_BYTES = 65536
# A cancellation is delivered once, so nothing else bounds a close awaited after the runtime deadline cancelled
# the request; this does, and so bounds how far a case can run past that deadline.
CLOSE_TIMEOUT_SECONDS = 1
# The largest integer a JSON number holds exactly; a usage count above it is invalid, which also keeps every
# charged cost finite (prices are at most 1000 USD per million tokens).
MAX_USAGE_COUNT = 2 ** 53 - 1
# live-run.schema.json bounds stop.detail; a longer detail is shortened to fit, keeping its start, its length and
# the SHA-256 of the full text.
MAX_DETAIL_CHARS = 500
_MILLION = Decimal(10 ** 6)
_USAGE_FIELDS = (("input_tokens", "input_usd_per_mtok", True), ("output_tokens", "output_usd_per_mtok", True),
                 ("cache_creation_input_tokens", "cache_write_usd_per_mtok", False),
                 ("cache_read_input_tokens", "cache_read_usd_per_mtok", False))


class LiveStopped(Exception):
    """A request refused or ended by a live-run stop condition."""


def _describe(value):
    """A JSON value for a stop detail: a scalar as its repr, an array or object by kind (its repr can recurse)."""
    if isinstance(value, list):
        return "a JSON array"
    if isinstance(value, dict):
        return "a JSON object"
    return repr(value)


def _bounded(detail):
    if len(detail) <= MAX_DETAIL_CHARS:
        return detail
    digest = sha256(detail.encode("utf-8", "surrogatepass")).hexdigest()
    suffix = f"... [{len(detail)} characters, sha256:{digest}]"
    return detail[:MAX_DETAIL_CHARS - len(suffix)] + suffix


def _count(usage, key, required):
    value = usage.get(key)
    if value is None and not required:
        return 0
    if type(value) is not int or not 0 <= value <= MAX_USAGE_COUNT:
        raise ValueError(key)
    return value


class MeteredTransport(httpx.AsyncBaseTransport):
    def __init__(self, protocol, *, connect):
        self._provider, self._caps = protocol["provider"], protocol["caps"]
        self._price = {key: Decimal(str(value)) for key, value in protocol["prices"].items()
                       if key.endswith("_per_mtok")}
        self._overhead = protocol["input_overhead_tokens"]
        self._connect = connect
        self._cost = Decimal(0)
        self._tokens = {key: 0 for key, _, _ in _USAGE_FIELDS}
        self._calls = self._worst_case_charged = 0
        self._statuses = {}
        self.stop = None

    def ledger(self):
        return {"calls": self._calls, "input_tokens": self._tokens["input_tokens"],
                "output_tokens": self._tokens["output_tokens"],
                "cache_write_tokens": self._tokens["cache_creation_input_tokens"],
                "cache_read_tokens": self._tokens["cache_read_input_tokens"], "cost_usd": float(self._cost),
                "worst_case_charged": self._worst_case_charged, "http_statuses": dict(sorted(self._statuses.items()))}

    def _latch(self, condition, detail):
        if self.stop is None:
            self.stop = {"condition": condition, "detail": _bounded(detail)}

    def _halt(self, condition, detail):
        self._latch(condition, detail)
        raise LiveStopped(f"live run stopped: {self.stop['condition']}: {self.stop['detail']}")

    def _check_request(self, request):
        try:
            body = json.loads(request.content)
        except Exception:  # any parse failure, including the parser's depth limit
            body = None
        if not isinstance(body, dict):
            self._halt("request_mismatch", "request body is not a JSON object")
        expected = {"url": self._provider["endpoint"], "model": self._provider["model"],
                    "max_tokens": self._provider["max_tokens"],
                    "anthropic-version": self._provider["anthropic_version"]}
        actual = {"url": str(request.url), "model": body.get("model"), "max_tokens": body.get("max_tokens"),
                  "anthropic-version": request.headers.get("anthropic-version")}
        for key in expected:
            if actual[key] != expected[key]:
                self._halt("request_mismatch", f"{key} is {_describe(actual[key])}, protocol says {expected[key]!r}")

    def _worst_case(self, body_bytes):
        bound = body_bytes + self._overhead
        input_price = max(self._price["input_usd_per_mtok"], self._price["cache_write_usd_per_mtok"],
                          self._price["cache_read_usd_per_mtok"])
        return bound, (bound * input_price + self._provider["max_tokens"] * self._price["output_usd_per_mtok"]) / _MILLION

    def _charge_worst_case(self, worst):
        self._cost += worst
        self._worst_case_charged += 1

    async def _exchange(self, request):
        """Open, send, read and close one request. An exception from the inner transport, from opening it to closing
        it even during a cancellation, is latched as transport_error before the next await, so nothing later can
        hide it. The close has its own bound (CLOSE_TIMEOUT_SECONDS), so it cannot outlast a deadline cancellation
        unchecked."""
        inner, failed, data = None, False, bytearray()
        try:
            inner = self._connect()
            response = await inner.handle_async_request(request)
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > MAX_RESPONSE_BYTES:
                    break
            await response.aclose()
        except Exception as exc:
            self._latch("transport_error", type(exc).__name__ if inner is not None
                        else f"opening the transport failed: {type(exc).__name__}")
            failed = True
        finally:
            if inner is not None:
                bound = asyncio.timeout(CLOSE_TIMEOUT_SECONDS)
                try:
                    async with bound:
                        await inner.aclose()
                except Exception as exc:
                    self._latch("transport_error", f"closing the transport took longer than {CLOSE_TIMEOUT_SECONDS} s"
                                if bound.expired() else f"closing the transport failed: {type(exc).__name__}")
                    failed = True
        if failed:
            self._halt("transport_error", "")
        return response, data

    async def handle_async_request(self, request):
        if self.stop is not None:
            raise LiveStopped(f"live run already stopped: {self.stop['condition']}")
        self._check_request(request)
        bound, worst = self._worst_case(len(request.content))
        if self._calls + 1 > self._caps["max_model_calls"]:
            self._halt("max_model_calls", f"call {self._calls + 1} exceeds the cap {self._caps['max_model_calls']}")
        if self._cost + worst > Decimal(str(self._caps["max_cost_usd"])):
            self._halt("max_cost_usd", f"spent {self._cost} + worst case {worst} exceeds {self._caps['max_cost_usd']}")
        self._calls += 1
        accounted = False
        try:
            response, data = await self._exchange(request)
            status = str(response.status_code)
            self._statuses[status] = self._statuses.get(status, 0) + 1
            if not 200 <= response.status_code < 300:
                self._halt("http_status", status)
            if len(data) > MAX_RESPONSE_BYTES:
                self._halt("response_too_large", f"more than {MAX_RESPONSE_BYTES} bytes")
            try:
                message = json.loads(data)
                usage = message["usage"]
                counts = {key: _count(usage, key, required) for key, _, required in _USAGE_FIELDS}
            except Exception:  # any parse or shape failure, including the parser's depth limit
                self._halt("usage_missing", "usage is missing or invalid")
            cost = sum((counts[key] * self._price[price] for key, price, _ in _USAGE_FIELDS), Decimal(0)) / _MILLION
            self._cost += cost
            accounted = True
            for key, value in counts.items():
                self._tokens[key] += value
            if message.get("model") != self._provider["model"]:
                self._halt("served_model_mismatch", f"served by {_describe(message.get('model'))}")
            input_side = (counts["input_tokens"] + counts["cache_creation_input_tokens"]
                          + counts["cache_read_input_tokens"])
            if input_side > bound or counts["output_tokens"] > self._provider["max_tokens"] or cost > worst:
                self._halt("worst_case_exceeded", f"{input_side} input tokens (bound {bound}), "
                                                  f"{counts['output_tokens']} output tokens, cost {cost} (worst {worst})")
            return httpx.Response(response.status_code, headers={"content-type": "application/json"},
                                  content=bytes(data))
        except LiveStopped:
            raise
        except Exception as exc:
            # A sent call either returns a fully checked response or stops the run, whatever went wrong.
            self._halt("response_unchecked", f"checking the response raised {type(exc).__name__}")
        finally:
            # Every sent call is charged exactly once: its actual usage above, otherwise its worst case here,
            # however the request ends (a stop, any exception, or a deadline cancellation).
            if not accounted:
                self._charge_worst_case(worst)

    async def aclose(self):
        """Each request opens and closes its own inner transport; there is nothing shared to close."""
