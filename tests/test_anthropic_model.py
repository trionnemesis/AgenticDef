import asyncio
import json

import httpx
import pytest

from agenticdef.adapters.anthropic_model import AnthropicModel, ENDPOINT
from agenticdef.domain.errors import ModelError, PolicyError
from test_investigator import setup


def message(value):
    return {"type": "message", "stop_reason": "end_turn", "content": [{"type": "text", "text": json.dumps(value)}]}


def test_fixed_endpoint_and_protocol():
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=message({"type": "finish"}))
    model = AnthropicModel(model="operator-selected-model", api_key="test-placeholder", transport=httpx.MockTransport(handler))
    assert asyncio.run(model.choose_action({"evidence": []}, ("get_change_event",))) == {"type": "finish"}
    request = seen[0]
    assert str(request.url) == ENDPOINT and request.method == "POST"
    assert request.headers["anthropic-version"] == "2023-06-01"
    body = json.loads(request.content)
    assert body["max_tokens"] == 4096
    assert "tools" not in body


@pytest.mark.parametrize("response", [
    httpx.Response(401, json={"error": "unauthorized"}),
    httpx.Response(429, json={"error": "rate limit"}),
    httpx.Response(200, json={"type": "error", "error": {"message": "not a model response"}}),
    httpx.Response(200, json={"type": "message", "stop_reason": "max_tokens", "content": []}),
    httpx.Response(200, json={"type": "message", "stop_reason": "end_turn", "content": []}),
    httpx.Response(200, json=message({"type": "finish", "policy": {}})),
    httpx.Response(200, content=b"not-json"),
    httpx.Response(200, content=b"x" * 65537),
])
def test_invalid_responses_fail_without_retry(response):
    calls = []
    def handler(request): calls.append(request); return response
    model = AnthropicModel(model="test", api_key="test-placeholder", transport=httpx.MockTransport(handler))
    with pytest.raises(ModelError): asyncio.run(model.choose_action({}, ()))
    assert len(calls) == 1


def test_http_adapter_uses_same_authority_boundary(tmp_path):
    bad = {"type": "tool_request", "tool": "shell", "arguments": {}}
    model = AnthropicModel(model="test", api_key="test-placeholder", transport=httpx.MockTransport(lambda request: httpx.Response(200, json=message(bad))))
    inv, event, _, tools, _ = setup(tmp_path, model=model)
    record = asyncio.run(inv.run(event))
    assert record["result"]["termination_reason"] == "ToolNotAllowedError"
    assert not tools.executed
    assert record["metadata"]["model_provider"] == "anthropic_api"


def test_replay_record_cannot_masquerade_as_real_model(tmp_path):
    inv, event, _, _, _ = setup(tmp_path)
    asyncio.run(inv.run(event))
    model = AnthropicModel(model="test", api_key="test-placeholder", transport=httpx.MockTransport(lambda request: pytest.fail("must not call")))
    inv, event, _, _, _ = setup(tmp_path, model=model)
    with pytest.raises(PolicyError): asyncio.run(inv.run(event))


def test_real_adapter_budget_cancels_transport(tmp_path):
    cancelled = []
    async def handler(request):
        try: await asyncio.sleep(60)
        finally: cancelled.append(True)
    model = AnthropicModel(model="test", api_key="test-placeholder", transport=httpx.MockTransport(handler))
    inv, event, _, tools, _ = setup(tmp_path, model=model, changes={"max_runtime_seconds": 0.1})
    record = asyncio.run(inv.run(event))
    assert record["result"]["termination_reason"] == "BudgetError" and cancelled
    assert not tools.executed
