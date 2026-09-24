# One model adapter / 單一模型介面

`AnthropicModel` implements `choose_action` and `produce_result` through the fixed Anthropic Messages endpoint. The operator supplies a model ID and `ANTHROPIC_API_KEY`; event/model/evidence content cannot supply an endpoint, credential or tool grant.

The adapter follows the [Messages API](https://platform.claude.com/docs/en/api/messages) and the [official Python SDK request example](https://github.com/anthropics/anthropic-sdk-python). It uses httpx directly to keep response-byte and cancellation behavior explicit. It sends one user JSON envelope and a fixed system instruction, requests at most 4,096 output tokens, follows no redirects and performs no automatic retries. Invalid JSON, error envelopes (including HTTP 200 errors), refusal/truncation and unexpected blocks raise `ModelError`.

JSON-only prompting improves interoperability; it grants no permissions. Every parsed action/result still traverses the same deterministic checks as replay. The model cannot request HTTP itself. A real-provider response has no more authority than a hostile replay script.

## Tested boundary

Offline httpx transports test request headers/body, response limits, malformed and failed responses, deadline cancellation, unsupported tool rejection, preservation of replay-vs-provider provenance, and complete S01/S02 runs graded by the scenario evaluator, including an inverted-verdict negative control. Responses are scripted. These tests make no external calls and require no real API key.

## Not yet verified

No actual provider request was made during this delivery because no operator API credential was configured. Model availability, provider latency, actual-model S01–S08 behavior and detection accuracy remain unverified. Do not label the M6 mock tests as live acceptance.

To run an explicit live-provider check, install `.[anthropic]`, configure the key locally and select an available model with `--provider anthropic --model ...`. Use a fresh output directory and a reviewed policy with sufficient runtime/model-call headroom. The run still reads synthetic fixture evidence; it cannot prove live GKE support. Preserve the resulting audit and result as a distinct evidence bundle.
