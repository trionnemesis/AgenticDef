# AgenticDef v0.2.0 — bounded investigation proof

First experimental implementation of the supplied v0.2 specification.

* Normative contracts, trusted exact-scope policy, pre-call budgets and explicit terminal states.
* Exactly four fixture-backed read-only capabilities, content-addressed evidence and grounding validation.
* Shared investigator core, atomic local idempotency, persisted audit/evidence/results.
* S01–S08 offline replay, structural assertions and security boundary regressions.
* Optional Anthropic Messages adapter, bounded transport and offline protocol/core integration tests.
* English/Traditional Chinese README, static introduction, reproducible CI evidence and source/wheel distributions.

Install the attached wheel plus dependencies, or extract the source distribution for the scenarios and tests. Replay requires no network after installation. SHA256SUMS covers the attached distributions and replay summary.

**Validation boundary:** synthetic replay and HTTP mocks are exercised; actual Anthropic API calls, live GKE evidence and model detection accuracy are not validated. Cloud deployment, remediation, multi-agent and production operation are not implemented. This release is not a production SOC service.
