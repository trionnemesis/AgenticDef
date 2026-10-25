# Verification / 驗收證據

The source of truth is the [CI run](https://github.com/trionnemesis/AgenticDef/actions/workflows/ci.yml) for the exact commit, its JUnit and replay artifacts, and the [release](https://github.com/trionnemesis/AgenticDef/releases) assets. A green replay means the fixture assertions passed, not that a live environment is secure.

| Gate | Evidence |
|---|---|
| A — contracts | Valid events/policies/results/evidence; invalid dates, tools, statuses, references and extra fields rejected |
| B — authority | Registry/scope rejection before adapter execution; untrusted policy fields cannot grant shell; same check for HTTP model responses |
| C — grounding | S08 rejects fabricated IDs; incomplete conclusive findings rejected; evidence body/request digests verified |
| D — termination | All four budgets; synthesis counted; active model/tool cancellation; missing/non-callable evidence methods persist a failed terminal result before provider calls; terminal records reject subsequent work |
| E — replay | S01–S08 run locally without cloud credentials; structural status/risk/reason/method/forbidden-action assertions |
| F — idempotency | Repeated completed or adapter-contract-failed events return identical records without calls or writes; concurrent claim has one winner; crashed claim stays bounded |

Local development ran the contract gate before deterministic primitives, then the full replay before the real-provider adapter. Test results and the final test count are available in CI/JUnit rather than a manually maintained badge.

## Truthful completion boundary

The v0.2.1 regression `test_invalid_evidence_adapter_persists_failed_result`
removes or replaces each of the four required evidence methods with `None`.
It checks `ContractError`, `investigation_failed` / `FAILED`, zero provider
calls, an audit identifying the rejected tool, and an unchanged persisted
record on duplicate delivery, including after replacing the broken adapter.
Complete duck-typed adapters remain supported; event scope rejection still
precedes adapter validation. See the [patch decision and limits](release-v0.2.1.md).

* M0–M5: implemented and locally exercised through full regression and offline replay.
* M6: Anthropic adapter implemented; HTTP-contract and common-core integration exercised using mock transport. `tests/test_anthropic_evaluation.py` runs S01/S02 end to end through `AnthropicModel` (five exact reads, finish, grounded draft citing the evidence IDs the adapter actually sent) and grades the records with the replay evaluator. A referentially valid but inverted S01 verdict completes in the runtime and fails only the evaluator's status/risk checks; a fabricated reference over HTTP fails with `GroundingError`. These are **scripted mock HTTP responses over fixture evidence**, not live model accuracy or real prompt-injection resistance. The adapter skips `thinking`/`redacted_thinking` blocks (decision D8, option A); `tests/test_anthropic_model.py` pins that and every other response-shape rule.
* Actual model API use: **not tested** in this delivery. An opt-in, metered smoke protocol for `claude-sonnet-5-5` (decision D8) is committed under `evals/protocols/`; it has not been run.
* Live GCP/GKE evidence, event subscription, production deployment, remediation, multi-agent: **not implemented**, intentionally out of v0.2 scope.
* GitHub Pages and Release: only successful deployment/release records establish publication; their workflow files alone do not.

The v0.2 release is experimental and documents the live-provider gap. The supplied SPEC's local definition of done can be evaluated without a cluster. This does not claim all possible interpretations of live-model acceptance are satisfied.

## 2026-10-26 refactor acceptance

The [#26](https://github.com/trionnemesis/AgenticDef/issues/26) review compares
the original `4885652` baseline with the fixed capability contract
([#30](https://github.com/trionnemesis/AgenticDef/pull/30)) and the shared replay
helper extraction ([#31](https://github.com/trionnemesis/AgenticDef/pull/31)).
These are dated measurements, not a live-model result or a moving test badge.

| Check | Observed result |
|---|---|
| Local Python 3.12.14 baseline | 882 tests passed |
| Capability refactor alone | 893 tests passed |
| Replay helper refactor alone | 887 tests passed |
| Both refactors combined | 898 tests passed |
| S01–S08 with the same injected StepClock | All eight complete persisted records equal the baseline, including evidence, audit ordering, budgets and terminal results |
| Moved replay helpers | Both function ASTs identical to the baseline implementations |
| Capability negative controls | Tests reject deliberate schema-name drift, port-argument drift and an omitted approval read |
| HTTP cancellation proof | A controlled setup delay reproduces the old test failure; an injected budget clock keeps real timeout/cancellation and requires transport entry plus CancelledError |

The final exact-head CI runs for [#30](https://github.com/trionnemesis/AgenticDef/actions/runs/40214149917)
and [#31](https://github.com/trionnemesis/AgenticDef/actions/runs/40213489708)
provide Python 3.11/3.12, clean dev-extra and standalone-wheel evidence.
Their retained artifacts contain acceptance evidence; only a successful main
Pages deployment establishes website publication.

**Unresolved live boundary:** [#29](https://github.com/trionnemesis/AgenticDef/issues/29)
reproduces stale import-cached schema validation after a clean schema-only
revision change. This refactor does not fix that provenance defect. The paid
D8 protocol remains unrun; resolve #29 before exercising it.

## Reproduce

```bash
pip install -r requirements-dev.lock
pip install --no-deps -e .
python -m pytest -q --junitxml=results/junit.xml
replay scenarios --all --output results/acceptance
python -m build
```

Use a new output directory for a new execution. Reusing an existing directory intentionally exercises idempotency. Raw persisted records retain failed candidate results in audit; only the separately validated `result` is accepted.

## PR security questions

1. Capability added? Four fixture reads only; one optional model provider is not a fifth tool.
2. Can evidence influence authority? No; copied data cannot alter trusted policy/registry.
3. Can the model increase cost/runtime? No; per-call reservations, a response cap and cancellation apply.
4. Can failures become benign? Required evidence/model/grounding/persistence failures are unresolved or failed.
5. Nonexistent evidence accepted? Rejected before final result persistence.
6. Duplicate work amplification? Atomic local claim; running and terminal records prevent duplicate calls.
7. Write path? Local audit/evidence/result persistence and requested project publication only; no target mutation.
8. Replay-testable? All eight required scenarios plus negative boundary regressions are offline.
