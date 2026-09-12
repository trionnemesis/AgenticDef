# Verification / 驗收證據

The source of truth is the [CI run](https://github.com/trionnemesis/AgenticDef/actions/workflows/ci.yml) for the exact commit, its JUnit and replay artifacts, and the [release](https://github.com/trionnemesis/AgenticDef/releases) assets. A green replay means the fixture assertions passed, not that a live environment is secure.

| Gate | Evidence |
|---|---|
| A — contracts | Valid events/policies/results/evidence; invalid dates, tools, statuses, references and extra fields rejected |
| B — authority | Registry/scope rejection before adapter execution; untrusted policy fields cannot grant shell; same check for HTTP model responses |
| C — grounding | S08 rejects fabricated IDs; incomplete conclusive findings rejected; evidence body/request digests verified |
| D — termination | All four budgets; synthesis counted; active model/tool cancellation; terminal records reject subsequent work |
| E — replay | S01–S08 run locally without cloud credentials; structural status/risk/reason/method/forbidden-action assertions |
| F — idempotency | Repeated completed events return identical records; concurrent claim has one winner; crashed claim stays bounded |

Local development ran the contract gate before deterministic primitives, then the full replay before the real-provider adapter. Test results and the final test count are available in CI/JUnit rather than a manually maintained badge.

## Truthful completion boundary

* M0–M5: implemented and locally exercised through full regression and offline replay.
* M6: Anthropic adapter implemented; HTTP-contract and common-core integration exercised using mock transport.
* Actual model API use: **not tested** in this delivery.
* Live GCP/GKE evidence, event subscription, production deployment, remediation, multi-agent: **not implemented**, intentionally out of v0.2 scope.
* GitHub Pages and Release: only successful deployment/release records establish publication; their workflow files alone do not.

The v0.2 release is experimental and documents the live-provider gap. The supplied SPEC's local definition of done can be evaluated without a cluster. This does not claim all possible interpretations of live-model acceptance are satisfied.

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
