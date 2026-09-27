# Roadmap / 下一階段規劃

Status checked on 2026-09-27 (Asia/Taipei), against `main` at
[`cf7272d`](https://github.com/trionnemesis/AgenticDef/commit/cf7272d00ee2fee6c48f1667eeaf90d3eafbeeb4).
This page sequences **existing** issues; it does
not approve new capabilities, designs or releases. Authority order in
[AGENTS.md](../AGENTS.md) still governs, and a human decides every merge and
publication.

## Where v0.2 stands / 現況

| Item | State | Evidence |
|---|---|---|
| [#2](https://github.com/trionnemesis/AgenticDef/issues/2) E3 — adapter contract failure leaves a stuck claim | Fixed (v0.2.1 source) | `41c5b18`, [patch notes](release-v0.2.1.md) |
| [#4](https://github.com/trionnemesis/AgenticDef/issues/4) — lost-claim duplicate skipped identity checks | Fixed, closed | `d9eb89f`, `tests/test_duplicate_claim.py` |
| [#5](https://github.com/trionnemesis/AgenticDef/issues/5) — `expected.yaml` accepted malformed input | Fixed, closed | `df6468c`, `contracts/expected.schema.json`, `tests/test_expectations.py` |
| [#6](https://github.com/trionnemesis/AgenticDef/issues/6) — 0.2.1 package could attach to `v0.2.0` | Fixed, closed | `4ea55cd`, `tools/release.py`, `tests/test_release_guard.py` |
| [#7](https://github.com/trionnemesis/AgenticDef/issues/7) — `.[dev]` could not collect tests | Fixed, closed | `c2af276`, CI `dev-extra` job |
| [#8](https://github.com/trionnemesis/AgenticDef/issues/8) — no full HTTP-mock verdict evaluation | Delivered, closed | `tests/test_anthropic_evaluation.py` |
| [#9](https://github.com/trionnemesis/AgenticDef/issues/9) — follow-up tracker | Checklist complete; tracker closed | #4–#8 delivered |
| [#16](https://github.com/trionnemesis/AgenticDef/issues/16) — public documentation consistency | Delivered in this documentation increment | README EN/ZH, Pages and this roadmap |
| [#17](https://github.com/trionnemesis/AgenticDef/pull/17) — manual release path | Merged; publication remains a separate action | `cf7272d`, [publication](publication.md) |
| Published releases | `v0.2.0` only | [Releases](https://github.com/trionnemesis/AgenticDef/releases) |

Historical local check at `c2af276` (not a current-main measurement): `pytest` 132 passed from a clean `.[dev]`
install; `replay scenarios --all` S01–S08 all `passed: true`.

## Phase 1 — close out v0.2.x / 收斂 v0.2.x

No new capability, event type, dependency or runtime semantics.

1. **#8 — full HTTP-mock verdict evaluation** (tests only, Gates C/E, M6) — implemented.
   Runs S01/S02 end to end through `AnthropicModel` with `httpx.MockTransport`,
   grades the persisted record with the existing expectation evaluator, and adds
   an inverted-but-grounded S01 verdict that fails only status/risk checks.
   No runtime seam was missing; runtime code is unchanged.
2. **Tracker hygiene completed.** #6 and #8 are closed; the #9 checklist is
   complete and its tracker is closed. Keep #2 open; its deferred observations
   stay there.
3. **Documentation consistency delivered (#16).** README EN/ZH, Pages and this
   roadmap now distinguish source 0.2.1 from the only published release v0.2.0,
   use `.[dev]` for offline setup, and separate deterministic controls, scripted
   HTTP-mock integration and unmeasured live behavior.
4. **v0.2.1 publication (separate maintainer action).** #17 implemented the
   version-aware, fail-closed manual release path. Pushes and PRs do not publish
   releases. A human must start `workflow_dispatch` on `main`; this documentation
   increment does not do so. See [publication](publication.md).

#8's delivered verification is recorded in
[PR #15](https://github.com/trionnemesis/AgenticDef/pull/15) and
[CI run 35958321757](https://github.com/trionnemesis/AgenticDef/actions/runs/35958321757)
for `f912fb0`: Python 3.11/3.12 tests, replay, build and installed-wheel checks,
plus the clean `.[dev]` job. These are historical CI results, not a new local run.
The scripted S01/S02 HTTP responses and inverted-verdict negative control prove
integration and evaluator behavior, not real-model accuracy or resistance to
injected evidence. See [verification](verification.md).

## Phase 2 — decision gate before v0.3 / v0.3 前的決策關卡

SPEC v0.2 permits the next version to add **one live read-only GCP/GKE
evidence adapter**, and only after the v0.2 gates pass. No v0.3 design is
proposed here. The unresolved questions from #2 section D need human answers first; the
publication decision already delivered by #17 is marked below. Several
observations resolve in opposite directions depending on these answers:

1. Is the four-capability surface frozen, or is a fifth tool expected? (E1/E2)
2. Is `rbac_change` the only event type, or is a second type in scope? (E4)
3. What is the measured response size of a live `get_subject_bindings` in the
   target cluster, and do the 8 KiB envelope / 64 KiB context limits hold? (E5/E6)
4. Who owns semantic correctness outside replay — a domain evaluator or an
   external eval suite? (V1/V2; #8 only covers the offline mock boundary)
5. Is a permanently blocked crashed claim acceptable outside replay; if not,
   what authorizes reclaim, and is that authorization human? (E3/E9)
6. Must replay artifacts be byte-reproducible by third parties? (V5)
7. Publication trigger resolved by #17: releases require manual dispatch on
   `main`; pushes may deploy Pages but cannot publish a release. (C)
8. Which provider API version and model IDs should an opt-in live M6 check use,
   and under what cost limit? (#2 D8)

The next candidate is a small external evaluation slice, only after human
decisions on D4 (semantic-evaluation ownership) and D8 (provider/model/API,
explicit opt-in and cost ceiling). Start with offline counterexamples; paid
experiments require separate authorization. This is not an approved design.

A live adapter can also surface E7 (multi-item evidence accounting) and E8
(synchronous repository outside the deadline). Treat them as entry criteria to
evaluate with the answers above, not as pre-approved work.

## Not planned / 不在規劃內

Per SPEC non-goals: remediation, multi-agent orchestration, shell/kubectl or
arbitrary HTTP/SQL tools, Pub/Sub or GKE Job dispatch, Argo Events, production
Wazuh/OTel, graph DB, long-term memory, model routing, production UI or GKE
deployment.
