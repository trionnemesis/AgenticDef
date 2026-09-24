# AgenticDef v0.2.1 — bounded-investigation hardening

Patch release of the v0.2 local investigation core / v0.2 本機調查核心的修補版本。
No new capability, event type, schema field or runtime dependency. The four
read-only tools, budgets, grounding rules and terminal states are unchanged.
Published versions are recorded in
[GitHub Releases](https://github.com/trionnemesis/AgenticDef/releases).

## Changes since v0.2.0 / 自 v0.2.0 以來

| Change | Issue / PR | Gate |
|---|---|---|
| An evidence adapter missing a callable required tool now persists a failed terminal record instead of a stuck `INVESTIGATING` claim (details below) | #2 E3 / #3 | D, F |
| A lost atomic claim runs the same identity and terminal-result checks as a found duplicate record | #4 / #12 | A, F |
| `expected.yaml` is schema-validated before any model, tool or record exists; malformed acceptance input exits `2` | #5 / #13 | A, E |
| `.[dev]` alone installs everything the offline suite needs; CI checks it in a clean virtualenv | #7 / #14 | — |
| S01/S02 run end to end through the Anthropic adapter over a mock HTTP transport, graded by the scenario evaluator, with an inverted-verdict negative control | #8 / #15 | C, E |
| Publishing requires a human-started `workflow_dispatch` run on `main`; the tag comes from the package version and the guard fails closed | #6 / #10, this release | — |

**Validation boundary / 驗證界線:** synthetic replay and scripted mock HTTP
responses are exercised. Actual Anthropic API calls, live GKE evidence, model
detection accuracy and real prompt-injection resistance are **not** validated.
This is not a production SOC service.

The remaining sections record the evidence adapter decision (#2 E3).

## Problem and first-principles decision / 問題與取捨

[Issue #2, E3](https://github.com/trionnemesis/AgenticDef/issues/2) identifies
a gap in the existing bounded-investigation contract. At base `e53f716`,
an evidence adapter missing `get_rbac_object` raises `AttributeError`
after the local claim is created. The stored record remains
`INVESTIGATING` with no result, even though no model call has occurred.
A duplicate submission then returns that unfinished record indefinitely.

The smallest correction is to finish this known integration failure using
the existing error and persistence path. It advances Gate D (termination)
and Gate F (bounded duplicates) without granting permission to reclaim a
crashed investigation. Valid adapters and public JSON Schemas keep their
existing behavior, so this is a `0.2.x` patch rather than a new feature version.

缺少必要方法是 adapter 整合契約錯誤。這次以既有 `ContractError` 保存失敗
終態，讓重送能取得明確結果；不需要先導入新工具、registry 框架或自動恢復機制。

## Behavior / 行為

- After event/policy admission, validate the four fixed evidence capability
  attributes before calling any provider. Each must exist and be callable.
- A missing or non-callable attribute produces an `adapter_rejected` audit
  entry naming the tool, followed by a `ContractError` failure and terminal
  record: `status: investigation_failed`, `risk: unknown`, `state: FAILED`.
- No model, tool or evidence budget is consumed. Repeated delivery returns
  the same failed record, including after the adapter is repaired.
- Complete duck-typed adapters remain valid. Policy/scope checks still
  authorize individual calls. No capability, authority or target write path
  is added, and no failure becomes benign.
- `v0.2.0` and its assets stay published unchanged.

## Evidence / 驗收

The targeted regression set fails against the original runtime with
**8 failed, 2 passed**: four missing methods escape as `AttributeError`, and
four non-callable methods are classified as missing evidence only after
provider work starts. With the patch the same set reports **10 passed**.
Assertions cover persisted terminal state, audit, zero provider calls,
duplicate delivery, valid duck typing and event-scope rejection precedence.
Exact-commit CI/JUnit and S01–S08 replay artifacts remain the authority for
the complete suite; no live API or cluster was used for this patch.

## Limits and deferred observations / 限制與後續

This only validates required callable attributes. It does not prove Python
method signatures, async/cancellation behavior or semantic correctness.
Existing call handling remains responsible for invocation failures. A
process crash, cancellation outside that handling, or persistence failure
can still leave a blocked claim; no recovery/lease policy is introduced.
Existing unfinished records are not migrated or reopened.

Issue #2 is an audit, not a blanket implementation order, and remains open:

- E1/E2/E4: no fifth capability or second event type is required by the
  current SPEC. A fifth-tool scope failure needs a separate approved extension.
- E5–E9 beyond this E3 case: context size, evidence accounting, remote
  persistence and reclaim require their own demonstrated scenario/decision.
  Budget maxima are ceilings, not a promise that every run reaches a verdict.
- V1–V4/V6: referential grounding and real-model semantic evaluation are
  distinct. This patch does not claim model accuracy or move fixture verdict
  logic into production.
- V5: a checksum verifies a downloaded artifact's integrity; it does not
  promise byte-identical regeneration with a wall clock. No clock or release
  checksum change is needed for this defect.
- V7 is a separate small packaging candidate: assess the `dev` extra's
  missing `httpx` dependency in a clean environment before changing it.
- V8 and publication-policy observations are not prerequisites for fixing
  the reproduced adapter failure.
