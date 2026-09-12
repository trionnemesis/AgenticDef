# AGENTS.md --- Frontier Model Handoff Contract

## Mission

Build v0.2 according to `SPEC-v0.2.md` and `DESIGN-v0.2.md`.

The goal is not feature count. The goal is the smallest executable proof
of bounded, read-only, evidence-grounded AI security investigation.

## Authority order

When instructions conflict:

1.  security invariants in SPEC;
2.  acceptance gates in SPEC;
3.  architecture/stop conditions in DESIGN;
4.  this file;
5.  implementation convenience.

## Required loop

Before editing: inspect repository/tests, identify the earliest
incomplete milestone and gate, list expected files, and check whether
authority/capability changes.

During implementation: make one coherent increment, add regression
tests, keep authorization outside prompts, avoid unrelated cleanup, and
do not add cloud infrastructure before replay gates pass.

After implementation: run focused tests, then the full replay/CI suite
when feasible; inspect diff for scope leakage; report evidence and
remaining failures.

## Prohibited shortcuts

Do not add shell/kubectl/arbitrary HTTP tools, weaken
schemas/assertions, hard-code fixture verdicts, convert failures to
benign, fabricate live support, add multi-agent/remediation, or silently
change contracts.

## Decision rule

When uncertain, choose the design with fewer capabilities, fewer
dependencies, less authority, and stronger deterministic validation.

If that prevents a mandatory scenario from passing, stop and document
the exact contradiction instead of broadening scope.

## Completion report

Return:

``` text
Gate advanced:
Files changed:
Tests executed:
Evidence:
Invariant impact:
Known limitations:
Next smallest work item:
```
