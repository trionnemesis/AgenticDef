# Event-Driven Agentic Defense --- SPEC v0.2

Status: implementation-ready.

## First principles

A defensive system reduces expected loss while preserving availability
and operator control. AI is justified only where adaptive evidence
gathering adds value beyond deterministic rules.

The normative invariants are:

1.  The model has no authority to grant permissions, expand scope,
    change budgets, enable tools, or mutate infrastructure.
2.  Only typed, registered, read-only capabilities exist. No shell,
    arbitrary HTTP/SQL, kubectl passthrough, or generic code execution.
3.  Policy, scope, budgets, and terminal rules are enforced outside the
    model.
4.  Every material finding references existing evidence IDs.
5.  Missing or failed evidence never silently becomes benign.
6.  Every investigation has hard runtime, model-call, tool-call, and
    evidence limits.
7.  Duplicate event delivery is safe and bounded.
8.  Replay and future live adapters use the same investigator core.
9.  v0.2 performs investigation only; remediation is out of scope.
10. Model/tool/policy/budget/terminal transitions are auditable.

## Mission

Implement one vertical slice:

``` text
RBAC-change fixture
 → schema validation
 → trusted policy
 → bounded investigator
 → typed read-only tools
 → evidence ledger
 → grounded result
 → persisted terminal state
```

It MUST run locally without GCP/GKE credentials.

## Non-goals

Do not implement autonomous SOC, hack-back, remediation, multi-agent
orchestration, graph DB, long-term agent memory, arbitrary web research,
malware sandbox, host EDR, Wazuh/OTel production integration, Argo
Events, production UI, multi-tenancy, model routing, or production GKE
deployment.

## Normative objects

`SecurityEvent`: event_id, event_type, observed_at, source, actor,
resource, change, attributes.

`InvestigationPolicy`: policy_version, allowed_tools, resource_scope,
max_runtime_seconds, max_model_calls, max_tool_calls,
max_evidence_items.

`Evidence`: evidence_id, source, observed_at, acquired_at, method,
content_ref, summary, integrity.

`InvestigationResult`: investigation_id, event_id, status, risk,
summary, findings, missing_evidence, recommended_next_actions,
budget_usage, termination_reason, timestamps.

JSON Schema files are normative.

Allowed status values:

``` text
confirmed_suspicious
likely_benign
insufficient_evidence
inconclusive
investigation_failed
```

## State machine

``` text
RECEIVED → VALIDATED → POLICY_LOADED → INVESTIGATING
                                      ├→ COMPLETED
                                      ├→ INSUFFICIENT_EVIDENCE
                                      ├→ INCONCLUSIVE
                                      └→ FAILED
```

Invalid event → model call, exhausted budget → additional call, rejected
action → tool execution, and terminal → investigating are forbidden
transitions.

## Minimum tool surface

Implement exactly these logical capabilities first:

1.  get_change_event(event_id)
2.  get_rbac_object(kind, namespace, name, version)
3.  get_subject_bindings(subject_id)
4.  get_approval_record(change_id)

A fifth tool requires a failing acceptance scenario that proves
necessity.

## Mandatory scenarios

S01 suspicious privilege increase without approval.\
S02 approved privileged change.\
S03 required evidence unavailable.\
S04 prompt injection embedded in evidence.\
S05 duplicate event delivery.\
S06 budget exhaustion.\
S07 unsupported tool request.\
S08 finding references nonexistent evidence.

## Acceptance gates

Gate A --- contracts: schemas validate good fixtures/results and reject
invalid ones.

Gate B --- authority boundary: no generic execution capability;
event/model content cannot change policy; unsupported tools fail before
adapter execution.

Gate C --- grounding: every accepted material finding references
existing evidence; fabricated IDs fail.

Gate D --- termination: all budgets are enforced before calls; terminal
state blocks later calls.

Gate E --- replay: S01--S08 run locally; assertions target structure and
accepted verdict sets rather than exact prose.

Gate F --- idempotency: repeated event submission cannot create
unbounded duplicate work.

## Coding-agent constraints

The coding agent MUST inspect current repository state first, implement
the earliest incomplete gate, preserve invariants, keep replay
cloud-independent, isolate model and evidence providers behind
interfaces, add regression tests with behavior changes, and report
ambiguity instead of inventing requirements.

It MUST NOT broaden scope, add write-capable tools, weaken validation to
pass tests, hard-code fixture verdicts into production logic, claim
untested live support, or rely on prompt wording as the only security
control.

## Definition of done

A clean checkout executes S01--S08 and demonstrates bounded,
evidence-grounded, read-only investigation with deterministic
termination. No live cluster is required.

The next version may add one live read-only GCP/GKE evidence adapter
only after these gates pass.
