# WORK ORDER --- v0.2 First Implementation

## Objective

Produce the first locally executable vertical slice. Do not implement
GKE infrastructure.

## Ordered milestones

### M0 --- Contracts and replay fixtures

Create normative JSON Schemas and S01--S08 fixture directories. Add
schema-validation tests.

Stop when Gate A is green.

### M1 --- Deterministic primitives

Implement policy loading, budget accounting, explicit investigation
state transitions, typed errors, and idempotency key behavior.

Tests must prove forbidden transitions and pre-call budget enforcement.

### M2 --- Read-only capability layer

Implement the four fixture-backed tools, capability registry, scope
validation, and evidence ledger.

Tests must prove an unavailable tool cannot reach an adapter.

### M3 --- Investigator with fake model

Implement structured `tool_request` / `finish` actions through a fake
deterministic model port.

Do not connect a real model yet.

### M4 --- Result and grounding

Implement InvestigationResult validation and evidence-reference
validation. S08 must fail safely.

### M5 --- Replay CLI

Implement `replay <scenario>` and run S01--S08 end-to-end. Keep semantic
assertions structural.

### M6 --- One real model adapter

Only after M0--M5 pass, add one provider adapter without changing domain
contracts or authority boundaries.

## Required CI gates

-   unit tests;
-   schema validation;
-   S01--S08 replay;
-   forbidden-capability regression;
-   grounding regression;
-   budget/termination regression;
-   duplicate-event regression.

## Out of scope

No Pub/Sub, GKE Job dispatcher, Argo Events, CronJob hunting, live
Wazuh/OTel, remediation, multi-agent, graph DB, UI, or production
database.

## Final review condition

A reviewer must be able to answer yes to all:

-   Can I run the proof locally?
-   Does every accepted finding point to evidence?
-   Can the model only request pre-registered read-only tools?
-   Can policy reject the model deterministically?
-   Does budget exhaustion stop execution?
-   Are duplicate events bounded?
-   Does malicious evidence fail to gain authority?
-   Is there no hidden mutation path?

If any answer is no, v0.2 is not complete.
