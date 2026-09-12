# Event-Driven Agentic Defense --- DESIGN v0.2

Normative companion: `SPEC-v0.2.md`.

## Design thesis

This is a deterministic security runtime containing a bounded reasoning
component, not an autonomous agent with security tooling attached.

``` text
validate → policy → budget → model proposes action
                              ↓
                    schema/policy/scope check
                              ↓
                       typed read-only tool
                              ↓
                         evidence ledger
                              ↓
                    grounding validation
                              ↓
                           persist/exit
```

The model proposes. Deterministic code permits or rejects.

## Dependency rule

Domain/application logic must not depend on Kubernetes, GCP SDK,
Pub/Sub, a database implementation, or a model vendor.

``` text
domain ← application ← ports ← adapters
```

Suggested layout:

``` text
src/
  domain/{events,evidence,findings,policy,budget,state}
  application/{investigate,validate_result,persist_result}
  ports/{model,evidence_tools,repository,clock}
  adapters/{fixture_tools,fixture_repository,model_provider}
  cli/replay
contracts/
scenarios/
tests/
```

## Control flow

1.  Validate event.
2.  Derive investigation identity and check idempotency.
3.  Load trusted policy and initialize budget.
4.  Ask the model for a structured next action.
5.  Validate action schema, tool permission, and resource scope.
6.  Reserve budget before execution.
7.  Execute a typed read-only adapter.
8.  Normalize and store returned evidence.
9.  Repeat while useful and within budget.
10. Produce a structured result.
11. Validate schema and evidence references.
12. Persist and transition terminal.
13. Exit.

Only adaptive action selection and semantic synthesis require model
reasoning.

## Action protocol

The model emits either a typed `tool_request` or `finish`. It never
emits executable commands.

Callable capability is:

``` text
registered tools ∩ policy.allowed_tools ∩ resource scope
```

A model cannot create a capability by naming it.

## Budget engine

Check and reserve before every model/tool call. Once any hard limit is
exhausted, no further calls are legal. Use an injectable monotonic clock
for deterministic tests.

## Evidence architecture

``` text
authoritative fixture/live evidence
 → normalize
 → evidence ledger
 → compact working context
 → model
```

Every material finding must have a non-empty evidence list and every
referenced ID must exist in the ledger. This proves referential
grounding; scenario evals test semantic correctness.

## Prompt-injection boundary

``` text
untrusted evidence
 → data framing
 → model
 → structured action
 → capability registry
 → policy/scope validation
 → read-only adapter
```

Prompt instructions are defense-in-depth, not authorization.

## Idempotency

Use `event_id + policy_version` as the initial idempotency key.

No record → create. Running record → no duplicate. Terminal record →
return/reference existing result. Re-investigation semantics are
deferred.

## Ports

Repository port: get_by_idempotency_key, create_investigation,
append_audit_event, append_evidence, save_result, mark_terminal.

Model port: choose_action(context, allowed_tools),
produce_result(context).

Replay may use filesystem/JSON persistence.

## Replay runner

Target:

``` text
replay <scenario-directory>
```

Each scenario contains event.json, policy.yaml, evidence fixtures, and
expected.yaml. No internet or cloud credentials are required.

Assertions should be structural: accepted statuses/risks, required
evidence IDs, forbidden tools, forbidden claims. Avoid exact prose
matching.

## Error taxonomy

Use typed errors: ContractError, PolicyError, BudgetError,
ToolNotAllowedError, ScopeError, ToolExecutionError, ModelError,
GroundingError, PersistenceError.

Do not collapse all failures into model failure.

## Test order

M0 contracts + fixtures.\
M1 policy/budget/state primitives.\
M2 fixture tools + evidence ledger.\
M3 fake-model investigator loop.\
M4 grounding/result validation.\
M5 replay CLI + S01--S08.\
M6 one real model adapter.

Stop at M6 for v0.2. Do not implement GKE dispatch yet.

## PR security questions

Every behavior-changing PR answers:

1.  Does this add a capability?
2.  Can untrusted evidence influence authority?
3.  Can the model increase runtime/cost?
4.  Can failure become falsely benign?
5.  Can a result cite nonexistent evidence?
6.  Can duplicate delivery multiply work?
7.  Does this introduce a write path?
8.  Is the behavior replay-testable?

A new capability, authority expansion, write path, or weakened failure
semantics requires explicit design review.

## Stop conditions

Stop and request review if a required capability mutates infrastructure,
an invariant must change, infrastructure dependencies leak into domain
logic, stable evidence references cannot be preserved, authorization
would need to trust the model, or replay/live modes require different
investigator semantics.

Future GKE support must plug into the existing ports rather than
redesign the investigator core.
