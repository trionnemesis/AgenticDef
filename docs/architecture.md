# Architecture / 架構

AgenticDef contains a deterministic authority runtime and replaceable reasoning/evidence adapters. Domain code has no Kubernetes, cloud SDK, HTTP client or database implementation dependency.

| Layer | Owns | May not own |
|---|---|---|
| Domain | Validation, policy, budgets, state, evidence identity, grounding | Network, cluster SDK, provider credentials |
| Application | Ordering, admission, calls, error classification, persistence coordination | Model-controlled permissions |
| Ports | Async model/tools; synchronous local repository; injectable clock | Vendor-specific semantics |
| Adapters | Fixture reads, JSON store, replay model, Anthropic HTTP | New model-callable capabilities |

## Runtime sequence

Validate the event before any model call. Load a defensive copy of trusted policy at construction. Derive a path-safe SHA-256 identity from a JSON tuple of event ID and policy version. Atomically claim the local investigation directory. Reject identity collisions with different event, policy or provider metadata.

Transition through RECEIVED, VALIDATED, POLICY_LOADED and INVESTIGATING. Model calls propose `tool_request` or `finish`. A tool request passes action schema, fixed registry, exact argument shape and scope membership before the adapter is invoked. A permitted tool returns at most one envelope. Normalize it, derive an evidence identity, persist its body, and audit the accepted reference.

The final `produce_result` call consumes model budget. Validate its draft, persist the candidate in audit, then verify all findings reference existing evidence. Conclusive results require the exact change event, before/after role versions, subject bindings and approval request. Save a schema-valid result, then atomically mark the terminal record. Do not return success if persistence fails.

## Budget semantics

Every call reserves its own model/tool unit before invocation. The reservation authorizes that one call even if it reaches its counter limit. Before any *later* call, all limits are checked; exhaustion of any counter stops every kind of further call. Evidence capacity is checked before tool invocation and incremented only for a new stored item. Runtime checks use a monotonic clock and `asyncio.wait_for` with the remaining duration.

The deadline bounds provider activity. Local validation, file flush and terminal persistence add small local overhead; there is no hard real-time OS guarantee. Registered async adapters are trusted to cooperate with cancellation. There are no untrusted Python plugins, subprocesses or generic code-execution tools.

## Evidence and results

Evidence IDs hash canonical JSON containing tool, exact arguments, source, observed time and content. `content_ref` and `integrity.digest` refer to those same bytes; acquisition timestamps do not change evidence identity. Repeated identical evidence is deduplicated. Raw fixture strings, including injection text, remain untrusted data in working context.

Grounding proves reference integrity only. The replay model's rule comparison and matching approval check are a limited deterministic test double, not a comprehensive Kubernetes authorization evaluator. A real model's semantic accuracy is not established by the HTTP-contract tests.

## Persistence and failures

One `mkdir` claim wins across local processes. Running or crashed claims never launch a replacement investigator. Each audit/evidence/result update replaces a flushed JSON record atomically. This is a single-host filesystem adapter; distributed storage, recovery leases, cancellation APIs and production databases are deferred.

Tool evidence failures end as `insufficient_evidence`; budgets end as `inconclusive`; invalid contracts, forbidden scope/tools, model failures and grounding errors end as `investigation_failed`. All retain unknown risk. Persistence errors escape to CLI exit 2 and leave a bounded claim; they never masquerade as a benign result.

## Future adapter boundary

One future live read-only GCP/GKE adapter may implement the existing four evidence methods after review. It must retain the same core, policy checks, cancellation behavior, evidence IDs and failure semantics. No cloud dispatcher or remediation implementation is included here.
