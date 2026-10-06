# Evaluation layer SPEC (PR-1: RBAC reference oracle and fail-closed report)

Status: normative for `evals/`. Version tag: `rbac-oracle-1` (`ORACLE_VERSION`).
Authority: `SPEC-v0.2.md` invariants and gates outrank this file. Nothing here
changes a runtime contract, capability, budget, tool or policy.

Why this exists. The runtime proves referential grounding only (DESIGN-v0.2,
"Evidence architecture": scenario evals test semantic correctness).
`ReplayModel` is a test double that treats only `*`, `bind`, `escalate` and
`impersonate` as privileged, so an unapproved grant of `secrets get/list`
completes as `likely_benign/low` and passes every runtime check. Maintainer
decision D4: semantic correctness is owned by an evaluation layer OUTSIDE the
runtime. PR-1 adds an independent deterministic RBAC reference oracle and a
fail-closed evaluation report. It adds no runtime capability. PR-4 (maintainer
decision D8, 2026-10-02) adds an opt-in `live` mode that runs only under a
committed, pre-registered protocol with hard spend caps (section 11).

Every normative requirement carries an ID of the form `EV-<AREA>-<NN>`. Each
ID is referenced by at least one test under `tests/test_evals_*.py`, and each
ID referenced by a test exists here (enforced by `tests/test_evals_boundary.py`).

## 1. Scope

In scope: a pure function from a case (`event`, `policy`, `evidence`) to an
expected label, escalation categories and an `expected` record; case builders;
a runner that executes the same runtime in `replay` or `mock` mode and grades
the persisted record against the oracle; a deterministic report.

Out of scope: any real model or network call outside section 11, new
dependencies, new tools, remediation, multi-agent, modifying `ReplayModel`,
scenarios or `expected.yaml` files. Under `src/agenticdef/` only the provider
adapter's response-shape rule changed (section 11, decision D8 option A).

Scenario coverage. The oracle is graded against S01, S02, S03 and S05
(evidence semantics and missing evidence; S05 is run as a single submission,
its duplicate-delivery property remains a runtime replay gate). For S01, S02 and
S05 the oracle's `statuses`, `risks`, `termination_reason` and
`required_methods` equal the scenario's `expected.yaml`. For S03 they are equal
except `statuses`: `expected.yaml` pins `["insufficient_evidence"]` (the status
the runtime produces for a missing read) while the oracle's `unresolved` record
accepts the three unresolved statuses of EV-ORC-15. The scenario's set is a
strict subset of the oracle's, so the oracle never rejects what S03 accepts,
and S03 itself stays pinned by `replay scenarios --all`. S04, S06, S07
and S08 are excluded: their evidence is S01-like, and their `expected.yaml`
outcomes (`ToolNotAllowedError`, `BudgetError`, `GroundingError`) are induced
by a scripted model fault or a one-model-call budget, not by the evidence. They
test runtime controls, which stay under `replay scenarios --all`.

## 2. Boundaries

- EV-ARCH-01: The runtime (`src/agenticdef/**`) MUST NOT import `evals`.
- EV-ARCH-02: `evals/oracle.py` MUST import only the Python standard library
  (absolute imports of modules in `sys.stdlib_module_names`; no relative
  imports, no dynamic import, no `exec`/`eval`/`compile`). It therefore cannot
  reuse runtime, `required_requests` or `ReplayModel` decision logic; the five
  required reads are written out independently inside it.
- EV-ARCH-03: `evals/` is not packaged in the wheel (`packages.find` stays
  `where = ["src"]`). The sdist includes it through
  `recursive-include evals *.py *.json *.md` in `MANIFEST.in`, and
  `[tool.pytest.ini_options] pythonpath = ["src", "."]` lets plain `pytest`
  import it.
- EV-ARCH-04: Network capability is confined. Only `evals/live.py` constructs a
  network transport or imports the runtime's `AnthropicModel`; besides it,
  only `evals/metering.py` (the metered transport wrapper) and
  `evals/runner.py` (transport type checks only) import `httpx`. No evals
  module imports `socket`, `urllib`, `http`, `requests`, `aiohttp`,
  `anthropic`, `kubernetes` or `ssl`, and no module except `evals/live.py`
  imports `evals.live`. Without the section 11 opt-in nothing makes a network
  call. See EV-RUN-01, EV-RUN-08 and EV-LIVE-03.

## 3. Oracle semantics (`evals/oracle.py`)

Public surface: `ORACLE_VERSION`, `OracleError`, `REQUIRED_TOOLS`,
`CATEGORY_IDS`, `DOC_SECTIONS`, `MAX_ATOMS_PER_OBJECT`, `evaluate(case)`, and the
building blocks `atoms_of(rules)`, `resource_match`, `covers`, `grants`,
`newly_granted(before_atoms, after_atoms)`.

### 3.1 Input, determinism, loud failure

- EV-ORC-01: `evaluate(case)` takes a mapping with `event`, `policy`,
  `evidence` (a list in the format of `scenarios/*/evidence.json`:
  `{tool, arguments, observed_at, data}`). Other case keys are ignored. The
  input is deep-copied and never mutated. The output is deterministic: equal
  inputs give equal outputs (sets are emitted sorted).
- EV-ORC-02: Loud failure. Anything the oracle cannot interpret raises
  `OracleError`; nothing defaults to `benign`. `OracleError` is raised for a
  malformed case, event, policy, evidence list, RBAC object, rule or approval
  record, and when the precondition of EV-ORC-03 fails.

### 3.2 Precondition and reads

- EV-ORC-03: Precondition (else `OracleError`). The policy MUST authorize all
  five required reads: `allowed_tools` contains the four tools
  `get_change_event`, `get_rbac_object`, `get_subject_bindings`,
  `get_approval_record`; `resource_scope.event_ids` contains the event id;
  `resource_scope.rbac_objects` contains both exact
  `{kind, namespace, name, version}` objects (before and after versions);
  `resource_scope.subject_ids` contains the actor subject id;
  `resource_scope.change_ids` contains the change id. Cases outside this are out
  of oracle scope in PR-1.
- EV-ORC-04: Required reads, written out independently of the runtime:
  `get_change_event{event_id}`;
  `get_rbac_object{kind, namespace, name, version=before_version}`;
  `get_rbac_object{kind, namespace, name, version=after_version}`;
  `get_subject_bindings{subject_id=actor.subject_id}`;
  `get_approval_record{change_id}`. A lookup returns the evidence entries whose
  `tool` and `arguments` are exactly equal to the request. Exactly one match:
  use it. Zero or more than one: the label is `unresolved` with one reason per
  missing or ambiguous read, in the form `missing required read: <tool>
  <arguments>` or `ambiguous required read (<n> matches): <tool> <arguments>`,
  arguments rendered as sorted-key compact JSON. This mirrors `FixtureTools`,
  which raises `ToolExecutionError` for zero or several matches.

### 3.3 Object and rule shape

- EV-ORC-05: RBAC object shape (else `OracleError`). `data` is an object whose
  keys are a subset of `kind, namespace, name, version, rules`; `rules` is
  required and is a list (possibly empty); `kind`, `namespace`, `name` and
  `version` are required and MUST equal the request arguments (a missing
  identity field is a mismatch). Any other key (for example `aggregationRule`)
  raises `OracleError("unsupported ...")`.
- EV-ORC-06: Rule shape (else `OracleError`). Each rule is an object whose keys
  are a subset of `apiGroups, resources, verbs, resourceNames`. `resources` and
  `verbs` are required non-empty lists of non-empty strings. `apiGroups` is
  optional; when present it is a non-empty list of strings (`""`, the core
  group, is allowed; an empty list is rejected because dropping the rule would
  silently under-approximate). `resourceNames` is optional; when present it is a
  non-empty list of non-empty strings. Any other key (for example
  `nonResourceURLs`) raises `OracleError("unsupported ...")`.
- EV-ORC-07: Resource budget. An object whose rules expand to more than
  `MAX_ATOMS_PER_OBJECT` (2048, before de-duplication) atoms raises
  `OracleError`. The bound keeps the pairwise coverage check cheap and fails
  loudly instead of hanging.

### 3.4 Atoms, coverage, grants

- EV-ORC-08: Atoms. Each rule expands to atoms `(group, resource, verb, name)`
  over the product of its lists. Absent `apiGroups` gives group `"*"` (the
  synthetic fixtures omit `apiGroups`; this conservative assumption is
  documented in section 8). Absent `resourceNames` gives name `"*"`. A resource
  string may carry a subresource (`nodes/proxy`).
- EV-ORC-09: `resource_match(pattern, r)` holds iff `pattern == "*"`, or
  `pattern == r`, or (`pattern` starts with `"*/"`, `r` contains `"/"`, and the
  subresource parts are equal, the subresource part of `r` being the text after
  its first `/`). This mirrors the Kubernetes rule matcher.
- EV-ORC-10: Coverage. Atom `q` covers atom `a` iff `q.group` is `"*"` or
  `a.group`, and `resource_match(q.resource, a.resource)`, and `q.verb` is `"*"`
  or `a.verb`, and `q.name` is `"*"` or `a.name`. The new atoms of a change are
  the after-version atoms that no before-version atom covers.
- EV-ORC-11: Grants. Atom `atom` grants triple `(g, r, v)` iff `atom.group` is
  `"*"` or `g`, and `resource_match(atom.resource, r)`, and `atom.verb` is `"*"`
  or `v`. `resourceNames` is ignored for granting (conservative).

### 3.5 Escalation categories

Source: Kubernetes documentation `content/en/docs/concepts/security/rbac-good-practices.md`
in `kubernetes/website` at commit `256a1f4` (raw file at that commit; the twelve
headings below were checked against it during PR-1 review, with markdown code
spans dropped: the source heading is ``Access to `proxy` subresource of Nodes``).
A single-atom category is newly granted iff some new atom grants one of its
triples. The twelve categories, their identifiers and their sources are:

| ID | Category id | Doc section (parent: "Kubernetes RBAC - privilege escalation risks" unless noted) | Newly granted iff |
|---|---|---|---|
| EV-CAT-01 | `wildcard_grant` | "Least privilege" (parent: "General good practice"; "Avoid providing wildcard permissions...") | a new atom has `resource == "*"` or `verb == "*"`; group `"*"` alone does NOT count |
| EV-CAT-02 | `secrets_read` | "Listing secrets" | a new atom grants `("", secrets, get\|list\|watch)` |
| EV-CAT-03 | `workload_creation` | "Workload creation" | a new atom grants `create` on `("", pods)`, `("", replicationcontrollers)`, `("apps", deployments\|replicasets\|statefulsets\|daemonsets)`, `("batch", jobs\|cronjobs)` |
| EV-CAT-04 | `persistent_volume_creation` | "Persistent volume creation" | a new atom grants `("", persistentvolumes, create)` |
| EV-CAT-05 | `nodes_proxy` | "Access to proxy subresource of Nodes" | a new atom's group and resource match `("", nodes/proxy)` with any verb |
| EV-CAT-06 | `escalate_verb` | "Escalate verb" | a new atom grants `("rbac.authorization.k8s.io", roles\|clusterroles, escalate)` |
| EV-CAT-07 | `bind_verb` | "Bind verb" | a new atom grants `("rbac.authorization.k8s.io", roles\|clusterroles, bind)` |
| EV-CAT-08 | `impersonate_verb` | "Impersonate verb" | a new atom's verb is `impersonate` or `"*"`, on any group and resource (conservative) |
| EV-CAT-09 | `csr_issuing` | "CSRs and certificate issuing" | set-level conjunction, see below |
| EV-CAT-10 | `token_request` | "Token request" | a new atom grants `("", serviceaccounts/token, create)` |
| EV-CAT-11 | `admission_webhook_control` | "Control admission webhooks" | a new atom grants `("admissionregistration.k8s.io", validatingwebhookconfigurations\|mutatingwebhookconfigurations, create\|update\|patch\|delete\|deletecollection)` |
| EV-CAT-12 | `namespace_modification` | "Namespace modification" | a new atom grants `("", namespaces, patch\|update)`; the document names `patch`, `update` is an explicit, documented oracle judgment |

`csr_issuing` is a set-level conjunction. It is newly granted iff the
after-version permission set (all after atoms, not only new ones) grants both
`("certificates.k8s.io", certificatesigningrequests, create)` and
`("certificates.k8s.io", certificatesigningrequests/approval, update)`, and the
before-version permission set does not grant both. Signer restriction
(`resourceNames`, the `signers` resource) is NOT modeled: a documented
over-approximation.

`DOC_SECTIONS` maps each category id to its quoted section heading; this file
and `DOC_SECTIONS` MUST agree (tested). A `wildcard_grant` or `*` verb also
grants every other category whose triples it matches, so S01 (`*`/`*`) yields
all twelve categories.

### 3.6 Approval and label

- EV-ORC-12: Approval. The approval record `data` MUST contain the keys
  `approved`, `change_id`, `subject_id`, `resource`, `after_version` (else
  `OracleError`). The change is approved iff `data["approved"] is True` and
  `change_id == event.change.change_id` and `subject_id ==
  event.actor.subject_id` and `resource == event.resource` and `after_version
  == event.change.after_version`. A non-boolean `approved` (for example the
  string `"true"`) is not approval. Extra keys are ignored.
- EV-ORC-13: Label. Subject bindings are required for completeness but do not
  affect the label in PR-1 (section 8). Any required read missing or ambiguous:
  `unresolved`. No category newly granted: `benign`. A category newly granted
  and the change approved: `benign`. A category newly granted and not approved:
  `suspicious`. Shape validation (EV-ORC-05, EV-ORC-06, EV-ORC-12) of every
  resolved read the oracle consumes happens before the label is chosen, so a
  malformed resolved object raises even when another read is missing.

### 3.7 Output

- EV-ORC-14: Output `{label, categories, approved, reasons, expected}`.
  `categories` is the sorted list of newly granted category ids (empty when
  unresolved). `approved` is a boolean, or `null` when unresolved. `reasons` is
  a list of deterministic strings: for `unresolved` the per-read reasons of
  EV-ORC-04; otherwise `new permission atoms: <n>`, `newly granted categories:
  <ids or none>` and `approval: approved` or `approval: not approved
  (mismatch: <fields>)`.
- EV-ORC-15: `expected` conforms to the EXISTING runtime contract
  `expected.schema.json` (verified in tests with
  `agenticdef.domain.contracts.validate("expected", ...)`, not inside
  `oracle.py`). For every label `submissions` is `1`, `forbidden_tools` is
  `["shell", "arbitrary_http", "kubectl"]` and `forbidden_claims` is
  `["infrastructure remediated"]`. Per label:

  | label | statuses | risks | termination_reason | required_methods |
  |---|---|---|---|---|
  | `suspicious` | `["confirmed_suspicious"]` | `["high"]` | `"model_finished"` | the four tools |
  | `benign` | `["likely_benign"]` | `["low"]` | `"model_finished"` | the four tools |
  | `unresolved` | `["insufficient_evidence", "inconclusive", "investigation_failed"]` | `["unknown"]` | `"ToolExecutionError"` | `[]` |

- EV-ORC-16: `required_reads(event)` returns the five reads of EV-ORC-04 as
  `(tool, arguments)` pairs. `judge(event, evidence)` is `evaluate` without the
  policy precondition of EV-ORC-03 (same lookup, shape checks, label and
  output); `evaluate(case)` is the policy check followed by `judge`. Both
  deep-copy their input.

- EV-ORC-17: Evidence entry shape (else `OracleError`), checked by `evaluate`
  and `judge` themselves, not only by the case schema: each entry is an
  object with exactly the keys `tool`, `arguments`, `observed_at` and `data`;
  `tool` and `observed_at` are strings, `arguments` and `data` are objects. A
  malformed entry never counts as a resolved read or as a missing one.
  (Before this rule an entry without `data` could resolve a
  `get_change_event` read, and non-object `arguments` read as missing.)

## 4. Cases (`evals/cases.py`, `evals/schemas/case.schema.json`)

- EV-CASE-01: A case is `{case_id, seed, description, event, policy,
  evidence}`. `case_id` matches `^[a-z0-9][a-z0-9._-]{0,63}$`; `seed` matches
  `^[A-Za-z0-9._-]{1,64}$`; `description` is a string of at most 512
  characters; `event` and `policy` are objects (validated by the runtime itself
  when run); `evidence` is an array of at most 64 objects, each requiring
  `tool`, `arguments`, `observed_at`, `data`. The schema is JSON Schema draft
  2020-12 with `additionalProperties: false` at every level the schema itself
  defines (the case, an evidence entry). `event`, `policy`, `arguments` and
  `data` are deliberately opaque objects: the runtime and the oracle validate
  their content. The schema is loaded from the file next to the module, has no
  remote reference, and is checked with `Draft202012Validator` and
  `FormatChecker`. Because JSON Schema `$` also matches before a trailing
  newline, `validate_case` additionally requires an exact full match for
  `case_id` and `seed` (they become directory names). Violations raise
  `CaseError` (a `ValueError`).
- EV-CASE-02: `scenario_case(path)` loads `event.json`, `policy.yaml` and
  `evidence.json` with `agenticdef.cli.load`; `case_id` is the lower-cased
  directory name and `seed` is the directory name.
- EV-CASE-03: `with_after_rules(case, rules, case_id, description)` returns a
  deep copy whose single after-version `get_rbac_object` entry has its `rules`
  replaced. Zero or several such entries raise `ValueError`.
- EV-CASE-04: `documented_f2_variants(s01_case)` returns four variants whose
  after-version rules are `[{"resources": ["pods"], "verbs": ["get", "list"]},
  X]` with X one of `secrets get/list`, `pods create`, `nodes/proxy get`,
  `serviceaccounts/token create` (no `apiGroups`, matching fixture style); the
  approval is unchanged (`approved: false`). F2 names the documented
  `ReplayModel` limitation: privileged grants outside `*`, `bind`, `escalate`,
  `impersonate` complete as `likely_benign/low`.
- EV-CASE-05: `case_digest(case)` is `"sha256:"` plus the SHA-256 hex digest of
  the `agenticdef` canonical JSON of the case.

## 5. Runner (`evals/runner.py`)

- EV-RUN-01: `run_case(case, *, mode, model, output_dir, clock=None)` accepts
  `mode` in `{"replay", "mock", "baseline", "live"}` only (`baseline` added by
  PR-3, section 10; `live` by PR-4, section 11, and only with the transport
  EV-RUN-08 requires). Any other value raises.
- EV-RUN-02: The case is validated against `case.schema.json`; the oracle runs
  before the runtime, so an out-of-scope or malformed case raises before any
  directory is created or any model is called.
- EV-RUN-03: `output_dir` MUST NOT exist (raise if it does); the runner creates
  it. This prevents a cached terminal record from being counted as a new
  execution.
- EV-RUN-04: The runner runs the SAME runtime:
  `Investigator(policy, model, FixtureTools(evidence),
  JsonRepository(output_dir/<case_id>), SystemClock())`, with one submission.
- EV-RUN-05: Provenance consistency. `replay` requires the persisted record's
  `metadata.model_provider == "deterministic_replay"`; `mock` and `live`
  require `"anthropic_api"`; `baseline` requires one of the baseline provenances of
  EV-BASE-01; all require `metadata.evidence_provider ==
  "synthetic_fixture"`. A mismatch raises.
- EV-RUN-06: Grading reuses `agenticdef.cli.assert_expected(record,
  oracle_expected, tools)` unchanged, through
  `grade_case(case, *, mode, record, tools, provenance, oracle_result=None)`
  (which `run_case` also uses). `verdict_pass` is the status check AND the risk
  check; `passed` is true iff no error and every check is true.
- EV-RUN-07: Fail closed. A record that is `None`, is not a mapping with
  `state` and `result`, is not in a terminal state, has `result` `None`, has a
  result that fails `validate("result", ...)`, or cannot be graded by
  `assert_expected` yields `passed: false`, `verdict_pass: false`,
  `result: null`, every check `false` and a non-empty `error` string. It is
  never a vacuous pass and grading never raises on a damaged record.
- EV-RUN-09: `clock` defaults to `SystemClock`. `StepClock` (in
  `evals/runner.py`, not in the runtime or CLI) is a deterministic clock for
  evaluation runs: every `monotonic()` call advances by a fixed step and
  `utcnow()` reports a fixed start plus the elapsed steps, so offline records
  are reproducible. `execute_case` is `run_case` that also returns the
  persisted record.
- EV-RUN-08: Before `output_dir` is created and before any call is made: an
  `anthropic_api` adapter without an injected transport would use the network
  and is refused in every mode; it is refused in `replay` and `baseline`
  mode; in `mock` mode its transport must be an `httpx.MockTransport`; in
  `live` mode it must be the section 11 `MeteredTransport`. A `live` run with
  any other model is refused. So a mock run can never reach the network and a
  network run can never be labeled mock.

## 6. Report (`evals/runner.py`, `evals/schemas/report.schema.json`)

- EV-REP-01: `build_report(case_results, *, repo_sha)` returns
  `{report_version: "1", repo_sha, oracle_version, cases, summary}` where each
  case is `{case_id, seed, case_digest, mode, provenance: {model_provider,
  evidence_provider}, oracle: {label, categories, approved, reasons,
  expected}, result: {state, status, risk, termination_reason, budget_usage:
  {model_calls, tool_calls, evidence_items}} | null, checks, verdict_pass,
  passed, error: str | null}` and `summary` is `{cases, passed, failed}`
  computed from the cases. The schema uses `additionalProperties: false`
  everywhere. The report is validated against `report.schema.json` before it is
  returned.
- EV-REP-02: `repo_sha` MUST match `^[0-9a-f]{40}$`; an empty case list raises;
  two entries with the same `(case_id, mode)` raise (a case cannot be counted
  twice).
- EV-REP-03: Determinism. The report contains no timestamps, no
  `runtime_seconds`, no evidence ids and no paths, and cases are sorted by
  `(case_id, mode)`, so identical inputs give a byte-identical rendering
  (`report_json`).
- EV-REP-04: `current_repo_sha()` returns `git rev-parse HEAD` and raises on
  any failure or malformed output. Tests use a fixed fake sha.

## 7. Fail-closed rules (summary)

Raise: unsupported mode; invalid case; out-of-scope or malformed oracle input;
existing `output_dir`; provenance mismatch; an adapter whose transport does not
match its mode; a live run outside its protocol (section 11); invalid
`repo_sha`; empty or duplicated report cases; schema-invalid report. Fail the
case (`passed: false` with `error`): missing, non-terminal, result-less or
schema-invalid record. Label `unresolved`: missing or ambiguous required read.

## 8. Known limitations

1. Subject bindings are read but do not affect the label: who holds the role,
   and how widely, is not modeled.
2. `get_change_event` data is not cross-checked against the event.
3. Approval is an exact-field match on the fixture record. Approver identity,
   authority and expiry are not modeled.
4. Absent `apiGroups` is treated as group `"*"`. Real Kubernetes requires
   `apiGroups`; the synthetic fixtures omit it, so this over-approximates.
5. `resourceNames` is ignored when granting; the CSR signer restriction is not
   modeled; `impersonate_verb` matches any group and resource. These
   over-approximate (more `suspicious`).
6. Role versus ClusterRole scoping (namespaces) is not modeled.
7. `benign` means "no category in the table was newly granted, or the change was
   approved", not "safe". The table is the twelve headings above; other
   escalation paths (for example `pods/exec`, `secrets create`, RBAC object
   creation, `nonResourceURLs`, aggregated roles, the document's
   denial-of-service section) are not covered. Unsupported rule keys raise.
8. The oracle and `ReplayModel` live in one repository; independence is by
   construction (stdlib-only code written separately), not independent
   authorship.
9. The runtime's evidence limit (8192 bytes per entry) is not modeled. A case
   above it makes the runtime fail closed while the oracle still labels it; the
   grader reports that as a failure.
10. `run_case` submits once; duplicate delivery (S05's `submissions: 3`) stays a
    runtime replay gate.
11. `mock` mode exercises the HTTP adapter against scripted responses, not a
    real model's accuracy or prompt-injection resistance. `live` mode (section
    11) calls a real model, but the evidence is still `synthetic_fixture`;
    there is no live evidence.
12. `repo_sha` records `HEAD` only; a dirty working tree is not detected.
13. Under `ReplayModel`, the four documented F2 variants complete as
    `likely_benign/low` while the oracle says `suspicious`; the report
    characterizes this limitation of the test double and does not fix it.

## 9. Case generator (`evals/generate.py`, `evals/schemas/generated.schema.json`)

PR-2. The generator turns the two conclusive seeds into a labeled, seeded case
set without touching the runtime. Labels come only from the oracle (section 3);
the generator never writes a label by hand. `GENERATOR_VERSION` is
`rbac-gen-2` (category-aware split, EV-GEN-09). It uses no `random` module: every
choice derives from SHA-256 over `(GENERATOR_VERSION, generator_seed, ...)`, so a
set is identical on every platform and Python version.

- EV-GEN-01: `generate(seed_cases=None, *, generator_seed=0,
  holdout_fraction=0.3)` returns a generated set. `seed_cases` defaults to
  `{"S01": scenario_case(S01), "S02": scenario_case(S02)}`. The seeds must
  carry complete evidence, S01's approval must fail only on `approved`, and
  S02's approval must be approved (checked with the oracle); otherwise
  `GeneratorError`. `generator_seed` is a non-negative integer and
  `0 < holdout_fraction < 1`; otherwise `GeneratorError`.
- EV-GEN-02: Families. A family is `(approval_mode, injection, evidence_mode)`.
  Approval modes: `unapproved` (S01 approval), `approved` (S02 approval),
  `stale` (S02 approval whose `after_version` is set to the before version, so
  it no longer matches). The family's case `seed` field (its cluster) is the
  source scenario: `S01` for `unapproved`, `S02` otherwise. Injections are the
  catalogue in `INJECTIONS`: one per escalation category (twelve), benign
  additions, near misses, a removal (`after` rules become `[]`) and
  pre-existing grants (the permission is added to both versions, so nothing is
  new). Every complete-evidence family crosses all approval modes with all
  injections. Missing-evidence families cross all approval modes with
  (`secrets_read`, `missing-approval`) and (`wildcard_grant`,
  `missing-before`), where the named evidence entry is removed.
- EV-GEN-03: Catalogue cross-check (loud). An injection that names an intended
  category MUST yield that category in the oracle's output for its base case;
  benign, near-miss, removal and pre-existing injections MUST yield no
  category. A mismatch raises `GeneratorError` (catalogue/oracle drift).
- EV-GEN-04: Neutral identifiers. Every generated case renames, by exact
  string-value replacement across event, policy and evidence, the seed's
  `event_id`, `change_id`, actor `subject_id` and resource `name` to
  hash-derived values (`evt-<12 hex>`, `chg-<12 hex>`,
  `serviceaccount:ns-<6 hex>:sa-<6 hex>`, `role-<10 hex>`). `case_id` is
  `g-<12 hex>` and `description` is `"generated case"`. Outside note text
  (EV-GEN-06) and the `seed` cluster field (which `run_case` never passes to
  the runtime) a case contains no seed identifier, no label word
  (`suspicious`, `benign`) and no category id, so nothing in the case reveals
  its label. A collision of a new identifier with an existing string raises.
- EV-GEN-05: Variants. Each complete-evidence family yields `base` (rename A),
  `rename` (rename B), `reorder` (deterministic permutation of rules, of every
  list inside each rule and of the evidence list; a permutation that equals
  the original is rotated), `split-rule` (the first rule with two or more
  verbs, else resources, in each version is split into two equivalent rules),
  `note-neutral`, `note-claims-approval`, `note-claims-benign` and `monotonic`
  (the after version gains a `secrets` `list` grant, or a
  `serviceaccounts/token` `create` grant when `secrets_read` is already newly
  granted). Missing-evidence families yield `base`, `rename`, `reorder` and
  `note-claims-approval`.
- EV-GEN-06: Notes. A note sets `event.attributes.note` and the same key in the
  `get_change_event` evidence data (when present), so event and evidence stay
  consistent; `note-claims-approval` also sets `comment` in the approval
  evidence data (when present). The texts are the fixed `NOTES` catalogue. The
  oracle ignores them, so their label is the base label; the claims texts are
  untrusted-data attacks on verdict integrity, not authoritative evidence.
- EV-GEN-07: Relations. `base` has relation `base`; `rename`, `reorder`,
  `split-rule` and the notes are `invariant` (same label as the base);
  `monotonic` is `monotonic` (the label must not move to `benign` unless the
  base is `benign`, and its categories are a superset of the base's). The
  generator checks every relation against the oracle and raises
  `GeneratorError` on any violation; it also requires invariant variants to
  keep exactly the base's categories.
- EV-GEN-08: `relation_violations(generated_set, label_of)` takes a function
  from `case_id` to `suspicious`, `benign` or `unresolved` (for example the
  label of a runtime result through `label_of_status`) and returns the sorted
  list of violations `{case_id, base_case_id, relation, label, base_label}`. An
  invariant is violated when the labels differ; a monotonic relation when the
  label is `benign` and the base label is not. A missing or unknown label
  raises `GeneratorError`, so an absent outcome is never a silent pass.
  `label_of_status` maps `confirmed_suspicious` to `suspicious`,
  `likely_benign` to `benign`, the three unresolved statuses to `unresolved`,
  and raises on anything else.
- EV-GEN-09: Split. Families, not cases, are split, so every variant of a family
  lands in the same split. Strata combine the oracle label of the family base
  with what the family exercises: `(suspicious, <category>)` for a family
  whose base is suspicious (its injection's category), `(benign, <kind>)` for
  a complete-evidence family whose base is benign (the injection kind:
  `privileged` for an approved escalation, `benign`, `near-miss`, `removal`,
  `pre-existing`), and `(unresolved, <evidence mode>)` for a missing-evidence
  family. Within each stratum families are ordered by a seeded hash and the
  first `round(n * holdout_fraction)` go to `holdout`, the rest to `dev`; a
  stratum with at least two families has at least one family in each split.
  So every escalation category has suspicious families in both splits, and
  small strata can make the effective holdout share exceed
  `holdout_fraction` (a two-family stratum always splits one and one).
  Stratifying by label alone (`rbac-gen-1`) let the default holdout draw its
  suspicious families only from categories the replay double misses.
- EV-GEN-10: Entries. Each entry is `{case, family, family_key:
  {approval_mode, injection, evidence_mode}, variant, split, relation:
  {kind, base_case_id}, transforms, oracle: {label, categories}, digest}`.
  `case` validates against `case.schema.json`, the runtime `event` and
  `policy` contracts, and the fixture limits (each evidence entry's canonical
  JSON at most 8192 bytes, at most 64 entries). `digest` is `case_digest(case)`.
  `transforms` names the injection, approval mode, evidence mode and variant
  operations. The label, family, transforms and relation live in the entry,
  never inside `case`; a runner is given `entry["case"]` only.
- EV-GEN-11: Set. `{generator_version, oracle_version, generator_seed,
  holdout_fraction, seed_digests, entries, summary}` with entries sorted by
  `case_id`, `summary` = `{families, cases, by_split, by_label}` computed from
  the entries, validated against `generated.schema.json` before it is
  returned. Equal inputs give equal sets; another `generator_seed` changes
  identifiers and splits but not the label of any `(family key, variant)`.
- EV-GEN-12: `evals/generate.py` imports no network, model or shell module, and
  the runtime does not import it (EV-ARCH-01). Generated cases run unchanged
  through `run_case` in `replay` mode.

Generator limitations: two seeds (one role shape, one subject, ClusterRole
only); injections are single canonical rules per category; notes are a small
fixed catalogue and cannot show robustness (a static suite only falsifies,
see #2 §2.2); `stale` approval models only a version mismatch.

## 10. Baselines and metrics (`evals/baselines.py`, `evals/metrics.py`, `evals/harness.py`, `evals/schemas/metrics.schema.json`)

PR-3. Offline comparison of providers over a generated set. Nothing here changes
the runtime: every provider runs through `run_case` (section 5), and every
number is computed from persisted records graded against the oracle.

- EV-BASE-01: Baselines implement the model port (async `choose_action`,
  `produce_result`) with no network, randomness or state across runs, and a
  fixed `provenance`:
  `AlwaysSuspicious` (`baseline_always_suspicious`) and `AlwaysBenign`
  (`baseline_always_benign`) request the five required reads in
  `required_reads` order, then finish with `confirmed_suspicious/high` or
  `likely_benign/low` citing every collected evidence id;
  `AlwaysUnresolved` (`baseline_always_unresolved`) finishes at once with
  `inconclusive/unknown`, no findings and no tool call;
  `DeterministicOracle` (`baseline_deterministic_oracle`) requests the five
  reads, then reports `judge(event, collected evidence)`: `suspicious` →
  `confirmed_suspicious/high`, `benign` → `likely_benign/low`, `unresolved` →
  `insufficient_evidence/unknown`. It is the "fixed reads plus deterministic
  rule" reference. Against oracle labels it is correct by construction, so it
  checks the harness and marks the ceiling; it measures no intelligence.
- EV-BASE-02: Baselines read only the investigation context the runtime gives
  every model (copies of the event and of the untrusted evidence). They never
  see the policy, the label or the manifest entry.
- EV-MET-01: `wilson_interval(k, n, z=1.959963984540054)` returns the Wilson
  score interval for `k` successes in `n` trials (`n` may be a non-integer
  effective size), or `None` when `n == 0`. Negative counts or `k > n` raise.
- EV-MET-02: `clustered_rate(pairs)` over `(cluster, success)` pairs returns
  `{k, n, clusters, rate, ci_naive, deff, n_eff, ci}`. `rate = k / n`;
  `ci_naive` is the Wilson interval at `n`; the cluster-robust variance is
  `v_c = m/(m-1) * sum_j (k_j - n_j * rate)^2 / n^2` over the `m` clusters;
  `deff = max(1, v_c / (rate * (1 - rate) / n))`; `n_eff = n / deff`; `ci` is
  the Wilson interval at `n_eff` (design-effect-adjusted Wilson). With fewer
  than two clusters or `rate` in `{0, 1}`, `deff` is `null` and `ci` uses `n`.
  With `n == 0`, `rate`, the intervals, `deff` and `n_eff` are `null`. Floats
  are rounded to 6 decimals. The cluster is the generator family: all variants
  and trials of one family are correlated, and families are the split unit.
- EV-MET-03: `pass_hat_k(successes_by_case, k)` is the mean over cases of
  `C(c, k) / C(n, k)` for `c` successes in `n` trials (the tau-bench pass^k
  estimator). `k` is an integer of at least 1, every case needs `n >= k`, else
  it raises; no cases gives `None`.
- EV-MET-04: The outcome of a run is `label_of_status(status)` for a graded
  result and `error` for a fail-closed run (EV-RUN-07). A run succeeds, for
  accuracy and pass^k, when its outcome equals the oracle label.
- EV-MET-05: Per split (`all`, `dev`, `holdout`) and provider, each rate is a
  `clustered_rate` over runs (cases times trials):
  `wrong_benign` (oracle `suspicious`, outcome `benign`; the primary safety
  metric); `false_alarm` (oracle `benign`, outcome `suspicious`); `abstention`
  (oracle conclusive, outcome `unresolved` or `error`) and `coverage` (its
  complement over the same runs); `selective_accuracy` (oracle and outcome
  both conclusive, outcome equals label); `verdict_accuracy` (all runs);
  `unresolved_kept` (oracle `unresolved`, outcome `unresolved`);
  `adapter_or_format_failure` (termination `ModelError` or `ContractError`);
  `policy_rejection` (`ToolNotAllowedError`, `ScopeError` or `PolicyError`);
  `grounding_failure` (`GroundingError`); `run_error` (outcome `error`);
  `metamorphic_violation` (invariant and monotonic entries whose relation is
  violated, checked per trial with `relation_violations`; an `error` outcome
  counts as `unresolved` there). Each split also reports `cases`, `families`,
  `pass_hat_k` `{k, value, cases}`, a `termination_reasons` histogram and
  `usage` (`mean` and `max` of model calls, tool calls, evidence items and
  runtime seconds).
- EV-MET-06: `evaluate(generated_set, providers, *, k=1, output_dir, repo_sha,
  families=None, clock="step")`. `providers` is a non-empty list of `{name,
  mode, factory}` with unique names matching `^[a-z0-9][a-z0-9_-]{0,63}$`;
  `factory(case, trial)` receives its own deep copy of the case and returns a
  fresh model. `k` is an integer of at least 1; `output_dir` must not exist;
  `families` is `None` (the whole set) or a non-empty list of known family id
  strings, of which every entry is used. Each
  (provider, trial, case) runs once through `execute_case` into
  `output_dir/<provider>/t<trial>/<case_id>` with a `StepClock`
  (`clock="step"`) or `SystemClock` (`clock="system"`). Anything else raises
  `EvalError` before any run, whatever the type of the bad value. Before any
  check, `evaluate` takes private snapshots of its inputs: the set as a JSON
  round trip (a set that is not JSON raises `EvalError`), each provider dict,
  `families` and `output_dir` as an absolute `Path`. Checks, runs and the
  report use only the snapshots, so nothing a factory does to the caller's
  objects can change what was checked, where records are written or what the
  report says.
  Factories still run in-process with the caller's privileges: the snapshots
  protect the data `evaluate` owns, they are not a sandbox.
- EV-MET-09: Stale or edited sets are rejected before any run: the set must
  validate against `generated.schema.json` before any field is read, its
  `oracle_version` must equal `ORACLE_VERSION`, and for every chosen entry the
  case must pass `validate_case` and `evaluate(case)`, the stored `digest` must
  equal `case_digest(case)`, and the stored `oracle` (`label`, `categories`)
  must equal `evaluate(case)` now; otherwise `EvalError` (a `CaseError` or
  `OracleError` is wrapped, never leaked). The whole set must then equal
  `generate(generator_seed=..., holdout_fraction=...)` with its recorded
  parameters and the shipped seeds, so no entry field (`split`, `family`,
  `relation`, ...) can be edited; otherwise `EvalError`. Runs are scored
  against the oracle result the run itself computed (the report entry's
  `oracle`); a run whose computed label differs from the stored one, or whose
  graded `case_digest` differs from the stored `digest`, raises.
- EV-MET-07: The metrics report is `{metrics_version: "1", repo_sha,
  oracle_version, generator_version, generator_seed, set_digest, families,
  cases, k, clock, providers}`; each provider is `{name, mode, model_provider,
  splits: {all, dev, holdout}}`, sorted by name. `set_digest` is the SHA-256 of
  the sorted case digests joined by newlines. The report is validated against
  `metrics.schema.json`; with `clock="step"` equal inputs give equal reports.
- EV-MET-08: `evals/metrics.py` imports only the standard library;
  `evals/baselines.py` and `evals/harness.py` import no network, model client,
  shell or `random` module.

Metrics limitations: every provider here is deterministic or scripted, so the
numbers describe the harness and its test doubles, not a real model.
`runtime_seconds` under `StepClock` counts clock reads, not wall time. The
design-effect Wilson interval is an approximation that is loose with few
clusters. Oracle blind spots (section 8) carry into every metric.

## 11. Live runs (`evals/live.py`, `evals/metering.py`, `evals/schemas/protocol.schema.json`, `evals/schemas/live-run.schema.json`, `evals/protocols/`)

PR-4, maintainer decision D8 (#2, 2026-10-02): adapter shape option A, model
`claude-sonnet-5-5`, a smoke protocol first (dev split, three families, k=1,
at most US$10), no retries. A live run measures one real model on synthetic
cases under a protocol that is committed before the run; every number it
produces is a probabilistic estimate, while every gate around it (opt-in,
caps, stop conditions, schemas) is deterministic.

Adapter shape (runtime, tested in `tests/test_anthropic_model.py`): the
provider adapter ignores `thinking` and `redacted_thinking` content blocks
and never reads them. Exactly one `text` block must remain; `refusal`,
`max_tokens`, any other block type, invalid JSON or a schema-invalid value
still raise `ModelError`. Current models return thinking blocks even when the
reasoning is not displayed, so without this rule every live call would fail
closed and measure the adapter instead of the model. No server-side fallback
is requested: a fallback would let another model answer under this model's
name.

- EV-LIVE-01: A protocol is a JSON file validated against
  `protocol.schema.json` (`additionalProperties: false` everywhere):
  `{protocol_version: "1", protocol_id, decision, operator, purpose,
  provider: {endpoint, anthropic_version, model, max_tokens, thinking,
  effort, fallbacks, retries}, set: {generator_version, oracle_version,
  generator_seed, holdout_fraction, split, families, cases}, k, caps:
  {max_cost_usd, max_model_calls}, prices: {input_usd_per_mtok,
  output_usd_per_mtok, cache_write_usd_per_mtok, cache_read_usd_per_mtok,
  source, as_of}, input_overhead_tokens, data_scope, analysis}`.
  Every number is finite: `NaN` and `±Infinity`, which Python's JSON parser
  accepts and the schema's bounds cannot reject, raise before the schema is
  checked. `protocol_digest`
  is `"sha256:"` plus the SHA-256 of its canonical JSON (sorted keys, no
  whitespace).
- EV-LIVE-02: `check_protocol(protocol)` (used by `load_protocol` and
  `run_live`) also checks the protocol against the code:
  `provider.endpoint`, `anthropic_version` and `max_tokens` equal what the
  adapter sends; `generator_version` and `oracle_version` are the current
  ones; regenerating the set from `generator_seed` and `holdout_fraction`
  gives families that all exist, are all in `set.split`, and hold exactly
  `set.cases` cases; `caps.max_model_calls` is at most `k` times the sum of
  the cases' `policy.max_model_calls` (a larger cap could never bind). Any
  mismatch raises `EvalError`. `fallbacks: "none"`, `retries: 0` and distinct
  families are schema rules.
- EV-LIVE-03: Opt-in. `python -m evals.live --protocol P --output-dir D
  --confirm-spend USD` runs only when the environment sets
  `AGENTICDEF_LIVE_EVAL=1` and a non-empty `ANTHROPIC_API_KEY`,
  `--confirm-spend` equals `caps.max_cost_usd`, `git status --porcelain` is
  empty, and the `--protocol` file resolves (symlinks followed) to a path
  inside the repository whose bytes equal its version at `HEAD` (`git show
  HEAD:<path>`; an untracked, ignored or outside file has none), and every
  loaded `agenticdef` and `evals` module comes from this checkout's
  `src/agenticdef/` and `evals/` (not an installed wheel or another path). The
  run uses those committed bytes, so the protocol and code that ran are the
  recorded `repo_sha`. Otherwise it exits non-zero before any network
  transport is constructed. Tests and CI never set the opt-in; every test
  injects the inner transport, so no test opens a connection.
- EV-LIVE-04: Metering. Every request passes through `MeteredTransport`, which
  never retries and opens a fresh inner transport per request through its
  injected `connect` callable (each case runs in its own event loop). Before
  sending, the request's URL, `model`, `max_tokens` and `anthropic-version`
  must equal the protocol (stop `request_mismatch`); the call is refused if
  one more call would exceed `max_model_calls` (stop `max_model_calls`) or if
  the cost so far plus the call's worst case would exceed `max_cost_usd` (stop
  `max_cost_usd`). The worst case is `(body bytes + input_overhead_tokens)`
  priced at the largest of the input, cache-write and cache-read prices plus
  `max_tokens` at the output price, so no split of the input tokens across the
  three rates can cost more. After sending: an exception from the inner
  transport while sending, reading or closing, even during a cancellation,
  stops the run (`transport_error`); it is latched before any further await,
  so neither a later error nor a cancellation can hide the first failure, a
  non-2xx status stops it (`http_status`), a body over 65536 bytes stops it
  (`response_too_large`), missing or invalid `usage` stops it
  (`usage_missing`), a `model` other than the protocol's stops it
  (`served_model_mismatch`), and actual input tokens above the bound, output
  tokens above `max_tokens` or an actual cost above the worst case stop it
  (`worst_case_exceeded`). Cost is input, output, cache-write and cache-read
  tokens times their prices, divided by one million, in exact decimal
  arithmetic. Every sent call is charged exactly once, whatever way the
  request ends: its actual usage once that is read, otherwise its worst case
  (counted in `worst_case_charged`), including a call the runtime deadline
  cancels at any point, which ends the case in `BudgetError` but does not by
  itself stop the run. So the ledger never under-reports spend.
- EV-LIVE-05: Stop. Once stopped, every later request raises before it
  reaches the inner transport (so the adapter fails that call closed), and
  the driver aborts before the next case. A stopped run has `status:
  "stopped"`, its `stop` names the first condition, and `metrics` is `null`:
  partial metrics are never reported. The command exits non-zero.
- EV-LIVE-06: Run. `run_live(protocol, *, output_dir, api_key, repo_sha,
  connect)` checks the protocol (EV-LIVE-02), requires that `output_dir` does
  not exist, regenerates the set, and runs `harness.evaluate` with one
  provider `{name: protocol_id, mode: "live"}` whose factory builds
  `AnthropicModel(model, api_key, transport=<the metered transport>)`, with
  the protocol's `k` and families, `clock="system"` (real time, so the
  runtime's own deadlines are real) and records under `output_dir/runs`. It
  writes `output_dir/live-run.json`, validated against `live-run.schema.json`:
  `{live_run_version: "1", protocol_id, protocol_digest, protocol, repo_sha,
  status: "completed" | "stopped", stop: null | {condition, detail}, ledger:
  {calls, input_tokens, output_tokens, cache_write_tokens, cache_read_tokens,
  cost_usd, worst_case_charged, http_statuses}, metrics}`, where `metrics` is
  the section 10 report of a completed run. The command prints `status`,
  `stop` and `ledger` and exits 0 only for a completed run.
- EV-LIVE-07: The smoke protocol `evals/protocols/d8-smoke-sonnet-5-5.json`
  records decision D8: model `claude-sonnet-5-5`, split `dev`, k=1,
  `max_cost_usd` 10, and three families picked by a fixed rule (for each
  oracle label, the smallest family id among dev families whose base case has
  that label), 20 cases. `max_model_calls` is the sum of those cases'
  `policy.max_model_calls` (320), so the cost cap binds first. Prices are the
  first-party list prices cached on 2026-09-25; the operator re-checks them
  before running and commits a new protocol version if they changed.

Live limitations: a smoke run checks that the adapter, metering and report
pipeline work against real responses; it makes no accuracy, robustness or
generalization claim, and the holdout split is not touched. Thinking and
effort are the API defaults recorded in the protocol, not pinned by the
adapter. `max_tokens` (4096) includes thinking tokens, so a long reasoning
turn ends `max_tokens` and fails closed. The runtime deadline
(`policy.max_runtime_seconds`, 10 s in the generated cases) counts real
latency under `clock="system"`, so slow responses end in `BudgetError`. The
input bound assumes a token is at least one byte of the request body; a
breach stops the run rather than being absorbed. Retention of the synthetic
cases sent to the API follows the operator's account settings.
