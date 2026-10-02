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
fail-closed evaluation report. It adds no runtime capability.

Every normative requirement carries an ID of the form `EV-<AREA>-<NN>`. Each
ID is referenced by at least one test under `tests/test_evals_*.py`, and each
ID referenced by a test exists here (enforced by `tests/test_evals_boundary.py`).

## 1. Scope

In scope: a pure function from a case (`event`, `policy`, `evidence`) to an
expected label, escalation categories and an `expected` record; case builders;
a runner that executes the same runtime in `replay` or `mock` mode and grades
the persisted record against the oracle; a deterministic report.

Out of scope (PR-1): `live` mode (needs maintainer decision D8), any real model
or network call, new dependencies, new tools, remediation, multi-agent,
modifying `ReplayModel`, scenarios, `expected.yaml` files or any file under
`src/agenticdef/`.

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
- EV-ARCH-04: No network, no real model call, no `live` mode. See EV-RUN-01 and
  EV-RUN-08.

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

- EV-RUN-01: `run_case(case, *, mode, model, output_dir)` accepts `mode` in
  `{"replay", "mock"}` only. `"live"` and any other value raise (live needs
  maintainer decision D8).
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
  `metadata.model_provider == "deterministic_replay"`; `mock` requires
  `"anthropic_api"`; both require `metadata.evidence_provider ==
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
- EV-RUN-08: An `anthropic_api` adapter without an injected transport would use
  the network and is refused in every mode, before `output_dir` is created and
  before any call is made. `mock` mode therefore only works with an injected
  (mock) transport.

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
existing `output_dir`; provenance mismatch; network-capable adapter; invalid
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
    real model's accuracy or prompt-injection resistance. Evidence is always
    `synthetic_fixture`; there is no live evidence.
12. `repo_sha` records `HEAD` only; a dirty working tree is not detected.
13. Under `ReplayModel`, the four documented F2 variants complete as
    `likely_benign/low` while the oracle says `suspicious`; the report
    characterizes this limitation of the test double and does not fix it.
