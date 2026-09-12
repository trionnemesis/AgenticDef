import asyncio
from copy import deepcopy
from hashlib import sha256

from ..domain.contracts import canonical, validate
from ..domain.errors import (BudgetError, ContractError, GroundingError, InvestigationError,
                             ModelError, PersistenceError, PolicyError, ToolExecutionError)
from ..domain.evidence import Ledger, validate_grounding
from ..domain.runtime import Budget, Policy, TERMINAL, identity, transition

STATUS_STATE = {"confirmed_suspicious": "COMPLETED", "likely_benign": "COMPLETED",
                "insufficient_evidence": "INSUFFICIENT_EVIDENCE", "inconclusive": "INCONCLUSIVE",
                "investigation_failed": "FAILED"}


class Investigator:
    def __init__(self, *, policy, model, tools, repository, clock):
        self.policy = Policy(policy)
        self.model, self.tools, self.repository, self.clock = model, tools, repository, clock

    async def run(self, event):
        event = deepcopy(validate("event", event))
        key = identity(event["event_id"], self.policy.version)
        fingerprint = sha256(canonical(event).encode()).hexdigest()
        metadata = dict(event_digest=fingerprint, policy_digest=self.policy.digest,
                        policy_version=self.policy.version,
                        model_provider=getattr(self.model, "provenance", "test_double"),
                        evidence_provider=getattr(self.tools, "provenance", "test_double"))
        existing = self.repository.get_by_idempotency_key(key)
        if existing is not None:
            if "metadata" in existing and existing["metadata"] != metadata:
                raise PolicyError("Idempotency key reused with changed event or policy")
            if existing["state"] in TERMINAL:
                validate("result", existing["result"])
            return existing
        if not self.repository.create_investigation(key, metadata):
            return self.repository.get_by_idempotency_key(key)
        budget = Budget(self.policy, self.clock)
        started_at = self.clock.utcnow()
        ledger = Ledger()
        state = "RECEIVED"
        missing = []

        def audit(kind, **fields):
            self.repository.append_audit_event(key, {"kind": kind, "at": self.clock.utcnow(), **fields})

        def move(target):
            nonlocal state
            state = transition(state, target)
            audit("state", target=target)

        def context():
            value = {"event": deepcopy(event), "evidence": ledger.context(), "missing_evidence": list(missing)}
            if len(canonical(value).encode()) > 65536:
                raise ContractError("Working context byte limit / 工作上下文大小超限")
            return value

        async def call(kind, operation, label):
            # Reservation precedes adapter invocation. It authorizes just this call.
            budget.reserve(kind)
            audit("budget_reserved", counter=kind, usage=budget.usage())
            if budget.remaining() <= 0: raise BudgetError("Deadline before invocation")
            audit("call_started", call_kind=kind, operation=label)
            try:
                value = await asyncio.wait_for(operation(), timeout=budget.remaining())
            except asyncio.TimeoutError as exc:
                raise BudgetError("Active call deadline / 執行逾時") from exc
            except InvestigationError:
                raise
            except Exception as exc:
                error = ModelError if kind == "model_calls" else ToolExecutionError
                raise error("Provider call failed / 提供者呼叫失敗") from exc
            if budget.remaining() <= 0: raise BudgetError("Deadline after invocation")
            audit("call_completed", call_kind=kind, operation=label)
            return value

        try:
            move("VALIDATED")
            audit("policy_loaded", policy_version=self.policy.version, policy_digest=self.policy.digest)
            move("POLICY_LOADED")
            # Admission checks identifiers without relying on model behavior.
            if not self.policy.admits_event(event["event_id"]):
                raise PolicyError("Event outside trusted scope")
            move("INVESTIGATING")
            dispatch = {
                "get_change_event": self.tools.get_change_event,
                "get_rbac_object": self.tools.get_rbac_object,
                "get_subject_bindings": self.tools.get_subject_bindings,
                "get_approval_record": self.tools.get_approval_record,
            }
            while True:
                ctx = context()
                action = await call("model_calls", lambda: self.model.choose_action(ctx, self.policy.allowed_tools), "choose_action")
                validate("action", action)
                audit("model_action", action=deepcopy(action))
                if action["type"] == "finish":
                    ctx = context()
                    draft = await call("model_calls", lambda: self.model.produce_result(ctx), "produce_result")
                    # The result-producing call must also be budgeted and grounded.
                    validate("draft", draft)
                    audit("model_result_received", draft=deepcopy(draft))
                    validate_grounding(draft, ledger, event)
                    reason = "model_finished"
                    break
                tool, arguments = action["tool"], action["arguments"]
                try:
                    self.policy.authorize(tool, arguments)
                except InvestigationError as exc:
                    audit("policy_rejected", tool=tool, error=type(exc).__name__)
                    raise
                audit("policy_permitted", tool=tool)
                try:
                    response = await call("tool_calls", lambda: dispatch[tool](**arguments), tool)
                    evidence, body, added = ledger.add(tool, arguments, response, self.clock.utcnow())
                except ToolExecutionError:
                    missing.append(tool + ": required evidence unavailable")
                    raise
                if added:
                    # A tool returns at most one item and check() reserved capacity.
                    budget.evidence_items += 1
                    self.repository.append_evidence(key, evidence, body)
                    audit("evidence_added", evidence_id=evidence["evidence_id"], usage=budget.usage())
        except PersistenceError:
            budget.stopped = True
            raise
        except InvestigationError as exc:
            reason = type(exc).__name__
            audit("failure", error=reason)
            status = "insufficient_evidence" if isinstance(exc, ToolExecutionError) else "inconclusive" if isinstance(exc, BudgetError) else "investigation_failed"
            draft = dict(status=status, risk="unknown", summary="Investigation unresolved / 調查未能完成判定",
                         findings=[], missing_evidence=missing, recommended_next_actions=["Review persisted evidence and audit / 人工檢視證據與稽核紀錄"])
        budget.stopped = True
        result = dict(investigation_id=key, event_id=event["event_id"], **draft,
                      budget_usage=budget.usage(), termination_reason=reason,
                      timestamps=dict(started_at=started_at, finished_at=self.clock.utcnow()))
        validate("result", result)
        target = STATUS_STATE[result["status"]]
        # Admission errors can terminate before INVESTIGATING; never jump forward.
        transition(state, target)
        self.repository.save_result(key, result)
        self.repository.mark_terminal(key, target)
        return self.repository.get_by_idempotency_key(key)
