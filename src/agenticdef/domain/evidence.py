from copy import deepcopy
from hashlib import sha256

from .contracts import canonical, validate
from .errors import GroundingError, ToolExecutionError


class Ledger:
    def __init__(self):
        self.items = {}
        self.bodies = {}

    def add(self, tool, arguments, response, acquired_at):
        if not isinstance(response, dict) or set(response) != {"source", "observed_at", "data"}:
            raise ToolExecutionError("Invalid evidence envelope")
        if not isinstance(response["data"], dict) or len(canonical(response).encode()) > 8192:
            raise ToolExecutionError("Evidence byte limit or invalid body")
        body = {"tool": tool, "arguments": deepcopy(arguments), **deepcopy(response)}
        digest = sha256(canonical(body).encode()).hexdigest()
        eid = "ev-" + digest
        evidence = dict(evidence_id=eid, source=response["source"], observed_at=response["observed_at"],
                        acquired_at=acquired_at, method=tool, content_ref="sha256:" + digest,
                        summary="Read-only evidence / 唯讀證據: " + tool,
                        integrity=dict(algorithm="sha256", digest=digest))
        validate("evidence", evidence)
        if eid in self.items:
            if self.bodies[eid] != body:
                raise GroundingError("Conflicting evidence identity")
            return self.items[eid], body, False
        self.items[eid], self.bodies[eid] = evidence, body
        return evidence, body, True

    def context(self):
        return [{"evidence": deepcopy(e), "untrusted_data": deepcopy(self.bodies[eid])} for eid, e in self.items.items()]


def required_requests(event):
    resource, change = event["resource"], event["change"]
    return [("get_change_event", {"event_id": event["event_id"]}),
            ("get_rbac_object", {**resource, "version": change["before_version"]}),
            ("get_rbac_object", {**resource, "version": change["after_version"]}),
            ("get_subject_bindings", {"subject_id": event["actor"]["subject_id"]}),
            ("get_approval_record", {"change_id": change["change_id"]})]


def validate_grounding(draft, ledger, event=None):
    validate("draft", draft)
    for finding in draft["findings"]:
        if not finding["evidence_ids"] or any(eid not in ledger.items for eid in finding["evidence_ids"]):
            raise GroundingError("Finding cites missing evidence / 發現引用不存在的證據")
    if draft["status"] in {"confirmed_suspicious", "likely_benign"}:
        if not draft["findings"] or draft["missing_evidence"]:
            raise GroundingError("Conclusive result requires findings and complete evidence")
        required = {"get_change_event", "get_rbac_object", "get_subject_bindings", "get_approval_record"}
        if not required <= {e["method"] for e in ledger.items.values()}:
            raise GroundingError("Required investigation evidence not collected")
        if event is not None:
            for tool, arguments in required_requests(event):
                if not any(b["tool"] == tool and b["arguments"] == arguments for b in ledger.bodies.values()):
                    raise GroundingError("Exact event, versions, subject, and approval evidence required")
        if draft["risk"] != ("high" if draft["status"] == "confirmed_suspicious" else "low"):
            raise GroundingError("Status and risk disagree")
    if draft["status"] in {"insufficient_evidence", "inconclusive", "investigation_failed"} and draft["risk"] != "unknown":
        raise GroundingError("Unresolved investigation must retain unknown risk")
    return draft
