"""Deterministic test double, not a language model or production RBAC evaluator.

Decisions follow evidence values, never scenario names or expected verdicts.
Fault scripts deliberately simulate hostile/invalid model output in replay.
"""
from copy import deepcopy

from ..domain.errors import ModelError


def requests_for(event):
    resource, change = event["resource"], event["change"]
    pairs = [("get_change_event", {"event_id": event["event_id"]}),
             ("get_rbac_object", {**resource, "version": change["before_version"]}),
             ("get_rbac_object", {**resource, "version": change["after_version"]}),
             ("get_subject_bindings", {"subject_id": event["actor"]["subject_id"]}),
             ("get_approval_record", {"change_id": change["change_id"]})]
    return [{"type": "tool_request", "tool": name, "arguments": args} for name, args in pairs]


class ReplayModel:
    provenance = "deterministic_replay"
    def __init__(self, fault=None):
        self.fault = deepcopy(fault or {})
        self.calls = 0

    async def choose_action(self, context, allowed_tools):
        self.calls += 1
        collected = context["evidence"]
        if "action" in self.fault and len(collected) >= self.fault.get("after_evidence", 0):
            return deepcopy(self.fault["action"])
        for request in requests_for(context["event"]):
            if not any(e["untrusted_data"]["tool"] == request["tool"] and e["untrusted_data"]["arguments"] == request["arguments"] for e in collected):
                return request
        return {"type": "finish"}

    async def produce_result(self, context):
        self.calls += 1
        records = context["evidence"]
        event = context["event"]
        def data(tool, version=None):
            for record in records:
                body = record["untrusted_data"]
                if body["tool"] == tool and (version is None or body["arguments"].get("version") == version):
                    return body["data"]
            raise ModelError("Required fixture evidence missing")
        try:
            before = data("get_rbac_object", event["change"]["before_version"])
            after = data("get_rbac_object", event["change"]["after_version"])
            approval = data("get_approval_record")
            def permissions(role):
                return {(resource, verb) for rule in role["rules"] for resource in rule["resources"] for verb in rule["verbs"]}
            increase = permissions(after) - permissions(before)
            privileged = any(r == "*" or v in {"*", "bind", "escalate", "impersonate"} for r, v in increase)
            approved = (approval["approved"] is True and approval["change_id"] == event["change"]["change_id"]
                        and approval["subject_id"] == event["actor"]["subject_id"]
                        and approval["resource"] == event["resource"]
                        and approval["after_version"] == event["change"]["after_version"])
        except (KeyError, TypeError) as exc:
            raise ModelError("Unsupported synthetic RBAC evidence shape") from exc
        suspicious = privileged and not approved
        ids = [r["evidence"]["evidence_id"] for r in records]
        if self.fault.get("fabricate_evidence"): ids = ["ev-" + "0" * 64]
        return dict(status="confirmed_suspicious" if suspicious else "likely_benign",
                    risk="high" if suspicious else "low",
                    summary="See evidence-backed finding / 請參閱附證據的發現",
                    findings=[dict(claim="Unapproved privileged increase / 未核准的權限提升" if suspicious else "Change consistent with fixture approval and scope / 變更符合測試資料的核准與範圍", evidence_ids=ids)],
                    missing_evidence=[], recommended_next_actions=["Human review; no remediation executed / 人工審查；未執行修復"])
