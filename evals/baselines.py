"""Reference model-port baselines. Normative text: evals/SPEC.md, section 10 (EV-BASE-01, EV-BASE-02).

Each baseline is a deterministic stand-in for a model: it reads only the
investigation context the runtime passes to every model and returns a typed
action or draft, which then crosses the same runtime checks as any provider.
No network, no randomness, no state across runs.
"""
from . import oracle

VERDICTS = {"suspicious": ("confirmed_suspicious", "high"), "benign": ("likely_benign", "low"),
            "unresolved": ("insufficient_evidence", "unknown")}


def _collected(context):
    return [item["untrusted_data"] for item in context["evidence"]]


def _evidence_ids(context):
    return [item["evidence"]["evidence_id"] for item in context["evidence"]]


def _draft(status, risk, claim, evidence_ids):
    findings = [{"claim": claim, "evidence_ids": evidence_ids}] if evidence_ids else []
    return {"status": status, "risk": risk, "summary": "Baseline verdict / 基準判定", "findings": findings,
            "missing_evidence": [], "recommended_next_actions": ["Human review; no remediation executed / 人工審查"]}


class _ReadsThenVerdict:
    """Request the five required reads in order, then finish."""

    async def choose_action(self, context, allowed_tools):
        collected = _collected(context)
        for tool, arguments in oracle.required_reads(context["event"]):
            if not any(body["tool"] == tool and body["arguments"] == arguments for body in collected):
                return {"type": "tool_request", "tool": tool, "arguments": arguments}
        return {"type": "finish"}


class AlwaysSuspicious(_ReadsThenVerdict):
    provenance = "baseline_always_suspicious"

    async def produce_result(self, context):
        return _draft("confirmed_suspicious", "high", "Trivial baseline: always suspicious", _evidence_ids(context))


class AlwaysBenign(_ReadsThenVerdict):
    provenance = "baseline_always_benign"

    async def produce_result(self, context):
        return _draft("likely_benign", "low", "Trivial baseline: always benign", _evidence_ids(context))


class AlwaysUnresolved:
    provenance = "baseline_always_unresolved"

    async def choose_action(self, context, allowed_tools):
        return {"type": "finish"}

    async def produce_result(self, context):
        return _draft("inconclusive", "unknown", "", [])


class DeterministicOracle(_ReadsThenVerdict):
    """Fixed reads plus the deterministic oracle rule: the ceiling against oracle labels, by construction."""

    provenance = "baseline_deterministic_oracle"

    async def produce_result(self, context):
        evidence = [{"tool": body["tool"], "arguments": body["arguments"], "observed_at": body["observed_at"],
                     "data": body["data"]} for body in _collected(context)]
        verdict = oracle.judge(context["event"], evidence)
        status, risk = VERDICTS[verdict["label"]]
        claim = "Deterministic rule: " + "; ".join(verdict["reasons"])
        return _draft(status, risk, claim[:2048], _evidence_ids(context))


BASELINE_PROVENANCES = tuple(model.provenance for model in (AlwaysSuspicious, AlwaysBenign, AlwaysUnresolved,
                                                            DeterministicOracle))
