"""Statistics and per-split summaries. Normative text: evals/SPEC.md, section 10 (EV-MET-01..05).

Python standard library only. Pure functions over observations; nothing here
runs a model or reads a file.
"""
from collections import defaultdict
from math import comb, sqrt

Z95 = 1.959963984540054
CONCLUSIVE = ("suspicious", "benign")
FORMAT_FAILURES = ("ModelError", "ContractError")
POLICY_REJECTIONS = ("ToolNotAllowedError", "ScopeError", "PolicyError")


def _round(value):
    return None if value is None else round(value, 6)


def _wilson(p, n, z=Z95):
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return [max(0.0, round(centre - half, 6)), min(1.0, round(centre + half, 6))]


def wilson_interval(k, n, z=Z95):
    """Wilson score interval for k successes in n trials (n may be an effective, non-integer size)."""
    if k < 0 or n < 0 or k > n:
        raise ValueError(f"impossible counts k={k!r}, n={n!r}")
    if n == 0:
        return None
    return _wilson(k / n, n, z)


def clustered_rate(pairs):
    """Rate over (cluster, success) pairs with a naive and a design-effect-adjusted Wilson interval."""
    pairs = list(pairs)
    n = len(pairs)
    if n == 0:
        return {"k": 0, "n": 0, "clusters": 0, "rate": None, "ci_naive": None, "deff": None, "n_eff": None,
                "ci": None}
    totals = defaultdict(lambda: [0, 0])
    for cluster, success in pairs:
        totals[cluster][0] += bool(success)
        totals[cluster][1] += 1
    k = sum(hit for hit, _ in totals.values())
    rate, m = k / n, len(totals)
    deff = None
    if m >= 2 and 0 < rate < 1:
        clustered = m / (m - 1) * sum((hit - size * rate) ** 2 for hit, size in totals.values()) / n ** 2
        deff = max(1.0, clustered / (rate * (1 - rate) / n))
    n_eff = n / deff if deff is not None else float(n)
    return {"k": k, "n": n, "clusters": m, "rate": _round(rate), "ci_naive": wilson_interval(k, n),
            "deff": _round(deff), "n_eff": _round(n_eff), "ci": _wilson(rate, n_eff)}


def pass_hat_k(successes_by_case, k):
    """tau-bench pass^k: mean over cases of C(c, k) / C(n, k)."""
    if type(k) is not int or k < 1:
        raise ValueError("k must be an integer of at least 1")
    if not successes_by_case:
        return None
    total = 0.0
    for case_id, trials in successes_by_case.items():
        n = len(trials)
        if n < k:
            raise ValueError(f"case {case_id!r} has {n} trial(s), fewer than k={k}")
        total += comb(sum(bool(t) for t in trials), k) / comb(n, k)
    return total / len(successes_by_case)


def _usage(observations, key):
    values = [obs["usage"][key] for obs in observations]
    if not values:
        return {"mean": None, "max": None}
    return {"mean": _round(sum(values) / len(values)), "max": max(values)}


def summarize(observations, violated, k):
    """Per-split metrics (EV-MET-05) over observations of one provider.

    Each observation is {case_id, family, oracle_label, outcome, termination_reason, usage, relation_kind, trial};
    `violated` is the set of (case_id, trial) whose relation is violated.
    """
    observations = list(observations)

    def rate(selected, success):
        return clustered_rate((obs["family"], success(obs)) for obs in observations if selected(obs))

    def correct(obs):
        return obs["outcome"] == obs["oracle_label"]

    conclusive = lambda obs: obs["oracle_label"] in CONCLUSIVE  # noqa: E731
    successes = defaultdict(list)
    for obs in sorted(observations, key=lambda o: (o["case_id"], o["trial"])):
        successes[obs["case_id"]].append(correct(obs))
    reasons = defaultdict(int)
    for obs in observations:
        reasons[obs["termination_reason"] or "none"] += 1
    value = pass_hat_k(successes, k)
    return {
        "cases": len(successes),
        "families": len({obs["family"] for obs in observations}),
        "wrong_benign": rate(lambda o: o["oracle_label"] == "suspicious", lambda o: o["outcome"] == "benign"),
        "false_alarm": rate(lambda o: o["oracle_label"] == "benign", lambda o: o["outcome"] == "suspicious"),
        "abstention": rate(conclusive, lambda o: o["outcome"] not in CONCLUSIVE),
        "coverage": rate(conclusive, lambda o: o["outcome"] in CONCLUSIVE),
        "selective_accuracy": rate(lambda o: conclusive(o) and o["outcome"] in CONCLUSIVE, correct),
        "verdict_accuracy": rate(lambda o: True, correct),
        "unresolved_kept": rate(lambda o: o["oracle_label"] == "unresolved", lambda o: o["outcome"] == "unresolved"),
        "adapter_or_format_failure": rate(lambda o: True, lambda o: o["termination_reason"] in FORMAT_FAILURES),
        "policy_rejection": rate(lambda o: True, lambda o: o["termination_reason"] in POLICY_REJECTIONS),
        "grounding_failure": rate(lambda o: True, lambda o: o["termination_reason"] == "GroundingError"),
        "run_error": rate(lambda o: True, lambda o: o["outcome"] == "error"),
        "metamorphic_violation": rate(lambda o: o["relation_kind"] in ("invariant", "monotonic"),
                                      lambda o: (o["case_id"], o["trial"]) in violated),
        "pass_hat_k": {"k": k, "value": _round(value), "cases": len(successes)},
        "termination_reasons": dict(sorted(reasons.items())),
        "usage": {key: _usage(observations, key) for key in ("model_calls", "tool_calls", "evidence_items",
                                                              "runtime_seconds")},
    }
