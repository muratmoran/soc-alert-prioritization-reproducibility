"""Independent reference implementation of the WP3 metric contract, for verification only.

Written from docs/revision/wp3/metric_contract.md with plain Python loops, sets and
fractions. It deliberately shares no code with soc_alert_ranking.revision (no numpy
vectorization, no production helpers) so that agreement is evidence, not tautology.
"""

from __future__ import annotations

import hashlib
import itertools
import math
from fractions import Fraction


def interval_key(interval):
    return (interval["scenario"], interval["phase"], float(interval["start"]), float(interval["end"]))


def reference_labels(alerts, intervals, severity_table, tau):
    """alerts: list of dicts with id, t. intervals: list of dicts (any file order, may repeat)."""

    distinct = {}
    for interval in intervals:
        distinct.setdefault(interval_key(interval), interval)
    critical_keys = sorted(k for k, iv in distinct.items() if severity_table[iv["phase"]] >= tau)
    labelled = []
    for alert in alerts:
        containing = [k for k in distinct if k[2] <= alert["t"] < k[3]]
        severities = [severity_table[k[1]] for k in containing]
        y = len(containing) > 0
        s_star = max(severities) if y else 0.0
        labelled.append({**alert, "y": y, "s_star": s_star, "z": y and s_star >= tau, "r": s_star if y else 0.0,
                         "critical": {k for k in containing if k in critical_keys}})
    return labelled, critical_keys


def tie_hash(alert_id):
    return int.from_bytes(hashlib.sha256(f"cose04000|{alert_id}".encode()).digest()[:8], "big")


def reference_order(labelled):
    def key(alert):
        score = alert["score"]
        missing = score is None or (isinstance(score, float) and math.isnan(score))
        return (1 if missing else 0, 0.0 if missing else -score, alert["t"], tie_hash(alert["id"]))

    return sorted(labelled, key=key)


def reference_at_k(ordered, critical_keys, k):
    n = len(ordered)
    k_eff = min(k, n)
    top = ordered[:k_eff]
    positives_total = sum(1 for a in ordered if a["y"])
    critical_total = sum(1 for a in ordered if a["z"])
    positives_top = sum(1 for a in top if a["y"])
    critical_top = sum(1 for a in top if a["z"])
    dcg = sum(a["r"] / math.log2(j + 2) for j, a in enumerate(top))
    ideal = sorted((a["r"] for a in ordered), reverse=True)[:k_eff]
    idcg = sum(r / math.log2(j + 2) for j, r in enumerate(ideal))
    dcg_exp = sum((2 ** a["r"] - 1) / math.log2(j + 2) for j, a in enumerate(top))
    ideal_exp = sorted((2 ** a["r"] - 1 for a in ordered), reverse=True)[:k_eff]
    idcg_exp = sum(g / math.log2(j + 2) for j, g in enumerate(ideal_exp))
    eligible = set().union(*(a["critical"] for a in ordered)) if ordered else set()
    covered = set().union(*(a["critical"] for a in top)) if top else set()
    div = lambda a, b: None if b == 0 else a / b  # noqa: E731
    return {
        "n": n, "k_eff": k_eff, "short_queue": n < k, "empty_queue": n == 0,
        "positives_in_top": positives_top, "negatives_in_top": k_eff - positives_top,
        "precision": div(positives_top, k_eff), "attack_recall": div(positives_top, positives_total),
        "critical_in_top": critical_top, "critical_recall": div(critical_top, critical_total),
        "ndcg_linear": div(dcg, idcg), "ndcg_exponential": div(dcg_exp, idcg_exp),
        "covered_intervals": len(covered), "eligible_intervals": len(eligible),
        "defined_intervals": len(critical_keys),
        "coverage_eligible": div(len(covered), len(eligible)), "coverage_all": div(len(covered), len(critical_keys)),
    }


def reference_subgroup_in_mixed(ordered, members, k):
    """Subgroup counts among the first min(k, n) alerts of the full mixed order."""

    n = len(ordered)
    k_eff = min(k, n)
    top = [a for a in ordered[:k_eff] if a["id"] in members]
    group = [a for a in ordered if a["id"] in members]
    div = lambda a, b: None if b == 0 else a / b  # noqa: E731
    positives_top = sum(1 for a in top if a["y"])
    positives_total = sum(1 for a in group if a["y"])
    critical_top = sum(1 for a in top if a["z"])
    critical_total = sum(1 for a in group if a["z"])
    eligible = set().union(*(a["critical"] for a in group)) if group else set()
    covered = set().union(*(a["critical"] for a in top)) if top else set()
    return {
        "n": n, "k_eff": k_eff, "subgroup_n": len(group), "subgroup_in_top": len(top),
        "subgroup_share_of_top": div(len(top), k_eff),
        "subgroup_positives_in_top": positives_top, "subgroup_negatives_in_top": len(top) - positives_top,
        "subgroup_positives_total": positives_total, "subgroup_attack_recall": div(positives_top, positives_total),
        "subgroup_critical_in_top": critical_top, "subgroup_critical_total": critical_total,
        "subgroup_critical_recall": div(critical_top, critical_total),
        "subgroup_covered_intervals": len(covered), "subgroup_eligible_intervals": len(eligible),
        "subgroup_coverage": div(len(covered), len(eligible)),
    }


def reference_fraction_budget(n, fraction: Fraction):
    if n == 0:
        return None
    return max(1, math.ceil(Fraction(n) * fraction))


def reference_effort_critical(ordered, target: Fraction):
    total = sum(1 for a in ordered if a["z"])
    if total == 0:
        return None
    required = math.ceil(Fraction(total) * target)
    seen = 0
    for position, alert in enumerate(ordered, start=1):
        seen += alert["z"]
        if seen >= required:
            return {"required": required, "position": position, "queue_fraction": position / len(ordered)}
    raise AssertionError("unreachable")


def reference_effort_coverage(ordered, target: Fraction):
    eligible = set().union(*(a["critical"] for a in ordered)) if ordered else set()
    if not eligible:
        return None
    required = math.ceil(Fraction(len(eligible)) * target)
    covered = set()
    for position, alert in enumerate(ordered, start=1):
        covered |= alert["critical"]
        if len(covered) >= required:
            return {"required": required, "position": position, "queue_fraction": position / len(ordered)}
    raise AssertionError("unreachable")


def reference_first_critical(ordered):
    for position, alert in enumerate(ordered, start=1):
        if alert["z"]:
            return position
    return None


def score_blocks(ordered):
    blocks = []
    for alert in ordered:
        score = alert["score"]
        token = "nan" if score is None or (isinstance(score, float) and math.isnan(score)) else score
        if blocks and blocks[-1][0] == token:
            blocks[-1][1].append(alert)
        else:
            blocks.append((token, [alert]))
    return [members for _, members in blocks]


def brute_force_expectation(ordered, critical_keys, k, metric):
    """Average a metric over every within-block ordering (exhaustive; small queues only)."""

    blocks = score_blocks(ordered)
    total, count = 0.0, 0
    for arrangement in itertools.product(*(itertools.permutations(block) for block in blocks)):
        candidate = [alert for block in arrangement for alert in block]
        value = reference_at_k(candidate, critical_keys, k)[metric]
        total += value
        count += 1
    return total / count


def reference_clusters(alerts, window):
    """alerts: dicts with id, t, detector, key, host. Returns id -> representative id."""

    representative = {}
    groups = {}
    for alert in alerts:
        groups.setdefault((alert["detector"], alert["key"], alert["host"]), []).append(alert)
    for members in groups.values():
        members.sort(key=lambda a: (a["t"], tie_hash(a["id"])))
        anchor = None
        for alert in members:
            if anchor is None or alert["t"] >= anchor["t"] + window:
                anchor = alert
            representative[alert["id"]] = anchor["id"]
    return representative
