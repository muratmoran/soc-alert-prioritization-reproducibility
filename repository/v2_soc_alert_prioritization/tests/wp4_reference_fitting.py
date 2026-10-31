"""Independent reference implementation of the WP4 fitting specification, for verification only.

Written from docs/revision/wp4/fitting_specification.md with plain Python loops and
dictionaries over individual alerts. It shares no code with soc_alert_ranking.revision.features
(no key tables, no numpy aggregation, no production shrinkage or fallback helpers), so
agreement with production is evidence rather than tautology. Inputs are plain per-alert
records: detector, native_key, y and the set of containing phases.
"""

from __future__ import annotations

LAMBDA = 50.0
H_MIN, H_MAX = 0.05, 0.95
MIN_SUPPORT, MIN_POSITIVE, MIN_PRECISION, MIN_PURITY = 5, 3, 0.5, 0.7
UNKNOWN = "unknown"


def clip(value):
    return min(max(value, H_MIN), H_MAX)


def shrink(positives, n, prior):
    weight = n / (n + LAMBDA)
    return weight * (positives / n) + (1 - weight) * prior


def records(rows, labels, phases, excluded=frozenset()):
    """Per-alert dicts for one scenario, without alerts whose (detector, native_key) is excluded."""

    out = []
    for i, (detector, key) in enumerate(zip(rows["detector"], rows["native_key"])):
        if (detector, key) in excluded:
            continue
        out.append({"detector": str(detector), "key": (str(detector), str(key)), "y": bool(labels.y[i]),
                    "phases": {phases[p] for p in range(len(phases)) if labels.phase_membership[i, p]}})
    return out


def mapping(alerts_by_scenario, fit_set, phases):
    """Key -> accepted phase (alphabetical tie on the largest containing-phase count) or UNKNOWN."""

    stats = {}
    for scenario in fit_set:
        for alert in alerts_by_scenario[scenario]:
            entry = stats.setdefault(alert["key"], {"n": 0, "pos": 0, "phase": {}})
            entry["n"] += 1
            if alert["y"]:
                entry["pos"] += 1
            for phase in alert["phases"]:
                entry["phase"][phase] = entry["phase"].get(phase, 0) + 1
    classes = {}
    for key, entry in stats.items():
        if entry["pos"] == 0:
            classes[key] = UNKNOWN
            continue
        best = max(entry["phase"].values())
        top = sorted(p for p, count in entry["phase"].items() if count == best)[0]
        precision = entry["pos"] / entry["n"]
        purity = best / entry["pos"]
        ok = entry["n"] >= MIN_SUPPORT and entry["pos"] >= MIN_POSITIVE and precision >= MIN_PRECISION and purity >= MIN_PURITY
        classes[key] = top if ok else UNKNOWN
    return classes, stats


def class_heights(alerts_by_scenario, fit_set, phases, grouping="detector_class"):
    """Cross-fitted pooled cells: rows of j classed by the mapping fitted on fit_set minus {j}."""

    cells, detector_totals = {}, {}
    total_pos = total_n = 0
    for j in sorted(fit_set):
        classes, _ = mapping(alerts_by_scenario, [s for s in fit_set if s != j], phases)
        for alert in alerts_by_scenario[j]:
            cls = classes.get(alert["key"], UNKNOWN)
            if grouping == "detector_class":
                cell = (alert["detector"], cls)
            elif grouping == "global_class":
                cell = ("__all__", cls)
            else:
                cell = (alert["detector"], "all_classes")
            pos_n = cells.setdefault(cell, [0, 0])
            pos_n[0] += alert["y"]
            pos_n[1] += 1
            det = detector_totals.setdefault(alert["detector"], [0, 0])
            det[0] += alert["y"]
            det[1] += 1
            total_pos += alert["y"]
            total_n += 1
    heights = {}
    for cell, (pos, n) in cells.items():
        prior_pos, prior_n = detector_totals[cell[0]] if grouping == "detector_class" else (total_pos, total_n)
        unclipped = shrink(pos, n, prior_pos / prior_n)
        heights[cell] = {"positives": pos, "n": n, "prior_positives": prior_pos, "prior_n": prior_n,
                         "unclipped": unclipped, "height": clip(unclipped)}
    return heights, detector_totals, (total_pos, total_n)


def applied_class_height(key, final_classes, heights, detector_totals, global_prior, grouping="detector_class"):
    """Height and fallback code (0 cell, 1 detector prior, 2 global prior) for one key."""

    detector = key[0]
    cls = final_classes.get(key, UNKNOWN)
    cell = {"detector_class": (detector, cls), "global_class": ("__all__", cls)}.get(grouping, (detector, "all_classes"))
    if cell in heights:
        return heights[cell]["height"], 0
    if grouping == "detector_class" and detector_totals.get(detector, [0, 0])[1] > 0:
        pos, n = detector_totals[detector]
        return clip(pos / n), 1
    if global_prior[1] > 0:
        return clip(global_prior[0] / global_prior[1]), 2
    raise RuntimeError("no permitted training labels")


def key_heights(alerts_by_scenario, fit_set, all_keys):
    """Per-key shrunk observed-positive frequency with the pooled detector prior."""

    per_key, detector_totals = {}, {}
    total_pos = total_n = 0
    for scenario in fit_set:
        for alert in alerts_by_scenario[scenario]:
            entry = per_key.setdefault(alert["key"], [0, 0])
            entry[0] += alert["y"]
            entry[1] += 1
            det = detector_totals.setdefault(alert["detector"], [0, 0])
            det[0] += alert["y"]
            det[1] += 1
            total_pos += alert["y"]
            total_n += 1
    out = {}
    for key in all_keys:
        detector = key[0]
        if key in per_key:
            pos, n = per_key[key]
            prior_pos, prior_n = detector_totals[detector]
            out[key] = (clip(shrink(pos, n, prior_pos / prior_n)), 0)
        elif detector_totals.get(detector, [0, 0])[1] > 0:
            pos, n = detector_totals[detector]
            out[key] = (clip(pos / n), 1)
        elif total_n > 0:
            out[key] = (clip(total_pos / total_n), 2)
        else:
            raise RuntimeError("no permitted training labels")
    return out
