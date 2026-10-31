"""Independent and boundary checks for review-response extensions."""
import numpy as np
from soc_alert_ranking.revision.review_extensions import (
    simulate, random_priorities, group_arrays, CriticalReliabilityProvider, service_outcomes,
)
from soc_alert_ranking.revision.replay import replay_alerts
from soc_alert_ranking.revision.duplicates import assign_clusters, static_cluster_labels
from soc_alert_ranking.revision.features import RankingFrame
from soc_alert_ranking.revision.labels import LabelStore, phase_order, intervals_from_frame
from soc_alert_ranking.revision.synthetic import make_synthetic_alerts
from soc_alert_ranking.mappings.severity import SeverityMapping


def test_replay_independent_scan_and_original_agree():
    for seed in range(10):
        rng = np.random.default_rng(seed)
        t = np.sort(rng.integers(0, 1000, 300)).astype(float)
        scores = rng.integers(0, 5, len(t)).astype(float); scores[::13] = np.nan
        hashes = rng.permutation(len(t)).astype(np.uint64)
        old = replay_alerts(scores, t, hashes, 300)
        new = simulate(scores, t, hashes, 300, t.min(), t.max())
        np.testing.assert_array_equal(old.selected, new.selected)
        np.testing.assert_array_equal(old.start, new.start)
        np.testing.assert_array_equal(old.backlog_at_selection, new.backlog_at_selection)
        np.testing.assert_array_equal(old.tie_decided, new.tie_decided)
        pri = random_priorities(hashes, seed)
        new = simulate(scores, t, hashes, 300, t.min(), t.max(), pri)
        remaining = set(range(len(t))); now = t.min(); chosen = []; starts = []
        while remaining and now <= t.max():
            ready = [i for i in remaining if t[i] <= now]
            if not ready:
                now = min(t[i] for i in remaining)
                continue
            i = min(ready, key=lambda i: (np.inf if np.isnan(scores[i]) else -scores[i],
                                         int(pri[i]), t[i], int(hashes[i])))
            chosen.append(i); starts.append(now); remaining.remove(i); now += 12
        np.testing.assert_array_equal(chosen, new.selected)
        np.testing.assert_array_equal(starts, new.start)


def test_priority_prefix_and_permutation_invariance():
    h = np.array([123, 77, 500, 991], dtype=np.uint64)
    np.testing.assert_array_equal(random_priorities(h, 7)[:2], random_priorities(h[:2], 7))
    np.testing.assert_array_equal(random_priorities(h[::-1], 7), random_priorities(h, 7)[::-1])
    assert len(np.unique(random_priorities(h, 7))) == len(h)


def test_closed_groups_do_not_look_ahead_or_shorten_horizon():
    t = np.array([0., 4., 10., 14., 20.])
    h = np.arange(len(t), dtype=np.uint64)
    clusters = assign_clusters(np.array(['d']*5), np.array(['k']*5), np.array(['h']*5), t, h, 10)
    reps, index, release, scores = group_arrays(clusters, t, np.array([1.,9.,2.,8.,100.]))
    np.testing.assert_array_equal(release, [10.,20.,30.])
    np.testing.assert_array_equal(scores, [9.,8.,100.])
    trace = simulate(scores, release, h[reps], 360, 0., 20.)
    np.testing.assert_array_equal(trace.selected, [0, 1])
    np.testing.assert_array_equal(trace.start, [10.,20.])
    assert trace.arrivals == 2 and trace.idle_seconds == 10.
    empty = simulate(scores, release, h[reps], 360, 0., 5.)
    assert empty.investigations == 0 and empty.idle_seconds == 5.


def setup():
    alerts, intervals = make_synthetic_alerts(4, 200)
    severity = SeverityMapping.from_file()
    ranking = RankingFrame.from_alerts(alerts)
    store = LabelStore.from_alerts(ranking.frame, intervals_from_frame(intervals, severity, 8),
                                  phase_order(severity), 8)
    return ranking, store, severity


def test_critical_target_preserves_mapping_and_enforces_lock():
    from soc_alert_ranking.revision.features import KeyTableProvider
    from soc_alert_ranking.revision.labels import LabelAccessError
    ranking, store, severity = setup()
    normal = KeyTableProvider(ranking, store, phase_order(severity))
    critical = CriticalReliabilityProvider(ranking, store, phase_order(severity))
    for s in ranking.scenarios:
        a, b = normal.get(s, 'mapping'), critical.get(s, 'mapping')
        np.testing.assert_array_equal(a.positives, b.positives)
        c = critical.get(s, 'class_heights')
        assert c.positives.sum() == store.get(s, 'test').z.sum()
        assert c.positives.sum() <= a.positives.sum()
        with store.locked([s]):
            try:
                critical.get(s, 'class_heights')
            except LabelAccessError:
                pass
            else:
                raise AssertionError('locked labels were accessed')


def test_group_coverage_never_precedes_last_member_and_end_is_late():
    from dataclasses import replace
    ranking, store, severity = setup()
    s = ranking.scenarios[0]; rows = ranking.rows(s); labels = store.get(s, 'test')
    clusters = assign_clusters(rows.detector, rows.native_key, rows.host, rows.timestamp, rows.hash_key, 300)
    grouped, reps, _ = static_cluster_labels(labels, clusters)
    reps2, index, release, scores = group_arrays(clusters, rows.timestamp.to_numpy(), np.ones(len(rows)))
    np.testing.assert_array_equal(reps, reps2)
    trace = simulate(scores, release, rows.hash_key.to_numpy()[reps], 3600,
                     rows.timestamp.min(), rows.timestamp.max())
    for i, started in zip(trace.selected, trace.start):
        assert started > rows.timestamp.to_numpy()[index == i].max()
    outcomes = service_outcomes(trace, grouped, labels, index)
    assert outcomes['critical_records_contained'] <= outcomes['critical_records_total']
    # A hit exactly at an exclusive end must be late.
    hit = np.flatnonzero(labels.critical_membership.any(axis=1))[0]
    end = float(labels.critical_interval_ids[np.flatnonzero(labels.critical_membership[hit])[0]].rsplit('|',1)[1])
    special = replace(trace, selected=np.array([hit]), start=np.array([end]), tie_decided=np.array([False]))
    assert service_outcomes(special, labels)['late'] >= 1


def test_critical_reliability_excluded_label_mutation():
    from dataclasses import replace
    from soc_alert_ranking.revision.features import FeatureBuilder, InputPolicy
    ranking, store, severity = setup()
    provider = CriticalReliabilityProvider(ranking, store, phase_order(severity))
    builder = FeatureBuilder(ranking, provider, severity)
    target = ranking.scenarios[0]; training = ranking.scenarios[1:]
    original = builder.alert_features(target, training, InputPolicy(), 'test:outer_validation')
    labels = store.get(target, 'mutation')
    store.replace(target, replace(labels, y=~labels.y, z=~labels.z,
                                  phase_membership=~labels.phase_membership))
    builder.clear_cache()
    with store.locked([target]):
        mutated = builder.alert_features(target, training, InputPolicy(), 'test:outer_validation')
    for field in ['c', 'u', 'h', 'h_key']:
        np.testing.assert_array_equal(getattr(original, field), getattr(mutated, field))


def load_tests(loader, tests, pattern):
    import unittest
    return unittest.TestSuite(unittest.FunctionTestCase(value)
                              for name,value in sorted(globals().items()) if name.startswith('test_'))
