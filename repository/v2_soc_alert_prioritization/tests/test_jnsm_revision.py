"""Hand-computed checks of the added endpoint and aggregation logic."""
import sys
import unittest
from pathlib import Path
import pandas as pd
import numpy as np

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/revision'))
from jnsm_revision_analysis import timing_summary, aggregate_replay
from jnsm_ait_rate import fit_scores, reference_scores


class RevisionChecks(unittest.TestCase):
    def test_rate_score_support_zero_counts_and_exclusions(self):
        # Training a contributes .5, b contributes 0; held-out x must not enter.
        counts=pd.DataFrame([
            dict(scenario=s,key_id=0,phase='p',attack_count=a,normal_count=b,
                 attack_seconds=10,normal_seconds=100)
            for s,a,b in [('a',2,10),('b',0,0),('x',1000,0)]])
        np.testing.assert_array_equal(fit_scores(counts,['a','b'],2),[.25,0])
        np.testing.assert_array_equal(reference_scores(counts,['a','b'],2),[.25,0])
        counts.loc[counts.scenario=='a','normal_count']=100
        np.testing.assert_array_equal(fit_scores(counts,['a','b'],2),[0,0])

    def test_exclusive_end_and_uncovered(self):
        frame=pd.DataFrame({'interval':['s|p|100|3700']*4,
            'detected':[True,True,True,False],
            'detection_offset_hours':[0,1,2,float('nan')],
            'delay_hours':[0,1,2,float('nan')]})
        self.assertEqual(timing_summary(frame,100),{'covered_intervals':3,'before_interval_end':1,
            'late_covered_intervals':2,'uncovered_intervals':1,'within_1h':2})

    def test_aggregation_keeps_counts_and_median_of_scenario_means(self):
        rows=[]
        for scenario,delay in zip(['a','b','c'],[0.5,2,90]):
            rows.append(dict(design='Forward',method='P',scenario=scenario,defined_intervals=4,
                covered_intervals=2,before_interval_end=1,late_covered_intervals=1,within_1h=1,
                critical_total=10,critical_investigations=3,fp_investigations=20,investigations=25,
                backlog_at_horizon=100,restricted_mean_delay_hours_lower_bound=delay))
        r=aggregate_replay(pd.DataFrame(rows)).iloc[0]
        self.assertEqual(r.covered,6); self.assertEqual(r.intervals,12)
        self.assertEqual(r.critical_total,30); self.assertEqual(r.delay_lower_bound_median,2)


if __name__=='__main__': unittest.main()
