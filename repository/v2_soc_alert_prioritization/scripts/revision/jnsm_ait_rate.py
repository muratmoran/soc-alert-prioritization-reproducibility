#!/usr/bin/env python
"""Training-only native-key adaptation of the published AIT detector rate score."""
from __future__ import annotations
import json
from pathlib import Path
import numpy as np
import pandas as pd
from jnsm_revision_analysis import (PROJECT, DATA, DOC, OUT, sha, load_everything,
    timing_summary, aggregate_replay, full_order, metrics_at_k, replay_fold, write_fold)
from soc_alert_ranking.revision.labels import load_label_intervals

WINDOWS = {
 'fox': ('2022-01-17 11:00','2022-01-17 16:00'),
 'harrison': ('2022-02-07 05:00','2022-02-07 09:00'),
 'russellmitchell': ('2022-01-23 01:00','2022-01-23 06:00'),
 'santos': ('2022-01-16 10:00','2022-01-16 15:00'),
 'shaw': ('2022-01-28 12:00','2022-01-28 17:00'),
 'wardbeck': ('2022-01-22 10:00','2022-01-22 15:00'),
 'wheeler': ('2022-01-29 07:30','2022-01-29 18:00'),
 'wilson': ('2022-02-06 13:00','2022-02-06 18:00'),
}

def fit_scores(counts, training, nkeys):
    selected=counts[counts.scenario.isin(training)].copy()
    assert len(selected)>0
    a=selected.attack_count.to_numpy(float)
    rate_ratio=np.divide(selected.normal_count.to_numpy(float)*selected.attack_seconds.to_numpy(float),
                         a*selected.normal_seconds.to_numpy(float),out=np.ones(len(a)),where=a>0)
    selected['contribution']=np.where(a>0,np.maximum(0,1-rate_ratio),0)
    # Every existing phase has one row per key, even when that key never fires.
    phase_scores=selected.groupby(['key_id','phase']).contribution.mean()
    scores=np.zeros(nkeys)
    best=phase_scores.groupby('key_id').max()
    scores[best.index.to_numpy(int)]=best.to_numpy()
    return scores

def reference_scores(counts, training, nkeys):
    by={}
    for r in counts.itertuples(index=False):
        if r.scenario not in training: continue
        val=0 if r.attack_count==0 else max(0,1-(r.normal_count/r.normal_seconds)/(r.attack_count/r.attack_seconds))
        by.setdefault((r.key_id,r.phase),[]).append(val)
    scores=np.zeros(nkeys)
    for (key,phase),vals in by.items(): scores[key]=max(scores[key],sum(vals)/len(vals))
    return scores

def main():
    print('Loading verified data for declared rate-score adaptation',flush=True)
    config,severity,ranking,store,identity=load_everything()
    intervals=load_label_intervals(DATA/'ait_alert/labels.csv',severity,config.tau)
    records=[]
    for scenario in ranking.scenarios:
        rows=ranking.rows(scenario); ts=rows.timestamp.to_numpy(float); ids=rows.key_id.to_numpy(int)
        lo,hi=[pd.Timestamp(x,tz='UTC').timestamp() for x in WINDOWS[scenario]]
        assert ts.min()<=lo<hi<=ts.max()
        phases=intervals[intervals.scenario==scenario]
        assert not ((phases.start<hi)&(phases.end>lo)).any()
        bg=np.bincount(ids[(ts>=lo)&(ts<hi)],minlength=ranking.n_keys)
        for phase,ivs in phases.groupby('phase'):
            mask=np.zeros(len(ts),bool)
            for iv in ivs.itertuples(): mask|=(ts>=iv.start)&(ts<iv.end)
            counts=np.bincount(ids[mask],minlength=ranking.n_keys)
            dur=float((ivs.end-ivs.start).sum())
            for key in range(ranking.n_keys):
                records.append(dict(scenario=scenario,key_id=key,phase=phase,attack_count=int(counts[key]),
                                    normal_count=int(bg[key]),attack_seconds=dur,normal_seconds=hi-lo))
    counts=pd.DataFrame(records); counts.to_csv(DOC/'ait_rate_training_counts.csv',index=False)
    summaries=[]; statics=[]; fitted=[]
    for scenario in ranking.scenarios:
        training=tuple(x for x in ranking.scenarios if x!=scenario)
        with store.locked([scenario]):
            key_scores=fit_scores(counts,training,ranking.n_keys)
            np.testing.assert_allclose(key_scores,reference_scores(counts,training,ranking.n_keys),atol=1e-14,rtol=0)
            mutation=counts.copy()
            mutation.loc[mutation.scenario==scenario,['attack_count','normal_count']]=999999
            np.testing.assert_array_equal(key_scores,fit_scores(mutation,training,ranking.n_keys))
            np.testing.assert_array_equal(key_scores,fit_scores(counts[counts.scenario!=scenario],training,ranking.n_keys))
            rows=ranking.rows(scenario); scores=key_scores[rows.key_id.to_numpy(int)]
        for key,score in enumerate(key_scores): fitted.append(dict(held_out=scenario,key_id=key,score=score,training=';'.join(training)))
        ts=rows.timestamp.to_numpy(float); hk=rows.hash_key.to_numpy(); labels=store.get(scenario,purpose='ait_rate:evaluation')
        m=metrics_at_k(full_order(scores,ts,hk),labels,100)
        statics.append(dict(scenario=scenario,covered=m.covered_intervals,negative=m.negatives_in_top))
        cid='AIT_rate_native_key_adaptation'
        replay=replay_fold('ait_rate',scenario,{cid:scores},{cid:{'family':cid,'rules':'untuned'}},ts,hk,labels,np.zeros(len(ts),bool),rates=(12.0,))
        write_fold(OUT/'ait_rate'/scenario,replay)
        r=replay['summaries'].iloc[0].to_dict()
        summaries.append({**r,**timing_summary(replay['intervals'],float(ts.min())),
                          'scenario':scenario,'method':'AIT_rate','design':'LOSO_all'})
        print(f'{scenario}: independent score, held-out mutation/deletion, replay checks passed',flush=True)
    pd.DataFrame(fitted).to_csv(DOC/'ait_rate_fitted_scores.csv',index=False)
    pd.DataFrame(statics).to_csv(DOC/'ait_rate_static.csv',index=False)
    pd.DataFrame(summaries).to_csv(DOC/'ait_rate_replay_by_scenario.csv',index=False)
    aggregate_replay(pd.DataFrame(summaries)).to_csv(DOC/'ait_rate_replay.csv',index=False)
    record={'date':'2026-10-26','analysis':'exploratory native-key adaptation; not a replication',
            'spec_sha256':sha(DOC/'ait_rate_adaptation.md'),'script_sha256':sha(Path(__file__)),
            'data':identity,'folds':len(statics),'independent_scores_agree':True,'held_out_invariance':True,
            'replay_integrity_passed':True,'normal_windows_utc':WINDOWS}
    record['outputs']={str(p.relative_to(PROJECT)):sha(p) for p in list(DOC.glob('ait_rate_*.csv'))+list((OUT/'ait_rate').rglob('*')) if p.is_file()}
    (DOC/'ait_rate_manifest.json').write_text(json.dumps(record,indent=2)+'\n')

if __name__=='__main__': main()
