#!/usr/bin/env python
"""Reproduce the exploratory review response (amendment dated 2026-10-30).

Run from any directory. Existing completed folds are resumed only if their
amendment, source, input and configuration fingerprints match.
"""
from __future__ import annotations
import argparse
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import numpy as np
import pandas as pd

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT/'src'))
sys.path.insert(0, str(PROJECT/'scripts/revision'))
from wp4_stage2_run import load_everything, check_gates, sha256
from wp5_common import fold_inputs, verify_stage2_copy, candidate_roles
from soc_alert_ranking.revision.pipeline import ComparisonPipeline, verify_fold_trace
from soc_alert_ranking.revision.features import FeatureBuilder
from soc_alert_ranking.revision.labels import LabelStore, load_label_intervals, phase_order
from soc_alert_ranking.revision.evaluation import full_order
from soc_alert_ranking.revision.metrics import metrics_at_k
from soc_alert_ranking.revision.duplicates import assign_clusters, static_cluster_labels
from soc_alert_ranking.revision.review_extensions import (
    CriticalReliabilityProvider, simulate, random_priorities, group_arrays, service_outcomes,
)
from soc_alert_ranking.revision.replay import replay_alerts
from soc_alert_ranking.revision.paired_stats import sign_flip_test

DOC = PROJECT/'docs/revision/jnsm_20261030'
OUT = PROJECT/'results/jnsm_20261030'
DATA = Path(os.environ.get('SOC_REVISION_DATA', str(Path.home()/'soc_revision_data')))
PRIMARY = 'primary_coverage_fp_ndcg'
REPLAY_FAMILIES = ['P_probability_proxy','S1_linear_log_constrained',
    'S0_linear_log_historical_key','S1_linear_log_constrained_key',
    'S2_exponential_discount_key','R_severity_key_reliability','O_severity']
SHORT = {'P_probability_proxy':'P','H_weighted':'H','W_weighted':'W',
    'A_additive':'A','C_cost_sensitive':'C','M_multiplicative':'M',
    'S0_linear_log_historical':'S0','S1_linear_log_constrained':'S1','S2_exponential_discount':'S2',
    'S0_linear_log_historical_key':'S0key','S1_linear_log_constrained_key':'S1key',
    'S2_exponential_discount_key':'S2key','R_severity_key_reliability':'Rsev,key',
    'R_key_reliability':'Rkey','L1_logistic':'L1','L2_gradient_boosting':'L2',
    'O_severity':'Severity','O_oldest_first':'FIFO','O_newest_first':'LIFO',
    'O_native_rule_level':'Native level','O_native_suricata_severity':'Native Suricata'}


def selected(config, selections):
    result = {}
    for family, spec in config.families.items():
        if spec.tuned:
            sub = selections[(selections.family == family) & (selections.rule == PRIMARY)]
            if len(sub) != 1: raise ValueError(f'missing selection {family}')
            result[family] = sub.iloc[0].selected_candidate
        else: result[family] = spec.candidates[0].candidate_id
    return result


def variants():
    result = {'baseline':{}}
    for p in [.3,.4,.6,.7]: result[f'precision_{p:g}']={'min_precision':p}
    for q in [.5,.9]: result[f'purity_{q:g}']={'min_phase_purity':q}
    for p in [.3,.7]:
        for q in [.5,.9]: result[f'joint_{p:g}_{q:g}']={'min_precision':p,'min_phase_purity':q}
    for n,a in [(1,1),(10,5)]: result[f'support_{n}_{a}']={'min_support':n,'min_positive':a}
    for lam in [0,10,200]: result[f'lambda_{lam}']={'class_lambda':lam,'key_lambda':lam}
    for delta in [-1,1]:
        result[f'severity_input_{delta:+d}']={'severity_shift':delta}
        result[f'severity_endpoint_{delta:+d}']={'severity_shift':delta,'endpoint_shift':True}
    for tau in [7,9]: result[f'tau_{tau}']={'tau':tau}
    result['critical_reliability']={'critical_target':True}
    return result


def identity(stage, data_identity):
    files = [Path(__file__), PROJECT/'src/soc_alert_ranking/revision/review_extensions.py', DOC/'amendment.md']
    source = {str(p.relative_to(PROJECT)):sha256(p) for p in files}
    return {'stage':stage,'source':source,'data':data_identity,'python':sys.version,
            'numpy':np.__version__,'pandas':pd.__version__}


def save_fold(directory, frames, record):
    directory.mkdir(parents=True,exist_ok=True)
    hashes = {}
    for name,frame in frames.items():
        path=directory/f'{name}.csv.gz'; frame.to_csv(path,index=False,compression='gzip')
        hashes[path.name]=sha256(path)
    (directory/'done.json').write_text(json.dumps({**record,'outputs':hashes},indent=2,default=str)+'\n')


def completed(directory, fingerprint):
    path=directory/'done.json'
    if not path.exists(): return False
    record=json.loads(path.read_text())
    if record['fingerprint'] != fingerprint: raise RuntimeError(f'Stale completed output: {directory}')
    for name,digest in record['outputs'].items():
        if sha256(directory/name)!=digest: raise RuntimeError(f'Changed completed output: {directory/name}')
    return True


def sensitivity(config,severity,ranking,store,data_identity,only):
    base_identity=identity('sensitivity',data_identity)
    # Mechanism sensitivity retains every formula grid and operational reference;
    # learned families are outside this comparison, not silently retuned or replaced.
    families={k:v for k,v in config.families.items() if not v.learned}
    baseline_tables=PROJECT/'docs/revision/wp4/stage2_tables'
    original_selections=pd.read_csv(baseline_tables/'r1_e12_selections.csv')
    original_results=pd.read_csv(baseline_tables/'r1_t1_primary_long.csv')
    for name,params in variants().items():
        if only and name not in only: continue
        settings=replace(config.settings,**{k:v for k,v in params.items() if k in asdict(config.settings)})
        severity2=replace(severity,ait_phase_severity={p:float(np.clip(s+params.get('severity_shift',0),0,10))
                         for p,s in severity.ait_phase_severity.items()})
        tau=params.get('tau',config.tau)
        use_changed_labels=params.get('endpoint_shift') or tau!=config.tau
        store2=store
        if use_changed_labels:
            iv=load_label_intervals(DATA/'ait_alert/labels.csv',severity2,tau)
            store2=LabelStore.from_alerts(ranking.frame,iv,phase_order(severity2),tau)
        cfg=replace(config,settings=settings,families=families,tau=tau)
        pipeline=ComparisonPipeline(ranking,store2,severity2,cfg)
        if params.get('critical_target'):
            provider=CriticalReliabilityProvider(ranking,store2,phase_order(severity2))
            pipeline.provider=provider
            pipeline.builder=FeatureBuilder(ranking,provider,severity2,settings)
        fingerprint=hashlib.sha256(json.dumps({**base_identity,'params':params},sort_keys=True,default=str).encode()).hexdigest()
        for scenario in ranking.scenarios:
            directory=OUT/'sensitivity'/name/scenario
            if completed(directory,fingerprint): continue
            started=time.perf_counter()
            print(f'FIT {name} / {scenario}',flush=True)
            result=pipeline.run_outer_fold(scenario,cfg.primary_policy)
            verification=verify_fold_trace(result,ranking)
            if not verification.passed: raise RuntimeError(verification.violations)
            selections=selected(cfg,result.selections)
            rows=ranking.rows(scenario); labels=store2.get(scenario,'review:outer_evaluation')
            perkey=pd.DataFrame(result.fit_records['per_key'])
            key=rows.key_id.to_numpy(); mapped=perkey.accepted.to_numpy()[key]
            records=[]
            for family,cid in selections.items():
                score=result.outer_scores[cid]
                order=full_order(score,rows.timestamp.to_numpy(),rows.hash_key.to_numpy())
                m=metrics_at_k(order,labels,100)
                deferred=order[len(order)//2:]; deep=deferred[labels.z[deferred]]
                recall_half=float(labels.z[order[:len(order)//2]].sum()/labels.z.sum()) if labels.z.sum() else np.nan
                records.append({'variant':name,'scenario':scenario,'family':family,'method':SHORT.get(family,family),
                    'candidate_id':cid,'coverage':m.covered_intervals,'defined_intervals':m.defined_intervals,
                    'fp':m.negatives_in_top,'critical_recall':m.critical_recall,'critical_total':int(labels.z.sum()),
                    'deferred':len(deep),'half_recall':recall_half,'distinct_scores':len(np.unique(score[~np.isnan(score)])),
                    'mapped_alerts':int(mapped.sum()),'mapped_keys':int(perkey.accepted.sum()),
                    'deferred_unmapped':int((~mapped[deep]).sum()),
                    'deferred_precision_failed':int((perkey.precision.to_numpy()[key[deep]]<settings.min_precision).sum()),
                    'deferred_purity_failed':int((perkey.purity.to_numpy()[key[deep]]<settings.min_phase_purity).sum())})
                if name=='baseline':
                    expected=original_results[(original_results['split']==f'loso:{scenario}')&(original_results.candidate_id==cid)]
                    if len(expected)!=1: raise RuntimeError(f'Baseline selected candidate differs: {scenario} {cid}')
                    old=expected.iloc[0]
                    if int(old.covered_intervals)!=m.covered_intervals or int(old.negatives_in_top)!=m.negatives_in_top:
                        raise RuntimeError(f'Baseline result mismatch: {scenario} {cid}')
                    if cfg.families[family].tuned:
                        sel=original_selections[(original_selections['split']==f'loso:{scenario}')&(original_selections.family==family)&(original_selections.rule==PRIMARY)]
                        if len(sel)!=1 or sel.iloc[0].selected_candidate!=cid: raise RuntimeError('Baseline selection mismatch')
            save_fold(directory,{'outcomes':pd.DataFrame(records),'selections':result.selections,
                       'inner_metrics':result.inner_metrics,'mapping':perkey},
                      {'fingerprint':fingerprint,'identity':base_identity,'params':params,
                       'trace_verified':verification.passed,'trace_checks':verification.checks,
                       'elapsed_seconds':time.perf_counter()-started})
            print(f'DONE {name} / {scenario}: {time.perf_counter()-started:.1f}s',flush=True)
            # Persist trace before releasing potentially large objects.
            import gzip
            with gzip.open(directory/'trace.json.gz','wt') as f:
                json.dump({'manifest':result.manifest,'trace':result.trace,'label_access':result.label_access_log},f,default=str)


def saved_static(config,ranking,store,sums,data_identity):
    records=[]; seed_records=[]; deep=[]
    for scenario in ranking.scenarios:
        source=DATA/'wp4_stage2/R1'/f'loso_{scenario}'
        inputs=fold_inputs('R1',f'loso_{scenario}',sums)
        tables={}
        for name in ['e2_expected','e2_ties','e3_seed_k100']:
            path=source/f'{name}.csv.gz'
            if sha256(path)!=sums[str(path.relative_to(DATA/'wp4_stage2'))]: raise RuntimeError('Saved table hash mismatch')
            tables[name]=pd.read_csv(path)
        rows=ranking.rows(scenario); labels=store.get(scenario,'review:static')
        for family,cid in selected(config,inputs['selections']).items():
            part=tables['e3_seed_k100'].query('candidate_id == @cid')
            expected=tables['e2_expected'].query('candidate_id == @cid and k == 100').iloc[0]
            ties=tables['e2_ties'].query('candidate_id == @cid').iloc[0]
            scores=inputs['scores'][cid]; order=full_order(scores,rows.timestamp.to_numpy(),rows.hash_key.to_numpy())
            m=metrics_at_k(order,labels,100)
            tag={'scenario':scenario,'family':family,'method':SHORT.get(family,family),'candidate_id':cid}
            records.append({**tag,'declared_coverage':m.covered_intervals,'declared_fp':m.negatives_in_top,
                'mean_coverage':part.covered_intervals.mean(),'min_coverage':part.covered_intervals.min(),
                'max_coverage':part.covered_intervals.max(),'expected_fp':expected.expected_negatives_in_top,
                'distinct_scores':int(ties.distinct_finite_scores)})
            for r in part.itertuples(): seed_records.append({**tag,'seed':r.seed,'coverage':r.covered_intervals,'fp':r.negatives_in_top})
            deferred=order[len(order)//2:]
            deep.append({**tag,'critical_total':int(labels.z.sum()),'deferred':int(labels.z[deferred].sum())})
    for name,frame in [('static_ties',pd.DataFrame(records)),('static_seeds',pd.DataFrame(seed_records)),('all_deferral',pd.DataFrame(deep))]:
        frame.to_csv(DOC/f'{name}_by_scenario.csv',index=False)
    (DOC/'static_identity.json').write_text(json.dumps(identity('saved_static',data_identity),indent=2,default=str))


def replay(config,ranking,store,sums,data_identity,mode):
    base_identity=identity(mode,data_identity)
    fingerprint=hashlib.sha256(json.dumps(base_identity,sort_keys=True,default=str).encode()).hexdigest()
    for scenario in ranking.scenarios:
        directory=OUT/mode/scenario
        if completed(directory,fingerprint): continue
        started=time.perf_counter(); print(f'REPLAY {mode} / {scenario}',flush=True)
        inputs=fold_inputs('R1',f'loso_{scenario}',sums)
        rows=ranking.rows(scenario); labels=store.get(scenario,'review:replay_evaluation')
        t=rows.timestamp.to_numpy(); h=rows.hash_key.to_numpy(); t0=float(t.min()); end=float(t.max())
        if not np.array_equal(inputs['alert_ids'],labels.alert_ids): raise RuntimeError('Score/label misalignment')
        chosen={k:v for k,v in selected(config,inputs['selections']).items() if k in REPLAY_FAMILIES}
        records=[]
        if mode=='random_replay':
            for family,cid in chosen.items():
                scores=inputs['scores'][cid]
                reference=replay_alerts(scores,t,h,12)
                check=simulate(scores,t,h,12,t0,end)
                if not np.array_equal(reference.selected,check.selected) or not np.array_equal(reference.start,check.start):
                    raise RuntimeError('Historical replay disagreement')
                records.append({'scenario':scenario,'method':SHORT[family],'candidate_id':cid,'seed':-1,
                                **service_outcomes(check,labels)})
                for seed in range(100):
                    trace=simulate(scores,t,h,12,t0,end,random_priorities(h,seed))
                    if np.any(t[trace.selected]>trace.start): raise RuntimeError('Lookahead')
                    records.append({'scenario':scenario,'method':SHORT[family],'candidate_id':cid,'seed':seed,
                                    **service_outcomes(trace,labels)})
                print(f'  {SHORT[family]}: 100 seeds complete',flush=True)
        else:
            for window in [60,300,900]:
                clusters=assign_clusters(rows.detector.to_numpy(),rows.native_key.to_numpy(),rows.host.to_numpy(),t,h,window)
                grouped,reps,summary=static_cluster_labels(labels,clusters)
                for family,cid in chosen.items():
                    reps2,index,release,scores=group_arrays(clusters,t,inputs['scores'][cid])
                    if not np.array_equal(reps,reps2): raise RuntimeError('Group alignment')
                    trace=simulate(scores,release,h[reps],12,t0,end)
                    if np.any(release[trace.selected]>trace.start): raise RuntimeError('Group lookahead')
                    records.append({'scenario':scenario,'method':SHORT[family],'candidate_id':cid,'window':window,
                        **asdict(summary),**service_outcomes(trace,grouped,labels,index)})
        save_fold(directory,{'outcomes':pd.DataFrame(records)},
                  {'fingerprint':fingerprint,'identity':base_identity,'elapsed_seconds':time.perf_counter()-started})
        print(f'DONE {mode} / {scenario}: {time.perf_counter()-started:.1f}s',flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=['static','sensitivity','random_replay','grouped_replay'])
    parser.add_argument('--variants',nargs='+')
    args=parser.parse_args()
    DOC.mkdir(parents=True,exist_ok=True); OUT.mkdir(parents=True,exist_ok=True)
    # Redirect legacy read-only helpers to an explicit data root for archive reproduction.
    import wp4_stage2_run as loader, wp5_common as saved
    loader.DATA=DATA; loader.CACHE=DATA/'cache/ait_canonical_original_labels.pkl.gz'
    loader.PROVENANCE=DATA/'cache/ait_native_score_provenance.pkl.gz'; loader.LABELS=DATA/'ait_alert/labels.csv'
    saved.STAGE2=DATA/'wp4_stage2'
    print('Loading verified data',flush=True)
    config,severity,ranking,store,data_identity=load_everything()
    check_gates(config)
    if args.stage=='sensitivity': sensitivity(config,severity,ranking,store,data_identity,args.variants)
    else:
        sums=verify_stage2_copy()['files']
        if args.stage=='static': saved_static(config,ranking,store,sums,data_identity)
        else: replay(config,ranking,store,sums,data_identity,args.stage)


if __name__=='__main__': main()
