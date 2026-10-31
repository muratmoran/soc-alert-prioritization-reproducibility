#!/usr/bin/env python
"""Dated exploratory diagnostics and forward replay; original modules stay unchanged."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / 'src'))
sys.path.insert(0, str(PROJECT / 'scripts/revision'))
from wp4_stage2_run import check_gates, load_everything
from wp5_common import verify_stage2_copy, replay_fold, write_fold
from soc_alert_ranking.revision.evaluation import full_order
from soc_alert_ranking.revision.metrics import metrics_at_k
from soc_alert_ranking.revision.pipeline import ComparisonPipeline, verify_fold_trace
from soc_alert_ranking.revision.splits import forward_chaining_splits, identifier_groups

DATA = Path.home() / 'soc_revision_data'
OUT = PROJECT / 'results/jnsm_20261026'
DOC = PROJECT / 'docs/revision/jnsm_20261026'
PRIMARY = 'primary_coverage_fp_ndcg'
METHODS = {
    'P': 'P_probability_proxy', 'S1': 'S1_linear_log_constrained',
    'S0_key': 'S0_linear_log_historical_key', 'S1_key': 'S1_linear_log_constrained_key',
    'S2_key': 'S2_exponential_discount_key', 'R_severity_key': 'R_severity_key_reliability',
    'O_severity': 'O_severity', 'FIFO': 'O_oldest_first', 'LIFO': 'O_newest_first',
}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(4 * 1024 ** 2), b''): h.update(b)
    return h.hexdigest()


def timing_summary(intervals, t0):
    """A start at an interval's exclusive end is late, including zero delays."""
    detected = intervals['detected'].astype(bool)
    ends = intervals['interval'].str.rsplit('|', n=1).str[-1].astype(float)
    starts = t0 + intervals['detection_offset_hours'].astype(float) * 3600
    late = detected & (starts >= ends)
    return {'covered_intervals': int(detected.sum()), 'before_interval_end': int((detected & ~late).sum()),
            'late_covered_intervals': int(late.sum()), 'uncovered_intervals': int((~detected).sum()),
            'within_1h': int((detected & (intervals['delay_hours'] <= 1)).sum())}


def primary_ids(selections, config):
    result = {}
    for short, family in METHODS.items():
        spec = config.families[family]
        if not spec.tuned: result[short] = spec.candidates[0].candidate_id
        else:
            part = selections[(selections.family == family) & (selections.rule == PRIMARY)]
            if len(part) != 1: raise ValueError(f'Expected one selection: {family}')
            result[short] = part.iloc[0].selected_candidate
    return result


def checked(path, root, sums):
    key = str(path.relative_to(root))
    if sha(path) != sums.get(key): raise ValueError(f'Input checksum mismatch: {path}')
    return path


def sum_file(path):
    return {n.strip().removeprefix('./'): d for d, n in
            (line.split(maxsplit=1) for line in path.read_text().splitlines())}


def write_csv(name, rows):
    frame = rows if isinstance(rows, pd.DataFrame) else pd.DataFrame(rows)
    frame.to_csv(DOC / name, index=False)
    return frame


def aggregate_replay(frame):
    return frame.groupby(['design', 'method'], sort=False).agg(
        scenarios=('scenario', 'nunique'), intervals=('defined_intervals', 'sum'),
        covered=('covered_intervals', 'sum'), before_end=('before_interval_end', 'sum'),
        late=('late_covered_intervals', 'sum'), within_1h=('within_1h', 'sum'),
        critical_total=('critical_total', 'sum'), critical_investigated=('critical_investigations', 'sum'),
        negative_investigations=('fp_investigations', 'sum'), investigations=('investigations', 'sum'),
        backlog=('backlog_at_horizon', 'sum'),
        delay_lower_bound_median=('restricted_mean_delay_hours_lower_bound', 'median')).reset_index()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostics-only', action='store_true')
    args = parser.parse_args()
    DOC.mkdir(parents=True, exist_ok=True); OUT.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(OUT).free < 6 * 1024 ** 3: raise RuntimeError('Less than 6 GiB free')
    started = time.perf_counter()
    print('Loading verified caches and labels', flush=True)
    config, severity, ranking, store, data_identity = load_everything()
    gates = check_gates(config)
    replay_gate = json.loads((PROJECT / 'docs/revision/wp5/replay_verification.json').read_text())
    assert replay_gate['verified']
    for name, digest in replay_gate['code_identity']['file_sha256'].items():
        if sha(PROJECT / name) != digest: raise ValueError(f'Stale replay gate: {name}')
    stage_sums = verify_stage2_copy()['files']
    rep_root = DATA / 'wp5_replay'
    rep_manifest = json.loads((PROJECT / 'docs/revision/wp5/replay_output_manifest.json').read_text())
    assert sha(rep_root / 'SHA256SUMS') == rep_manifest['sha256sums_sha256']
    rep_sums = sum_file(rep_root / 'SHA256SUMS')
    provenance = {'date': '2026-10-26', 'analysis': 'post-results exploratory',
                  'amendment_sha256': sha(DOC / 'amendment.md'), 'script_sha256': sha(Path(__file__)),
                  'data': data_identity, 'gates': gates, 'python': sys.version,
                  'numpy': np.__version__, 'pandas': pd.__version__, 'folds': []}
    # Support is counted once per group/scenario, independent of the candidate rows.
    groups = identifier_groups(ranking)
    write_csv('identifier_groups.csv', groups)
    support = []
    for group in range(5):
        keys = groups[groups.group == group].key_id.to_numpy()
        for scenario in ranking.scenarios:
            rows = ranking.rows(scenario)
            labels = store.get(scenario, purpose='jnsm:holdout_support')
            mask = np.isin(rows.key_id.to_numpy(), keys)
            support.append({'group': group, 'scenario': scenario, 'identifiers': len(keys),
                            'present_identifiers': int(rows.loc[mask, 'key_id'].nunique()),
                            'alerts': int(mask.sum()), 'critical_records': int(labels.z[mask].sum()),
                            'eligible_intervals': int(labels.critical_membership[mask].any(axis=0).sum())})
    support = write_csv('holdout_support_by_scenario.csv', support)
    write_csv('holdout_support.csv', support.groupby('group').agg(
        identifiers=('identifiers','first'), alerts=('alerts','sum'),
        critical_records=('critical_records','sum'), eligible_intervals=('eligible_intervals','sum')).reset_index())
    table_root = PROJECT / 'docs/revision/wp4/stage2_tables'
    table_index = json.loads((table_root / 'index.json').read_text())['tables']
    needed = ['r6_e7_subgroup_mixed_queue','r6_e12_selections','r6_t1_primary_long',
              'r7_e12_selections','r7_t1_primary_long']
    for name in needed:
        assert sha(table_root / f'{name}.csv') == table_index[name]['sha256']
    mixed = pd.read_csv(table_root / 'r6_e7_subgroup_mixed_queue.csv')
    selections = pd.read_csv(table_root / 'r6_e12_selections.csv')
    whole = pd.read_csv(table_root / 'r6_t1_primary_long.csv')
    selected_rows = []
    for split, select in selections.groupby('split'):
        group = int(split.split(':')[0].split('_')[2])
        scenario = split.split(':')[1]
        for method, cid in primary_ids(select, config).items():
            row = mixed[(mixed['split']==split) & (mixed.candidate_id==cid) &
                        (mixed.subgroup=='held_out_group_identifier') & (mixed.k==100)]
            assert len(row) == 1
            r = row.iloc[0].to_dict()
            w = whole[(whole['split']==split)&(whole.candidate_id==cid)]
            assert len(w) == 1
            selected_rows.append({'group': group,'scenario':scenario,'method':method,
                'whole_covered':int(w.iloc[0].covered_intervals), **{k:r[k] for k in
                ['subgroup_n','subgroup_critical_in_top','subgroup_critical_total',
                 'subgroup_covered_intervals','subgroup_eligible_intervals','subgroup_in_top']}})
    selected = write_csv('holdout_selected_by_scenario.csv', selected_rows)
    agg = selected.groupby(['group','method']).sum(numeric_only=True).reset_index()
    agg['critical_recall'] = agg.subgroup_critical_in_top / agg.subgroup_critical_total.replace(0,np.nan)
    write_csv('holdout_selected.csv', agg)
    print('Identifier support and mixed-queue diagnostics extracted', flush=True)
    # Read original per-interval results; do not rerun or refit LOSO.
    loso = []
    for scenario in ranking.scenarios:
        fold = DATA / f'wp4_stage2/R1/loso_{scenario}'
        select = pd.read_csv(checked(fold/'e12_selections.csv.gz',DATA/'wp4_stage2',stage_sums))
        rep = rep_root / f'P1/loso_{scenario}'
        summaries = pd.read_csv(checked(rep/'summaries.csv.gz',rep_root,rep_sums))
        intervals = pd.read_csv(checked(rep/'intervals.csv.gz',rep_root,rep_sums))
        t0 = float(ranking.rows(scenario).timestamp.min())
        for method, cid in primary_ids(select, config).items():
            s = summaries[(summaries.candidate_id==cid)&(summaries.rate_per_hour==12)].iloc[0].to_dict()
            iv = intervals[(intervals.candidate_id==cid)&(intervals.rate_per_hour==12)]
            t = timing_summary(iv,t0)
            assert t['covered_intervals'] == s['covered_intervals']
            loso.append({**s,**t,'scenario':scenario,'method':method,'design':'LOSO_all'})
    loso = write_csv('loso_timing_by_scenario.csv',loso)
    write_csv('loso_timing.csv',aggregate_replay(loso))
    forward_splits, extents = forward_chaining_splits(ranking)
    assert len(forward_splits) == 5
    write_csv('forward_split_extents.csv',extents)
    if args.diagnostics_only:
        provenance['diagnostics_only'] = True
    else:
        pipeline = ComparisonPipeline(ranking,store,severity,config)
        expected_select = pd.read_csv(table_root/'r7_e12_selections.csv')
        expected_static = pd.read_csv(table_root/'r7_t1_primary_long.csv')
        forward = []
        for split in forward_splits:
            tic = time.perf_counter()
            print(f'Reconstructing {split.name}, training={split.training}',flush=True)
            result = pipeline.run_outer_fold(split,config.primary_policy)
            verification = verify_fold_trace(result,ranking)
            assert verification.passed, verification.violations
            expected = expected_select[expected_select['split']==split.name]
            columns = ['rule','family','selected_candidate']
            actual_set = set(map(tuple,result.selections[columns].to_numpy()))
            assert actual_set == set(map(tuple,expected[columns].to_numpy()))
            ids = primary_ids(result.selections,config)
            rows = ranking.rows(split.held_out)
            assert np.array_equal(result.outer_alert_ids,rows.alert_id.astype(str).to_numpy())
            ts,hk = rows.timestamp.to_numpy(float),rows.hash_key.to_numpy(np.uint64)
            labels = store.get(split.held_out,purpose='jnsm:forward_metrics_after_fitting')
            static_checks=[]
            for method,cid in ids.items():
                m=metrics_at_k(full_order(result.outer_scores[cid],ts,hk),labels,100)
                expected_row=expected_static[(expected_static['split']==split.name)&(expected_static.candidate_id==cid)]
                assert len(expected_row)==1
                assert m.covered_intervals == int(expected_row.iloc[0].covered_intervals)
                assert m.negatives_in_top == int(expected_row.iloc[0].negatives_in_top)
                static_checks.append({'method':method,'candidate_id':cid,'covered':m.covered_intervals,'negatives':m.negatives_in_top})
            with store.locked([split.held_out]):
                features=pipeline.builder.alert_features(split.held_out,split.training,config.primary_policy,
                                                         role=f'{split.name}:jnsm_replay')
            scores={cid:result.outer_scores[cid] for cid in ids.values()}
            roles={cid:{'family':METHODS[method],'rules':'untuned' if not config.families[METHODS[method]].tuned else 'primary'}
                   for method,cid in ids.items()}
            replay=replay_fold('forward',split.held_out,scores,roles,ts,hk,labels,
                               ~features.mapped|(features.h<=0.2),rates=(12.0,))
            folder=OUT/split.name.replace(':','_')
            write_fold(folder,replay)
            np.savez_compressed(folder/'outer_scores.npz',alert_ids=result.outer_alert_ids.astype(str),**scores)
            result.selections.to_csv(folder/'selections.csv',index=False)
            result.inner_metrics.to_csv(folder/'inner_metrics.csv.gz',index=False,compression='gzip')
            trace_record={'split':split.to_record(),'verification':vars(verification),
                          'feature_requests':result.manifest,'trace':result.trace,'fit_records':result.fit_records,
                          'label_access_log':result.label_access_log,'static_checks':static_checks}
            with gzip.open(folder/'fitting_trace.json.gz','wt') as f: json.dump(trace_record,f,default=str)
            for method,cid in ids.items():
                s=replay['summaries'][replay['summaries'].candidate_id==cid].iloc[0].to_dict()
                iv=replay['intervals'][replay['intervals'].candidate_id==cid]
                forward.append({**s,**timing_summary(iv,float(ts.min())),'scenario':split.held_out,
                                'method':method,'design':'Forward'})
            provenance['folds'].append({'split':split.name,'training':split.training,'static_reproduced':True,
                                       'replay_integrity_passed':True,'seconds':round(time.perf_counter()-tic,2)})
            (OUT/'run_manifest.json').write_text(json.dumps(provenance,indent=2,default=str)+'\n')
            print(f'{split.name}: selections/static checks reproduced; 9 replays passed ({time.perf_counter()-tic:.1f}s)',flush=True)
            pipeline.builder.clear_cache()
        forward=pd.DataFrame(forward)
        matched=loso[loso.scenario.isin([s.held_out for s in forward_splits])].copy()
        matched['design']='LOSO_same_five'
        joined=pd.concat([matched,forward],ignore_index=True)
        write_csv('forward_replay_by_scenario.csv',joined)
        write_csv('forward_replay.csv',aggregate_replay(joined))
    provenance['seconds']=round(time.perf_counter()-started,2)
    provenance['outputs']={str(p.relative_to(PROJECT)):sha(p) for root in (DOC,OUT)
                           for p in sorted(root.rglob('*')) if p.is_file() and p.name not in ('run_manifest.json','analysis_manifest.json')}
    (DOC/'analysis_manifest.json').write_text(json.dumps(provenance,indent=2,default=str)+'\n')
    print('Exploratory analysis complete',flush=True)


if __name__=='__main__': main()
