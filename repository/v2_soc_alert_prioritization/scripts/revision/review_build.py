#!/usr/bin/env python
"""Build review-response tables/figures only from complete, verified outputs."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import sys

import numpy as np
import pandas as pd

from review_run import DOC, OUT, PROJECT, DATA, variants, SHORT
from soc_alert_ranking.revision.paired_stats import sign_flip_test

GEN=PROJECT.parent/'computers_security_revision/generated'
METHODS=['P','H','S0','S1','S2','W','A','M','C','L2','L1','S0key','S1key','S2key',
         'Rsev,key','Rkey','Severity','O_reliability','Native level','Native Suricata','FIFO','LIFO']
REPLAY=['P','S1','S0key','S1key','S2key','Rsev,key','Severity']
SCENARIOS=['fox','harrison','russellmitchell','santos','shaw','wardbeck','wheeler','wilson']
LABEL={m:m for m in METHODS}
LABEL.update({m:m[:-3]+r'\key' for m in ['S0key','S1key','S2key']})
LABEL.update({'Rsev,key':r'\Rsev','Rkey':r'R\key','Severity':r'O\textsubscript{sev}',
              'O_reliability':r'O\textsubscript{rel}'})


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(name,text):
    path=GEN/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(text+'\n')
def number(x):
    return f'{x:.2f}'.rstrip('0').rstrip('.')
def table(headers,rows,align=None):
    return '\n'.join([r'\begin{tabular}{'+(align or 'l'+'r'*(len(headers)-1))+'}',r'\toprule',
        ' & '.join(headers)+r' \\',r'\midrule']+
        [' & '.join(map(str,row))+r' \\' for row in rows]+[r'\bottomrule',r'\end{tabular}'])
def wrap_table(label,caption,content,wide=True):
    return (r'\begin{tableorg}[htbp]'+'\n'+r'\centering\small'+'\n'+r'\caption{'+caption+'}\n'+
            r'\label{'+label+'}\n'+(r'\resizebox{\textwidth}{!}{'+content+'}' if wide else content)+'\n'+r'\end{tableorg}')


def contrasts(frame,values,label,pairs=None):
    pairs=pairs or [('S1key','S1'),('S0key','P'),('Rsev,key','P')]
    records=[]
    for a,b in pairs:
        for field in values:
            pivot=frame.pivot(index='scenario',columns='method',values=field)
            d=pivot[a]-pivot[b]
            stat=sign_flip_test(d.to_numpy())
            records.append({'design':label,'contrast':f'{a} - {b}','outcome':field,
                'mean_difference':stat.mean_difference,'positive':stat.positive,'negative':stat.negative,
                'zero':stat.zero,'p_two_sided':stat.p_two_sided,'scenarios':len(d)})
    return pd.DataFrame(records)


def static():
    frame=pd.read_csv(DOC/'static_ties_by_scenario.csv')
    seeds=pd.read_csv(DOC/'static_seeds_by_scenario.csv')
    agg=frame.groupby('method').agg(declared=('declared_coverage','sum'),mean=('mean_coverage','sum'),
        declared_fp=('declared_fp','median'),expected_fp=('expected_fp','median')).reindex(METHODS)
    totals=seeds.groupby(['method','seed']).coverage.sum().reset_index()
    ranges=totals.groupby('method').coverage.agg(['min','max'])
    agg=agg.join(ranges); agg.to_csv(DOC/'static_summary.csv')
    write('tables/tab_static_summary.tex',table(
        ['Ranker','Declared / 32','Tie mean [seed range] / 32','Declared FP','Expected FP'],
        [[LABEL[m],int(r.declared),f'{r["mean"]:.2f} [{int(r["min"])}--{int(r["max"])}]',
          number(r.declared_fp),number(r.expected_fp)] for m,r in agg.iterrows()]))
    # Clarify the historical diagnostic without changing its numerical results.
    tie_path=GEN/'tables/tab_ties.tex'
    tie_path.write_text(tie_path.read_text().replace('Covered, 100 seeds', 'Sum of extrema'))
    class_methods=['P','H','W','A','C','M','S0','S1','S2']
    score_table=frame[frame.method.isin(class_methods)].pivot(index='method',columns='scenario',values='distinct_scores')
    write('tables/tab_review_distinct.tex',table(['Ranker']+SCENARIOS,
        [[m]+[int(score_table.loc[m,s]) for s in SCENARIOS] for m in class_methods]))
    tests=contrasts(frame,['mean_coverage','expected_fp'],'static tie-averaged')
    tests.to_csv(DOC/'static_tie_contrasts.csv',index=False)
    write('tables/tab_review_tie_tests.tex',table(['Contrast','Outcome','Mean diff.','$+/-/0$','Exact $p$'],
        [[r.contrast.replace('key',r'\key'),r.outcome.replace('mean_coverage','covered intervals').replace('expected_fp','expected FP'),
          number(r.mean_difference),f'{r.positive}/{r.negative}/{r.zero}',f'{r.p_two_sided:.4f}'] for r in tests.itertuples()]))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,2,figsize=(7,6.8),sharey=True)
    y=np.arange(len(agg))
    for ax,left,right,title in [(axes[0],'declared','mean','Critical intervals covered / 32'),
                                 (axes[1],'declared_fp','expected_fp','Median FP@100 across scenarios')]:
        ax.hlines(y,agg[left],agg[right],color='#8a949e',lw=1)
        ax.scatter(agg[left],y,color='#264c78',s=22,label='Declared order',zorder=3)
        ax.scatter(agg[right],y,facecolors='white',edgecolors='#b34d2e',s=26,label='Random ties',zorder=4)
        ax.set_xlabel(title,fontsize=10); ax.grid(axis='x',alpha=.2)
        ax.spines[['top','right']].set_visible(False)
    plot_labels = {m:rf'$S{m[1]}_{{\mathrm{{key}}}}$' for m in ['S0key','S1key','S2key']}
    plot_labels.update({'Rsev,key':r'$R_{\mathrm{sev,key}}$', 'Rkey':r'$R_{\mathrm{key}}$',
                        'Severity':r'$O_{\mathrm{sev}}$', 'O_reliability':r'$O_{\mathrm{rel}}$',
                        'Native level':'Native rule level', 'Native Suricata':'Native Suricata severity'})
    display=[plot_labels.get(m,m) for m in METHODS]
    axes[0].set_yticks(y,display,fontsize=10); axes[0].invert_yaxis()
    axes[0].set_xlim(-1,33);axes[1].set_xlim(-3,103)
    axes[1].legend(loc='lower right',fontsize=9)
    fig.tight_layout();fig.savefig(GEN/'figures/fig_static_tradeoff.pdf');plt.close(fig)
    return agg


def historical():
    # Rate and utilization extraction uses the original chosen fits.
    from wp5_common import verify_stage2_copy, fold_inputs
    from review_run import selected
    from soc_alert_ranking.revision.config import load_comparison_config
    import wp5_common
    wp5_common.STAGE2=DATA/'wp4_stage2'
    cfg=load_comparison_config(PROJECT/'configs/revision_wp2.yaml'); sums=verify_stage2_copy()['files']
    records=[]
    replay_root=DATA/'wp5_replay'
    replay_manifest=json.loads((PROJECT/'docs/revision/wp5/replay_output_manifest.json').read_text())
    if sha(replay_root/'SHA256SUMS')!=replay_manifest['sha256sums_sha256']: raise RuntimeError('Replay manifest mismatch')
    replay_sums={name.strip().removeprefix('./'):digest for digest,name in
                 (line.split(maxsplit=1) for line in (replay_root/'SHA256SUMS').read_text().splitlines())}
    for scenario in SCENARIOS:
        inp=fold_inputs('R1',f'loso_{scenario}',sums)
        path=replay_root/f'P1/loso_{scenario}/summaries.csv.gz'
        if sha(path)!=replay_sums[str(path.relative_to(replay_root))]: raise RuntimeError('Replay table checksum')
        data=pd.read_csv(path)
        for family,cid in selected(cfg,inp['selections']).items():
            if family not in ['P_probability_proxy','S0_linear_log_historical_key','R_severity_key_reliability',
                              'S1_linear_log_constrained_key','S2_exponential_discount_key','O_newest_first']:continue
            for r in data[data.candidate_id==cid].to_dict('records'):
                records.append({**r,'scenario':scenario,'method':SHORT[family]})
    rates=pd.DataFrame(records)
    rates.to_csv(DOC/'rates_and_utilization_by_scenario.csv',index=False)
    rows=[]
    for rate in [6,12,30,60]:
        part=rates[rates.rate_per_hour==rate]
        p=part[part.method=='P']
        rows.append([rate,f'{int(p.investigations.sum()):,}']+
                    [int(part[part.method==m].covered_intervals.sum()) for m in ['P','S0key','Rsev,key','S1key','S2key','LIFO']])
    write('tables/tab_rates.tex',table(['Rate (per h)','Investigations','P',r'S0\key',r'\Rsev',r'S1\key',r'S2\key','LIFO'],rows))
    u=rates[rates.method=='P'].groupby('rate_per_hour').agg(horizon=('horizon_hours','sum'),
               idle=('idle_seconds','sum'),busy=('busy_seconds','sum'),starts=('investigations','sum'))
    write('tables/tab_review_utilization.tex',table(['Rate/h','Horizon (h)','Idle (h)','Utilization (\%)','Starts'],
        [[int(rate),number(r.horizon),number(r.idle/3600),number(100*r.busy/(r.busy+r.idle)),f'{int(r.starts):,}'] for rate,r in u.iterrows()]))
    extents=pd.read_csv(PROJECT/'docs/revision/jnsm_20261026/forward_split_extents.csv')
    rows=[]
    for r in extents[extents.eligible].sort_values('start').itertuples():
        start=pd.to_datetime(r.start,unit='s',utc=True).strftime('%Y-%m-%d')
        end=pd.to_datetime(r.end,unit='s',utc=True).strftime('%Y-%m-%d')
        rows.append([r.test_scenario,start,end,', '.join(ast.literal_eval(r.fit_scenarios))])
    write('tables/tab_review_forward.tex',table(['Test scenario','Start (UTC)','End (UTC)','Fitting scenarios'],rows,
                                               'lll p{0.42\\textwidth}'))


def complete(stage,variant=None):
    frames=[]
    for scenario in SCENARIOS:
        directory=OUT/stage
        if variant is not None: directory=directory/variant
        directory=directory/scenario
        record=json.loads((directory/'done.json').read_text())
        for name,digest in record['outputs'].items():
            if sha(directory/name)!=digest: raise RuntimeError(f'Checksum mismatch {directory/name}')
        if stage=='sensitivity' and not (directory/'trace.json.gz').exists(): raise RuntimeError('Missing fit trace')
        frames.append(pd.read_csv(directory/'outcomes.csv.gz'))
    return pd.concat(frames,ignore_index=True)


def sensitivity():
    frame=pd.concat([complete('sensitivity',v) for v in variants()],ignore_index=True)
    frame.to_csv(DOC/'sensitivity_by_scenario.csv',index=False)
    agg=frame.groupby(['variant','method']).agg(coverage=('coverage','sum'),fp=('fp','median'),
        critical_total=('critical_total','sum'),deferred=('deferred','sum'),intervals=('defined_intervals','sum'),
        mapped_alerts=('mapped_alerts','sum'),unmapped_deferred=('deferred_unmapped','sum')).reset_index()
    agg.to_csv(DOC/'sensitivity_summary.csv',index=False)
    rows=[]
    for variant in variants():
        part=agg[agg.variant==variant].set_index('method'); p=part.loc['P']
        rows.append([variant.replace('_',r'\_'),int(p.intervals),f'{int(p.critical_total):,}']+
                    [f'{int(part.loc[m,"coverage"])}/{number(part.loc[m,"fp"])}' for m in ['P','S1','S1key','Rsev,key']])
    write('tables/tab_review_sensitivity.tex',table(['Policy','Intervals','Critical records','P','S1',r'S1\key',r'\Rsev'],rows))
    # Complete scenario contrasts remain exploratory; retain original primary tests separately.
    tests=[]
    for v in variants():
        part=frame[frame.variant==v]
        tests.append(contrasts(part,['coverage','fp'],v,[('S1','P'),('S1','A'),('S1','M'),('S1key','S1')]))
    pd.concat(tests).to_csv(DOC/'sensitivity_contrasts.csv',index=False)
    return agg


def replays():
    random=complete('random_replay'); groups=complete('grouped_replay')
    random.to_csv(DOC/'random_replay_by_scenario.csv',index=False)
    groups.to_csv(DOC/'grouped_replay_by_scenario.csv',index=False)
    fields=['covered','before_end','late','critical_investigated','negative_investigations','investigations',
            'critical_units','idle_seconds','horizon_seconds']
    total=random[random.seed>=0].groupby(['method','seed'])[fields].sum().reset_index()
    total.to_csv(DOC/'random_replay_seed_totals.csv',index=False)
    means=total.groupby('method')[fields].mean()
    ranges=total.groupby('method').covered.agg(['min','max'])
    means=means.join(ranges); means.to_csv(DOC/'random_replay_summary.csv')
    base=random[random.seed==-1].groupby('method')[fields].sum()
    rows=[]
    for m in REPLAY:
        r=means.loc[m]; b=base.loc[m]
        rows.append([LABEL[m],int(b.covered),f'{r.covered:.2f} [{int(r["min"])}--{int(r["max"])}]',
                     f'{r.before_end:.2f}',f'{r.critical_investigated:.1f}',f'{r.negative_investigations:.1f}'])
    write('tables/tab_review_random.tex',table(['Ranker','FIFO ties','Random mean [range]','Before end','Critical starts',r'\shortstack{Interval-negative\\starts}'],rows))
    per_scenario=random[random.seed>=0].groupby(['scenario','method'])[fields].mean().reset_index()
    contrasts(per_scenario,['covered','negative_investigations'],'random replay scenario means').to_csv(DOC/'random_replay_contrasts.csv',index=False)
    gfields=fields+['units','released_units','critical_records_contained','critical_records_total']
    agg=groups.groupby(['window','method'])[gfields].sum().reset_index()
    agg.to_csv(DOC/'grouped_replay_summary.csv',index=False)
    for window in [60,300,900]:
        part=agg[agg.window==window].set_index('method');rows=[]
        for m in REPLAY:
            r=part.loc[m]
            rows.append([LABEL[m],int(r.covered),int(r.before_end),f'{int(r.critical_investigated)}/{int(r.critical_units)}',
                number(100*r.critical_investigated/r.critical_units),f'{int(r.negative_investigations):,}',
                f'{int(r.critical_records_contained):,}'])
        write(f'tables/tab_review_grouped_{window}.tex',table(['Ranker','Covered','Before end','Critical groups','Retrieved (\%)',r'\shortstack{Interval-negative\\groups}','Critical members'],rows))
    return means,agg


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--static-only',action='store_true');args=parser.parse_args()
    static();historical()
    if args.static_only:return
    sensitivity();replays()
    import review_reporting
    review_reporting.build()
    manifest={'date':'2026-10-30','script_sha256':sha(__file__),
              'reporting_generator_sha256':sha(Path(review_reporting.__file__)),
              'inputs':{str(p.relative_to(PROJECT)):sha(p) for p in sorted(OUT.rglob('*')) if p.is_file()},
              'tables_and_figures':{str(p.relative_to(GEN)):sha(p) for p in sorted(GEN.rglob('*')) if p.is_file() and p.suffix in ['.tex','.pdf']}}
    (DOC/'assets_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')

if __name__=='__main__':main()
