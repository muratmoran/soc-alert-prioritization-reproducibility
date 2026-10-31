#!/usr/bin/env python
"""Reformat verified original tables and render the dated revision's new results."""
import hashlib
import json
import re
from pathlib import Path
import sys
import numpy as np
import pandas as pd

PROJECT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(PROJECT/'src'))
from soc_alert_ranking.mappings.severity import SeverityMapping
DOC=PROJECT/'docs/revision/jnsm_20261026'
GEN=PROJECT.parent/'computers_security_revision/generated'
BASE=DOC/'baseline/generated'
LABEL={'P':'P','S1':'S1','S0_key':r'S0\key','S1_key':r'S1\key','S2_key':r'S2\key',
       'R_severity_key':r'\Rsev','O_severity':r'O\textsubscript{sev}','FIFO':'FIFO','LIFO':'LIFO'}
inputs={}; outputs=[]
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):
    inputs[str(p.relative_to(PROJECT.parent))]=digest(p)
    return p.read_text()
def csv(p):
    read(p); return pd.read_csv(p)
def write(name,text):
    p=GEN/name; p.write_text(text+'\n'); outputs.append(p)
def table(headers,rows,align=None):
    return '\n'.join([r'\begin{tabular}{'+(align or 'l'+'r'*(len(headers)-1))+'}',r'\toprule',
                       ' & '.join(headers)+r' \\',r'\midrule']+
                      [' & '.join(str(x) for x in row)+r' \\' for row in rows]+[r'\bottomrule',r'\end{tabular}'])
def num(x): return f'{int(x):,}'

def main():
    # Validate saved source inputs against the analysis manifest before rendering.
    manifest=json.loads((DOC/'analysis_manifest.json').read_text())
    for rel,sha in manifest['outputs'].items():
        if rel.endswith('.csv'): assert digest(PROJECT/rel)==sha,rel
    text=read(BASE/'tables/tab_static_primary.tex')
    rows=[line.removesuffix(r' \\').split(' & ') for line in text.splitlines() if ' & ' in line][1:]
    summary=[[r[0],r[-2],r[-1]] for r in rows]
    write('tables/tab_static_summary.tex',table(['Ranker','Covered / 32','Median FP@100'],summary))
    scenarios=['fox','harrison','russellmitchell','santos','shaw','wardbeck','wheeler','wilson']
    for name,inds in [('a',range(1,5)),('b',range(5,9))]:
        headers=['Ranker']+[scenarios[i-1] for i in inds]
        write(f'tables/tab_static_panel_{name}.tex',table(headers,[[r[0]]+[r[i] for i in inds] for r in rows],'lcccc'))
    policy=SeverityMapping.from_file()
    read(PROJECT/'configs/severity_mapping.yaml')
    rows=[[p.replace('_',' '),f'{c:g}',f'{policy.uncertainty_for_ait_phases([p]):.2f}'] for p,c in policy.ait_phase_severity.items()]
    rows.append(['unknown','5','0.50'])
    write('tables/tab_policy.tex',table(['Phase','Severity $c$','Uncertainty $u$'],rows))
    replay=csv(DOC/'loso_timing.csv').set_index('method')
    order=['P','S1','S0_key','S1_key','S2_key','R_severity_key','O_severity','LIFO','FIFO']
    a=table(['Ranker','Covered / 32','Before end','At/after end','Uncovered'],
        [[LABEL[m]]+[num(replay.loc[m,x]) for x in ['covered','before_end','late']]+[num(32-replay.loc[m,'covered'])] for m in order])
    b=table(['Ranker','Negative starts','Critical starts','Uninvestigated','Share (\%)'],
        [[LABEL[m],num(replay.loc[m,'negative_investigations']),num(replay.loc[m,'critical_investigated']),
          num(replay.loc[m,'critical_total']-replay.loc[m,'critical_investigated']),
          f"{100*(1-replay.loc[m,'critical_investigated']/replay.loc[m,'critical_total']):.1f}"] for m in order])
    write('tables/tab_replay_panels.tex',r'\textbf{(a) Critical intervals}\par\medskip'+'\n'+a+'\n'+r'\par\bigskip\textbf{(b) Alert records}\par\medskip'+'\n'+b)
    support=csv(DOC/'holdout_support.csv').set_index('group')
    selected=csv(DOC/'holdout_selected.csv'); selected=selected[selected.method=='S1_key'].set_index('group')
    headers=['Group','Keys','Alerts',r'\shortstack{Critical\\records}',r'\shortstack{Subgroup\\retrieved}',r'\shortstack{Subgroup\\covered/eligible}',r'\shortstack{Whole\\covered/32}']
    rows=[]
    for g,r in support.iterrows():
        t=selected.loc[g]
        rows.append([g,num(r.identifiers),num(r.alerts),num(r.critical_records),num(t.subgroup_critical_in_top),
                     f'{int(t.subgroup_covered_intervals)}/{int(r.eligible_intervals)}',num(t.whole_covered)])
    write('tables/tab_holdout_support.tex',table(headers,rows))
    f=csv(DOC/'forward_replay.csv').set_index(['design','method'])
    rows=[]
    for m in order:
        rows.append([LABEL[m]]+[f"{num(f.loc[('LOSO_same_five',m),x])} / {num(f.loc[('Forward',m),x])}"
                                  for x in ['covered','before_end','critical_investigated','negative_investigations']])
    write('tables/tab_forward_replay.tex',table(['Ranker','Covered / 20','Before end','Critical starts','Negative starts'],rows))
    r=f.loc[('Forward','S1_key')]; p=f.loc[('Forward','P')]
    write('forward_interpretation.tex',r'S1\key{} covered '+num(r.covered)+r' of 20 intervals with either fitting design, but '+num(r.late)+
          r' were first investigated at or after their end. Forward fitting investigated '+num(r.critical_investigated)+r' of '+num(r.critical_total)+
          r' critical records and started '+num(r.negative_investigations)+r' interval-negative investigations. P covered '+num(p.covered)+
          r' intervals in forward replay versus 7 with LOSO fitting. Temporal isolation therefore preserves the large coverage--retrieval gap; the five scenarios do not establish general transfer.')
    r=replay.loc['S1_key']
    write('revision_numbers.tex',r'\newcommand{\RevisionLateSOneKey}{'+num(r.late)+'}\n'+
          r'\newcommand{\RevisionBeforeSOneKey}{'+num(r.before_end)+'}')
    delay=read(BASE/'tables/tab_delay.tex')
    delay=delay.replace('Covered within 1 h',r'\shortstack{Within\\1 h}').replace('Median delay, covered (h)',r'\shortstack{Covered median\\delay (h)}').replace('Restricted mean delay, censored (h)',r'\shortstack{Lower-bound mean\\delay (h)}')
    write('tables/tab_delay.tex',delay)
    # All eight original effect panels, with legible labels in a 4x2 layout.
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    e=csv(PROJECT/'docs/revision/wp7/per_scenario_effects.csv')
    panels=[('primary','S1 - A','static','FP@100'),('primary','S1 - P','static','FP@100'),
        ('exploratory','S1_key - S1','replay P1 12/h','replay covered intervals'),('exploratory','S1_key - S1','replay P1 12/h','replay FP investigations'),
        ('exploratory','S0_key - P','replay P1 12/h','replay covered intervals'),('exploratory','S0_key - P','replay P1 12/h','replay FP investigations'),
        ('exploratory','R_severity_key - P','replay P1 12/h','replay covered intervals'),('exploratory','R_severity_key - P','replay P1 12/h','replay FP investigations')]
    fig,axes=plt.subplots(4,2,figsize=(6.3,7.8),layout='constrained')
    for ax,(fam,contrast,source,metric) in zip(axes.ravel(),panels):
        part=e[(e.family==fam)&(e.contrast==contrast)&(e.source==source)&(e.metric==metric)].set_index('scenario').reindex(scenarios)
        assert part.difference.notna().all()
        ax.axhline(0,color='.6',lw=.7); ax.scatter(range(8),part.difference,s=18,color='black')
        ax.set_xticks(range(8),[x[:3] for x in scenarios],rotation=45,fontsize=8)
        ax.tick_params(axis='y',labelsize=8)
        ax.set_title(contrast.replace('_key',' (key)')+'\n'+metric,fontsize=9)
    path=GEN/'figures/fig_paired_effects.pdf'; fig.savefig(path,metadata={'CreationDate':None}); plt.close(fig); outputs.append(path)
    # Preserve the actual selected candidates for direct inspection.
    for run in ('r1','r6','r7'):
        source=PROJECT/f'docs/revision/wp4/stage2_tables/{run}_e12_selections.csv'
        frame=csv(source); frame.to_csv(DOC/f'{run}_selected_candidates.csv',index=False)
    if (DOC/'ait_rate_manifest.json').exists():
        a=csv(DOC/'ait_rate_static.csv'); r=csv(DOC/'ait_rate_replay.csv').iloc[0]
        write('ait_rate_interpretation.tex',r'The adaptation covered '+num(a.covered.sum())+r' of 32 intervals statically, with median FP@100 '+f'{a.negative.median():g}'+
              r'. In replay it covered '+num(r.covered)+r' intervals ('+num(r.before_end)+r' before their end), investigated '+num(r.critical_investigated)+
              r' critical records, and started '+num(r.negative_investigations)+r' interval-negative investigations. These outcomes describe the declared native-key adaptation and do not reproduce the published detector-filtering evaluation.')
        rows=[[x.scenario,num(x.covered),num(x.negative)] for x in a.itertuples()]
        write('tables/tab_ait_rate_static.tex',table(['Scenario','Covered / 4','FP@100'],rows))
    (DOC/'revision_assets_manifest.json').write_text(json.dumps({'inputs':inputs,'outputs':{str(p.relative_to(PROJECT.parent)):digest(p) for p in outputs},'script_sha256':digest(Path(__file__))},indent=2)+'\n')
    print(f'Generated {len(outputs)} manuscript assets')

if __name__=='__main__': main()
