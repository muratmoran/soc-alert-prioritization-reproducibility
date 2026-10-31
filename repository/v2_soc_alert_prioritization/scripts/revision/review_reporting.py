"""Reporting refinements from saved results; no fitting or replay is rerun."""
import json

import numpy as np
import pandas as pd


def build():
    from review_build import DOC, GEN, PROJECT, DATA, REPLAY, LABEL, sha, table, write

    original = PROJECT / 'docs/revision/jnsm_20261026'
    manifest = json.loads((original / 'analysis_manifest.json').read_text())
    for name, digest in manifest['outputs'].items():
        if name.endswith('.csv'):
            assert sha(PROJECT / name) == digest, name

    def partition(frame):
        frame = frame.copy()
        frame['noncritical_positive'] = (frame.investigations
                                        - frame.negative_investigations
                                        - frame.critical_investigated)
        assert (frame.noncritical_positive >= -1e-9).all()
        return frame

    names = {'P': 'P', 'S1': 'S1', 'S0_key': r'S0\key', 'S1_key': r'S1\key',
             'S2_key': r'S2\key', 'R_severity_key': r'\Rsev',
             'O_severity': r'O\textsubscript{sev}', 'LIFO': 'LIFO', 'FIFO': 'FIFO'}
    replay = partition(pd.read_csv(original / 'loso_timing.csv')).set_index('method')
    assert (replay.investigations == 11508).all()
    panel_a = table(['Ranker', 'Covered / 32', 'Before end', 'At/after end', 'Uncovered'],
                    [[names[m], int(r.covered), int(r.before_end), int(r.late),
                      32-int(r.covered)] for m in names for r in [replay.loc[m]]])
    headers = ['Ranker', r'\shortstack{Interval-\\negative}',
               r'\shortstack{Noncritical\\positive}', 'Critical',
               r'\shortstack{Uninvestigated\\critical}', r'\shortstack{Share\\(\%)}']
    rows = [[names[m], f'{int(r.negative_investigations):,}',
             f'{int(r.noncritical_positive):,}', f'{int(r.critical_investigated):,}',
             f'{int(r.critical_total-r.critical_investigated):,}',
             f'{100*(1-r.critical_investigated/r.critical_total):.1f}']
            for m in names for r in [replay.loc[m]]]
    panel_b = table(headers, rows)
    write('tables/tab_replay_panels.tex',
          r'\textbf{(a) Critical intervals}\par\medskip' + '\n' + panel_a + '\n' +
          r'\par\bigskip\textbf{(b) Alert records}\par\medskip' + '\n' +
          r'{\setlength{\tabcolsep}{4pt}' + '\n' + panel_b + '\n}')

    forward = partition(pd.read_csv(original / 'forward_replay.csv'))
    assert (forward.investigations == 7477).all()
    forward = forward.set_index(['design', 'method'])
    fields = ['investigations', 'negative_investigations', 'noncritical_positive', 'critical_investigated']
    headers = ['Ranker', 'Total starts', r'\shortstack{Interval-\\negative}',
               r'\shortstack{Noncritical\\positive}', 'Critical']
    rows = [[names[m]] + [f"{int(forward.loc[('LOSO_same_five', m), f]):,} / "
                            f"{int(forward.loc[('Forward', m), f]):,}" for f in fields] for m in names]
    write('tables/tab_review_forward_starts.tex', table(headers, rows))

    random = partition(pd.read_csv(DOC / 'random_replay_summary.csv')).set_index('method')
    assert (random.investigations == 11508).all()
    write('tables/tab_review_random_starts.tex', table(headers,
          [[LABEL[m]] + [f'{random.loc[m, f]:,.2f}' for f in fields] for m in REPLAY]))
    groups = partition(pd.read_csv(DOC / 'grouped_replay_summary.csv'))
    for window in [60, 300, 900]:
        part = groups[groups.window == window].set_index('method')
        assert part.investigations.nunique() == 1
        if window == 300:
            assert (part.investigations == 11500).all()
        write(f'tables/tab_review_group_starts_{window}.tex', table(headers,
              [[LABEL[m]] + [f'{int(part.loc[m, f]):,}' for f in fields] for m in REPLAY]))

    # Keep the complete historical diagnostic in the supplement.
    full = (GEN / 'tables/tab_ties.tex').read_text()
    rows = [line.removesuffix(r' \\').split(' & ') for line in full.splitlines() if ' & ' in line][1:]
    write('tables/tab_review_ties_main.tex', table(
          ['Ranker', r'\shortstack{Cutoff\\block}', r'\shortstack{Selected\\from block}',
           r'\shortstack{Declared\\FP}', r'\shortstack{Expected\\FP}'],
          [[r[i] for i in [0, 3, 4, 6, 7]] for r in rows]))
    delay = (original / 'baseline/generated/tables/tab_delay.tex').read_text()
    delay = delay.replace('Covered within 1 h', r'\shortstack{Within\\1 h}')
    delay = delay.replace('Median delay, covered (h)', r'\shortstack{Covered median\\delay (h)}')
    delay = delay.replace('Restricted mean delay, censored (h)',
                          r'\shortstack{Median scenario\\mean lower-bound\\delay (h)}')
    write('tables/tab_delay.tex', delay)
    path = GEN / 'tables/tab_forward_replay.tex'
    path.write_text(path.read_text().replace('Negative starts', r'\shortstack{Interval-negative\\starts}'))

    # Replot the unchanged curve values with larger type and a shared legend.
    from wp5_common import verify_stage2_copy
    import wp5_common
    wp5_common.STAGE2 = DATA / 'wp4_stage2'
    sums = verify_stage2_copy()['files']
    paths = sorted((DATA / 'wp4_stage2/R1').glob('loso_*/e10_curves.csv.gz'))
    assert len(paths) == 8
    for path in paths:
        assert sha(path) == sums[str(path.relative_to(DATA / 'wp4_stage2'))], path
    curves = pd.concat([pd.read_csv(p) for p in paths], ignore_index=True)
    grid = np.unique(np.round(np.logspace(0, 5.5, 60)).astype(int))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(6.6, 2.8))
    for label, name, style in [('P_probability_proxy', 'P / S1 (class level)', '-'),
                              ('S1_linear_log_constrained_key', r'$S1_{\mathrm{key}}$', '--'),
                              ('S2_exponential_discount_key', r'$S2_{\mathrm{key}}$', ':')]:
        data = curves[curves.agreement_label == label]
        for ax, metric in zip(axes, ['coverage_all', 'critical_recall']):
            values = []
            for scenario, part in data.groupby('held_out'):
                part = part.sort_values('rank')
                idx = np.searchsorted(part['rank'].to_numpy(), grid, side='right') - 1
                v = np.where(idx >= 0, part[metric].to_numpy()[np.clip(idx, 0, None)], 0.0)
                v = np.where(grid > part['rank'].max(), part[metric].to_numpy()[-1], v)
                values.append(v)
            assert len(values) == 8
            ax.plot(grid, np.mean(values, axis=0), style, color='black', lw=1.4, label=name)
    for ax, title in zip(axes, ['Critical-interval coverage', 'Alert-level critical recall']):
        ax.set_title(title, fontsize=10)
        ax.set_ylabel('Macro mean', fontsize=10)
        ax.set_xscale('log')
        ax.set_xlabel('Queue position (static order)', fontsize=10)
        ax.tick_params(labelsize=9)
        ax.axvline(100, color='0.6', lw=0.8)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper center', ncol=3, frameon=False, fontsize=10)
    fig.tight_layout(rect=(0, 0, 1, 0.88), pad=0.6)
    fig.savefig(GEN / 'figures/fig_rank_curves.pdf', metadata={'CreationDate': None})
    plt.close(fig)
