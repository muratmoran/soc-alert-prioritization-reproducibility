#!/usr/bin/env python
"""Portable entry point: rerun dated analyses, or regenerate supplied manuscript assets."""
import argparse
import os
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--analysis',action='store_true',help='also refit five forward folds and rerun the eight rate-score folds')
    p.add_argument('--assets',action='store_true',help='regenerate manuscript tables, figures and numerical macros')
    p.add_argument('--compile',action='store_true',help='compile and compare the two manuscript source forms')
    args=p.parse_args()
    if args.analysis:
        import jnsm_revision_analysis as analysis
        import wp4_stage2_run as source
        import wp5_common as replay
        root=Path(os.environ.get('SOC_REVISION_DATA',Path.home()/'soc_revision_data')).resolve()
        analysis.DATA=root
        source.DATA=root
        source.CACHE=root/'cache/ait_canonical_original_labels.pkl.gz'
        source.PROVENANCE=root/'cache/ait_native_score_provenance.pkl.gz'
        source.LABELS=root/'ait_alert/labels.csv'
        replay.STAGE2=root/'wp4_stage2'
        # The original record-pinned files are unchanged; only their input paths
        # are rebound for this explicit reproduction invocation.
        import sys
        saved=sys.argv; sys.argv=[sys.argv[0]]
        try:
            analysis.main()
            import jnsm_ait_rate as rate
            rate.DATA=root
            rate.main()
        finally: sys.argv=saved
    if args.assets:
        import jnsm_build_assets
        jnsm_build_assets.main()
    if args.compile:
        import jnsm_compile
        jnsm_compile.main()
    if not any(vars(args).values()): p.error('choose --analysis, --assets and/or --compile')

if __name__=='__main__': main()
