#!/usr/bin/env python
"""Portable reproduction entry point for the October 30 release."""
import argparse
from pathlib import Path
import sys
import review_run as run


def invoke(function,arguments):
    saved=sys.argv
    try:
        sys.argv=[saved[0],*arguments];function()
    finally:sys.argv=saved


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analysis',action='store_true',help='verify/resume all supplied analysis stages')
    parser.add_argument('--rerun-dir',type=Path,help='recompute detailed analyses in a new directory, preserving supplied folds')
    parser.add_argument('--assets',action='store_true')
    parser.add_argument('--compile',action='store_true')
    args=parser.parse_args()
    if args.rerun_dir:
        if args.rerun_dir.exists():parser.error('--rerun-dir must be a new directory')
        run.OUT=args.rerun_dir.resolve()
        args.analysis=True
    if args.analysis:
        for stage in ['static','sensitivity','random_replay','grouped_replay']:
            invoke(run.main,[stage])
    if args.assets:
        import review_build,review_writeup
        review_build.OUT=run.OUT
        invoke(review_build.main,[]);review_writeup.main()
        # Include the generated narrative in the final asset inventory.
        import json
        manifest=json.loads((run.DOC/'assets_manifest.json').read_text())
        for name in ['review_sections.tex','review_supplement.tex']:
            manifest['tables_and_figures'][name]=review_build.sha(review_build.GEN/name)
        manifest['narrative_generator_sha256']=review_build.sha(Path(review_writeup.__file__))
        (run.DOC/'assets_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    if args.compile:
        import review_compile
        review_compile.main()
    if not any(vars(args).values()):parser.error('choose --analysis, --assets, --compile, or --rerun-dir')

if __name__=='__main__':main()
