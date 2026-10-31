#!/usr/bin/env python
"""Compile the October 30 manuscript and record its own build provenance."""
import json
import os
from pathlib import Path
import re
import subprocess
from review_run import DOC, PROJECT
import wp9_compile_manuscript as build
from jnsm_compile import flatten


def main():
    build.SOURCE_DATE_EPOCH='1793318400'  # 2026-10-30 00:00:00 UTC
    record=build.compile_pdf()
    record.pop('assets_manifest_sha256')
    record['review_assets_manifest_sha256']=build.sha(DOC/'assets_manifest.json')
    path=flatten()
    record['submission_tex_sha256']=build.sha(path)
    check=build.check_flattened(path,record['pages'])
    record['submission_single_file_check']=check
    record['script_sha256']=build.sha(Path(__file__))
    (DOC/'manuscript_manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    env=os.environ|{'SOURCE_DATE_EPOCH':build.SOURCE_DATE_EPOCH,'FORCE_SOURCE_DATE':'1'}
    result=subprocess.run(['latexmk','-pdf','-interaction=nonstopmode','-halt-on-error','supplementary.tex'],
                          cwd=build.MANUSCRIPT,env=env,capture_output=True,text=True)
    (build.MANUSCRIPT/'supplementary_build.log').write_text(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError('Supplement failed: inspect supplementary_build.log')
    log=(build.MANUSCRIPT/'supplementary.log').read_text(errors='replace')
    pages=subprocess.run(['gs','-q','-dNODISPLAY','-dNOSAFER','-c',
                          '(supplementary.pdf) (r) file runpdfbegin pdfpagecount = quit'],
                         cwd=build.MANUSCRIPT,capture_output=True,text=True,check=True).stdout.strip()
    supplement={'pages':int(pages),'undefined_references':len(re.findall('undefined',log)),
        'overfull_hboxes':len(re.findall(r'Overfull \\hbox',log)),
        'source_sha256':build.sha(build.MANUSCRIPT/'supplementary.tex'),
        'pdf_sha256':build.sha(build.MANUSCRIPT/'supplementary.pdf'),'source_date_epoch':build.SOURCE_DATE_EPOCH}
    (DOC/'supplementary_manifest.json').write_text(json.dumps(supplement,indent=2)+'\n')
    print(json.dumps({'main_pages':record['pages'],'main_undefined':record['undefined_references'],
                     'main_overfull':record['overfull_hboxes'],'flattened':check,
                     'supplement':supplement},indent=2))
    if not all(check.get(k) for k in ['compiles','same_pages_as_main','same_text_as_main','same_rendered_pages_as_main']):
        raise RuntimeError('Flattened source differs')
    if record['undefined_references'] or supplement['undefined_references']:
        raise RuntimeError('Unresolved references')

if __name__=='__main__':main()
