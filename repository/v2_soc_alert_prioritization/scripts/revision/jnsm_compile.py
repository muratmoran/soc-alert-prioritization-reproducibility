#!/usr/bin/env python
"""Build and compare the October manuscript without rewriting historical manifests."""
import json
import re
from pathlib import Path
import wp9_compile_manuscript as build

def flatten():
    text=(build.MANUSCRIPT/'main.tex').read_text()
    def inline(m):
        p=build.MANUSCRIPT/m.group(1)
        if p.suffix!='.tex': p=p.with_suffix('.tex')
        # TeX returns from an input file without forming a blank source line.
        content=p.read_text()
        prefix=text[text.rfind('\n',0,m.start())+1:m.start()]
        suffix=text[m.end():text.find('\n',m.end())]
        # Spaces at EOF are significant inside a resizebox argument. Preserve
        # those; remove the duplicate line ending only for standalone inputs.
        if not prefix.strip() and not suffix.strip(): content=content.removesuffix('\n')
        return content
    for _ in range(5):
        text,n=build.INPUT_PATTERN.subn(inline,text)
        if not n: break
    assert not build.INPUT_PATTERN.search(text)
    path=build.MANUSCRIPT/'main_submission.tex'
    path.write_text('%% Generated from main.tex by scripts/revision/jnsm_compile.py.\n'+text)
    return path

def compile_supplement():
    """Compile the electronic supplement and record its independent build manifest."""
    name='supplementary'
    for suffix in build.INTERMEDIATES:
        (build.MANUSCRIPT/f'{name}{suffix}').unlink(missing_ok=True)
    env=build.os.environ | {'SOURCE_DATE_EPOCH':build.SOURCE_DATE_EPOCH,'FORCE_SOURCE_DATE':'1'}
    result=build.subprocess.run(['latexmk','-pdf','-interaction=nonstopmode','-halt-on-error',f'{name}.tex'],
                                cwd=build.MANUSCRIPT,env=env,capture_output=True,text=True)
    (build.MANUSCRIPT/'supplementary_build.log').write_text(result.stdout+result.stderr,encoding='utf-8')
    if result.returncode:
        raise SystemExit(f'latexmk failed ({result.returncode}); see {build.MANUSCRIPT / "supplementary_build.log"}')
    log=(build.MANUSCRIPT/f'{name}.log').read_text(errors='replace')
    pages=build.subprocess.run(['gs','-q','-dNODISPLAY','-dNOSAFER','-c',
                                f'({name}.pdf) (r) file runpdfbegin pdfpagecount = quit'],
                               cwd=build.MANUSCRIPT,capture_output=True,text=True,check=True).stdout.strip()
    doc=build.PROJECT_ROOT/'docs/revision/jnsm_20261026'
    record={'supplementary_tex_sha256':build.sha(build.MANUSCRIPT/f'{name}.tex'),
            'references_bib_sha256':build.sha(build.MANUSCRIPT/'references.bib'),
            'supplementary_pdf_sha256':build.sha(build.MANUSCRIPT/f'{name}.pdf'),
            'pages':int(pages),
            'undefined_references':len(re.findall(r'undefined',log)),
            'overfull_hboxes':len(re.findall(r'Overfull \\hbox',log)),
            'source_date_epoch':build.SOURCE_DATE_EPOCH,
            'script_sha256':build.sha(Path(__file__))}
    (doc/'supplementary_manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    return record

def main():
    record=build.compile_pdf()
    record.pop('assets_manifest_sha256')
    doc=build.PROJECT_ROOT/'docs/revision/jnsm_20261026'
    record['revision_assets_manifest_sha256']=build.sha(doc/'revision_assets_manifest.json')
    record['script_sha256']=build.sha(Path(__file__))
    path=flatten()
    record['submission_tex_sha256']=build.sha(path)
    check=build.check_flattened(path,record['pages'])
    record['submission_single_file_check']=check
    (doc/'manuscript_manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    supplement=compile_supplement()
    required=['compiles','same_pages_as_main','same_text_as_main','same_rendered_pages_as_main']
    good=all(check.get(k) is True for k in required)
    print(json.dumps({'pages':record['pages'],'undefined_references':record['undefined_references'],
                      'overfull_hboxes':record['overfull_hboxes'],'single_file_identical':good},indent=2))
    print(json.dumps({'supplement_pages':supplement['pages'],
                      'supplement_undefined_references':supplement['undefined_references'],
                      'supplement_overfull_hboxes':supplement['overfull_hboxes']},indent=2))
    if not good: raise SystemExit('Submission-source comparison failed; inspect the dated manifest')

if __name__=='__main__': main()
