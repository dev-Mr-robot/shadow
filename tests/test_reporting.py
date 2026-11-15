import base64
from pathlib import Path
import pytest
from pypdf import PdfReader
from shadow.scope import EngagementInput
from shadow.research import create_finding,update_finding
from shadow.reporting import generate_report,export_report

@pytest.fixture
def engagement(runtime):
    return runtime.database.create_engagement(EngagementInput(name='Owned lab',scope=['lab.test'],authorization='Written permission for this isolated assessment'))

def test_markdown_html_pdf_are_factual_and_escaped(runtime,engagement,tmp_path):
    finding=create_finding(runtime.database,{'engagement_id':engagement['id'],'name':'<script>candidate</script>','asset':'lab.test','description':'A hypothesis, not independently verified.','severity':'Low'})
    markdown=generate_report(runtime.database,engagement['id'],'md')
    assert 'Verification: hypothesis' in markdown['content'] and '1 findings recorded' in markdown['content']
    html=generate_report(runtime.database,engagement['id'],'html')
    assert '<script>' not in html['content'] and '&lt;script&gt;' in html['content']
    pdf=generate_report(runtime.database,engagement['id'],'pdf')
    reader=PdfReader(pdf['path']);text='\n'.join(page.extract_text() for page in reader.pages)
    assert 'SHADOW Security Assessment' in text and 'Verification: hypothesis' in text
    assert Path(pdf['path']).read_bytes().startswith(b'%PDF')

def test_snapshot_immutable_and_exports_exclusive(runtime,engagement,tmp_path):
    finding=create_finding(runtime.database,{'engagement_id':engagement['id'],'name':'Initial name','asset':'lab.test'})
    report=generate_report(runtime.database,engagement['id'],'md')
    update_finding(runtime.database,finding['id'],{'name':'Changed name'})
    stored=runtime.database.get('report',report['id'])
    assert stored['snapshot']['findings'][0]['name']=='Initial name'
    target=tmp_path/'export.md';export_report(runtime.database,report['id'],target)
    assert 'Initial name' in target.read_text(encoding='utf-8')
    with pytest.raises(FileExistsError):export_report(runtime.database,report['id'],target)
    with pytest.raises(FileExistsError):generate_report(runtime.database,engagement['id'],'md',target)
    runtime.database.update('report',report['id'],{'content':'tampered'})
    with pytest.raises(ValueError):export_report(runtime.database,report['id'],tmp_path/'tampered.md')

@pytest.mark.skipif(__import__('os').name!='posix',reason='POSIX symlink output boundary')
def test_report_refuses_symbolic_link_outputs(runtime,engagement,tmp_path):
    existing=tmp_path/'existing.md';existing.write_text('preserve')
    target=tmp_path/'link.md';target.symlink_to(existing)
    with pytest.raises(ValueError):generate_report(runtime.database,engagement['id'],'md',target)
    assert existing.read_text()=='preserve'

def test_pdf_treats_external_markup_as_text(runtime,engagement,monkeypatch):
    import urllib.request
    import httpx
    def denied(*args,**kwargs):raise AssertionError('Report generation must never fetch links')
    monkeypatch.setattr(urllib.request,'urlopen',denied)
    monkeypatch.setattr(httpx,'get',denied)
    create_finding(runtime.database,{'engagement_id':engagement['id'],'name':'Untrusted markup','asset':'lab.test','description':'<img src="https://unrelated.invalid/secret"><a href="file:///etc/passwd">link</a>'})
    record=generate_report(runtime.database,engagement['id'],'pdf')
    text='\n'.join(page.extract_text() for page in PdfReader(record['path']).pages)
    assert 'unrelated.invalid' in text and 'Untrusted markup' in text

def test_report_paginates_beyond_repository_default(runtime,engagement):
    for i in range(205):
        runtime.database.create('finding',{'engagement_id':engagement['id'],'name':f'Candidate {i}','asset':'lab.test','severity':'Informational','verification':'hypothesis'},engagement['id'])
    report=generate_report(runtime.database,engagement['id'],'md')
    assert len(report['snapshot']['findings'])==205
    assert '205 findings recorded' in report['content']
