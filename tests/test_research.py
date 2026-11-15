import base64
import io
import json
import struct
from contextlib import contextmanager
from pathlib import Path
import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner
from shadow.scope import EngagementInput
from shadow.research import analyze_http,compare_http,import_evidence,create_finding,update_finding,import_advisory,static_analyze,MAX_BYTES
from shadow.research_cli import register

@pytest.fixture
def engagement(runtime):
    return runtime.database.create_engagement(EngagementInput(name='Owned lab',scope=['lab.test','192.168.56.10'],exclusions=['excluded.lab.test'],authorization='Written permission for isolated lab'))

def test_request_parameters_json_jwt_and_static_boundary():
    encode=lambda obj:base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')
    jwt=encode({'alg':'none'})+'.'+encode({'sub':'test'})+'.'
    request='POST /api?id=42&redirect=%2Fhome HTTP/1.1\r\nHost: lab.test\r\nAuthorization: Bearer '+jwt+'\r\nCookie: sid=redacted; theme=dark\r\nContent-Type: application/json\r\n\r\n{"url":"https://lab.test/"}'
    result=analyze_http(request)
    assert result['method']=='POST' and result['parameters']['id']==['42']
    assert result['json_body']['url']=='https://lab.test/'
    assert result['jwt'][0]['signature_verified'] is False and result['jwt'][0]['header']['alg']=='none'
    assert len(result['candidates'])==3 and result['request_cookie_names']==['sid','theme']
    assert 'No request was sent' in result['disclaimer']

def test_response_cookies_cors_cache_duplicate_headers_and_compare():
    first='HTTP/1.1 200 OK\nSet-Cookie: sid=x; HttpOnly\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\nCache-Control: private\nContent-Length: 1\nContent-Length: 2\n\nx'
    second='HTTP/1.1 403 Forbidden\nContent-Type: text/plain\n\nDenied'
    result=analyze_http(first)
    assert result['cookies'][0]['missing_attributes']==['secure','samesite']
    assert result['cache']['cache-control']==['private']
    assert 'content-length' in result['duplicate_headers']
    assert any('Browsers reject' in note for note in result['parse_notes'])
    diff=compare_http(first,second)
    assert diff['status_changed'] and 'set-cookie' in diff['header_changes'] and diff['verification']=='observation'

def test_http_xml_rejects_entities_and_invalid_formats():
    result=analyze_http('HTTP/1.1 200 OK\nContent-Type: application/xml\n\n<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')
    assert result['xml_body'] is None and result['parse_notes']
    assert analyze_http('HTTP/1.1 200 OK\nContent-Type: application/xml\n\n<root><item/></root>')['xml_body']['elements']==2
    for text in ['', 'not http', 'HTTP/1.1 invalid OK']:
        with pytest.raises(ValueError):analyze_http(text)

def test_http_multipart_inspects_metadata_without_extracting_paths():
    raw='POST /upload HTTP/1.1\nHost: lab.test\nContent-Type: multipart/form-data; boundary=fixture\n\n--fixture\nContent-Disposition: form-data; name="id"\n\n42\n--fixture\nContent-Disposition: form-data; name="attachment"; filename="../../untrusted.py"\n\nprint("never executed")\n--fixture--\n'
    result=analyze_http(raw)
    assert result['parameters']['id']==['42']
    assert result['uploads'][0]['filename']=='../../untrusted.py'
    assert result['uploads'][0]['parameter']=='attachment' and 'not executed' in result['uploads'][0]['note']

def test_evidence_hash_scope_and_burp_import(runtime,engagement,tmp_path):
    request=b'GET /api?id=1 HTTP/1.1\r\nHost: lab.test\r\n\r\n'
    response=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}'
    path=tmp_path/'burp.xml'
    path.write_text('<items><item><host>lab.test</host><url>https://lab.test/api</url><request base64="true">'+base64.b64encode(request).decode()+'</request><response base64="true">'+base64.b64encode(response).decode()+'</response></item></items>')
    row=import_evidence(runtime.database,engagement['id'],path,'burp')
    assert len(row['analyses'])==2 and len(row['sha256'])==64
    assert row['scope_checks'][0]['in_scope']
    bad=tmp_path/'request.txt';bad.write_text('GET / HTTP/1.1\nHost: excluded.lab.test\n\n')
    row=import_evidence(runtime.database,engagement['id'],bad)
    assert row['scope_checks'][0]['in_scope'] is False
    assert runtime.database.get('import',row['id'])['text'].startswith('GET')

def test_evidence_rejects_oversize_and_unsafe_burp(runtime,engagement,tmp_path):
    bad=tmp_path/'bad.xml';bad.write_text('<!DOCTYPE items [<!ENTITY e SYSTEM "file:///etc/passwd">]><items>&e;</items>')
    with pytest.raises(ValueError):import_evidence(runtime.database,engagement['id'],bad,'burp')
    huge=tmp_path/'huge';huge.write_bytes(b'x'*(MAX_BYTES+1))
    with pytest.raises(ValueError):import_evidence(runtime.database,engagement['id'],huge,'other')

def test_nmap_xml_text_and_entity_rejection(runtime,engagement,tmp_path):
    path=tmp_path/'scan.xml';path.write_text('<nmaprun><host><address addr="192.168.56.10"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="fixture"/></port></ports></host><host><address addr="8.8.8.8"/><ports><port protocol="tcp" portid="53"><state state="open"/></port></ports></host></nmaprun>')
    row=import_evidence(runtime.database,engagement['id'],path,'nmap')
    assert row['services'][0]['in_scope'] and not row['services'][1]['in_scope']
    assert row['services'][0]['port']==443
    path.write_text('<!DOCTYPE nmaprun [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>')
    with pytest.raises(ValueError):import_evidence(runtime.database,engagement['id'],path,'nmap')

async def test_completed_tool_job_imports_captured_nmap_xml(runtime,engagement):
    import sys
    from shadow.integrations import ToolManager
    xml='<nmaprun><host><address addr="192.168.56.10"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>'
    manager=ToolManager(runtime);job=manager.preview(engagement['id'],'192.168.56.10')
    result=await manager._capture(job['id'],[sys.executable,'-c','print('+repr(xml)+')'],3)
    assert result['status']=='completed' and result['evidence_id']
    evidence=runtime.database.get('import',result['evidence_id'])
    assert evidence['services'][0]['service']=='ssh' and evidence['services'][0]['in_scope']

def test_finding_validations_ownership_duplicate_candidates(runtime,engagement,tmp_path):
    base={'engagement_id':engagement['id'],'name':'Object access review','asset':'https://lab.test/api/objects/1'}
    with pytest.raises(ValueError):create_finding(runtime.database,{**base,'verification':'confirmed'})
    with pytest.raises(ValueError):create_finding(runtime.database,{**base,'cvss':9.8})
    with pytest.raises(ValueError):create_finding(runtime.database,{**base,'asset':'https://outside.test/'})
    with pytest.raises(ValueError):create_finding(runtime.database,{**base,'asset':'https://secret:password@lab.test/'})
    with pytest.raises(ValueError):create_finding(runtime.database,{**base,'workflow_status':'reported'})
    first=create_finding(runtime.database,base);second=create_finding(runtime.database,base)
    assert second['duplicate_candidates']==[first['id']]
    updated=update_finding(runtime.database,first['id'],{'evidence':'Manual test with owned accounts returned another test object','verification':'confirmed','workflow_status':'reported'})
    assert updated['verification']=='confirmed'
    with pytest.raises(ValueError):update_finding(runtime.database,first['id'],{'engagement_id':'other'})

def test_finding_rejects_cross_engagement_evidence(runtime,engagement,tmp_path):
    other=runtime.database.create_engagement(EngagementInput(name='Other lab',scope=['other.test'],authorization='Written permission for other lab'))
    path=tmp_path/'notes.txt';path.write_text('local evidence')
    evidence=import_evidence(runtime.database,other['id'],path,'other')
    with pytest.raises(ValueError):create_finding(runtime.database,{'engagement_id':engagement['id'],'name':'Test','asset':'lab.test','evidence_ids':[evidence['id']]})

def test_advisory_source_date_and_no_fabricated_claims(runtime,tmp_path):
    path=tmp_path/'advisory.json';path.write_text(json.dumps({'cve':'CVE-2026-12345','title':'Fixture advisory','affected_versions':'Supplied fixture only'}))
    row=import_advisory(runtime.database,path,'https://vendor.example/advisory','2026-11-14')
    assert row['source_date']=='2026-11-14' and row['cvss'] is None
    assert 'not independently verified' in row['verification']
    with pytest.raises(ValueError):import_advisory(runtime.database,path,'file:///etc/passwd','2026-11-14')
    path.write_text(json.dumps({'cve':'invented','title':'invalid'}))
    with pytest.raises(ValueError):import_advisory(runtime.database,path,'https://vendor.example','2026-11-14')

def test_static_python_config_log_binary_and_pcap(tmp_path):
    path=tmp_path/'source.py';path.write_text('import json\nimport pickle\njson.loads("{}")\npickle.loads(value)\n')
    result=static_analyze(path)
    assert len(result['observations'])==1 and result['observations'][0]['line']==4
    config=tmp_path/'settings.ini';config.write_text('api_key = never-display-this-value\ndebug=true')
    result=static_analyze(config)
    assert len(result['observations'])==2 and 'never-display' not in json.dumps(result)
    log=tmp_path/'app.log';log.write_text('ERROR failed\nwarning error')
    assert static_analyze(log)['keyword_counts']['error']==2
    binary=tmp_path/'sample';binary.write_bytes(b'\x7fELF\x00hello fixture string\x00')
    assert static_analyze(binary)['format']=='ELF'
    pcap=tmp_path/'sample.pcap';pcap.write_bytes(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1)+struct.pack('<IIII',0,0,3,3)+b'abc')
    assert static_analyze(pcap)['packet_count']==1
    pcap.write_bytes(pcap.read_bytes()[:-1])
    with pytest.raises(ValueError):static_analyze(pcap)

def test_cli_http_finding_report_and_research(runtime,engagement,tmp_path):
    @contextmanager
    def factory():yield runtime
    local=typer.Typer();register(local,factory,Console())
    runner=CliRunner();request=tmp_path/'request.txt';request.write_text('GET /?id=1 HTTP/1.1\nHost: lab.test\n\n')
    assert runner.invoke(local,['http','inspect',str(request)]).exit_code==0
    assert runner.invoke(local,['http','analyze',str(request),'--engagement',engagement['id']]).exit_code==0
    finding=tmp_path/'finding.json';finding.write_text(json.dumps({'name':'Review candidate','asset':'lab.test'}))
    result=runner.invoke(local,['finding','add',str(finding),'--engagement',engagement['id']]);assert result.exit_code==0,result.output
    assert runner.invoke(local,['report','generate','--engagement',engagement['id']]).exit_code==0
    assert runner.invoke(local,['research','analyze',str(request),'--kind','config']).exit_code==0
