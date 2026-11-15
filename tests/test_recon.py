import asyncio
import json
import time
from pathlib import Path
import httpx
import pytest
from sqlalchemy import text
from typer import Typer
from typer.testing import CliRunner
from rich.console import Console
from contextlib import contextmanager
from shadow import recon
from shadow.recon_cli import register
from shadow.scope import EngagementInput

@pytest.fixture
def lab(runtime):
    body=EngagementInput(name='Recon lab',scope=['lab.test','192.168.56.0/24'],exclusions=['192.168.56.20'],authorization='Authorized isolated lab')
    return runtime.database.create_engagement(body)

def test_normalization_and_streaming_import(runtime,lab,tmp_path):
    path=tmp_path/'assets.txt';path.write_text('LAB.TEST.\nhttps://lab.test/path\n192.168.56.10\n192.168.56.20\nevil.test\nhttp://user:secret@lab.test\n# comment\n'+('x'*5000)+'\n',encoding='utf-8')
    result=recon.import_assets(runtime.database,lab['id'],path)
    assert result['imported']==2 and result['duplicates']==1 and result['excluded']==2 and result['invalid']==2
    assert recon.stats(runtime.database,lab['id'])['total_assets']==2
    assert len(recon.list_assets(runtime.database,lab['id'],search='LAB'))==1
    assert recon.normalize('2001:4860:4860::8888')=='2001:4860:4860::8888'
    assert recon.normalize('https://bücher.test/')=='xn--bcher-kva.test'

def test_large_import_deduplicates_on_disk(runtime,lab,tmp_path):
    path=tmp_path/'large.txt'
    with path.open('w') as f:
        for _ in range(10000):f.write('192.168.56.10\n')
    counts=recon.import_assets(runtime.database,lab['id'],path)
    assert counts['imported']==1 and counts['duplicates']==9999
    assert recon.stats(runtime.database,lab['id'])['pending_assets']==1
    assert ''.join(recon.export_assets(runtime.database,lab['id'],'txt'))=='192.168.56.10\n'
    assert json.loads(''.join(recon.export_assets(runtime.database,lab['id'],'json')))[0]['state']=='pending'

def test_fifty_thousand_unique_assets_stream_on_disk(runtime,tmp_path):
    db=runtime.database
    lab=db.create_engagement(EngagementInput(name='Large owned network inventory',scope=['10.10.0.0/16'],authorization='Written permission for isolated inventory import'))
    path=tmp_path/'fifty-thousand.txt'
    with path.open('w') as f:
        for number in range(50000):f.write(f'10.10.{number//256}.{number%256}\n')
    counts=recon.import_assets(db,lab['id'],path)
    assert counts['imported']==50000 and counts['duplicates']==0
    assert recon.stats(db,lab['id'])['total_assets']==50000
    assert len(recon.list_assets(db,lab['id'],limit=7,offset=40000))==7
    assert next(recon.export_assets(db,lab['id'],'json'))=='['
    again=recon.import_assets(db,lab['id'],path)
    assert again['duplicates']==50000 and again['imported']==0

def import_one(runtime,lab,tmp_path,host='lab.test'):
    path=tmp_path/(host.replace(':','_')+'.txt');path.write_text(host+'\n')
    recon.import_assets(runtime.database,lab['id'],path)

async def test_approval_expiry_change_and_one_use(runtime,lab,tmp_path,monkeypatch):
    db=runtime.database;import_one(runtime,lab,tmp_path)
    plan=recon.preview(db,lab['id'],rate=20)
    with pytest.raises(ValueError):await recon.execute(db,plan['id'],'bad')
    async def resolve(*args):return ['192.168.56.10']
    async def probe(*args,**kwargs):return ([{'scheme':'http','status':200,'title':'Lab','technologies':[],'endpoints':[]}],[])
    monkeypatch.setattr(recon,'resolve',resolve);monkeypatch.setattr(recon,'probe',probe)
    result=await recon.execute(db,plan['id'],plan['digest'])
    assert result['status']=='completed' and result['completed']==1
    with pytest.raises(ValueError):await recon.execute(db,plan['id'],plan['digest'])
    with pytest.raises(ValueError):recon.preview(db,lab['id'])
    again=recon.preview(db,lab['id'],resume=False)
    recon._update_run(db,again['id'],{'expires':0})
    with pytest.raises(ValueError):await recon.execute(db,again['id'],again['digest'])
    changed=recon.preview(db,lab['id'],resume=False)
    import_one(runtime,lab,tmp_path,'192.168.56.11')
    with pytest.raises(ValueError):await recon.execute(db,changed['id'],changed['digest'])

async def test_concurrent_import_does_not_expand_approved_targets(runtime,lab,tmp_path,monkeypatch):
    db=runtime.database;import_one(runtime,lab,tmp_path,'192.168.56.10')
    plan=recon.preview(db,lab['id'],rate=20);seen=[]
    async def resolve(host,timeout):
        seen.append(host)
        import_one(runtime,lab,tmp_path,'192.168.56.11')
        return [host]
    async def probe(*args,**kwargs):return ([{'scheme':'http','status':200,'title':'Lab','technologies':[],'endpoints':[]}],[])
    monkeypatch.setattr(recon,'resolve',resolve);monkeypatch.setattr(recon,'probe',probe)
    await recon.execute(db,plan['id'],plan['digest'])
    assert seen==['192.168.56.10']
    assert recon.stats(db,lab['id'])['total_assets']==2
    assert recon.preview(db,lab['id'])['count']==1

async def test_scope_rechecked_before_dns_and_http(runtime,lab,tmp_path,monkeypatch):
    db=runtime.database;import_one(runtime,lab,tmp_path)
    plan=recon.preview(db,lab['id'],rate=20)
    calls=[]
    async def resolve(*args):calls.append('dns');return ['8.8.8.8']
    async def probe(*args,**kwargs):calls.append('http');return [],[]
    monkeypatch.setattr(recon,'resolve',resolve);monkeypatch.setattr(recon,'probe',probe)
    await recon.execute(db,plan['id'],plan['digest'])
    assert calls==['dns']
    row=recon.list_assets(db,lab['id'])[0]
    assert row['state']=='failed' and 'authorized IP/CIDR' in row['errors'][0]['detail']

async def test_scope_revocation_after_dns_prevents_http(runtime,lab,tmp_path,monkeypatch):
    db=runtime.database;import_one(runtime,lab,tmp_path);plan=recon.preview(db,lab['id'],rate=20)
    original_probe=recon.probe;requests=[]
    async def resolve(*args):
        db.update_engagement(lab['id'],EngagementInput(name=lab['name'],scope=lab['scope'],exclusions=['lab.test'],authorization=lab['authorization']))
        return ['192.168.56.10']
    def handler(request):requests.append(request);return httpx.Response(200,stream=Bytes(b'ok'))
    async def probe(host,addresses,timeout,limiter,engagement_check):
        return await original_probe(host,addresses,timeout,limiter,engagement_check,httpx.MockTransport(handler))
    monkeypatch.setattr(recon,'resolve',resolve);monkeypatch.setattr(recon,'probe',probe)
    await recon.execute(db,plan['id'],plan['digest'])
    assert not requests and recon.list_assets(db,lab['id'])[0]['state']=='failed'

async def test_global_run_limit_and_stale_recovery(runtime,lab,tmp_path,monkeypatch):
    db=runtime.database;import_one(runtime,lab,tmp_path)
    first=recon.preview(db,lab['id'],rate=20);second=recon.preview(db,lab['id'],rate=20)
    entered=asyncio.Event()
    async def waiting(*args):entered.set();await asyncio.sleep(30)
    monkeypatch.setattr(recon,'resolve',waiting)
    task=asyncio.create_task(recon.execute(db,first['id'],first['digest']))
    await entered.wait()
    with pytest.raises(ValueError,match='another reconnaissance run'):await recon.execute(db,second['id'],second['digest'])
    task.cancel()
    with pytest.raises(asyncio.CancelledError):await task
    recon._update_run(db,second['id'],{'status':'running','owner_pid':__import__('os').getpid(),'owner_started':0})
    assert recon.recover_stale(db)==[second['id']]
    assert recon.get_run(db,second['id'])['status']=='interrupted'

async def test_global_rate_limiter_spaces_operations():
    limiter=recon.RateLimiter(20);start=asyncio.get_running_loop().time()
    await asyncio.gather(limiter.wait(),limiter.wait(),limiter.wait())
    assert asyncio.get_running_loop().time()-start>=.09

def test_pending_cancellation_cannot_overwrite_a_claimed_run(runtime,lab,tmp_path):
    db=runtime.database;import_one(runtime,lab,tmp_path)
    plan=recon.preview(db,lab['id'])
    assert recon.cancel_preview(db,plan['id'])['status']=='cancelled'
    claimed=recon.preview(db,lab['id'])
    recon._update_run(db,claimed['id'],{'status':'running'})
    with pytest.raises(ValueError):recon.cancel_preview(db,claimed['id'])
    assert recon.get_run(db,claimed['id'])['status']=='running'

class Bytes(httpx.AsyncByteStream):
    def __init__(self,data):self.data=data
    async def __aiter__(self):
        for i in range(0,len(self.data),8192):yield self.data[i:i+8192]

async def test_pinned_probe_headers_redirects_and_raw_caps():
    requests=[]
    def handler(request):
        requests.append(request)
        return httpx.Response(302,headers={'Location':'http://unrelated.test/private','Server':'LabServer','Set-Cookie':'secret=hidden'},stream=Bytes(b'<title>Lab</title><a href="/admin">admin</a><a href="http://evil.test/">offsite</a>'+b'x'*300000))
    results,errors=await recon.probe('lab.test',['192.168.56.10'],2,recon.RateLimiter(10000),transport=httpx.MockTransport(handler))
    assert not errors and len(requests)==2
    assert all(request.url.host=='192.168.56.10' and request.headers['host']=='lab.test' for request in requests)
    assert all(request.extensions['sni_hostname']=='lab.test' for request in requests)
    assert results[0]['title']=='Lab' and results[0]['body_truncated']
    assert results[0]['endpoints']==['/admin'] and 'set-cookie' not in results[0]['headers']
    assert results[0]['redirect'].startswith('http://unrelated.test')
    assert recon.prioritize(results)[0]['verification']=='unverified lead'

async def test_compressed_responses_not_decompressed():
    def handler(request):return httpx.Response(200,headers={'Content-Encoding':'gzip'},stream=Bytes(b'not actually compressed'))
    result,errors=await recon.probe('lab.test',['192.168.56.10'],2,recon.RateLimiter(10000),transport=httpx.MockTransport(handler))
    assert not errors and result[0]['encoded_body_omitted'] and result[0]['title']==''

async def test_history_diff_and_resume(runtime,lab,tmp_path,monkeypatch):
    db=runtime.database;import_one(runtime,lab,tmp_path)
    version=[200]
    async def resolve(*args):return ['192.168.56.10']
    async def probe(*args,**kwargs):return ([{'scheme':'http','status':version[0],'title':'Lab','technologies':['server: lab'],'endpoints':[]}],[])
    monkeypatch.setattr(recon,'resolve',resolve);monkeypatch.setattr(recon,'probe',probe)
    first=recon.preview(db,lab['id'],rate=20);await recon.execute(db,first['id'],first['digest'])
    version[0]=403;second=recon.preview(db,lab['id'],rate=20,resume=False);await recon.execute(db,second['id'],second['digest'])
    diff=recon.compare(db,first['id'],second['id'])
    assert diff['changes'][0]['change']=='changed'
    assert diff['changes'][0]['first']['http'][0]['status']==200
    assert recon.stats(db,lab['id'])['unique_technologies']==1
    assert len(recon.runs(db,lab['id']))==2

async def test_cancellation_checkpoints_and_bound_concurrency(runtime,lab,tmp_path,monkeypatch):
    db=runtime.database
    path=tmp_path/'ips.txt';path.write_text('\n'.join('192.168.56.'+str(i) for i in range(1,11)))
    recon.import_assets(db,lab['id'],path)
    active=0;maximum=0
    async def resolve(host,timeout):
        nonlocal active,maximum
        active+=1;maximum=max(maximum,active)
        try:await asyncio.sleep(.1);return [host]
        finally:active-=1
    async def probe(*args,**kwargs):return ([{'scheme':'http','status':200,'title':'Lab','technologies':[],'endpoints':[]}],[])
    monkeypatch.setattr(recon,'resolve',resolve);monkeypatch.setattr(recon,'probe',probe)
    plan=recon.preview(db,lab['id'],concurrency=2,rate=20)
    task=asyncio.create_task(recon.execute(db,plan['id'],plan['digest']))
    await asyncio.sleep(.24);task.cancel()
    with pytest.raises(asyncio.CancelledError):await task
    row=recon.get_run(db,plan['id'])
    assert row['status']=='cancelled' and maximum<=2
    resume=recon.preview(db,lab['id'],rate=20)
    assert resume['count']==10-row['completed']

def test_cli_import_preview_and_export(runtime,lab,tmp_path):
    @contextmanager
    def state():yield runtime
    app=Typer();register(app,state,Console());runner=CliRunner()
    path=tmp_path/'list.txt';path.write_text('lab.test\n')
    result=runner.invoke(app,['recon','import',str(path),'--engagement',lab['id']]);assert result.exit_code==0,result.output
    result=runner.invoke(app,['recon','analyze','--engagement',lab['id']]);assert result.exit_code==0,result.output
    assert 'No network activity started' in result.output
    output=tmp_path/'export.json'
    assert runner.invoke(app,['recon','export',str(output),'--engagement',lab['id']]).exit_code==0
    assert json.loads(output.read_text())[0]['host']=='lab.test'
    assert runner.invoke(app,['recon','export',str(output),'--engagement',lab['id']]).exit_code!=0
