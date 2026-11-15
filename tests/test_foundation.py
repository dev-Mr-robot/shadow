import asyncio
import json
import os
from pathlib import Path
import httpx
import pytest
from typer.testing import CliRunner
from shadow.config import Settings,load,save
from shadow.database import Database
from shadow.providers import OllamaProvider
from shadow.scope import EngagementInput,check
from shadow.diagnostics import recommendations
from shadow.main import app

def engagement():return EngagementInput(name='Owned lab',scope=['192.168.56.0/24','lab.test'],exclusions=['192.168.56.20'],authorization='Written authorization for isolated lab')

def test_config_round_trip_and_permissions(paths):
    paths.initialize();candidate=Settings(model='test:local',context_length=8192)
    save(paths,candidate);assert load(paths)==candidate
    assert paths.settings.exists()
    if os.name=='posix':
        assert paths.config.stat().st_mode&0o777==0o700
        assert paths.settings.stat().st_mode&0o777==0o600

@pytest.mark.parametrize('url',['https://remote.test','http://127.0.0.1.evil.test','http://localhost@remote.test','http://127.0.0.1/api','http://127.0.0.1?x=y','file:///etc/passwd','http://127.0.0.1:99999'])
def test_reject_nonlocal_or_ambiguous_provider(url):
    with pytest.raises(ValueError):Settings(ollama_url=url)

def test_invalid_config_does_not_overwrite_existing(paths):
    save(paths,Settings())
    original=paths.settings.read_bytes()
    with pytest.raises(ValueError):Settings(context_length=100)
    assert paths.settings.read_bytes()==original
    paths.settings.write_text('{bad json')
    with pytest.raises(ValueError):load(paths)

def test_migrations_are_repeatable_and_data_persists(runtime):
    assert runtime.database.revision()=='0004_soc'
    row=runtime.database.create_engagement(engagement())
    runtime.database.migrate()
    fresh=Database(runtime.paths)
    try:
        fresh.migrate();assert fresh.engagement(row['id'])['authorization']==engagement().authorization
        assert fresh.audit_rows()[0]['action']=='engagement.created'
    finally:fresh.close()

@pytest.mark.parametrize('entry',['*.test','http://lab.test','lab.test;id','../etc/passwd',''])
def test_scope_rejects_unsafe_entries(entry):
    with pytest.raises(ValueError):EngagementInput(name='Lab',scope=[entry],authorization='Written permission')

def test_scope_exact_domains_cidrs_and_exclusions(runtime):
    row=runtime.database.create_engagement(engagement())
    assert check('192.168.56.10',row)['in_scope']
    assert not check('192.168.56.20',row)['in_scope']
    assert not check('8.8.8.8',row)['in_scope']
    assert check('LAB.TEST.',row)['in_scope']
    assert not check('child.lab.test',row)['in_scope']
    with pytest.raises(ValueError):check('192.168.56.0/24',row)

async def test_local_provider_discovery_and_no_inference():
    seen=[]
    def handler(request):
        seen.append(request)
        return httpx.Response(200,json={'models':[{'name':'small:local','size':1000,'details':{'parameter_size':'3B','quantization_level':'Q4_K_M'}}]})
    result=await OllamaProvider(Settings(model='small:local'),httpx.MockTransport(handler)).status()
    assert result['selected_available'] and result['models'][0]['quantization']=='Q4_K_M'
    assert len(seen)==1 and seen[0].method=='GET' and seen[0].url.path=='/api/tags'

async def test_provider_caps_response_size_and_total_time():
    def oversized(request):return httpx.Response(200,content=b'x'*(2*1024*1024+1))
    result=await OllamaProvider(Settings(),httpx.MockTransport(oversized)).status()
    assert not result['available']
    async def slow(request):
        await asyncio.sleep(2)
        return httpx.Response(200,json={'models':[]})
    started=asyncio.get_running_loop().time()
    result=await OllamaProvider(Settings(request_timeout=1),httpx.MockTransport(slow)).status()
    assert not result['available'] and asyncio.get_running_loop().time()-started<1.7

@pytest.mark.parametrize('mode',['offline','redirect','malformed','details_null'])
async def test_provider_failure_and_validation(mode):
    def handler(request):
        if mode=='offline':raise httpx.ConnectError('sensitive exception detail')
        if mode=='redirect':return httpx.Response(302,headers={'Location':'https://remote.test'})
        if mode=='malformed':return httpx.Response(200,json={'models':'invalid'})
        return httpx.Response(200,json={'models':[{'name':'local','details':None}]})
    result=await OllamaProvider(Settings(),httpx.MockTransport(handler)).status()
    assert result['available']==(mode=='details_null')
    assert 'sensitive exception' not in json.dumps(result)

def test_model_fit_is_conservative_and_explicit():
    result=recommendations({'ram_available_bytes':4*1024**3,'gpus':[{'free_vram_mib':3000}]},{'models':[{'name':'small','size':1000000000},{'name':'large','size':8000000000}]})
    assert result['installed_candidates']==['small']
    assert 'No model is downloaded' in result['selection']

def test_cli_help_init_settings_engagement_and_exit_codes(paths):
    runner=CliRunner()
    assert runner.invoke(app,['--help']).exit_code==0
    from shadow import __version__
    assert runner.invoke(app,['--version']).stdout.strip()==__version__
    assert runner.invoke(app,['init']).exit_code==0
    assert runner.invoke(app,['upgrade']).exit_code==0
    result=runner.invoke(app,['settings','set','--model','small:local','--context','4096']);assert result.exit_code==0,result.output
    assert json.loads(runner.invoke(app,['settings','show']).stdout)['model']=='small:local'
    result=runner.invoke(app,['engagement','create','--name','Lab','--scope','lab.test','--authorization','Written authorization for this lab'])
    assert result.exit_code==0,result.output
    rid=json.loads(result.stdout)['id']
    assert runner.invoke(app,['engagement','check',rid,'lab.test']).exit_code==0
    assert runner.invoke(app,['engagement','check',rid,'elsewhere.test']).exit_code==3
    assert runner.invoke(app,['engagement','show',rid]).exit_code==0
    assert len(json.loads(runner.invoke(app,['engagement','list']).stdout))==1
    assert json.loads(runner.invoke(app,['audit']).stdout)
    assert runner.invoke(app,['roadmap']).exit_code==0
    assert runner.invoke(app,[]).exit_code==2

def test_doctor_json_and_exclusive_output(paths,monkeypatch,tmp_path):
    import shadow.main as module
    async def collect(settings,database):
        return {'ollama':{'available':False},'tools':[],'hardware':{'os':'test'},'database':{'revision':database.revision()}}
    monkeypatch.setattr(module,'collect',collect)
    runner=CliRunner();output=tmp_path/'doctor.json'
    result=runner.invoke(app,['doctor','--json','--output',str(output)])
    assert result.exit_code==0,result.output
    assert json.loads(result.stdout)['phase']=='integrated'
    assert output.exists()
    assert runner.invoke(app,['doctor','--json','--output',str(output)]).exit_code!=0

@pytest.mark.skipif(os.name!='posix',reason='POSIX symlink permission check')
def test_reject_symlink_config(paths,tmp_path):
    paths.initialize();outside=tmp_path/'outside';outside.write_text('{}')
    paths.settings.symlink_to(outside)
    with pytest.raises(ValueError):paths.initialize()
