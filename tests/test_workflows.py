import asyncio
import json
from contextlib import contextmanager
from pathlib import Path
import pytest
from rich.console import Console
from typer import Typer
from typer.testing import CliRunner

from shadow.scope import EngagementInput
from shadow.workflows import Workflow,import_workflow,preview_workflow,execute_workflow
from shadow.workflows_cli import register

@pytest.fixture
def workflow_lab(runtime):
    row=runtime.database.create_engagement(EngagementInput(name='Passive workflow lab',scope=['lab.test'],exclusions=['excluded.test'],authorization='Written permission for isolated research'))
    runtime.settings.active_engagement=row['id']
    return row

def definition(tmp_path,steps,**kwargs):
    path=tmp_path/'workflow.json';path.write_text(json.dumps({'name':'Local passive review','steps':steps,**kwargs}),encoding='utf-8')
    return path

@pytest.mark.parametrize('payload',[
    {'name':'Unsafe','steps':[{'capability':'shell','command':'id'}]},
    {'name':'Unsafe','steps':[{'capability':'static_analyze','input_file':'x','python':'exec(1)'}]},
    {'name':'Unsafe','steps':[{'capability':'http_inspect','input_file':'x','url':'https://remote.test'}]},
    {'name':'Too many','steps':[{'capability':'kb_search','query':'notes'}]*21},
    {'name':'Unknown top-level','steps':[{'capability':'kb_search','query':'notes'}],'execute':True},
    {'name':'No steps','steps':[]}
])
def test_workflow_schema_rejects_shell_extras_and_unbounded_steps(payload):
    with pytest.raises(ValueError):Workflow.model_validate(payload)

def test_import_does_not_open_referenced_inputs(runtime,tmp_path,monkeypatch):
    import shadow.workflows as module
    path=definition(tmp_path,[{'capability':'static_analyze','input_file':'does-not-exist.py'}])
    actual=module._read;opened=[]
    def spy(path,limit=module.MAX_INPUT):opened.append(Path(path).name);return actual(path,limit)
    monkeypatch.setattr(module,'_read',spy)
    result=import_workflow(runtime,path)
    assert opened==['workflow.json'] and result['definition']['steps'][0]['input_file']=='does-not-exist.py'
    assert not runtime.database.listing('workflow_run')
    with pytest.raises(FileNotFoundError):preview_workflow(runtime,result['id'])

async def test_missing_approval_and_changed_file_write_no_results(runtime,workflow_lab,tmp_path):
    source=tmp_path/'config.txt';source.write_text('debug=true\n')
    path=definition(tmp_path,[{'capability':'report_generate','format':'md'},{'capability':'static_analyze','input_file':'config.txt'}])
    workflow=import_workflow(runtime,path);preview=preview_workflow(runtime,workflow['id'])
    assert preview['steps'][1]['file']['path']==str(source.resolve())
    assert len(preview['steps'][1]['file']['sha256'])==64
    assert preview['steps'][0]['output_path'].startswith(str(runtime.paths.data))
    with pytest.raises(ValueError,match='approval'):await execute_workflow(runtime,preview['id'],preview['digest'])
    assert not runtime.database.listing('workflow_run') and not runtime.database.listing('report')
    source.write_text('debug=false\n')
    with pytest.raises(ValueError,match='input changed'):await execute_workflow(runtime,preview['id'],preview['digest'],approved=True)
    assert not runtime.database.listing('workflow_run') and not runtime.database.listing('report')
    assert not (runtime.paths.data/'reports').exists()
    assert runtime.database.get('workflow_preview',preview['id'])['status']=='pending'

async def test_approved_http_static_and_report_run_is_real_and_persistent(runtime,workflow_lab,tmp_path):
    request=tmp_path/'request.txt';request.write_text('GET /api?id=1 HTTP/1.1\nHost: lab.test\n\n')
    code=tmp_path/'review.py';code.write_text('value = eval(user_input)\n')
    path=definition(tmp_path,[{'capability':'http_inspect','input_file':'request.txt'},
        {'capability':'static_analyze','input_file':'review.py','kind':'python'},
        {'capability':'report_generate','format':'md'}])
    imported=import_workflow(runtime,path);preview=preview_workflow(runtime,imported['id'])
    result=await execute_workflow(runtime,preview['id'],preview['digest'],approved=True)
    assert result['status']=='completed' and len(result['steps'])==3
    assert result['steps'][0]['result']['parameters']['id']==['1']
    assert result['steps'][1]['result']['observations'][0]['line']==1
    report=runtime.database.get('report',result['steps'][2]['result']['id'])
    assert Path(report['path']).read_text(encoding='utf-8').startswith('# SHADOW Security Assessment')
    assert report['path']==preview['steps'][2]['output_path']
    assert runtime.database.get('workflow_run',result['id'])['status']=='completed'
    with pytest.raises(ValueError,match='consumed'):await execute_workflow(runtime,preview['id'],preview['digest'],approved=True)

def test_http_outside_scope_refused_and_response_requires_target(runtime,workflow_lab,tmp_path):
    source=tmp_path/'request.txt';source.write_text('GET / HTTP/1.1\nHost: unrelated.test\n\n')
    workflow=import_workflow(runtime,definition(tmp_path,[{'capability':'http_inspect','input_file':'request.txt'}]))
    with pytest.raises(ValueError,match='outside scope'):preview_workflow(runtime,workflow['id'])
    source.write_text('HTTP/1.1 200 OK\nContent-Type: text/plain\n\nHello')
    with pytest.raises(ValueError,match='specify target'):preview_workflow(runtime,workflow['id'])

async def test_scope_change_after_preview_refuses_before_report_write(runtime,workflow_lab,tmp_path):
    workflow=import_workflow(runtime,definition(tmp_path,[{'capability':'report_generate','format':'html'}]))
    preview=preview_workflow(runtime,workflow['id'])
    runtime.database.update_engagement(workflow_lab['id'],EngagementInput(name=workflow_lab['name'],scope=['lab.test'],authorization='Updated written permission',rules='Do not export evidence until reviewed'))
    with pytest.raises(ValueError,match='scope/rules changed'):await execute_workflow(runtime,preview['id'],preview['digest'],approved=True)
    assert not runtime.database.listing('workflow_run') and not runtime.database.listing('report')

async def test_step_error_stops_later_report_and_preserves_error(runtime,workflow_lab,tmp_path):
    code=tmp_path/'invalid.py';code.write_text('def invalid(:\n')
    workflow=import_workflow(runtime,definition(tmp_path,[{'capability':'static_analyze','input_file':'invalid.py','kind':'python'},{'capability':'report_generate'}]))
    preview=preview_workflow(runtime,workflow['id']);result=await execute_workflow(runtime,preview['id'],preview['digest'],approved=True)
    assert result['status']=='failed' and len(result['steps'])==1 and 'could not be safely parsed' in result['steps'][0]['error']
    assert not runtime.database.listing('report')

async def test_kb_workflow_never_calls_embedding_service(runtime,tmp_path,monkeypatch):
    from shadow.intelligence import InferenceProvider
    runtime.settings.embedding_model='configured-but-not-used'
    async def forbidden(*args,**kwargs):raise AssertionError('Passive workflow must not send embedding requests')
    monkeypatch.setattr(InferenceProvider,'embed',forbidden)
    runtime.database.create('knowledge_chunk',{'document_id':'fixture','name':'notes','index':0,'text':'SSRF validation requires explicit scope and evidence.','vector':[],'embedding_model':''},'fixture')
    workflow=import_workflow(runtime,definition(tmp_path,[{'capability':'kb_search','query':'SSRF'}]))
    preview=preview_workflow(runtime,workflow['id']);result=await execute_workflow(runtime,preview['id'],preview['digest'],approved=True)
    assert result['status']=='completed' and result['steps'][0]['result']['method']=='lexical'
    assert result['steps'][0]['result']['results'][0]['name']=='notes'

def test_cli_requires_concrete_confirmation_without_yes_shortcut(runtime,workflow_lab,tmp_path):
    @contextmanager
    def current():yield runtime
    app=Typer();register(app,current,Console());runner=CliRunner()
    path=definition(tmp_path,[{'capability':'report_generate','format':'md'}])
    imported=json.loads(runner.invoke(app,['workflow','import',str(path)]).stdout)
    preview=json.loads(runner.invoke(app,['workflow','preview',imported['id']]).stdout)
    command=['workflow','run',preview['id'],'--digest',preview['digest']]
    assert runner.invoke(app,command+['--yes']).exit_code==2
    result=runner.invoke(app,command,input='n\n');assert result.exit_code==1
    assert not runtime.database.listing('report')
    result=runner.invoke(app,command,input='y\n');assert result.exit_code==0,result.output
    assert runtime.database.listing('report') and len(runtime.database.listing('workflow_run'))==1
