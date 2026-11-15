"""Typed passive workflows with immutable previews and explicit one-use approval.

There is deliberately no shell, Python evaluation, HTTP replay, DNS, scanner,
embedding request or model execution capability in this workflow engine.
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import tempfile
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated,Literal,Union
from urllib.parse import urlsplit

from pydantic import BaseModel,ConfigDict,Field,TypeAdapter,field_validator
from .scope import check

MAX_DEFINITION=128*1024
MAX_INPUT=8*1024*1024
MAX_TOTAL_INPUT=32*1024*1024
MAX_RESULT=2*1024*1024

class Strict(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)

class HttpInspect(Strict):
    capability:Literal['http_inspect']
    input_file:str=Field(min_length=1,max_length=4096)
    target:str|None=Field(default=None,max_length=253)
    engagement_id:str|None=Field(default=None,max_length=36)

class StaticAnalyze(Strict):
    capability:Literal['static_analyze']
    input_file:str=Field(min_length=1,max_length=4096)
    kind:Literal['auto','python','config','log','binary','pcap']='auto'
    target:str|None=Field(default=None,max_length=253)
    engagement_id:str|None=Field(default=None,max_length=36)

class KnowledgeSearch(Strict):
    capability:Literal['kb_search']
    query:str=Field(min_length=1,max_length=4000)
    limit:int=Field(default=5,ge=1,le=20)
    @field_validator('query')
    @classmethod
    def nonblank(cls,value):
        if not value.strip():raise ValueError('Search query must not be blank')
        return value

class ReportGenerate(Strict):
    capability:Literal['report_generate']
    format:Literal['md','html','pdf']='md'
    engagement_id:str|None=Field(default=None,max_length=36)

Step=Annotated[Union[HttpInspect,StaticAnalyze,KnowledgeSearch,ReportGenerate],Field(discriminator='capability')]
STEP=TypeAdapter(Step)

class Workflow(Strict):
    version:Literal[1]=1
    name:str=Field(min_length=1,max_length=150)
    description:str=Field(default='',max_length=2000)
    engagement_id:str|None=Field(default=None,max_length=36)
    steps:list[Step]=Field(min_length=1,max_length=20)
    @field_validator('name')
    @classmethod
    def nonblank(cls,value):
        if not value.strip():raise ValueError('Workflow name must not be blank')
        return value.strip()

def _read(path,limit=MAX_INPUT):
    selected=Path(path).expanduser().resolve(strict=True)
    if not selected.is_file():raise ValueError('Workflow inputs must be regular files')
    if selected.stat().st_size>limit:raise ValueError(f'Workflow input exceeds {limit} bytes')
    with selected.open('rb') as source:data=source.read(limit+1)
    if len(data)>limit:raise ValueError('Workflow input grew beyond the allowed limit')
    return selected,data

def import_workflow(state,path):
    """Import only the definition. Referenced inputs are not inspected or opened."""
    selected,data=_read(path,MAX_DEFINITION)
    definition=Workflow.model_validate_json(data)
    record=state.database.create('workflow',{'name':definition.name,'definition':definition.model_dump(),
        'base_directory':str(selected.parent),'source_name':selected.name,'sha256':hashlib.sha256(data).hexdigest(),
        'warning':'Imported definition only. Referenced inputs have not been read and no steps have executed.'},definition.engagement_id)
    state.database.audit('workflow.imported',{'id':record['id'],'name':definition.name,'steps':len(definition.steps)})
    return record

def _scope_signature(engagement):
    return hashlib.sha256(json.dumps({key:engagement.get(key) for key in ['id','scope','exclusions','authorization','rules']},sort_keys=True).encode()).hexdigest()

def _targets_http(data,explicit):
    from .research import analyze_http
    result=analyze_http(data.decode('utf-8-sig',errors='replace'))
    hosts=set()
    for authority in result['headers'].get('host',[]):
        parsed=urlsplit('//'+authority)
        if parsed.username or parsed.password or not parsed.hostname:raise ValueError('HTTP Host authority is ambiguous')
        hosts.add(parsed.hostname)
    if result['path'].startswith(('http://','https://')):
        parsed=urlsplit(result['path'])
        if parsed.username or parsed.password or not parsed.hostname:raise ValueError('HTTP request target authority is ambiguous')
        hosts.add(parsed.hostname)
    if explicit:hosts.add(explicit)
    if not hosts:raise ValueError('HTTP response/file has no target host; specify target explicitly in the workflow step')
    return sorted(hosts)

def _scope(db,eid,targets,required=False):
    if not eid:
        if required or targets:raise ValueError('This workflow step requires an explicitly selected authorized engagement')
        return None
    engagement=db.engagement(eid)
    for target in targets:
        result=check(target,engagement)
        if not result['in_scope']:raise ValueError(f'Workflow target is outside scope: {result["target"]}')
    return {'engagement_id':eid,'signature':_scope_signature(engagement),'targets':targets}

def _payload(row):return {key:row[key] for key in ['workflow_id','name','engagement_id','steps']}
def _digest(payload):return hashlib.sha256(json.dumps(payload,sort_keys=True,ensure_ascii=True).encode()).hexdigest()

def preview_workflow(state,workflow_id,engagement_id=None):
    record=state.database.get('workflow',workflow_id);definition=Workflow.model_validate(record['definition'])
    selected_eid=engagement_id or definition.engagement_id or state.settings.active_engagement
    steps=[];total=0
    for index,step in enumerate(definition.steps,1):
        spec=step.model_dump();eid=getattr(step,'engagement_id',None) or selected_eid
        entry={'index':index,'spec':spec,'scope':None}
        targets=[]
        if isinstance(step,(HttpInspect,StaticAnalyze)):
            source=Path(step.input_file).expanduser()
            if not source.is_absolute():source=Path(record['base_directory'])/source
            selected,data=_read(source);total+=len(data)
            if total>MAX_TOTAL_INPUT:raise ValueError('Total workflow input exceeds 32 MiB')
            entry['file']={'path':str(selected),'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
            targets=_targets_http(data,step.target) if isinstance(step,HttpInspect) else [step.target] if step.target else []
        if not isinstance(step,KnowledgeSearch):entry['scope']=_scope(state.database,eid,targets,required=isinstance(step,(HttpInspect,ReportGenerate)))
        if isinstance(step,ReportGenerate):entry['output_path']=str((state.paths.data/'reports'/f'workflow-{uuid.uuid4().hex}.{step.format}').absolute())
        steps.append(entry)
    payload={'workflow_id':workflow_id,'name':definition.name,'engagement_id':selected_eid,'steps':steps}
    result=state.database.create('workflow_preview',{**payload,'digest':_digest(payload),'expires':time.time()+600,'status':'pending',
        'operations':'Ordered passive local analysis only. KB search is lexical-only; no embedding/model/network requests. Reports are written under the SHADOW data directory only after approval.',
        'input_bytes':total},selected_eid)
    state.database.audit('workflow.previewed',{'id':result['id'],'workflow_id':workflow_id,'digest':result['digest'],'steps':len(steps)})
    return result

def _preflight(state,row):
    """Read each approved file once and verify all inputs/scopes before writes."""
    verified={};total=0
    if not isinstance(row['steps'],list) or not 1<=len(row['steps'])<=20:raise ValueError('Invalid workflow preview step count')
    for entry in row['steps']:
        step=STEP.validate_python(entry['spec'])
        if isinstance(step,(HttpInspect,StaticAnalyze)):
            selected,data=_read(entry['file']['path']);total+=len(data)
            if total>MAX_TOTAL_INPUT:raise ValueError('Total workflow input exceeds 32 MiB')
            if str(selected)!=entry['file']['path'] or len(data)!=entry['file']['bytes'] or hashlib.sha256(data).hexdigest()!=entry['file']['sha256']:
                raise ValueError('Workflow input changed after preview; create a fresh preview')
            verified[entry['index']]=data
            targets=_targets_http(data,step.target) if isinstance(step,HttpInspect) else [step.target] if step.target else []
        else:targets=[]
        expected=entry.get('scope')
        if expected:
            current=_scope(state.database,expected['engagement_id'],targets,required=True)
            if current!=expected:raise ValueError('Engagement scope/rules changed after preview; create a fresh preview')
        elif isinstance(step,(HttpInspect,ReportGenerate)) or targets:
            raise ValueError('Workflow preview is missing required scope information')
    return verified

async def execute_workflow(state,preview_id,digest,approved=False):
    if approved is not True:raise ValueError('Explicit approval is required before running a workflow')
    row=state.database.get('workflow_preview',preview_id)
    if row['status']!='pending' or row['expires']<time.time() or digest!=row['digest'] or _digest(_payload(row))!=digest:
        raise ValueError('Workflow preview changed, expired or was already consumed')
    verified=_preflight(state,row)
    # Claim only after preflight; failed stale-file checks neither consume approval nor write results.
    state.database.claim('workflow_preview',preview_id)
    run=state.database.create('workflow_run',{'workflow_id':row['workflow_id'],'preview_id':preview_id,'name':row['name'],'status':'running','steps':[]},row.get('engagement_id'))
    results=[];status='completed'
    try:
        with tempfile.TemporaryDirectory(prefix='shadow-passive-workflow-') as staging:
            for entry in row['steps']:
                step=STEP.validate_python(entry['spec']);scope=entry.get('scope')
                # Recheck scope immediately before each operation, including report generation.
                if scope:
                    current=_scope(state.database,scope['engagement_id'],scope['targets'],required=True)
                    if current!=scope:raise ValueError('Engagement authorization changed while workflow was running')
                try:
                    if isinstance(step,HttpInspect):
                        from .research import analyze_http
                        result=analyze_http(verified[entry['index']].decode('utf-8-sig',errors='replace'))
                    elif isinstance(step,StaticAnalyze):
                        from .research import static_analyze
                        directory=Path(staging)/str(entry['index']);directory.mkdir()
                        copy=directory/Path(entry['file']['path']).name
                        copy.write_bytes(verified[entry['index']])
                        result=await asyncio.to_thread(static_analyze,copy,step.kind)
                    elif isinstance(step,KnowledgeSearch):
                        from .knowledge import KnowledgeService
                        passive=SimpleNamespace(settings=state.settings.model_copy(update={'embedding_model':''}),database=state.database,paths=state.paths)
                        result=await KnowledgeService(passive).search(step.query,step.limit)
                        result['workflow_note']='Lexical-only to preserve this passive workflow’s no-network boundary.'
                    else:
                        from .reporting import generate_report
                        directory=state.paths.data/'reports'
                        if directory.is_symlink():raise ValueError('Refusing symlink report directory')
                        directory.mkdir(mode=0o700,exist_ok=True)
                        output=Path(entry['output_path'])
                        if output.parent!=directory.absolute() or not output.name.startswith('workflow-') or output.suffix!='.'+step.format:
                            raise ValueError('Workflow report output is not confined to its approved directory')
                        report=generate_report(state.database,scope['engagement_id'],step.format,output)
                        result={key:report[key] for key in ['id','format','path','sha256','warning']}
                    if len(json.dumps(result,ensure_ascii=True).encode())>MAX_RESULT:raise ValueError('Workflow step result exceeds 2 MiB')
                    results.append({'index':entry['index'],'capability':step.capability,'status':'completed','result':result})
                    state.database.update('workflow_run',run['id'],{'steps':results})
                except asyncio.CancelledError:raise
                except Exception as exc:
                    results.append({'index':entry['index'],'capability':step.capability,'status':'failed','error':str(exc)[:1000]})
                    status='failed';break
    except asyncio.CancelledError:status='cancelled';raise
    except Exception as exc:
        status='failed';results.append({'status':'failed','error':str(exc)[:1000]})
    finally:
        state.database.update('workflow_preview',preview_id,{'status':status})
        state.database.update('workflow_run',run['id'],{'status':status,'steps':results})
        state.database.audit('workflow.finished',{'id':run['id'],'preview_id':preview_id,'status':status,'steps_completed':sum(r.get('status')=='completed' for r in results)})
    return state.database.get('workflow_run',run['id'])
