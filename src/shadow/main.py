"""Typer command surface. Running `shadow` starts the terminal foundation shell."""
import asyncio
import json
import sys
from contextlib import contextmanager
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text
from sqlalchemy.exc import SQLAlchemyError
from . import __version__
from .runtime import Runtime
from .config import Settings,save
from .diagnostics import collect,inventory
from .presentation import LOGO,startup,roadmap_table,safe
from .providers import OllamaProvider
from .scope import EngagementInput,check

app=typer.Typer(help='SHADOW — local AI security research workstation for the terminal.',no_args_is_help=False)
settings_app=typer.Typer(help='Inspect and update local model configuration.')
engagement_app=typer.Typer(help='Record explicit authorization and check scope. No network operations.')
app.add_typer(settings_app,name='settings');app.add_typer(engagement_app,name='engagement')
app.add_typer(engagement_app,name='bounty')
console=Console()

@contextmanager
def runtime():
    state=Runtime()
    try:yield state
    finally:state.close()

@app.callback(invoke_without_command=True)
def root(ctx:typer.Context,version:bool=typer.Option(False,'--version',help='Print version and exit.')):
    if version:console.print(__version__);raise typer.Exit()
    if ctx.invoked_subcommand is None:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            console.print('Interactive terminal required. Use shadow doctor --json or shadow --help for scripting.',markup=False)
            raise typer.Exit(2)
        from .tui import ShadowApp
        with runtime() as state:
            from .setup import first_run
            first_run(state,console,lambda question:typer.confirm(question,default=False),typer.prompt)
            ShadowApp(state).run()

@app.command()
def init():
    """Create private data/config directories and apply packaged database migrations."""
    with runtime() as state:
        state.database.audit('foundation.initialized',{'version':__version__})
        console.print(Text(f'Initialized SHADOW {__version__}\nDatabase: {state.paths.database}\nRevision: {state.database.revision()}\nConfiguration: {state.paths.settings}'))

@app.command()
def upgrade():
    """Apply forward-only schema migrations; no dependency or system changes."""
    with runtime() as state:
        state.database.audit('database.migrated',{'revision':state.database.revision()})
        console.print('Database at '+state.database.revision(),markup=False)

@app.command()
def doctor(repair_installation:bool=typer.Option(False,'--repair'),as_json:bool=typer.Option(False,'--json',help='Emit machine-readable JSON.'),output:Path|None=typer.Option(None,'--output',help='Write JSON to a new file; existing files are never overwritten.')):
    """Inspect CPU/RAM/GPU, local Ollama, SQLite and tool availability. No scans."""
    from .setup import diagnose,repair
    from .config import Paths
    installation=repair(Paths(),console,lambda question:typer.confirm(question,default=False))['diagnosis'] if repair_installation else diagnose()
    if not installation['ready']:
        console.print_json(data=installation)
        raise typer.Exit(1)
    with runtime() as state:
        result=asyncio.run(collect(state.settings,state.database))
        result['installation']=installation
        result['version']=__version__;result['phase']='integrated'
        encoded=json.dumps(result,indent=2,ensure_ascii=True)
        if output:
            if output.is_symlink():raise ValueError('Refusing symlink output file')
            with output.expanduser().open('x',encoding='utf-8') as f:f.write(encoded+'\n')
        if as_json:console.print(encoded,markup=False,highlight=False,soft_wrap=True)
        else:
            console.print(Text(LOGO,style='#c86576'));console.print(startup(result))
            console.print(Text(result['recommendations']['suggestion']))
            console.print(Text('Conservative installed candidates: '+(', '.join(result['recommendations']['installed_candidates']) or 'none fit the current memory heuristic')))
        state.database.audit('diagnostics.completed',{'ollama_available':result['ollama']['available'],'tools_detected':sum(t['detected'] for t in result['tools'])})


@app.command('setup')
def setup_command(repair_installation:bool=typer.Option(False,'--repair'),tools:bool=False):
    """Review first-run setup, repair configuration, and optional system integrations."""
    from .setup import first_run,repair,install_tools
    from .config import Paths
    confirm=lambda question:typer.confirm(question,default=False)
    if repair_installation:
        result=repair(Paths(),console,confirm)
        console.print_json(data=result)
        if not result['diagnosis']['ready']:raise typer.Exit(1)
    if tools:install_tools(console,confirm)
    with runtime() as state:first_run(state,console,confirm,typer.prompt,force=True)

@app.command()
def models(as_json:bool=typer.Option(False,'--json')):
    """List installed local Ollama models without loading one."""
    with runtime() as state:
        result=asyncio.run(OllamaProvider(state.settings).status())
        if as_json:console.print_json(data=result)
        else:
            if not result['available']:console.print(result['error'],markup=False);raise typer.Exit(1)
            table=Table('Model','Size GiB','Parameters','Quantization')
            for row in result['models']:table.add_row(Text(safe(row['name'])),str(round(row['size']/1024**3,2)) if row['size'] else 'unknown',Text(safe(row['parameters'])),Text(safe(row['quantization'])))
            console.print(table)

@app.command()
def tools(as_json:bool=typer.Option(False,'--json')):
    """Detect fourteen security tools. No version commands or tools are executed."""
    rows=inventory()
    if as_json:console.print_json(data=rows);return
    table=Table('Tool','Availability','Install manually')
    for row in rows:table.add_row(row['name'],Text(safe(row['path'] or 'not detected')),row['installation'])
    console.print(table)

@app.command()
def roadmap():
    """Show completed and planned engineering phases."""
    console.print(roadmap_table())

@app.command()
def audit(limit:int=typer.Option(30,min=1,max=500)):
    """Inspect persistent local lifecycle audit events."""
    with runtime() as state:console.print_json(data=state.database.audit_rows(limit))

@settings_app.command('show')
def settings_show():
    with runtime() as state:console.print_json(data=state.settings.model_dump())

@settings_app.command('set')
def settings_set(model:str|None=None,embedding_model:str|None=None,context:int|None=typer.Option(None,min=2048,max=32768),ollama_url:str|None=None):
    """Save local model settings; no model downloads or inference."""
    with runtime() as state:
        values=state.settings.model_dump()
        if model is not None:values['model']=model
        if embedding_model is not None:values['embedding_model']=embedding_model
        if context is not None:values['context_length']=context
        if ollama_url is not None:values['ollama_url']=ollama_url
        settings=Settings.model_validate(values);save(state.paths,settings)
        state.database.audit('settings.updated',{'model':settings.model,'context_length':settings.context_length})
        console.print('Settings saved. No model was loaded or downloaded.',markup=False)

@engagement_app.command('create')
def engagement_create(name:str=typer.Option(...,prompt='Program / engagement name'),scope:list[str]=typer.Option(...,'--scope',help='Repeat for each exact hostname, IP or CIDR.'),authorization:str=typer.Option(...,prompt='Authorization basis / notes'),exclude:list[str]=typer.Option(None,'--exclude'),rules:str=typer.Option('','--rules')):
    """Record scope and the operator's authorization attestation."""
    body=EngagementInput(name=name,scope=scope,exclusions=exclude or [],authorization=authorization,rules=rules)
    with runtime() as state:console.print_json(data=state.database.create_engagement(body))

@engagement_app.command('list')
def engagement_list():
    with runtime() as state:console.print_json(data=state.database.engagements())

@engagement_app.command('show')
def engagement_show(engagement_id:str):
    with runtime() as state:console.print_json(data=state.database.engagement(engagement_id))

@engagement_app.command('check')
def engagement_check(engagement_id:str,target:str):
    """Check one asset against recorded scope/exclusions without touching the target."""
    with runtime() as state:
        result=check(target,state.database.engagement(engagement_id));state.database.audit('scope.checked',result);console.print_json(data=result)
        if not result['in_scope']:raise typer.Exit(3)

@engagement_app.command('use')
def engagement_use(engagement_id:str):
    """Select the active workspace for chat, imports and reports."""
    with runtime() as state:
        row=state.database.engagement(engagement_id);state.settings.active_engagement=engagement_id;save(state.paths,state.settings)
        state.database.audit('engagement.selected',{'id':engagement_id});console.print(Text('Active engagement: '+row['name']))

@engagement_app.command('update')
def engagement_update(engagement_id:str,file:Path):
    """Replace authorization/scope fields from a validated JSON file."""
    if not file.is_file() or file.stat().st_size>8*1024*1024:raise ValueError('Select a JSON file no larger than 8 MiB')
    body=EngagementInput.model_validate_json(file.read_text(encoding='utf-8'))
    with runtime() as state:console.print_json(data=state.database.update_engagement(engagement_id,body))

@engagement_app.command('note')
def engagement_note(content:str,engagement:str|None=None):
    """Save an explicit investigation note in the selected workspace."""
    if not content.strip() or len(content)>100000:raise ValueError('Note must contain 1–100000 characters')
    with runtime() as state:
        eid=engagement or state.settings.active_engagement
        if not eid:raise ValueError('Select an engagement first')
        state.database.engagement(eid);row=state.database.create('note',{'content':content,'engagement_id':eid},eid)
        state.database.audit('note.saved',{'id':row['id'],'engagement_id':eid});console.print_json(data=row)

@engagement_app.command('notes')
def engagement_notes(engagement:str|None=None):
    with runtime() as state:
        eid=engagement or state.settings.active_engagement
        if not eid:raise ValueError('Select an engagement first')
        console.print_json(data=state.database.listing('note',eid))

@app.command('backup')
def database_backup(output:Path):
    """Write a consistent, private SQLite backup to a new destination."""
    from .backup import backup
    with runtime() as state:console.print(Text(str(backup(state,output))))

@app.command('restore')
def database_restore(source:Path):
    """Restore a selected backup, preserving a safety copy of current data."""
    from .backup import restore
    console.print('Stop other SHADOW sessions. A pre-restore backup will be retained.',markup=False)
    if not typer.confirm('Restore this database backup?',default=False):raise typer.Exit(1)
    with runtime() as state:console.print_json(data=restore(state,source,approved=True))

@app.command('analyze')
def analyze(file:Path,kind:str='auto'):
    """Passively inspect HTTP, Python, config, log, binary or classic PCAP evidence."""
    from .research import read_file,analyze_http,static_analyze
    _,data=read_file(file)
    first=data.splitlines()[0].decode('utf-8',errors='replace') if data else ''
    is_http=first.startswith('HTTP/') or bool(__import__('re').fullmatch(r'[A-Z]+ \S+ HTTP/\d(?:\.\d)?',first))
    if kind=='http' or kind=='auto' and is_http:result=analyze_http(data.decode('utf-8-sig',errors='replace'))
    else:result=static_analyze(file,kind)
    console.print_json(data=result)

# Independent feature groups share the same runtime and repositories.
from .recon_cli import register as register_recon
from .intelligence_cli import register as register_intelligence
from .research_cli import register as register_research
from .integrations import register as register_integrations
from .workflows_cli import register as register_workflows
from .soc_cli import register as register_soc
register_recon(app,runtime,console)
register_intelligence(app,runtime,console)
register_research(app,runtime,console)
register_integrations(app,runtime,console)
register_workflows(app,runtime,console)
register_soc(app,runtime,console)
from .experts_cli import register as register_experts
register_experts(app,runtime,console)

def main():
    try:app()
    except (ValueError,OSError) as exc:
        console.print(Text('SHADOW: '+safe(exc),style='red'));raise SystemExit(1)
    except SQLAlchemyError:
        console.print('SHADOW: Local database could not be opened or migrated. Check permissions and stop concurrent upgrades.',style='red')
        raise SystemExit(1)

if __name__=='__main__':main()
