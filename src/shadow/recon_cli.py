"""Reconnaissance Typer commands; approval is distinct from preview creation."""
import asyncio
from pathlib import Path
import typer
from rich.table import Table
from rich.text import Text
from . import recon
from .presentation import safe

def _eid(state,value):
    selected=value or getattr(state.settings,'active_engagement',None)
    if not selected:raise ValueError('Select an engagement with --engagement or engagement use first')
    state.database.engagement(selected);return selected

def register(app,runtime_factory,console):
    group=typer.Typer(help='Streaming scoped asset imports, approved root HTTP probes and persistent observations.')
    app.add_typer(group,name='recon')

    @group.command('import')
    def import_command(file:Path,engagement:str|None=typer.Option(None,'--engagement','-e')):
        """Normalize/deduplicate a line-oriented list without contacting targets."""
        with runtime_factory() as state:console.print_json(data=recon.import_assets(state.database,_eid(state,engagement),file))

    @group.command('show')
    def show(engagement:str|None=typer.Option(None,'--engagement','-e'),search:str='',state_filter:str=typer.Option('','--state'),sort:str='host',limit:int=typer.Option(100,min=1,max=1000),offset:int=typer.Option(0,min=0),as_json:bool=typer.Option(False,'--json')):
        """Search/filter current inventory; priority is evidence-based unverified interest."""
        with runtime_factory() as state:
            rows=recon.list_assets(state.database,_eid(state,engagement),search,state_filter,limit,offset,sort)
            if as_json:console.print_json(data=rows);return
            table=Table('Host','State','Addresses','HTTP','Review leads')
            for row in rows:table.add_row(Text(safe(row['host'])),row['state'],', '.join(row['addresses']),', '.join(str(h['status']) for h in row['http']),str(len(row['interesting'])))
            console.print(table)

    @group.command('stats')
    def statistics(engagement:str|None=typer.Option(None,'--engagement','-e')):
        with runtime_factory() as state:console.print_json(data=recon.stats(state.database,_eid(state,engagement)))

    @group.command('analyze')
    def analyze(engagement:str|None=typer.Option(None,'--engagement','-e'),concurrency:int=typer.Option(8,min=1,max=32),timeout:int=typer.Option(8,min=1,max=30),retries:int=typer.Option(0,min=0,max=2),rate:float=typer.Option(4,min=.1,max=20),resume:bool=typer.Option(True,'--resume/--no-resume')):
        """Create a scoped network plan. This command never starts the probe."""
        with runtime_factory() as state:
            plan=recon.preview(state.database,_eid(state,engagement),concurrency,timeout,retries,rate,resume)
            console.print_json(data=plan)
            console.print(Text(f"No network activity started. Review the plan, then: shadow recon approve {plan['id']} --digest {plan['digest']}"))

    @group.command('approve')
    def approve(run_id:str,digest:str=typer.Option(...,'--digest'),yes:bool=typer.Option(False,'--yes',help='Explicitly approve this exact persisted run/digest without another interactive prompt.')):
        """Approve and execute one unexpired, unchanged recon preview."""
        with runtime_factory() as state:
            plan=recon.get_run(state.database,run_id);console.print_json(data=plan)
            if not yes and not typer.confirm('Approve these DNS/HTTP operations within the displayed scope?',default=False):
                console.print('Not approved. No network operations started.');raise typer.Exit(1)
            def progress(done,total,host):console.print(Text(f'[{done}/{total}] {safe(host)}'))
            result=asyncio.run(recon.execute(state.database,run_id,digest,progress));console.print_json(data=result)

    @group.command('runs')
    def run_list(engagement:str|None=typer.Option(None,'--engagement','-e'),limit:int=typer.Option(50,min=1,max=500)):
        with runtime_factory() as state:console.print_json(data=recon.runs(state.database,_eid(state,engagement),limit))

    @group.command('cancel')
    def cancel(run_id:str):
        """Cancel an unstarted preview. Ctrl+C cancels an active CLI probe."""
        with runtime_factory() as state:console.print_json(data=recon.cancel_preview(state.database,run_id))

    @group.command('compare')
    def compare(first_run:str,second_run:str,limit:int=typer.Option(1000,min=1,max=10000)):
        with runtime_factory() as state:console.print_json(data=recon.compare(state.database,first_run,second_run,limit))

    @group.command('export')
    def export(output:Path,engagement:str|None=typer.Option(None,'--engagement','-e'),format:str=typer.Option('json','--format')):
        """Stream inventory to a new JSON/CSV/TXT file; never overwrite existing data."""
        if format not in {'json','csv','txt'}:raise ValueError('Use json, csv or txt')
        if output.is_symlink():raise ValueError('Refusing symlink output')
        with runtime_factory() as state:
            eid=_eid(state,engagement)
            with output.expanduser().open('x',encoding='utf-8',newline='') as file:
                for chunk in recon.export_assets(state.database,eid,format):file.write(chunk)
            state.database.audit('recon.exported',{'engagement_id':eid,'format':format,'file_name':output.name})
            console.print(Text('Exported '+str(output)))
