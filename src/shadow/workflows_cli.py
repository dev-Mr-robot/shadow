"""Direct commands for explicitly reviewed passive workflows."""
import asyncio
from pathlib import Path
import typer
from .workflows import import_workflow,preview_workflow,execute_workflow

def register(app,runtime_factory,console):
    group=typer.Typer(help='Bounded passive workflows. No shell, scanner, model or network execution.')
    app.add_typer(group,name='workflow')

    @group.command('import')
    def import_command(file:Path):
        """Validate/store a JSON definition without reading referenced input files."""
        with runtime_factory() as state:console.print_json(data=import_workflow(state,file))

    @group.command('list')
    def list_command(limit:int=typer.Option(100,min=1,max=1000)):
        with runtime_factory() as state:console.print_json(data=state.database.listing('workflow',limit=limit))

    @group.command('preview')
    def preview_command(workflow_id:str,engagement:str|None=typer.Option(None,'--engagement','-e')):
        """Read bounded inputs and display exact ordered steps, SHA256 hashes and scope."""
        with runtime_factory() as state:console.print_json(data=preview_workflow(state,workflow_id,engagement))

    @group.command('run')
    def run_command(preview_id:str,digest:str=typer.Option(...,'--digest')):
        """Show one saved preview and request concrete confirmation before execution."""
        with runtime_factory() as state:
            preview=state.database.get('workflow_preview',preview_id);console.print_json(data=preview)
            if not typer.confirm('Approve exactly these ordered passive steps and any displayed report writes?',default=False):
                console.print('Not approved. No workflow step executed.');raise typer.Exit(1)
            console.print_json(data=asyncio.run(execute_workflow(state,preview_id,digest,approved=True)))

    @group.command('show')
    def show_command(record_id:str,kind:str=typer.Option('workflow','--kind',help='workflow, workflow_preview or workflow_run')):
        if kind not in {'workflow','workflow_preview','workflow_run'}:raise ValueError('Unsupported workflow record kind')
        with runtime_factory() as state:console.print_json(data=state.database.get(kind,record_id))
