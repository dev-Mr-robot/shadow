"""Expert investigation, teaching and source-aware local research commands."""
import asyncio
import typer
from rich.markdown import Markdown
from rich.text import Text
from .experts import ExpertService,render_case,render_lesson
from .presentation import safe

def register(app,runtime_factory,console):
    @app.command('expert')
    def expert(question:str|None=typer.Argument(None),specialist:str='auto',support:list[str]=typer.Option(None,'--support'),engagement:str|None=None,conversation:str|None=None,offline:bool=False,list_profiles:bool=typer.Option(False,'--list')):
        """Shared-evidence specialist investigations; no tools or autonomous agents execute."""
        with runtime_factory() as state:
            service=ExpertService(state)
            if list_profiles:console.print_json(data=service.catalog());return
            cid=conversation
            async def turn(text):
                nonlocal cid
                result=await service.investigate(text,specialist,support,engagement,cid,offline=offline)
                cid=result['conversation_id'];console.print(Markdown(safe(render_case(result))))
                console.print(Text('Case: '+result['id']+' · Conversation: '+cid))
            if question is not None:asyncio.run(turn(question));return
            console.print('Expert investigation. Messages/cases persist locally. :quit exits; no action executes.',markup=False)
            while True:
                try:text=typer.prompt('expert >',prompt_suffix=' ')
                except (EOFError,KeyboardInterrupt,typer.Abort):break
                if text.strip()==':quit':break
                try:asyncio.run(turn(text))
                except (ValueError,OSError) as exc:console.print(Text(safe(exc),style='red'))

    @app.command('learn')
    def learn(topic:str|None=typer.Argument(None),level:str='beginner',answer:str|None=None,conversation:str|None=None,engagement:str|None=None,offline:bool=False):
        """Local teaching or a clearly labeled offline curated study checklist."""
        with runtime_factory() as state:
            service=ExpertService(state);cid=conversation
            async def turn(text):
                nonlocal cid
                result=await service.teach(text,level,answer,cid,engagement,offline=offline);cid=result['conversation_id']
                console.print(Markdown(safe(render_lesson(result))));console.print(Text('Lesson: '+result['id']+' · Conversation: '+cid))
            if topic is not None:asyncio.run(turn(topic));return
            console.print('Teaching mode. Enter a topic naturally; :quit exits. Offline feedback is not correctness grading.',markup=False)
            while True:
                try:text=typer.prompt('learn >',prompt_suffix=' ')
                except (EOFError,KeyboardInterrupt,typer.Abort):break
                if text.strip()==':quit':break
                try:asyncio.run(turn(text))
                except (ValueError,OSError) as exc:console.print(Text(safe(exc),style='red'))

    # Preserve the existing passive research group rather than creating a second app.
    group=next((info.typer_instance for info in app.registered_groups if info.name=='research'),None)
    if group is None:
        group=typer.Typer(help='Source-aware local cybersecurity research. No hidden external requests.')
        app.add_typer(group,name='research')

    @group.command('topic')
    def topic(question:str,specialist:str='auto',engagement:str|None=None,conversation:str|None=None,offline:bool=False):
        """Research a topic using actual local evidence and imported knowledge versions."""
        with runtime_factory() as state:
            result=asyncio.run(ExpertService(state).research(question,engagement,conversation,specialist,offline=offline))
            console.print(Markdown(safe(render_case(result))));console.print(Text('Case: '+result['id']))

    @group.command('cases')
    def cases(engagement:str|None=None):
        with runtime_factory() as state:
            console.print_json(data=[{k:value for k,value in row.items() if k not in {'analysis','evidence_packet'}} for row in ExpertService(state).cases(engagement)])

    @group.command('sources')
    def sources(case_id:str):
        with runtime_factory() as state:console.print_json(data=ExpertService(state).sources(case_id))

    @group.command('case')
    def case(case_id:str):
        with runtime_factory() as state:console.print(Markdown(safe(render_case(state.database.get('expert_case',case_id)))))
