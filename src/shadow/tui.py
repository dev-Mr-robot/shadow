"""Working Phase 1 terminal shell. Future research modules are explicitly planned."""
import json
from textual import work
from textual.app import App,ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll,Horizontal
from textual.widgets import Header,Footer,Static,TabbedContent,TabPane,DataTable,Button,Select,Input,Label
from rich.text import Text
from .diagnostics import collect
from .presentation import LOGO,startup,roadmap_table,safe
from .config import save,Settings
from .workspace_ui import WorkspaceMixin
from .soc_ui import SocMixin
from .expert_ui import ExpertMixin

class ShadowApp(ExpertMixin,SocMixin,WorkspaceMixin,App):
    TITLE='SHADOW · Personal Security Intelligence'
    SUB_TITLE='Local AI research workstation'
    BINDINGS=[('q','quit','Quit'),('r','refresh','Refresh'),Binding('f1','tab("overview")','Overview',priority=True),Binding('f2','tab("inventory")','Inventory',priority=True),Binding('f3','tab("models")','Models',priority=True),Binding('f4','tab("engagements")','Scope',priority=True),Binding('f5','tab("roadmap")','Roadmap',priority=True)]
    CSS='''
    Screen { background: #101216; color: #d6dce6; }
    Header { background: #22202a; color: #e19aa4; }
    Footer { background: #171b23; }
    TabbedContent { height: 1fr; }
    TabPane { padding: 1 2; }
    #logo { color: #c86576; text-align: center; height: auto; margin-bottom: 1; }
    .intro { color: #8c9caf; margin-bottom: 1; height: auto; }
    #overview-status { height: auto; margin-bottom: 1; }
    #message { color: #8ebba8; height: auto; min-height: 1; margin: 0 2; }
    DataTable { height: 1fr; min-height: 8; background: #161b23; margin-bottom: 1; }
    Button { background: #66333e; border: tall #66333e; margin-right: 2; }
    Select, Input { margin: 1 0; }
    .controls { height: auto; }
    #roadmap-view { height: auto; }
    #chat-transcript { height: 1fr; min-height: 8; border: solid #303b4b; padding: 0 1; }
    #chat-transcript Markdown { height: auto; margin-bottom: 1; }
    #action-panel { height: 5; border: solid #54333e; }
    #action-preview { height: auto; }
    #active-engagement, #conversation-select { width: 1fr; }
    #research-mode { height: 3; margin: 0; }
    #chat-input { margin: 0; }
    #http-raw { height: 12; }
    #engagement-scope { height: 5; }
    #findings-table { height: 12; }
    #recon-detail { height: 8; }
    #http-result, #knowledge-result, #workspace-result, #tool-result { height: 1fr; min-height: 8; }
    #workspace-result { height: 12; }
    .controls Input { width: 1fr; }
    .controls Button { min-width: 10; }
    '''

    def __init__(self,runtime,**kwargs):super().__init__(**kwargs);self.runtime=runtime;self.snapshot=None

    def compose(self)->ComposeResult:
        yield Header()
        with TabbedContent(initial='assistant',id='tabs'):
            yield from self.workspace_panels()
            yield from self.soc_panels()
            yield from self.expert_panels()
            with TabPane('1 Overview',id='overview'):
                with VerticalScroll():
                    yield Static(Text(LOGO),id='logo')
                    yield Static('LOCAL SECURITY INTELLIGENCE · Evidence before assumptions · Network actions require approval',classes='intro')
                    yield Static('Collecting real system status…',id='overview-status')
                    yield Button('Refresh system status',id='refresh')
            with TabPane('2 Inventory',id='inventory'):
                yield Static('Executable availability only. No security tool is executed or installed.',classes='intro')
                yield DataTable(id='tools-table',cursor_type='row')
            with TabPane('3 Models / settings',id='models'):
                yield Static('Installed local models. Selecting a model saves its name only; it does not load or run it.',classes='intro')
                yield DataTable(id='models-table',cursor_type='row')
                yield Select([],prompt='Select an installed local model',id='model-select')
                yield Label('Context length (2048–32768 tokens; default 4096)')
                yield Input(value=str(self.runtime.settings.context_length),type='integer',id='context')
                with Horizontal(classes='controls'):
                    yield Button('Save model settings',id='save-settings')
                    yield Button('Refresh model list',id='refresh-models')
            with TabPane('4 Authorizations',id='engagements'):
                yield Static('Read-only scope inventory. Create explicit records with: shadow engagement create --help',classes='intro')
                yield DataTable(id='engagement-table',cursor_type='row')
            with TabPane('5 Roadmap',id='roadmap'):
                with VerticalScroll():yield Static(roadmap_table(),id='roadmap-view')
        yield Static('Initializing local database and diagnostics…',id='message')
        yield Footer()

    def on_mount(self):
        self.query_one('#tools-table',DataTable).add_columns('Tool','Available','Executable','Install manually')
        self.query_one('#models-table',DataTable).add_columns('Model','File size GiB','Parameters','Quantization')
        self.query_one('#engagement-table',DataTable).add_columns('ID','Program','Authorized scope','Exclusions')
        self.mount_workspaces()
        self.mount_soc()
        self.refresh_status()

    @work(exclusive=True,group='diagnostics')
    async def refresh_status(self):
        self.query_one('#message',Static).update('Checking hardware and local Ollama…')
        try:
            self.snapshot=await collect(self.runtime.settings,self.runtime.database)
            self.query_one('#ai-status',Static).update(Text(f"Ollama {'online' if self.snapshot['ollama']['available'] else 'offline'} · Model: {self.runtime.settings.model or 'select in Models/settings'} · SQLite {self.runtime.database.revision()} · {self.snapshot['hardware']['distribution']}"))
            self.query_one('#overview-status',Static).update(startup(self.snapshot))
            table=self.query_one('#tools-table',DataTable);table.clear()
            for tool in self.snapshot['tools']:table.add_row(tool['name'],'yes' if tool['detected'] else 'no',Text(safe(tool['path'] or 'not detected')),Text(tool['installation']))
            table=self.query_one('#models-table',DataTable);table.clear()
            options=[]
            for model in self.snapshot['ollama']['models']:
                table.add_row(Text(safe(model['name'])),str(round(model['size']/1024**3,2)) if model['size'] else 'unknown',Text(safe(model['parameters'])),Text(safe(model['quantization'])))
                options.append((safe(model['name']),model['name']))
            selector=self.query_one('#model-select',Select);selector.set_options(options)
            if self.runtime.settings.model in [o[1] for o in options]:selector.value=self.runtime.settings.model
            table=self.query_one('#engagement-table',DataTable);table.clear()
            for row in self.runtime.database.engagements():table.add_row(row['id'],Text(safe(row['name'])),', '.join(row['scope']),', '.join(row['exclusions']))
            message='Status refreshed. Use AI Research for natural-language investigation; active operations require approval.'
            if not self.snapshot['ollama']['available']:message=self.snapshot['ollama']['error']
            self.query_one('#message',Static).update(Text(message))
        except Exception as exc:self.query_one('#message',Static).update(Text('Diagnostics failed: '+safe(exc)))

    def on_button_pressed(self,event:Button.Pressed):
        if self.handle_soc_button(event):return
        if self.handle_workflow_button(event):return
        if event.button.id in {'refresh','refresh-models'}:self.refresh_status()
        elif event.button.id=='save-settings':
            try:
                selected=self.query_one('#model-select',Select).value
                if selected is Select.BLANK:raise ValueError('Select an installed local model first')
                candidate=Settings.model_validate({**self.runtime.settings.model_dump(),'model':selected,'context_length':int(self.query_one('#context',Input).value)})
                save(self.runtime.paths,candidate);self.runtime.settings=candidate
                self.runtime.database.audit('settings.updated',{'model':candidate.model,'context_length':candidate.context_length})
                self.query_one('#message',Static).update('Settings saved locally; no model was loaded.')
            except (ValueError,TypeError) as exc:self.query_one('#message',Static).update(Text('Settings error: '+safe(exc)))

    def action_refresh(self):self.refresh_status()
    def action_tab(self,name):
        # Clear focus in the old pane before hiding it. Focus-driven pane reveal can
        # otherwise restore the old tab when navigating out of an Input widget.
        self.set_focus(None)
        self.query_one('#tabs',TabbedContent).active=name
