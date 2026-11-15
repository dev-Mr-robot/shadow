"""Integrated terminal research workflows over the shared service layer."""
import asyncio
import json
from pathlib import Path
from textual import work
from textual.worker import get_current_worker
from textual.containers import Horizontal,VerticalScroll
from textual.widgets import TabPane,TabbedContent,Static,Input,Button,Select,DataTable,TextArea,Markdown,RichLog
from rich.text import Text
from .config import save
from .presentation import safe,LOGO

class WorkspaceMixin:
    def workspace_panels(self):
        with TabPane('AI Research',id='assistant'):
            yield Static('Checking local AI and workspace status…',id='ai-status')
            with Horizontal(classes='controls'):
                yield Select([],prompt='Select engagement',id='active-engagement')
                yield Select([],prompt='Resume conversation',id='conversation-select')
                yield Button('New chat',id='new-chat')
            yield Select([(name.replace('_',' ').title(),name) for name in ['assistant','bug_bounty','reconnaissance','web_security','api_security','network_security','host_security','exploitation','reverse_engineering','vulnerability_research','soc']],value='assistant',allow_blank=False,id='research-mode')
            with VerticalScroll(id='chat-transcript'):
                yield Static(Text(LOGO,style='#c86576'))
                yield Static('Talk naturally about your assessment. Messages persist locally; avoid pasting secrets. Model actions are proposals until you approve a concrete preview.',classes='intro')
            yield Input(placeholder='shadow > Ask a question, refer to a previous result, or describe a research task…',id='chat-input')
            with Horizontal(classes='controls'):
                yield Button('Send',id='chat-send')
                yield Button('Stop',id='chat-stop')
                yield Button('Summarize',id='chat-summary')
                yield Button('Review next proposed action',id='action-review',disabled=True)
            with VerticalScroll(id='action-panel'):
                yield Static('No action awaiting approval.',id='action-preview')
            with Horizontal(classes='controls'):
                yield Button('Approve shown action',id='action-approve',disabled=True)
                yield Button('Reject shown action',id='action-reject',disabled=True)
        with TabPane('Recon',id='recon'):
            yield Static('Streaming imports are passive. DNS/HTTP probing requires a reviewed preview and explicit approval. Domain names AND resolved destination IPs must be authorized.',classes='intro')
            with Horizontal(classes='controls'):
                yield Input(placeholder='Subdomain list path',id='recon-file')
                yield Button('Import list',id='recon-import')
            with Horizontal(classes='controls'):
                yield Input(placeholder='Filter assets',id='asset-filter')
                yield Button('Search / refresh',id='recon-refresh')
                yield Button('Previous',id='recon-prev')
                yield Button('Next',id='recon-next')
            yield Static('Select an engagement to inspect saved assets.',id='recon-stats')
            yield DataTable(id='assets-table',cursor_type='row')
            with Horizontal(classes='controls'):
                yield Button('Preview DNS + HTTP probe',id='recon-preview')
                yield Button('Approve shown probe',id='recon-approve',disabled=True)
                yield Button('Cancel active operation',id='operation-stop')
            yield RichLog(id='recon-detail',wrap=True,markup=False,highlight=False)
        with TabPane('HTTP / API',id='http-lab'):
            yield Static('Static inspection only: headers, cookies, parameters, CORS, cache, JSON/XML and decoded JWT claims. Nothing is replayed.',classes='intro')
            yield TextArea(placeholder='Paste a raw HTTP request or response here…',id='http-raw',soft_wrap=True)
            with Horizontal(classes='controls'):
                yield Button('Inspect pasted HTTP',id='http-inspect')
                yield Input(placeholder='Raw HTTP or Burp XML file path',id='http-file')
                yield Button('Import evidence file',id='http-import')
            yield RichLog(id='http-result',wrap=True,markup=False,highlight=False)
        with TabPane('Engagements / reports',id='research-workspace'):
            with VerticalScroll():
                yield Static('Create an authorized workspace; record evidence-backed findings through the CLI or an explicit JSON finding file.',classes='intro')
                yield Input(placeholder='Engagement / program name',id='engagement-name')
                yield TextArea(placeholder='Authorized scope: exact hostnames, IPs or CIDRs, one per line',id='engagement-scope')
                yield Input(placeholder='Exclusions, comma separated',id='engagement-exclusions')
                yield Input(placeholder='Written authorization basis (required)',id='engagement-authorization')
                yield Input(placeholder='Program rules / constraints',id='engagement-rules')
                yield Button('Create and select engagement',id='engagement-create')
                yield Input(placeholder='Investigation note',id='note-content')
                yield Button('Save note to active engagement',id='note-save')
                yield Input(placeholder='Finding JSON file path',id='finding-file')
                yield Button('Import validated finding',id='finding-import')
                yield DataTable(id='findings-table',cursor_type='row')
                with Horizontal(classes='controls'):
                    yield Select([('Markdown','md'),('HTML','html'),('PDF','pdf')],value='md',allow_blank=False,id='report-format')
                    yield Input(placeholder='New report output path (optional; otherwise saved in SQLite)',id='report-path')
                    yield Button('Generate report',id='report-generate')
                yield RichLog(id='workspace-result',wrap=True,markup=False,highlight=False)
        with TabPane('Knowledge / memory',id='knowledge'):
            with Horizontal(classes='controls'):
                yield Input(placeholder='Research document path (PDF/DOCX/MD/TXT/HTML/JSON/CSV)',id='kb-file')
                yield Button('Import document',id='kb-import')
            with Horizontal(classes='controls'):
                yield Input(placeholder='Search local research',id='kb-query')
                yield Button('Search knowledge',id='kb-search')
            yield DataTable(id='kb-table',cursor_type='row')
            with Horizontal(classes='controls'):
                yield Input(placeholder='Explicit memory to save in the active engagement',id='memory-content')
                yield Button('Save explicit memory',id='memory-save')
                yield Button('List memories',id='memory-list')
            yield RichLog(id='knowledge-result',wrap=True,markup=False,highlight=False)
        with TabPane('Tool execution',id='tool-execution'):
            yield Static('Nmap fixed TCP connect recipe only. No scripts, arbitrary flags, model-generated shell or unsandboxed fallback. Other tool outputs can be imported with shadow tool import.',classes='intro')
            with Horizontal(classes='controls'):
                yield Input(placeholder='One authorized literal target IP',id='tool-target')
                yield Input(value='22,80,443',placeholder='Ports',id='tool-ports')
                yield Button('Preview command',id='tool-preview')
            yield RichLog(id='tool-result',wrap=True,markup=False,highlight=False)
            with Horizontal(classes='controls'):
                yield Button('Approve shown command',id='tool-approve',disabled=True)
                yield Button('Cancel active operation',id='tool-stop')

    def mount_workspaces(self):
        self.cid=None;self.proposed_actions=[];self.pending_action=None;self.pending_recon=None;self.pending_job=None;self.asset_offset=0;self.operation_worker=None;self.chat_worker=None
        self.query_one('#assets-table',DataTable).add_columns('Asset','State','Addresses','HTTP','Review reasons')
        self.query_one('#findings-table',DataTable).add_columns('ID','Finding','Asset','Severity','Verification')
        self.query_one('#kb-table',DataTable).add_columns('Document','ID','Retrieval')
        self.refresh_engagement_options();self.refresh_knowledge()

    def selected_engagement(self,required=True):
        eid=self.runtime.settings.active_engagement
        if required and not eid:raise ValueError('Select or create an authorized engagement first')
        if eid:self.runtime.database.engagement(eid)
        return eid

    def ui_message(self,value):self.query_one('#message',Static).update(Text(safe(value)))
    def ui_json(self,selector,value):
        log=self.query_one(selector,RichLog);log.clear();log.write(Text(safe(json.dumps(value,indent=2,ensure_ascii=False,default=str))))

    def refresh_engagement_options(self):
        rows=self.runtime.database.engagements();select=self.query_one('#active-engagement',Select)
        select.set_options([(safe(r['name']),r['id']) for r in rows])
        if self.runtime.settings.active_engagement in [r['id'] for r in rows]:select.value=self.runtime.settings.active_engagement
        self.refresh_conversations()

    def refresh_conversations(self):
        from .intelligence import ConversationService
        rows=ConversationService(self.runtime).conversations(self.runtime.settings.active_engagement)
        self.query_one('#conversation-select',Select).set_options([(safe(c.get('title','Conversation')),c['id']) for c in rows])

    def refresh_assets(self):
        from . import recon
        eid=self.selected_engagement();query=self.query_one('#asset-filter',Input).value
        rows=recon.list_assets(self.runtime.database,eid,search=query,limit=100,offset=self.asset_offset,sort='priority')
        table=self.query_one('#assets-table',DataTable);table.clear()
        for row in rows:
            codes=','.join(str(r.get('status','')) for r in row.get('http',[]))
            table.add_row(Text(safe(row['host'])),row['state'],Text(', '.join(row.get('addresses',[]))),codes,str(len(row.get('interesting',[]))),key=row['host'])
        self.query_one('#recon-stats',Static).update(Text(f"Offset {self.asset_offset} · "+json.dumps(recon.stats(self.runtime.database,eid))))

    def refresh_findings(self):
        eid=self.selected_engagement(False);table=self.query_one('#findings-table',DataTable);table.clear()
        if eid:
            for f in self.runtime.database.listing('finding',eid,limit=100):table.add_row(f['id'],Text(safe(f['name'])),Text(safe(f['asset'])),f['severity'],f['verification'])

    def refresh_knowledge(self):
        from .knowledge import KnowledgeService
        table=self.query_one('#kb-table',DataTable);table.clear()
        for doc in KnowledgeService(self.runtime).list():table.add_row(Text(safe(doc['name'])),doc['id'],'semantic' if doc.get('embedding_model') else 'lexical')

    def handle_workflow_button(self,event):
        name=event.button.id
        actions={'chat-send':self.send_chat,'new-chat':self.new_chat,'chat-summary':self.summarize_chat,'action-review':self.review_action,'action-approve':self.approve_action,
                 'recon-import':lambda:self.workspace_task('recon-import'),'recon-refresh':lambda:self.workspace_task('recon-refresh'),'recon-next':lambda:self.workspace_task('recon-next'),'recon-prev':lambda:self.workspace_task('recon-prev'),
                 'recon-preview':lambda:self.workspace_task('recon-preview'),'recon-approve':lambda:self.workspace_task('recon-approve'),'http-inspect':lambda:self.workspace_task('http-inspect'),'http-import':lambda:self.workspace_task('http-import'),
                 'engagement-create':lambda:self.workspace_task('engagement-create'),'note-save':lambda:self.workspace_task('note-save'),'finding-import':lambda:self.workspace_task('finding-import'),
                 'report-generate':lambda:self.workspace_task('report-generate'),'kb-import':lambda:self.workspace_task('kb-import'),'kb-search':lambda:self.workspace_task('kb-search'),
                 'memory-save':lambda:self.workspace_task('memory-save'),'memory-list':lambda:self.workspace_task('memory-list'),'tool-preview':lambda:self.workspace_task('tool-preview'),'tool-approve':lambda:self.workspace_task('tool-approve')}
        if name in actions:actions[name]();return True
        if name=='chat-stop':
            if self.chat_worker:self.chat_worker.cancel()
            return True
        if name in {'operation-stop','tool-stop'}:
            if self.operation_worker:self.operation_worker.cancel()
            return True
        if name=='action-reject':
            if self.pending_action:self.runtime.database.claim('action_preview',self.pending_action['id'],'pending','cancelled')
            self.pending_action=None;self.query_one('#action-preview',Static).update('Action rejected. Nothing executed.');self.set_approval_buttons(False);return True
        return False

    def set_approval_buttons(self,enabled):
        self.query_one('#action-approve',Button).disabled=not enabled;self.query_one('#action-reject',Button).disabled=not enabled

    async def append_chat(self,label,content):
        pane=self.query_one('#chat-transcript',VerticalScroll)
        await pane.mount(Static(Text(label,style='#91a7c5')),Markdown(content,open_links=False))
        pane.scroll_end(animate=False)

    def new_chat(self):
        if self.chat_worker and self.chat_worker.is_running:self.ui_message('Stop the current turn before starting a new chat');return
        if self.operation_worker and self.operation_worker.is_running:self.ui_message('Stop the active operation before changing conversation');return
        self.cid=None;self.proposed_actions=[];self.pending_action=None;self.query_one('#chat-transcript',VerticalScroll).remove_children();self.set_approval_buttons(False)
        self.query_one('#action-review',Button).disabled=True;self.ui_message('New conversation ready')

    def send_chat(self):self.chat_worker=self.chat_turn()

    @work(exclusive=True,group='chat-turn')
    async def chat_turn(self):
        from .intelligence import ConversationService
        prompt=self.query_one('#chat-input',Input).value.strip()
        if not prompt:return
        self.query_one('#chat-input',Input).value='';self.query_one('#chat-send',Button).disabled=True
        self.proposed_actions=[];self.pending_action=None;self.set_approval_buttons(False);self.query_one('#action-review',Button).disabled=True
        service=ConversationService(self.runtime)
        try:
            if not self.cid:
                mode=self.query_one('#research-mode',Select).value
                self.cid=service.new(mode,self.selected_engagement(False),prompt[:100])['id']
                self.refresh_conversations()
            await self.append_chat('YOU',prompt);self.ui_message('Understanding your objective with the local model…')
            plan=await service.plan(self.cid,prompt)
            if plan.clarification:
                service.record_clarification(self.cid,prompt,plan.clarification);await self.append_chat('SHADOW · clarification',plan.clarification);return
            self.ui_message('Streaming local model response…')
            pane=self.query_one('#chat-transcript',VerticalScroll);reply=Markdown('',open_links=False);await pane.mount(Static('SHADOW'),reply)
            text=''
            async for chunk in service.stream(self.cid,prompt,plan):
                text+=safe(chunk);await reply.update(text);pane.scroll_end(animate=False)
            self.proposed_actions=list(plan.actions);self.query_one('#action-review',Button).disabled=not bool(self.proposed_actions)
            self.ui_message(f'Response saved. {len(self.proposed_actions)} proposed actions require separate review.' if self.proposed_actions else 'Response saved locally.')
        except asyncio.CancelledError:self.ui_message('Turn stopped; any partial response is saved.');raise
        except Exception as exc:self.ui_message('Local research request failed: '+safe(exc));await self.append_chat('APPLICATION ERROR',safe(exc))
        finally:self.query_one('#chat-send',Button).disabled=False

    @work(exclusive=True,group='chat-summary')
    async def summarize_chat(self):
        try:
            if not self.cid:raise ValueError('Start or resume a conversation first')
            from .intelligence import ConversationService
            summary=await ConversationService(self.runtime).summarize(self.cid);await self.append_chat('SAVED SUMMARY',summary)
        except Exception as exc:self.ui_message(safe(exc))

    @work(exclusive=True,group='action-review')
    async def review_action(self):
        try:
            if self.pending_action:raise ValueError('Approve or reject the shown action before reviewing another')
            if not self.proposed_actions:raise ValueError('No actions remain to review')
            from .actions import ActionRunner
            self.pending_action=await ActionRunner(self.runtime).preview(self.proposed_actions.pop(0),self.selected_engagement(False))
            self.query_one('#action-preview',Static).update(Text(safe(json.dumps(self.pending_action,indent=2,default=str))))
            self.set_approval_buttons(True)
        except Exception as exc:self.ui_message(safe(exc))

    def approve_action(self):self.operation_worker=self.run_approved_action()

    @work(exclusive=True,group='approved-operation')
    async def run_approved_action(self):
        cid=self.cid
        try:
            if not self.pending_action:raise ValueError('Review a proposal first')
            from .actions import ActionRunner
            from .intelligence import ConversationService
            selected=self.pending_action;self.pending_action=None;self.set_approval_buttons(False)
            self.ui_message('Executing the explicitly approved application action…')
            result=await ActionRunner(self.runtime).execute(selected['id'],approved=True,on_progress=lambda *values:self.ui_message('Approved operation progress: '+str(values[:2])))
            service=ConversationService(self.runtime)
            if cid:service.record_result(cid,result)
            self.query_one('#action-preview',Static).update(Text(safe(json.dumps(result,indent=2,default=str))))
            if cid:
                pane=self.query_one('#chat-transcript',VerticalScroll);reply=Markdown('',open_links=False);await pane.mount(Static('SHADOW · approved result analysis'),reply);text=''
                async for chunk in service.stream(cid,'Explain the most recent approved application result. Distinguish observations, hypotheses and next steps. No new action has been approved.'):
                    text+=safe(chunk);await reply.update(text)
            self.ui_message('Approved action complete; result saved.')
        except asyncio.CancelledError:self.ui_message('Approved operation cancelled; completed checkpoints remain.');raise
        except Exception as exc:self.ui_message('Approved operation failed: '+safe(exc))

    def on_input_submitted(self,event:Input.Submitted):
        if event.input.id=='chat-input':self.send_chat()

    def on_select_changed(self,event:Select.Changed):
        if not hasattr(self,'cid'):return
        if event.select.id=='soc-section':
            if self.query_one('#tabs',TabbedContent).active=='soc-center':self.soc_task('soc-refresh')
            return
        if event.select.id=='active-engagement':
            if self.chat_worker and self.chat_worker.is_running or self.operation_worker and self.operation_worker.is_running:
                event.select.value=self.runtime.settings.active_engagement or Select.BLANK
                self.ui_message('Stop the current turn/operation before switching engagement');return
            eid=None if event.value is Select.BLANK else event.value
            if eid==self.runtime.settings.active_engagement:return
            self.runtime.settings.active_engagement=eid;save(self.runtime.paths,self.runtime.settings);self.new_chat();self.refresh_conversations()
            try:self.refresh_assets();self.refresh_findings()
            except ValueError:pass
        elif event.select.id=='conversation-select' and event.value is not Select.BLANK:self.load_conversation(event.value)

    @work(exclusive=True,group='load-conversation')
    async def load_conversation(self,cid):
        if self.chat_worker and self.chat_worker.is_running or self.operation_worker and self.operation_worker.is_running:return
        from .intelligence import ConversationService
        try:
            record=self.runtime.database.get('conversation',cid)
            if record.get('engagement_id')!=self.selected_engagement(False):raise ValueError('Select the conversation’s engagement first')
            self.cid=cid;pane=self.query_one('#chat-transcript',VerticalScroll);await pane.remove_children()
            for message in ConversationService(self.runtime).history(cid):await self.append_chat(message['role'].upper()+' · '+message.get('status',''),message['content'])
        except Exception as exc:self.ui_message(safe(exc))

    @work(exclusive=True,group='workspace-operation')
    async def workspace_task(self,operation):
        self.operation_worker=get_current_worker()
        try:
            db=self.runtime.database
            if operation.startswith('recon-'):
                from . import recon
                eid=self.selected_engagement()
                if operation=='recon-import':
                    result=await asyncio.to_thread(recon.import_assets,db,eid,Path(self.query_one('#recon-file',Input).value));self.ui_json('#recon-detail',result)
                elif operation=='recon-next':self.asset_offset+=100
                elif operation=='recon-prev':self.asset_offset=max(0,self.asset_offset-100)
                elif operation=='recon-preview':
                    self.pending_recon=recon.preview(db,eid);self.ui_json('#recon-detail',self.pending_recon);self.query_one('#recon-approve',Button).disabled=False
                elif operation=='recon-approve':
                    if not self.pending_recon:raise ValueError('Preview a scoped probe first')
                    plan=self.pending_recon;self.pending_recon=None;self.query_one('#recon-approve',Button).disabled=True
                    result=await recon.execute(db,plan['id'],plan['digest'],on_progress=lambda done,total,host:self.ui_message(f'Recon {done}/{total}: {host}'));self.ui_json('#recon-detail',result)
                self.refresh_assets()
            elif operation=='http-inspect':
                from .research import analyze_http
                self.ui_json('#http-result',analyze_http(self.query_one('#http-raw',TextArea).text))
            elif operation=='http-import':
                from .research import import_evidence
                result=await asyncio.to_thread(import_evidence,db,self.selected_engagement(),Path(self.query_one('#http-file',Input).value),'http');self.ui_json('#http-result',result)
            elif operation=='engagement-create':
                from .scope import EngagementInput
                body=EngagementInput(name=self.query_one('#engagement-name',Input).value,scope=[v.strip() for v in self.query_one('#engagement-scope',TextArea).text.splitlines() if v.strip()],exclusions=[v.strip() for v in self.query_one('#engagement-exclusions',Input).value.split(',') if v.strip()],authorization=self.query_one('#engagement-authorization',Input).value,rules=self.query_one('#engagement-rules',Input).value)
                row=db.create_engagement(body);self.runtime.settings.active_engagement=row['id'];save(self.runtime.paths,self.runtime.settings);self.refresh_engagement_options();self.ui_json('#workspace-result',row)
                table=self.query_one('#engagement-table',DataTable);table.clear()
                for e in db.engagements():table.add_row(e['id'],Text(safe(e['name'])),', '.join(e['scope']),', '.join(e['exclusions']))
            elif operation=='note-save':
                content=self.query_one('#note-content',Input).value
                if not content.strip():raise ValueError('Enter a note first')
                eid=self.selected_engagement();self.ui_json('#workspace-result',db.create('note',{'content':content,'engagement_id':eid},eid))
            elif operation=='finding-import':
                from .research import create_finding,read_file
                _,data=read_file(Path(self.query_one('#finding-file',Input).value));value=json.loads(data);value.setdefault('engagement_id',self.selected_engagement());self.ui_json('#workspace-result',create_finding(db,value));self.refresh_findings()
            elif operation=='report-generate':
                from .reporting import generate_report
                path=self.query_one('#report-path',Input).value.strip();result=await asyncio.to_thread(generate_report,db,self.selected_engagement(),self.query_one('#report-format',Select).value,Path(path) if path else None)
                self.ui_json('#workspace-result',{k:v for k,v in result.items() if k not in {'content','base64','snapshot'}})
            elif operation in {'kb-import','kb-search'}:
                from .knowledge import KnowledgeService
                service=KnowledgeService(self.runtime)
                result=await service.import_file(Path(self.query_one('#kb-file',Input).value)) if operation=='kb-import' else await service.search(self.query_one('#kb-query',Input).value)
                self.ui_json('#knowledge-result',result);self.refresh_knowledge()
            elif operation in {'memory-save','memory-list'}:
                from .intelligence import ConversationService
                service=ConversationService(self.runtime);eid=self.selected_engagement(False)
                result=service.memory_save(self.query_one('#memory-content',Input).value,engagement_id=eid) if operation=='memory-save' else service.memory_list(eid)
                self.ui_json('#knowledge-result',result)
            elif operation.startswith('tool-'):
                from .integrations import ToolManager
                manager=ToolManager(self.runtime)
                if operation=='tool-preview':
                    self.pending_job=manager.preview(self.selected_engagement(),self.query_one('#tool-target',Input).value,self.query_one('#tool-ports',Input).value);self.ui_json('#tool-result',self.pending_job);self.query_one('#tool-approve',Button).disabled=False
                else:
                    if not self.pending_job:raise ValueError('Preview a command first')
                    job=self.pending_job;self.pending_job=None;self.query_one('#tool-approve',Button).disabled=True
                    result=await manager.execute(job['id'],job['digest'],approved=True,on_progress=lambda value:self.ui_json('#tool-result',{'output':value}));self.ui_json('#tool-result',result)
            self.ui_message('Operation complete. No vulnerability status is inferred from an observation.')
        except asyncio.CancelledError:self.ui_message('Operation cancelled; saved checkpoints retained.');raise
        except Exception as exc:self.ui_message('Operation failed: '+safe(exc))

    def on_data_table_row_selected(self,event:DataTable.RowSelected):
        if self.soc_row_selected(event):return
        if event.data_table.id=='assets-table':
            try:
                from .recon import list_assets
                rows=list_assets(self.runtime.database,self.selected_engagement(),search=str(event.row_key.value),limit=100)
                selected=next((r for r in rows if r['host']==event.row_key.value),None)
                if selected:self.ui_json('#recon-detail',selected)
            except Exception as exc:self.ui_message(safe(exc))
