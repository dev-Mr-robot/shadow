"""SOC Operations Center terminal workspace; no graphical or browser surfaces."""
import asyncio
import json
from pathlib import Path
from textual import work
from textual.containers import Horizontal,VerticalScroll
from textual.widgets import TabPane,Static,Input,Button,Select,DataTable,RichLog,TabbedContent
from textual.worker import get_current_worker
from rich.text import Text
from . import soc,soc_logs,soc_detection
from .presentation import safe

class SocMixin:
    def soc_panels(self):
        with TabPane('SOC Operations Center',id='soc-center'):
            yield Select([(s,s) for s in soc.SECTIONS],value=soc.SECTIONS[0],allow_blank=False,id='soc-section')
            yield Static('Passive local defensive evidence. Indicators are hypotheses; no account, process, firewall or endpoint response action is automated.',classes='intro')
            with Horizontal(classes='controls'):
                yield Input(placeholder='Log/export, detection-rule or ATT&CK STIX file path',id='soc-file')
                yield Button('Ingest logs',id='soc-ingest')
                yield Button('Import rule',id='soc-rule-import')
            with Horizontal(classes='controls'):
                yield Input(placeholder='Search events, alerts or techniques',id='soc-search')
                yield Button('Refresh selected section',id='soc-refresh')
                yield Button('Run detections',id='soc-detect')
            yield DataTable(id='soc-table',cursor_type='row')
            with Horizontal(classes='controls'):
                yield Input(placeholder='Alert/incident/event ID, or IOC value',id='soc-id')
                yield Select([(s,s) for s in soc.STATES],value='TRIAGED',allow_blank=False,id='soc-status')
                yield Button('Update alert status',id='soc-alert-update')
            with Horizontal(classes='controls'):
                yield Input(placeholder='Investigation note / incident title',id='soc-note')
                yield Button('Create incident from alert',id='soc-incident-create')
                yield Button('Show timeline',id='soc-timeline')
            with Horizontal(classes='controls'):
                yield Input(placeholder='New incident report output path (optional)',id='soc-report-path')
                yield Select([('Markdown','md'),('PDF','pdf'),('HTML document','html')],value='md',allow_blank=False,id='soc-report-format')
                yield Button('Generate SOC report',id='soc-report')
                yield Button('Ask local SOC analyst',id='soc-ask')
            yield RichLog(id='soc-result',wrap=True,markup=False,highlight=False)

    def mount_soc(self):self.query_one('#soc-table',DataTable).add_columns('Record ID','Timestamp','Category / status','Asset / source','Evidence / description')

    def on_tabbed_content_tab_activated(self,event):
        if event.tabbed_content.active=='soc-center' and hasattr(self,'cid'):self.soc_task('soc-refresh')

    def handle_soc_button(self,event):
        if event.button.id and event.button.id.startswith('soc-'):
            if event.button.id=='soc-ask':
                if self.chat_worker and self.chat_worker.is_running or self.operation_worker and self.operation_worker.is_running:self.ui_message('Stop the current operation before changing workspace');return True
                self.new_chat();self.query_one('#research-mode',Select).value='soc'
                self.action_tab('assistant')
                self.query_one('#chat-input',Input).value=self.query_one('#soc-search',Input).value or 'Summarize actual ingested SOC evidence, cite event and alert IDs, and separate observations from hypotheses.'
                self.ui_message('SOC analyst mode selected. Submit your natural-language request.');return True
            self.soc_task(event.button.id);return True
        return False

    @work(exclusive=True,group='soc-operation')
    async def soc_task(self,operation='soc-refresh'):
        self.operation_worker=get_current_worker()
        try:
            db=self.runtime.database;query=self.query_one('#soc-search',Input).value;rid=self.query_one('#soc-id',Input).value.strip();note=self.query_one('#soc-note',Input).value
            if operation=='soc-ingest':
                result=await asyncio.to_thread(soc_logs.ingest,db,Path(self.query_one('#soc-file',Input).value),'auto',soc.settings(db)['default_year'],lambda line,counts:self.call_from_thread(self.ui_message,f'SOC ingested {line} lines; {counts["imported"]} events'))
                self.ui_json('#soc-result',result)
            elif operation=='soc-detect':self.ui_json('#soc-result',await asyncio.to_thread(soc_detection.detect,db,None,None,None,soc.settings(db)['detection_event_limit']))
            elif operation=='soc-rule-import':self.ui_json('#soc-result',soc_detection.import_rule(db,Path(self.query_one('#soc-file',Input).value)))
            elif operation=='soc-alert-update':self.ui_json('#soc-result',soc.update_alert(db,rid,status=self.query_one('#soc-status',Select).value,note=note))
            elif operation=='soc-incident-create':
                result=soc.create_incident(db,note or 'SOC investigation',[rid]);self.query_one('#soc-id',Input).value=result['id'];self.ui_json('#soc-result',result)
            elif operation=='soc-timeline':self.ui_json('#soc-result',soc.incident_timeline(db,rid))
            elif operation=='soc-report':
                destination=self.query_one('#soc-report-path',Input).value.strip();row=await asyncio.to_thread(soc.report,db,rid,self.query_one('#soc-report-format',Select).value,Path(destination) if destination else None)
                self.ui_json('#soc-result',{k:v for k,v in row.items() if k not in {'content','snapshot'}})
            else:self.render_soc_view(query)
            self.ui_message('SOC operation complete. Evidence and indicator status remain distinct.')
        except asyncio.CancelledError:self.ui_message('SOC operation stopped. Completed ingestion batches may remain.');raise
        except Exception as exc:self.ui_message('SOC operation failed: '+safe(exc))

    def render_soc_view(self,query=''):
        db=self.runtime.database;section=self.query_one('#soc-section',Select).value;table=self.query_one('#soc-table',DataTable);table.clear();rows=[]
        if section=='Security Monitoring':
            self.ui_json('#soc-result',{'statistics':soc_logs.stats(db),'new_alerts':len(soc.alerts(db,status='NEW',limit=1000)),'notice':'Snapshot of ingested data only; no live endpoint/packet sensor is running.'});rows=soc.alerts(db,search=query,limit=100)
        elif section=='Log Analysis':rows=soc_logs.events(db,search=query,limit=100)
        elif section=='Threat Detection':self.ui_json('#soc-result',{'last_runs':db.listing('soc_detection_run',limit=10),'enabled_rules':sum(r['enabled'] for r in soc_detection.rules(db))});rows=soc.alerts(db,search=query,limit=100)
        elif section=='Alert Management':rows=soc.alerts(db,search=query,limit=100)
        elif section=='Incident Response':rows=db.listing('soc_incident',limit=100);self.ui_json('#soc-result',{'playbooks':soc.PLAYBOOKS,'response_adapter':'Unavailable by design: no automatic containment; guidance and operator-recorded actions only.'})
        elif section=='Threat Intelligence':rows=db.listing('soc_ioc',limit=100);self.ui_json('#soc-result',soc.enrich(db,query) if query else {'notice':'Local source-tagged indicators only. No private data is sent to any provider.'})
        elif section=='Network Security Monitoring':self.ui_json('#soc-result',soc.network_summary(db));rows=soc_logs.events(db,event_type='network',search=query,limit=100)
        elif section=='Endpoint Security Analysis':rows=soc_logs.events(db,event_type='process',search=query,limit=50)+soc_logs.events(db,event_type='sudo',search=query,limit=50)
        elif section=='Detection Engineering':rows=soc_detection.rules(db);self.ui_json('#soc-result',{'rule_contract':soc_detection.Rule.model_json_schema(),'sigma':'One selection with one literal field (equals/contains); unsupported Sigma expressions are rejected.'})
        elif section=='MITRE ATT&CK Explorer':rows=soc_detection.attack_search(db,query);self.ui_json('#soc-result',{'notice':'Versioned official-page subset plus explicitly imported official STIX records; this is not a complete bundled ATT&CK catalog.'})
        elif section=='SOC Reports':rows=db.listing('soc_report',limit=100)
        else:self.ui_json('#soc-result',soc.settings(db))
        self._soc_rows={str(r.get('id') or r.get('technique_id')):r for r in rows}
        for rid,row in self._soc_rows.items():
            table.add_row(rid,str(row.get('timestamp') or row.get('created') or row.get('source_date') or ''),str(row.get('event_type') or row.get('status') or row.get('type') or row.get('tactic') or row.get('format') or ''),Text(safe(row.get('host') or row.get('asset') or row.get('src_ip') or row.get('value') or '')),Text(safe(str(row.get('message') or row.get('rule') or row.get('title') or row.get('name') or row.get('notice') or '')[:250])),key=rid)

    def soc_row_selected(self,event):
        if event.data_table.id!='soc-table':return False
        row=getattr(self,'_soc_rows',{}).get(str(event.row_key.value))
        if row:self.query_one('#soc-id',Input).value=str(row.get('id') or row.get('technique_id'));self.ui_json('#soc-result',row)
        return True
