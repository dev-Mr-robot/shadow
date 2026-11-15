"""Terminal-native SOC commands; all ingestion, detection and response data stays local."""
import asyncio
import json
from pathlib import Path
import typer
from rich.table import Table
from rich.text import Text
from . import soc,soc_logs,soc_detection
from .presentation import safe

def register(app,runtime_factory,console):
    group=typer.Typer(help='SOC Operations Center: passive evidence, detections, alerts, incidents and intelligence.')
    alert_group=typer.Typer(help='Alert lifecycle and evidence correlation.')
    incident_group=typer.Typer(help='Incident workspaces and evidence timelines.')
    rule_group=typer.Typer(help='Versioned literal rules and an explicit narrow Sigma subset.')
    ioc_group=typer.Typer(help='Local intelligence sources; no external enrichment transmissions.')
    attack_group=typer.Typer(help='Versioned sourced ATT&CK records and official STIX import.')
    app.add_typer(group,name='soc');group.add_typer(alert_group,name='alerts');group.add_typer(incident_group,name='incident');group.add_typer(rule_group,name='rule');group.add_typer(ioc_group,name='ioc');group.add_typer(attack_group,name='attack')

    @group.command('ingest')
    def ingest(file:Path,format:str='auto',year:int|None=typer.Option(None,min=1970,max=2100)):
        """Stream local JSONL/CSV/syslog/access/Suricata/Zeek or bounded Windows XML exports."""
        with runtime_factory() as state:
            result=soc_logs.ingest(state.database,file,format,year or soc.settings(state.database)['default_year'],on_progress=lambda line,counts:console.print(Text(f'Parsed {line} lines · {counts["imported"]} new events')))
            console.print_json(data=result)

    @group.command('stats')
    def stats():
        with runtime_factory() as state:console.print_json(data=soc_logs.stats(state.database))

    @group.command('logs')
    def logs(search:str='',event_type:str=typer.Option('','--type'),src_ip:str='',host:str='',since:str|None=None,until:str|None=None,source:str|None=None,limit:int=typer.Option(100,min=1,max=1000),offset:int=typer.Option(0,min=0),as_json:bool=typer.Option(False,'--json')):
        with runtime_factory() as state:
            rows=soc_logs.events(state.database,search,event_type,src_ip,host,since,until,limit,offset,source)
            if as_json:console.print_json(data=rows);return
            table=Table('UTC timestamp','Event ID','Type','Asset','Source','User','Evidence')
            for e in rows:table.add_row(e['timestamp'],e['id'],e['event_type'],Text(safe(e['host'])),e['src_ip'],Text(safe(e['username'])),Text(safe(e['message'][:200])))
            console.print(table)

    @group.command('event')
    def event(event_id:str):
        with runtime_factory() as state:console.print_json(data=soc_logs.event(state.database,event_id))

    @group.command('detect')
    def detect(since:str|None=None,until:str|None=None,source:str|None=None,limit:int|None=typer.Option(None,min=1,max=2000000)):
        """Evaluate local evidence; matched patterns are not proof of attack success."""
        with runtime_factory() as state:console.print_json(data=soc_detection.detect(state.database,since,until,source,limit or soc.settings(state.database)['detection_event_limit']))

    @alert_group.command('list')
    def alerts(severity:str='',status:str='',search:str='',limit:int=typer.Option(100,min=1,max=1000),offset:int=typer.Option(0,min=0)):
        with runtime_factory() as state:console.print_json(data=soc.alerts(state.database,severity,status,search,limit,offset))

    @alert_group.command('show')
    def alert_show(alert_id:str):
        with runtime_factory() as state:console.print_json(data=state.database.get('soc_alert',alert_id))

    @alert_group.command('update')
    def alert_update(alert_id:str,status:str|None=None,note:str='',assign:str|None=None,false_positive:bool=False,event:list[str]=typer.Option(None,'--event')):
        with runtime_factory() as state:console.print_json(data=soc.update_alert(state.database,alert_id,status,note,assign,false_positive,event))

    @alert_group.command('related')
    def related(alert_id:str):
        with runtime_factory() as state:console.print_json(data=soc.related(state.database,alert_id))

    @incident_group.command('create')
    def incident_create(title:str,alert:list[str]=typer.Option(...,'--alert'),type:str=typer.Option('account_compromise','--type'),severity:str='Medium',note:str=''):
        with runtime_factory() as state:console.print_json(data=soc.create_incident(state.database,title,alert,type,severity,note))

    @incident_group.command('list')
    def incidents():
        with runtime_factory() as state:console.print_json(data=state.database.listing('soc_incident'))

    @incident_group.command('show')
    def incident_show(incident_id:str):
        with runtime_factory() as state:console.print_json(data=state.database.get('soc_incident',incident_id))

    @incident_group.command('update')
    def incident_update(incident_id:str,status:str|None=None,note:str='',action_taken:str='',lessons:str=''):
        with runtime_factory() as state:console.print_json(data=soc.update_incident(state.database,incident_id,status,note,action_taken,lessons))

    @incident_group.command('timeline')
    def timeline(incident_id:str):
        with runtime_factory() as state:console.print_json(data=soc.incident_timeline(state.database,incident_id))

    @group.command('playbook')
    def playbook(type:str=typer.Argument('account_compromise')):
        if type not in soc.PLAYBOOKS:raise ValueError('Choose: '+', '.join(soc.PLAYBOOKS))
        console.print_json(data={'type':type,'steps':soc.PLAYBOOKS[type],'execution':'Guidance only. No account, endpoint, process, firewall or file modification adapter is enabled.'})

    @group.command('network')
    def network(since:str|None=None,limit:int=typer.Option(10000,min=1,max=100000)):
        with runtime_factory() as state:console.print_json(data=soc.network_summary(state.database,since,limit))

    @group.command('pcap')
    def pcap(file:Path):
        from .research import static_analyze
        with runtime_factory() as state:
            result=static_analyze(file,'pcap');console.print_json(data=state.database.create('soc_pcap',result))

    @rule_group.command('list')
    def rules():
        with runtime_factory() as state:console.print_json(data=soc_detection.rules(state.database))

    @rule_group.command('import')
    def rule_import(file:Path):
        with runtime_factory() as state:console.print_json(data=soc_detection.import_rule(state.database,file))

    @rule_group.command('enable')
    def rule_enable(rule_id:str,enabled:bool=typer.Option(True,'--enabled/--disabled')):
        with runtime_factory() as state:console.print_json(data=soc_detection.set_rule_enabled(state.database,rule_id,enabled))

    @rule_group.command('export')
    def rule_export(rule_id:str,output:Path):
        with runtime_factory() as state:
            row=next((r for r in soc_detection.rules(state.database) if r['id']==rule_id),None)
            if not row:raise ValueError('Rule not found')
            from .reporting import _write_exclusive
            _write_exclusive(output,json.dumps({k:v for k,v in row.items() if k in soc_detection.Rule.model_fields},indent=2).encode());console.print(Text(str(output)))

    @rule_group.command('test')
    def rule_test(rule_id:str,event_id:str):
        with runtime_factory() as state:
            rule=next((r for r in soc_detection.rules(state.database) if r['id']==rule_id),None)
            if not rule:raise ValueError('Rule not found')
            event=soc_logs.event(state.database,event_id);value=soc_detection.field(event,rule['field'])
            match=(not rule['event_type'] or event['event_type']==rule['event_type']) and (rule['equals'] is None or str(value)==str(rule['equals'])) and (not rule['contains'] or any(v.casefold() in str(value).casefold() for v in rule['contains']))
            console.print_json(data={'event_id':event_id,'rule_id':rule_id,'single_event_selection_matches':match,'threshold':rule['threshold'],'notice':'This tests selection only; threshold/window aggregation needs soc detect. No alert was created.'})

    @rule_group.command('history')
    def rule_history(name:str=''):
        with runtime_factory() as state:
            rows=state.database.listing('soc_rule',limit=1000)
            console.print_json(data={'versions':[r for r in rows if not name or r['name']==name],'execution_history':state.database.listing('soc_detection_run',limit=100)})

    @rule_group.command('coverage')
    def coverage():
        with runtime_factory() as state:
            rows=soc_detection.rules(state.database)
            console.print_json(data={'mapped_rules':[{'name':r['name'],'enabled':r['enabled'],'attack':r['attack']} for r in rows if r['attack']],
                'unmapped_rules':[r['name'] for r in rows if not r['attack']],'sources':soc_detection.attack_search(state.database),
                'notice':'Mapping is technique relevance, not proof of detection effectiveness or complete ATT&CK coverage.'})

    @rule_group.command('edit')
    def rule_edit(rule_id:str,file:Path):
        with runtime_factory() as state:
            previous=next((r for r in soc_detection.rules(state.database) if r['id']==rule_id),None)
            if not previous:raise ValueError('Rule not found')
            from .research import read_file
            _,data=read_file(file,limit=128*1024);patch=json.loads(data)
            if not isinstance(patch,dict) or 'name' in patch and patch['name']!=previous['name']:raise ValueError('Rule edit must be an object and preserve the rule name')
            body={k:v for k,v in previous.items() if k in soc_detection.Rule.model_fields};body.update(patch);body['version']=previous['version']+1
            validated=soc_detection.Rule.model_validate(body)
            if any(a not in {t['technique_id'] for t in soc_detection.attack_search(state.database)} for a in validated.attack):raise ValueError('Unknown ATT&CK mapping')
            row=state.database.create('soc_rule',validated.model_dump());state.database.audit('soc.rule_edited',{'id':row['id'],'version':row['version']});console.print_json(data=row)

    @ioc_group.command('import')
    def ioc_import(file:Path):
        from .research import read_file
        _,data=read_file(file);rows=json.loads(data)
        if not isinstance(rows,list) or len(rows)>10000:raise ValueError('A local IOC feed must be a JSON list of at most 10,000 source-tagged indicators')
        with runtime_factory() as state:
            imported=[]
            for row in rows:
                if not isinstance(row,dict) or set(row)-{'type','value','source','source_date','confidence','reputation','actor_reference'}:raise ValueError('Invalid IOC feed schema')
                imported.append(soc.add_ioc(state.database,row['type'],row['value'],row['source'],row['source_date'],row.get('confidence',.5),row.get('reputation','unknown'),row.get('actor_reference',''))['id'])
            console.print_json(data={'imported':len(imported),'ids':imported,'external_requests':False})

    @group.command('sensors')
    def sensors():
        import shutil
        console.print_json(data=[{'tool':name,'path':shutil.which(name),'integration':'Local export ingestion / passive PCAP metadata; automatic sensor launch is disabled.'} for name in ['tshark','zeek','suricata']])

    @attack_group.command('search')
    def attack_search(query:str=typer.Argument('')):
        with runtime_factory() as state:console.print_json(data=soc_detection.attack_search(state.database,query))

    @attack_group.command('import')
    def attack_import(file:Path,source:str=typer.Option(...),version:str=typer.Option(...)):
        with runtime_factory() as state:console.print_json(data=soc_detection.attack_import(state.database,file,source,version))

    @ioc_group.command('add')
    def ioc_add(type:str,value:str,source:str=typer.Option(...),date:str=typer.Option(...),confidence:float=.5,reputation:str='unknown',actor_reference:str=''):
        with runtime_factory() as state:console.print_json(data=soc.add_ioc(state.database,type,value,source,date,confidence,reputation,actor_reference))

    @ioc_group.command('list')
    def ioc_list():
        with runtime_factory() as state:console.print_json(data=state.database.listing('soc_ioc'))

    @ioc_group.command('enrich')
    def enrich(value:str):
        with runtime_factory() as state:console.print_json(data=soc.enrich(state.database,value))

    @group.command('report')
    def report(incident_id:str,format:str='md',output:Path|None=None):
        with runtime_factory() as state:
            row=soc.report(state.database,incident_id,format,output);console.print_json(data={k:v for k,v in row.items() if k not in {'content','snapshot'}})

    @group.command('settings')
    def settings(retention_days:int|None=None,year:int|None=None,event_limit:int|None=None):
        patch={key:value for key,value in [('retention_days',retention_days),('default_year',year),('detection_event_limit',event_limit)] if value is not None}
        with runtime_factory() as state:console.print_json(data=soc.settings(state.database,patch))

    @group.command('retention')
    def retention(before:str):
        with runtime_factory() as state:
            preview=soc.retention(state.database,before);console.print_json(data=preview)
            if not typer.confirm('Permanently delete exactly these old event rows? Back up first.',default=False):raise typer.Exit(1)
            console.print_json(data=soc.retention(state.database,before,approved=True))

    @group.command('ask')
    def ask(prompt:str,conversation:str|None=None):
        from .intelligence import ConversationService
        from rich.live import Live
        from rich.markdown import Markdown
        with runtime_factory() as state:
            service=ConversationService(state);cid=conversation or service.new('soc',title=prompt[:100])['id'];console.print(Text('SOC conversation: '+cid))
            async def run():
                plan=await service.plan(cid,prompt)
                if plan.clarification:service.record_clarification(cid,prompt,plan.clarification);console.print(Text(plan.clarification));return
                output=''
                with Live(Markdown('Waiting for the local SOC analyst…'),console=console,refresh_per_second=10) as live:
                    async for token in service.stream(cid,prompt,plan):output+=safe(token);live.update(Markdown(output,hyperlinks=False))
                from .actions import ActionRunner
                for action in plan.actions:
                    runner=ActionRunner(state);preview=await runner.preview(action);console.print_json(data=preview)
                    if not typer.confirm('Approve this exact local SOC action?',default=False):continue
                    result=await runner.execute(preview['id'],approved=True);service.record_result(cid,result);console.print_json(data=result)
            asyncio.run(run())
