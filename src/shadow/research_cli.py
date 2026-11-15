"""Terminal commands for passive evidence analysis, findings, advisories and reports."""
from pathlib import Path
import json
import typer
from . import research,reporting

def register(app,runtime_factory,console):
    http_app=typer.Typer(help='Static HTTP/API evidence inspection. No requests are sent.')
    finding_app=typer.Typer(help='Evidence-backed, scoped findings and verification labels.')
    report_app=typer.Typer(help='Immutable Markdown, HTML and PDF assessment reports.')
    advisory_app=typer.Typer(help='Local source/date-aware advisory research cache. No hidden online lookups.')
    research_app=typer.Typer(help='Static source/config/log/binary/PCAP triage; never executes content.')
    evidence_app=typer.Typer(help='Import and inspect engagement evidence.')
    app.add_typer(http_app,name='http');app.add_typer(finding_app,name='finding');app.add_typer(report_app,name='report')
    app.add_typer(advisory_app,name='advisory');app.add_typer(research_app,name='research');app.add_typer(evidence_app,name='evidence')

    def eid(state,value):
        selected=value or state.settings.active_engagement
        if not selected:raise ValueError('Select an engagement first or provide --engagement ID')
        state.database.engagement(selected);return selected

    def json_file(path):
        _,data=research.read_file(path)
        try:return json.loads(data)
        except (ValueError,UnicodeError,RecursionError) as exc:raise ValueError('Expected a bounded JSON object file') from exc

    @http_app.command('inspect')
    def inspect(file:Path):
        """Inspect raw request/response text without storing or replaying it."""
        _,data=research.read_file(file);console.print_json(data=research.analyze_http(data.decode('utf-8-sig',errors='replace')))

    @http_app.command('analyze')
    def analyze(file:Path,engagement:str|None=typer.Option(None,'--engagement'),store:bool=typer.Option(True,'--store/--no-store')):
        """Analyze raw HTTP or Burp XML. With storage enabled, associate the evidence with an engagement."""
        with runtime_factory() as state:
            if store:
                record=research.import_evidence(state.database,eid(state,engagement),file,'http')
                console.print_json(data={k:v for k,v in record.items() if k not in {'text','exchanges'}})
            else:
                _,data=research.read_file(file);console.print_json(data=research.analyze_http(data.decode('utf-8-sig',errors='replace')))

    @http_app.command('compare')
    def compare(first:Path,second:Path):
        """Compare two raw messages; differences are observations, not confirmed access-control flaws."""
        _,a=research.read_file(first);_,b=research.read_file(second)
        console.print_json(data=research.compare_http(a.decode('utf-8-sig',errors='replace'),b.decode('utf-8-sig',errors='replace')))

    @evidence_app.command('import')
    def import_evidence(file:Path,source:str=typer.Option('other','--source'),engagement:str|None=typer.Option(None,'--engagement')):
        """Import bounded HTTP/Burp or other tool text with its original-byte SHA-256."""
        with runtime_factory() as state:
            record=research.import_evidence(state.database,eid(state,engagement),file,source)
            console.print_json(data={k:v for k,v in record.items() if k not in {'text','exchanges','analyses'}})

    @evidence_app.command('list')
    def evidence_list(engagement:str|None=typer.Option(None,'--engagement'),limit:int=typer.Option(100,min=1,max=1000),offset:int=typer.Option(0,min=0)):
        with runtime_factory() as state:
            rows=state.database.listing('import',parent=eid(state,engagement),limit=limit,offset=offset)
            console.print_json(data=[{k:v for k,v in row.items() if k not in {'text','analyses','exchanges'}} for row in rows])

    @evidence_app.command('show')
    def evidence_show(record_id:str):
        with runtime_factory() as state:console.print_json(data=state.database.get('import',record_id))

    @finding_app.command('add')
    def finding_add(file:Path,engagement:str|None=typer.Option(None,'--engagement')):
        """Create a finding from JSON. Confirmation requires supplied evidence; CVSS requires justification."""
        with runtime_factory() as state:
            body=json_file(file)
            if not isinstance(body,dict):raise ValueError('Finding JSON must be an object')
            body.setdefault('engagement_id',eid(state,engagement or body.get('engagement_id')))
            console.print_json(data=research.create_finding(state.database,body))

    @finding_app.command('list')
    def finding_list(engagement:str|None=typer.Option(None,'--engagement'),limit:int=typer.Option(100,min=1,max=1000),offset:int=typer.Option(0,min=0)):
        with runtime_factory() as state:console.print_json(data=state.database.listing('finding',parent=eid(state,engagement),limit=limit,offset=offset))

    @finding_app.command('show')
    def finding_show(record_id:str):
        with runtime_factory() as state:console.print_json(data=state.database.get('finding',record_id))

    @finding_app.command('update')
    def finding_update(record_id:str,file:Path):
        """Apply a validated JSON patch while preserving engagement ownership."""
        with runtime_factory() as state:
            patch=json_file(file)
            if not isinstance(patch,dict):raise ValueError('Finding patch must be an object')
            console.print_json(data=research.update_finding(state.database,record_id,patch))

    @report_app.command('generate')
    def report_generate(engagement:str|None=typer.Option(None,'--engagement'),format:str=typer.Option('md','--format'),output:Path|None=typer.Option(None,'--output')):
        """Create a factual report snapshot and new file. Existing paths are never overwritten."""
        with runtime_factory() as state:
            row=reporting.generate_report(state.database,eid(state,engagement),format,output)
            console.print_json(data={k:v for k,v in row.items() if k not in {'snapshot','content'}})

    @report_app.command('list')
    def report_list(engagement:str|None=typer.Option(None,'--engagement'),limit:int=typer.Option(100,min=1,max=1000)):
        with runtime_factory() as state:
            rows=state.database.listing('report',parent=eid(state,engagement),limit=limit)
            console.print_json(data=[{k:v for k,v in row.items() if k not in {'snapshot','content'}} for row in rows])

    @report_app.command('export')
    def report_export(record_id:str,output:Path=typer.Option(...,'--output')):
        with runtime_factory() as state:console.print(str(reporting.export_report(state.database,record_id,output)),markup=False)

    @advisory_app.command('import')
    def advisory_import(file:Path,source:str=typer.Option(...,'--source'),source_date:str=typer.Option(...,'--date')):
        """Cache a supplied advisory JSON with an explicit source URL and source date; no URL is fetched."""
        with runtime_factory() as state:console.print_json(data=research.import_advisory(state.database,file,source,source_date))

    @advisory_app.command('list')
    def advisory_list(cve:str=typer.Option('','--cve'),limit:int=typer.Option(100,min=1,max=1000)):
        with runtime_factory() as state:
            rows=state.database.listing('advisory',limit=limit)
            console.print_json(data=[row for row in rows if not cve or row['cve']==cve.upper()])

    @advisory_app.command('show')
    def advisory_show(record_id:str):
        with runtime_factory() as state:console.print_json(data=state.database.get('advisory',record_id))

    @research_app.command('analyze')
    def static_analysis(file:Path,kind:str=typer.Option('auto','--kind'),engagement:str|None=typer.Option(None,'--engagement')):
        """Analyze local Python/config/log/binary/classic-PCAP content without executing it."""
        result=research.static_analyze(file,kind)
        with runtime_factory() as state:
            selected=engagement or state.settings.active_engagement
            if selected:state.database.engagement(selected)
            record=state.database.create('analysis',{**result,'engagement_id':selected},selected)
            state.database.audit('research.analyzed',{'id':record['id'],'kind':result['kind'],'sha256':result['sha256']})
            console.print_json(data=record)
