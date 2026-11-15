"""Shared SOC investigation, incident, intelligence and reporting services."""
import hashlib
import html
import io
import ipaddress
import json
import re
from datetime import datetime,timedelta,timezone
from pathlib import Path
from urllib.parse import urlsplit
from sqlalchemy import text
from . import soc_logs,soc_detection

STATES=['NEW','TRIAGED','INVESTIGATING','CONTAINED','RESOLVED','CLOSED']
SEVERITY=['Critical','High','Medium','Low','Informational']
SECTIONS=['Security Monitoring','Log Analysis','Threat Detection','Alert Management','Incident Response','Threat Intelligence','Network Security Monitoring','Endpoint Security Analysis','Detection Engineering','MITRE ATT&CK Explorer','SOC Reports','SOC Settings']
PLAYBOOKS={
 'brute_force':['Confirm authentication log completeness and source clock.','Compare failed/successful events, usernames and authorized testing.','Preserve relevant evidence and review account/MFA controls.'],
 'account_compromise':['Validate account ownership and session provenance.','Correlate logins, process activity and access changes.','Plan credential/session containment through approved administrative procedures.'],
 'malware':['Preserve file hashes and endpoint/process/network evidence.','Compare local sourced indicators; do not execute the sample.','Plan isolation in an approved response system; no endpoint change is automated.'],
 'phishing':['Preserve original message and headers without opening active content.','Review sender/domain/URL context and recipient reports.','Plan mailbox/session containment with approved administrators.'],
 'outbound_traffic':['Validate destination ownership and business need.','Compare DNS, flow/TLS metadata, bytes and timestamps.','Review periodicity and endpoint context before calling it command-and-control.'],
 'web_attack':['Correlate request patterns, status codes and application traces.','Look for evidence of actual impact; signatures alone do not prove exploitation.','Preserve request IDs and review remediation with application owners.'],
 'privilege_escalation':['Review effective users and authorization context.','Correlate policy/file changes with command execution.','Preserve audit evidence and validate actual privilege boundaries.'],
 'exfiltration':['Validate bytes/destinations against normal transfer workflows.','Correlate authenticated identities and accessible data.','Assess data exposure only from evidence; traffic volume alone is not proof.'],
 'lateral_movement':['Correlate source/destination identities and remote-access events.','Compare asset roles and approved administration.','Preserve session timelines and plan reviewed containment.'],
 'persistence':['Review scheduled tasks/services/startup changes and owner.','Correlate file/process timestamps with installations or approved changes.','Plan removal only through an approved response adapter.']}

def records(db,kind,limit=1000):return db.listing(kind,limit=limit)

def alerts(db,severity='',status='',search='',limit=100,offset=0):
    if severity and severity not in SEVERITY or status and status not in STATES:raise ValueError('Invalid severity/status filter')
    clauses=["kind='soc_alert'"];params={'limit':limit,'offset':offset}
    if not 1<=limit<=1000 or offset<0:raise ValueError('Invalid alert pagination')
    if severity:clauses.append("json_extract(body,'$.severity')=:severity");params['severity']=severity
    if status:clauses.append("json_extract(body,'$.status')=:status");params['status']=status
    if search:clauses.append("body LIKE :search ESCAPE '\\'");params['search']='%'+search.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
    with db.engine.connect() as c:
        rows=c.execute(text('SELECT id FROM workspace_records WHERE '+' AND '.join(clauses)+" ORDER BY CASE json_extract(body,'$.severity') WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,created DESC LIMIT :limit OFFSET :offset"),params).all()
    return [db.get('soc_alert',r[0]) for r in rows]

def update_alert(db,rid,status=None,note='',assigned_to=None,false_positive=False,evidence_ids=None):
    row=db.get('soc_alert',rid);changes={};timestamp=datetime.now(timezone.utc).isoformat()
    if status:
        status=status.upper()
        if status not in STATES:raise ValueError('Invalid alert lifecycle status')
        old=STATES.index(row['status']);new=STATES.index(status)
        if new!=old and new!=old+1 and not(false_positive and status=='CLOSED'):raise ValueError('Follow NEW → TRIAGED → INVESTIGATING → CONTAINED → RESOLVED → CLOSED; false-positive closure is an explicit exception')
        changes['status']=status
    if false_positive:
        if not note.strip():raise ValueError('False-positive classification requires a rationale')
        changes['classification']='false_positive'
    if assigned_to is not None:
        if len(assigned_to)>200:raise ValueError('Assignment metadata exceeds limit')
        changes['assigned_to']=assigned_to
    if evidence_ids:
        for event_id in evidence_ids:soc_logs.event(db,event_id)
        changes['event_ids']=list(dict.fromkeys(row['event_ids']+evidence_ids))[:200]
    if len(note)>10000:raise ValueError('Investigation note exceeds limit')
    changes['history']=row['history']+[{'timestamp':timestamp,'status':changes.get('status',row['status']),'note':note,'assigned_to':assigned_to,'false_positive':false_positive}]
    if len(changes['history'])>1000:raise ValueError('Alert history limit reached')
    result=db.update('soc_alert',rid,changes);db.audit('soc.alert_updated',{'id':rid,'status':result['status'],'classification':result['classification']});return result

def related(db,rid):
    row=db.get('soc_alert',rid);selected=[];offset=0
    while len(selected)<100:
        page=db.listing('soc_alert',limit=200,offset=offset)
        if not page:break
        offset+=len(page)
        for other in page:
            if other['id']!=rid and (row.get('src_ip') and other.get('src_ip')==row['src_ip'] or row.get('username') and other.get('username')==row['username'] or row['asset']!='unknown' and other['asset']==row['asset']):selected.append(other)
    return {'alert_id':rid,'related':selected[:100],'basis':'Shared source IP, username or affected asset; relationship is a correlation hypothesis, not attribution.'}

def create_incident(db,title,alert_ids,incident_type='account_compromise',severity='Medium',notes=''):
    if not title.strip() or len(title)>250 or incident_type not in PLAYBOOKS or severity not in SEVERITY:raise ValueError('Provide a title, supported incident type/playbook and severity')
    if not 1<=len(alert_ids)<=100:raise ValueError('Link 1–100 actual alert IDs')
    selected=[db.get('soc_alert',rid) for rid in dict.fromkeys(alert_ids)]
    row=db.create('soc_incident',{'title':title,'incident_type':incident_type,'severity':severity,'status':'NEW','alert_ids':[a['id'] for a in selected],
        'assets':sorted(set(a['asset'] for a in selected)),'iocs':sorted(set(a['src_ip'] for a in selected if a['src_ip'])),'notes':notes,'actions_taken':[],
        'lessons_learned':'','history':[{'timestamp':datetime.now(timezone.utc).isoformat(),'status':'NEW','note':notes}],
        'verification':'Investigation record based on linked alert evidence. Incident type is a working hypothesis unless separately verified.'})
    db.audit('soc.incident_created',{'id':row['id'],'alerts':len(selected)});return row

def update_incident(db,rid,status=None,note='',action_taken='',lessons=''):
    row=db.get('soc_incident',rid);changes={}
    if status:
        status=status.upper()
        if status not in STATES:raise ValueError('Invalid incident lifecycle status')
        old=STATES.index(row['status']);new=STATES.index(status)
        if new not in {old,old+1}:raise ValueError('Incident lifecycle transitions must advance one stage at a time')
        changes['status']=status
    if note:changes['notes']=(row.get('notes','')+'\n'+note)[-100000:]
    if lessons:changes['lessons_learned']=lessons[:20000]
    if action_taken:changes['actions_taken']=row['actions_taken']+[{'timestamp':datetime.now(timezone.utc).isoformat(),'operator_recorded_action':action_taken[:10000],'execution':'Metadata only. SHADOW did not execute a containment action.'}]
    changes['history']=row['history']+[{'timestamp':datetime.now(timezone.utc).isoformat(),'status':changes.get('status',row['status']),'note':note}]
    result=db.update('soc_incident',rid,changes);db.audit('soc.incident_updated',{'id':rid,'status':result['status']});return result

def incident_timeline(db,rid,limit=500):
    row=db.get('soc_incident',rid);event_ids=set()
    for alert_id in row['alert_ids']:event_ids.update(db.get('soc_alert',alert_id)['event_ids'])
    if len(event_ids)>limit:raise ValueError('Incident event timeline exceeds limit; narrow linked alerts')
    timeline=sorted([soc_logs.event(db,eid) for eid in event_ids],key=lambda e:(e['timestamp'],e['id']))
    return {'incident_id':rid,'events':timeline,'operator_history':row['history'],'notice':'Event timestamps may carry source assumptions; inspect timestamp_assumption per event.'}

def add_ioc(db,kind,value,source,source_date,confidence=.5,reputation='unknown',actor_reference=''):
    if not 0<=confidence<=1 or reputation not in {'unknown','benign','suspicious','malicious'}:raise ValueError('Invalid IOC confidence or source-supplied reputation')
    if not source.strip() or len(source)>2000:raise ValueError('Document the intelligence source')
    datetime.fromisoformat(source_date.replace('Z','+00:00'))
    if kind=='ip':value=str(ipaddress.ip_address(value))
    elif kind=='domain':
        from .scope import normalize
        value=normalize(value)
        if '/' in value:raise ValueError('Use an exact domain, not a CIDR')
    elif kind=='url':
        parsed=urlsplit(value)
        if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.password:raise ValueError('Invalid IOC URL')
    elif kind=='hash':
        value=value.lower()
        if not re.fullmatch(r'(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})',value):raise ValueError('Expected MD5/SHA1/SHA256 hex digest')
    elif kind=='email':
        value=value.casefold()
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',value):raise ValueError('Invalid email indicator')
    else:raise ValueError('IOC type must be ip, domain, url, hash or email')
    row=db.create('soc_ioc',{'type':kind,'value':value,'source':source,'source_date':source_date,'confidence':confidence,'reputation':reputation,'actor_reference':actor_reference[:3000],
        'verification':'Supplied local intelligence claim, not independently verified. No external enrichment request made.'})
    db.audit('soc.ioc_saved',{'id':row['id'],'type':kind});return row

def enrich(db,value):
    matched=[r for r in db.listing('soc_ioc',limit=1000) if r['value'].casefold()==value.casefold()]
    return {'indicator':value,'sources':matched,'reputation':'unknown' if not matched else 'See source-specific reputation/confidence; SHADOW does not merge conflicting claims into certainty.',
            'events':soc_logs.events(db,search=value,limit=100),'external_requests':False}

def network_summary(db,since=None,limit=10000):
    processed=0;offset=0;protocols={};destinations={};ports={};connections={}
    while processed<limit:
        page=soc_logs.events(db,event_type='network',since=since,limit=min(500,limit-processed),offset=offset)
        if not page:break
        processed+=len(page);offset+=len(page)
        for e in page:
            protocol=str(e['fields'].get('protocol') or 'unknown');protocols[protocol]=protocols.get(protocol,0)+1
            if e['dst_ip']:destinations[e['dst_ip']]=destinations.get(e['dst_ip'],0)+1
            port=str(e['fields'].get('dst_port') or 'unknown');ports[port]=ports.get(port,0)+1
            key=(e['src_ip'],e['dst_ip'],port);connections.setdefault(key,[]).append(e['timestamp'])
    periodic=[]
    for key,times in connections.items():
        if len(times)<5:continue
        stamps=sorted(datetime.fromisoformat(t).timestamp() for t in times);gaps=[b-a for a,b in zip(stamps,stamps[1:])]
        average=sum(gaps)/len(gaps)
        if average>0 and max(gaps)-min(gaps)<=max(1,average*.1):periodic.append({'source':key[0],'destination':key[1],'port':key[2],'samples':len(times),'interval_seconds':round(average,2),'verification':'Periodicity indicator; scheduled benign traffic can look identical.'})
    return {'analyzed':processed,'limited':processed==limit,'protocols':protocols,'destinations':destinations,'ports':ports,'periodicity_indicators':periodic[:100],
            'notice':'Exported connection metadata only; encrypted payload contents are not inspected. No live packet capture.'}

def settings(db,patch=None):
    rows=db.listing('soc_settings',limit=1);value=rows[0] if rows else {'retention_days':90,'default_year':datetime.now(timezone.utc).year,'detection_event_limit':200000}
    if patch:
        if set(patch)-{'retention_days','default_year','detection_event_limit'}:raise ValueError('Unsupported SOC setting')
        value={**value,**patch}
        if not 1<=value['retention_days']<=3650 or not 1970<=value['default_year']<=2100 or not 1<=value['detection_event_limit']<=2000000:raise ValueError('SOC setting outside supported resource limits')
        value=db.update('soc_settings',value['id'],value) if rows else db.create('soc_settings',value)
    return value

def retention(db,before,approved=False):
    cutoff=soc_logs.stamp(before)[0]
    with db.engine.connect() as c:count=c.execute(text('SELECT count(*) FROM soc_events WHERE timestamp<:cutoff'),{'cutoff':cutoff}).scalar_one()
    if approved:
        with db.engine.begin() as c:c.execute(text('DELETE FROM soc_events WHERE timestamp<:cutoff'),{'cutoff':cutoff})
        db.audit('soc.events_retained',{'before':cutoff,'removed':count})
    return {'before':cutoff,'affected_events':count,'deleted':approved,'warning':'Existing alerts retain their original evidence excerpts; deleting events removes full-event timeline access. Back up before approving.'}

def report(db,incident_id,format='md',output=None):
    if format not in {'md','html','pdf'}:raise ValueError('Use md, html or pdf')
    incident=db.get('soc_incident',incident_id);timeline=incident_timeline(db,incident_id)
    selected=[db.get('soc_alert',rid) for rid in incident['alert_ids']]
    sections=[('SHADOW SOC Incident Report',incident['title']),('Executive summary',f"Working incident type: {incident['incident_type']}. Severity: {incident['severity']}. Status: {incident['status']}. {len(selected)} linked alerts; {len(timeline['events'])} actual event records. No attack outcome is inferred automatically."),
      ('Affected assets','\n'.join(incident['assets'])),('Investigation status',incident['verification']),('Event timeline','\n'.join(f"{e['timestamp']} | {e['id']} | {e['host']} | {e['event_type']} | {e['message']}" for e in timeline['events'])),
      ('Detection evidence','\n\n'.join(f"Alert {a['id']} | {a['rule']} | confidence {a['confidence']} | {a['verification']}\nEvent IDs: {', '.join(a['event_ids'])}" for a in selected)),
      ('ATT&CK mapping','\n'.join(f"{t['technique_id']} {t['name']} | version {t['version']} | {t['source']}" for t in soc_detection.attack_search(db) if any(t['technique_id'] in a['attack'] for a in selected)) or 'No justified mapping recorded.'),
      ('Impact assessment','Not established automatically. Validate actual access, affected data and business effects from evidence.'),('Investigation notes',incident['notes']),
      ('Operator-recorded response actions',json.dumps(incident['actions_taken'],indent=2) if incident['actions_taken'] else 'None recorded. SHADOW executed no response action.'),('Suggested investigation / remediation','\n'.join(PLAYBOOKS[incident['incident_type']])+'\nNo containment operation was executed by SHADOW.'),('Lessons learned',incident['lessons_learned'] or 'Not yet recorded.')]
    if len(json.dumps(sections).encode())>5*1024*1024:raise ValueError('Incident report exceeds 5 MiB evidence cap; narrow linked alerts')
    md='\n\n'.join(('## '+heading+'\n\n'+body) for heading,body in sections)
    if format=='md':data=md.encode('utf-8')
    elif format=='html':data=('<!doctype html><meta charset="utf-8"><title>SOC incident report</title><body>'+''.join('<h2>'+html.escape(h)+'</h2><pre style="white-space:pre-wrap;overflow-wrap:anywhere">'+html.escape(b)+'</pre>' for h,b in sections)+'</body>').encode('utf-8')
    else:
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        buffer=io.BytesIO();styles=getSampleStyleSheet();story=[]
        for font_path in ['/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf','C:/Windows/Fonts/arial.ttf']:
            if Path(font_path).is_file():
                if 'ShadowSOC' not in pdfmetrics.getRegisteredFontNames():pdfmetrics.registerFont(TTFont('ShadowSOC',font_path))
                styles['BodyText'].fontName='ShadowSOC';styles['Heading2'].fontName='ShadowSOC';break
        for heading,body in sections:
            story.append(Paragraph(html.escape(heading),styles['Heading2']))
            for line in body.splitlines() or ['']:
                for start in range(0,max(1,len(line)),1500):story.append(Paragraph(html.escape(line[start:start+1500]) or ' ',styles['BodyText']))
            story.append(Spacer(1,8))
        def footer(canvas,document):
            canvas.saveState();canvas.setFont(styles['BodyText'].fontName,8);canvas.setFillColorRGB(.4,.45,.5)
            canvas.drawString(45,25,'SHADOW SOC | Evidence-linked investigation; operator review required')
            canvas.drawRightString(document.pagesize[0]-45,25,str(document.page));canvas.restoreState()
        SimpleDocTemplate(buffer,rightMargin=45,leftMargin=45,topMargin=45,bottomMargin=45,title='SHADOW SOC Incident Report').build(story,onFirstPage=footer,onLaterPages=footer);data=buffer.getvalue()
    if output:
        from .reporting import _write_exclusive
        _write_exclusive(output,data)
    import base64
    row=db.create('soc_report',{'incident_id':incident_id,'format':format,'snapshot':{'incident':incident,'timeline':timeline,'alerts':selected},'content':base64.b64encode(data).decode() if format=='pdf' else data.decode('utf-8'),
        'sha256':hashlib.sha256(data).hexdigest(),'path':str(output) if output else None,'warning':'Document export only; no web interface and no independent attack confirmation.'},incident_id)
    db.audit('soc.report_generated',{'id':row['id'],'incident_id':incident_id,'format':format});return row

def context(db,limit=8):
    return {'soc_statistics':soc_logs.stats(db),'soc_alerts':alerts(db,limit=limit),'soc_incidents':db.listing('soc_incident',limit=limit),'soc_recent_events':soc_logs.events(db,limit=limit),
            'soc_notice':'These are actual local event/alert IDs. Alerts are hypotheses; never invent events or claim that an attack succeeded.'}
