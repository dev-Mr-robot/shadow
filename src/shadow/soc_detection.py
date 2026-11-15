"""Deterministic defensive indicator rules. Alerts are evidence-backed hypotheses."""
import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime,timedelta,timezone
from pathlib import Path
from pydantic import BaseModel,ConfigDict,Field,model_validator
from sqlalchemy import text
from . import soc_logs

TECHNIQUES={
 'T1110.001':{'name':'Password Guessing','tactic':'Credential Access','version':'1.7','source':'https://attack.mitre.org/techniques/T1110/001/','guidance':'Correlate repeated authentication failures with account, source, target and any later success. Review legitimate password errors and authorized testing.','mitigations':'Strong authentication, rate limiting and account policy appropriate to the service.'},
 'T1110.003':{'name':'Password Spraying','tactic':'Credential Access','version':'1.8','source':'https://attack.mitre.org/techniques/T1110/003/','guidance':'Review authentication failures across multiple accounts and the time window; shared gateways and user mistakes can resemble this pattern.','mitigations':'Review MFA, authentication monitoring and carefully tuned lockout/rate policies.'},
 'T1046':{'name':'Network Service Discovery','tactic':'Discovery','version':'3.2','source':'https://attack.mitre.org/techniques/T1046/','guidance':'Correlate distinct destination ports/hosts with inventory, management systems and authorized scanners.','mitigations':'Restrict unnecessary service exposure and monitor network enumeration.'},
 'T1548.003':{'name':'Sudo and Sudo Caching','tactic':'Privilege Escalation / Defense Evasion','version':'source-page-snapshot-2026-11-15','source':'https://attack.mitre.org/techniques/T1548/003/','guidance':'Review sudoers/NOPASSWD/timestamp context and actual user privileges. A sudo event alone does not establish abuse.','mitigations':'Audit sudo policy changes and apply least privilege.'}}

def attack_search(db,query=''):
    rows=[{'technique_id':key,**value,'dataset':'SHADOW curated official-page snapshot 2026-11-15','source_date':'2026-11-15'} for key,value in TECHNIQUES.items()]
    offset=0
    while True:
        page=db.listing('soc_attack',limit=200,offset=offset)
        if not page:break
        rows.extend(page);offset+=len(page)
    return [r for r in rows if not query or query.casefold() in json.dumps(r).casefold()]

def attack_import(db,path,source,version):
    if not source.startswith(('https://attack.mitre.org/','https://github.com/mitre/','https://raw.githubusercontent.com/mitre/')):raise ValueError('Use a documented official MITRE ATT&CK source URL; importing does not fetch it')
    if not version.strip():raise ValueError('A dataset version/commit identifier is required')
    path=Path(path).expanduser().resolve(strict=True)
    if not path.is_file() or path.stat().st_size>64*1024**2:raise ValueError('ATT&CK bundle must be a regular JSON file under 64 MiB')
    bundle=json.loads(path.read_text(encoding='utf-8'));objects=bundle.get('objects') if isinstance(bundle,dict) else None
    if not isinstance(objects,list) or len(objects)>50000:raise ValueError('Expected a bounded STIX bundle')
    count=0
    for obj in objects:
        if obj.get('type')!='attack-pattern' or obj.get('revoked') or obj.get('x_mitre_deprecated'):continue
        ref=next((r for r in obj.get('external_references',[]) if r.get('source_name')=='mitre-attack' and re.fullmatch(r'T\d{4}(?:\.\d{3})?',r.get('external_id',''))),None)
        if not ref:continue
        db.create('soc_attack',{'technique_id':ref['external_id'],'name':obj.get('name',''),'tactic':', '.join(p.get('phase_name','') for p in obj.get('kill_chain_phases',[])),
             'description':str(obj.get('description',''))[:20000],'version':obj.get('x_mitre_version',version),'dataset':version,'source':source,'source_date':obj.get('modified',''),
             'guidance':'Consult the source technique and associated detection/mitigation objects. No detection content is invented.'})
        count+=1
    db.audit('soc.attack_imported',{'source':source,'version':version,'techniques':count});return {'imported':count,'source':source,'version':version}

class Rule(BaseModel):
    model_config=ConfigDict(extra='forbid')
    name:str=Field(min_length=1,max_length=200)
    description:str=Field(default='',max_length=3000)
    severity:str='Medium'
    confidence:float=Field(default=.5,ge=0,le=1)
    event_type:str=Field(default='',max_length=60)
    field:str='message'
    contains:list[str]=Field(default_factory=list,max_length=30)
    equals:str|int|None=None
    threshold:int=Field(default=1,ge=1,le=10000)
    window_seconds:int=Field(default=300,ge=1,le=86400)
    group_by:str='src_ip'
    distinct_field:str|None=None
    attack:list[str]=Field(default_factory=list,max_length=10)
    investigation:str=Field(default='Review linked event IDs, asset ownership and legitimate activity. Preserve evidence before deciding on containment.',max_length=5000)
    enabled:bool=True
    version:int=Field(default=1,ge=1)
    @model_validator(mode='after')
    def valid(self):
        if self.severity not in {'Critical','High','Medium','Low','Informational'}:raise ValueError('Invalid rule severity')
        allowed={'message','host','src_ip','dst_ip','username','event_id','event_type','fields.dst_port','fields.query','fields.url','fields.bytes_out','fields.process','fields.severity'}
        if self.field not in allowed or self.group_by not in {'src_ip','dst_ip','host','username'} or self.distinct_field not in {None,'username','dst_ip','fields.dst_port'}:raise ValueError('Unsupported rule field; executable expressions/regex are not allowed')
        if any(not isinstance(v,str) or not v or len(v)>500 for v in self.contains):raise ValueError('Rule contains literals must be 1–500 characters')
        if self.distinct_field and self.threshold<2:raise ValueError('Distinct threshold must be at least two')
        return self

BUILTINS=[
 Rule(name='Repeated authentication failures',event_type='auth_failure',threshold=5,attack=['T1110.001'],severity='Medium',confidence=.65),
 Rule(name='Password spraying pattern',event_type='auth_failure',threshold=5,distinct_field='username',attack=['T1110.003'],severity='High',confidence=.6),
 Rule(name='Potential port scan',event_type='network',threshold=12,distinct_field='fields.dst_port',attack=['T1046'],confidence=.55),
 Rule(name='Sudo policy/privilege indicator',event_type='sudo',contains=['nopasswd','/etc/sudoers','/etc/shadow','chmod +s'],attack=['T1548.003'],severity='High',confidence=.6),
 Rule(name='Suspicious process command',event_type='process',field='fields.process',contains=['-encodedcommand','frombase64string','curl |','wget |','/dev/tcp/','invoke-expression'],severity='High',confidence=.6),
 Rule(name='Persistence path indicator',contains=['/etc/cron','/etc/systemd/system','currentversion\\run','schtasks /create'],severity='Medium',confidence=.5),
 Rule(name='Web SQL injection indicator',event_type='web',field='fields.url',contains=['union select','union%20select','or%201=1','%27%20or','sleep(','../'],severity='Medium',confidence=.5),
 Rule(name='Web script injection indicator',event_type='web',field='fields.url',contains=['<script','%3cscript','javascript:','onerror='],severity='Medium',confidence=.5),
 Rule(name='Sensitive file access indicator',contains=['/etc/shadow','/.env','/.git/config','web.config','sam\\sam'],severity='Medium',confidence=.4),
 Rule(name='Malware/signature indicator',contains=['malware','trojan','ransomware','eicar'],severity='High',confidence=.5),
 Rule(name='Suspicious outbound destination indicator',event_type='network',field='fields.dst_port',equals=4444,severity='Medium',confidence=.3),
]

def field(event,name):
    value=event
    for key in name.split('.'):value=value.get(key) if isinstance(value,dict) else None
    return value

def import_rule(db,path):
    path=Path(path).expanduser().resolve(strict=True)
    if not path.is_file() or path.stat().st_size>128*1024:raise ValueError('Rule JSON/YAML must be under 128 KiB')
    if path.suffix.lower() in {'.yaml','.yml'}:
        try:import yaml
        except ImportError as exc:raise ValueError('Install PyYAML for the supported Sigma YAML subset') from exc
        raw=yaml.safe_load(path.read_text(encoding='utf-8'))
    else:raw=json.loads(path.read_text(encoding='utf-8'))
    if isinstance(raw,dict) and 'detection' in raw:
        # Intentionally narrow Sigma subset: one selection, one literal field condition.
        detection=raw['detection']
        if not isinstance(detection,dict) or detection.get('condition')!='selection' or set(detection)-{'selection','condition'}:raise ValueError('Sigma subset supports only condition: selection and one selection block; correlation/modifiers are not silently approximated')
        selection=detection['selection']
        if not isinstance(selection,dict) or len(selection)!=1:raise ValueError('Sigma subset supports exactly one literal field selector')
        key,value=next(iter(selection.items()));parts=key.split('|')
        if len(parts)>2 or len(parts)==2 and parts[1]!='contains':raise ValueError('Only the Sigma contains modifier is supported')
        aliases={'CommandLine':'fields.process','Image':'fields.process','EventID':'event_id','TargetUserName':'username','SourceIp':'src_ip','DestinationIp':'dst_ip'}
        selected=aliases.get(parts[0],parts[0])
        raw={'name':raw.get('title','Imported Sigma rule'),'description':raw.get('description',''),'severity':str(raw.get('level','medium')).title(),
             'field':selected,'contains':value if isinstance(value,list) else [value]} if len(parts)==2 else {'name':raw.get('title','Imported Sigma rule'),'field':selected,'equals':value}
    rule=Rule.model_validate(raw);known={r['technique_id'] for r in attack_search(db)}
    if any(a not in known for a in rule.attack):raise ValueError('Unknown ATT&CK IDs; import a versioned official dataset first')
    previous=[r for r in db.listing('soc_rule',limit=1000) if r['name']==rule.name]
    if previous:rule.version=max(r['version'] for r in previous)+1
    row=db.create('soc_rule',rule.model_dump());db.audit('soc.rule_imported',{'id':row['id'],'version':rule.version});return row

def rules(db):
    custom=db.listing('soc_rule',limit=1000);latest={}
    for r in custom:
        if r['name'] not in latest or r['version']>latest[r['name']]['version']:latest[r['name']]=r
    combined={r.name:{'id':'builtin-'+str(index),**r.model_dump()} for index,r in enumerate(BUILTINS)}
    combined.update(latest);return list(combined.values())

def set_rule_enabled(db,rid,enabled):
    row=next((r for r in rules(db) if r['id']==rid),None)
    if not row:raise ValueError('Detection rule not found')
    body={k:v for k,v in row.items() if k in Rule.model_fields};body['enabled']=enabled;body['version']+=1
    result=db.create('soc_rule',Rule.model_validate(body).model_dump());db.audit('soc.rule_tuned',{'id':result['id'],'enabled':enabled,'version':result['version']});return result

def emit(db,rule,rows,group,window,match_count=None):
    if not rows:return None
    ids=[e['id'] for e in rows[:100]];fingerprint=hashlib.sha256(json.dumps([rule['name'],rule['version'],group,window,ids],sort_keys=True).encode()).hexdigest()
    rid=str(uuid.uuid5(uuid.NAMESPACE_URL,'shadow-alert:'+fingerprint))
    with db.engine.begin() as connection:
        existing=connection.execute(text("SELECT id FROM workspace_records WHERE kind='soc_alert' AND json_extract(body,'$.fingerprint')=:hash LIMIT 1"),{'hash':fingerprint}).scalar_one_or_none()
    if existing:return None
    last=rows[-1];alert={'alert_id':rid,'timestamp':last['timestamp'],'severity':rule['severity'],'confidence':rule['confidence'],'rule':rule['name'],'rule_version':rule['version'],
        'fingerprint':fingerprint,'event_ids':ids,'source_event':ids[0],'event_count':match_count or len(rows),'asset':last['host'] or last['dst_ip'] or 'unknown','src_ip':last['src_ip'],'username':last['username'],
        'group':group,'window':window,'evidence':[{'event_id':e['id'],'timestamp':e['timestamp'],'message':e['message'][:500]} for e in rows[:20]],
        'attack':rule.get('attack',[]),'investigation':rule['investigation'],'status':'NEW','classification':'unverified_indicator','assigned_to':'',
        'history':[{'timestamp':datetime.now(timezone.utc).isoformat(),'status':'NEW','note':'Rule matched ingested event evidence; no attack success is implied.'}],
        'verification':'Suspicious pattern/hypothesis only. Validate context and outcome; this does not establish a successful attack.'}
    row=db.create('soc_alert',alert);db.audit('soc.alert_created',{'id':row['id'],'rule':rule['name'],'events':len(ids)});return row

def _detect(db,since=None,until=None,source_id=None,max_events=200000):
    if not 1<=max_events<=2000000:raise ValueError('Detection event cap must be 1–2,000,000')
    selected=[r for r in rules(db) if r['enabled']];created=processed=0;offset=0;buckets={};max_groups=5000;retained_bytes=0
    # Fixed time buckets bound memory and make repeat runs deterministic. Boundary effects are explicit.
    while processed<max_events:
        page=soc_logs.events(db,since=since,until=until,source_id=source_id,limit=min(500,max_events-processed),offset=offset)
        if not page:break
        offset+=len(page)
        for event in page:
            processed+=1;epoch=datetime.fromisoformat(event['timestamp']).timestamp()
            for rule in selected:
                if rule['event_type'] and event['event_type']!=rule['event_type']:continue
                value=field(event,rule['field'])
                if rule['equals'] is not None and str(value)!=str(rule['equals']):continue
                if rule['contains'] and not any(s.casefold() in str(value).casefold() for s in rule['contains']):continue
                group=str(event.get(rule['group_by']) or event['host'] or 'unknown');window=int(epoch//rule['window_seconds']);key=(rule['id'],group,window)
                if len(buckets)>=max_groups and key not in buckets:raise ValueError('Detection group cap reached; use a narrower source/time range')
                bucket=buckets.setdefault(key,{'rule':rule,'events':[],'distinct':set(),'count':0})
                bucket['count']+=1
                if len(bucket['events'])<100:
                    retained_bytes+=len(event['raw'].encode('utf-8'))+len(event['message'].encode('utf-8'))+1024
                    if retained_bytes>32*1024*1024:raise ValueError('Detection evidence memory cap reached; use a narrower time/source range')
                    bucket['events'].append(event)
                if rule['distinct_field']:
                    item=field(event,rule['distinct_field'])
                    if item not in (None,''):bucket['distinct'].add(str(item))
                count=len(bucket['distinct']) if rule['distinct_field'] else bucket['count']
                if count==rule['threshold']:
                    if emit(db,rule,bucket['events'],group,window,count):created+=1
            # Additional bounded heuristics with explicit evidence, never an outcome claim.
            extras=[]
            query=str(event['fields'].get('query') or '')
            if event['event_type']=='dns' and (len(query)>120 or any(len(label)>55 for label in query.split('.'))):extras.append(('Long DNS name indicator','Medium',.4))
            try:large=int(event['fields'].get('bytes_out') or 0)>100*1024*1024
            except (ValueError,TypeError):large=False
            if large:extras.append(('Large outbound-byte observation','Medium',.3))
            if event['event_type']=='auth_success' and event['src_ip']:
                with db.engine.connect() as c:
                    failures=c.execute(text("SELECT body FROM soc_events WHERE event_type='auth_failure' AND src_ip=:ip AND timestamp<:time AND timestamp>=:start ORDER BY timestamp DESC LIMIT 5"),{'ip':event['src_ip'],'time':event['timestamp'],'start':(datetime.fromisoformat(event['timestamp'])-timedelta(minutes=15)).isoformat(timespec='microseconds')}).all()
                if len(failures)>=5:extras.append(('Successful login after repeated failures','High',.6))
            for name,severity,confidence in extras:
                rule=Rule(name=name,severity=severity,confidence=confidence).model_dump()
                evidence=[json.loads(r[0]) for r in failures]+[event] if name=='Successful login after repeated failures' else [event]
                if emit(db,rule,evidence,event['src_ip'] or event['host'],int(epoch//300)):created+=1
    record=db.create('soc_detection_run',{'status':'completed','processed':processed,'alerts_created':created,'rules':len(selected),'rule_versions':[{'id':r['id'],'name':r['name'],'version':r['version']} for r in selected],'since':since,'until':until,'source_id':source_id,
        'limited':processed==max_events,'notice':'Fixed UTC time buckets are bounded heuristics and can miss patterns straddling a bucket boundary. Match/confidence is not proof of compromise.'})
    db.audit('soc.detection_completed',{'id':record['id'],'processed':processed,'alerts':created});return record

def detect(db,since=None,until=None,source_id=None,max_events=200000):
    try:return _detect(db,since,until,source_id,max_events)
    except Exception as exc:
        failed=db.create('soc_detection_run',{'status':'failed','error':str(exc)[:1000],'since':since,'until':until,'source_id':source_id,
            'notice':'Any alerts emitted before failure remain evidence-linked; this run did not complete.'})
        db.audit('soc.detection_failed',{'id':failed['id'],'error':str(exc)[:300]});raise
