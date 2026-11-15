"""Streaming defensive log normalization. No live host monitoring or network access."""
import csv
import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime,timezone
from pathlib import Path
from sqlalchemy import text
from defusedxml import ElementTree as ET

MAX_LINE=128*1024
MAX_EXPORT=16*1024*1024

def stamp(value=None,year=None):
    assumed=''
    if isinstance(value,(int,float)) or isinstance(value,str) and re.fullmatch(r'\d{10}(?:\.\d+)?',value):
        result=datetime.fromtimestamp(float(value),timezone.utc)
    elif value:
        raw=str(value).strip()
        try:result=datetime.fromisoformat(raw.replace('Z','+00:00'))
        except ValueError:
            result=None
            for fmt in ['%d/%b/%Y:%H:%M:%S %z','%b %d %H:%M:%S']:
                try:
                    if '%Y' not in fmt:
                        result=datetime.strptime(raw+' '+str(year or datetime.now(timezone.utc).year),fmt+' %Y');assumed='Syslog year supplied by import or current UTC year'
                    else:result=datetime.strptime(raw,fmt)
                    break
                except ValueError:pass
            if result is None:raise ValueError('Unrecognized event timestamp')
            if result.year==1900:
                result=result.replace(year=year or datetime.now(timezone.utc).year);assumed='Syslog year supplied by import or current UTC year'
        if result.tzinfo is None:result=result.replace(tzinfo=timezone.utc);assumed+='; timezone assumed UTC'
    else:result=datetime.now(timezone.utc);assumed='Missing timestamp; ingestion UTC time used'
    return result.astimezone(timezone.utc).isoformat(timespec='microseconds'),assumed.strip('; ')

def ip(value):
    try:return str(ipaddress.ip_address(str(value).strip('[]')))
    except ValueError:return ''

def nested(data,*keys):
    for key in keys:
        value=data
        for part in key.split('.'):
            value=value.get(part) if isinstance(value,dict) else None
        if value not in (None,'','-'):return value
    return None

def normalize_event(data,raw='',year=None):
    if not isinstance(data,dict):raise ValueError('Structured event must be an object')
    source=dict(data)
    if isinstance(data.get('Event'),dict):data=data['Event']
    if isinstance(data.get('EventData'),dict):
        detail=data['EventData'];data={**data,**{k:v for k,v in detail.items() if k!='Data'}}
        for entry in detail.get('Data',[]) if isinstance(detail.get('Data'),list) else []:
            if isinstance(entry,dict) and (entry.get('@Name') or entry.get('Name')):data[entry.get('@Name') or entry['Name']]=entry.get('#text') or entry.get('value','')
    timestamp,assumption=stamp(nested(data,'timestamp','@timestamp','time','ts','TimeCreated.SystemTime','System.TimeCreated.SystemTime','System.TimeCreated.@SystemTime','date'),year)
    message=str(nested(data,'message','msg','Message','event.original','alert.signature','CommandLine','process.command_line') or raw or json.dumps(data,ensure_ascii=False))[:32768]
    src=ip(nested(data,'src_ip','source.ip','src','client_ip','remote_addr','id.orig_h','SourceIp','IpAddress','source_address') or '')
    dst=ip(nested(data,'dest_ip','dst_ip','destination.ip','dst','id.resp_h','DestinationIp','destination_address') or '')
    username=str(nested(data,'username','user.name','user','TargetUserName','SubjectUserName','account') or '')[:200]
    host=str(nested(data,'host.name','hostname','host','Computer','System.Computer') or '')[:253]
    event_value=nested(data,'event_id','EventID','event.code','System.EventID')
    event_id=str(event_value.get('#text','') if isinstance(event_value,dict) else event_value or '')
    event_type=str(nested(data,'event_type','event.category','type') or 'generic')[:60]
    lowered=message.lower()
    if event_id=='4625' or any(s in lowered for s in ['failed password','authentication failure','login failed','failed login']):event_type='auth_failure'
    elif event_id=='4624' or any(s in lowered for s in ['accepted password','accepted publickey','successful login','login succeeded']):event_type='auth_success'
    elif event_id in {'4688','1'} and any(nested(data,k) for k in ['CommandLine','Image','process.command_line']) or 'process' in event_type:event_type='process'
    elif 'sudo:' in lowered or 'sudo[' in lowered:event_type='sudo'
    elif event_type=='alert' and isinstance(data.get('alert'),dict):event_type='ids_alert'
    elif event_type=='dns' or nested(data,'dns.query','query','query_name'):event_type='dns'
    elif nested(data,'url','http.url','request','uri','path') or event_type in {'http','access'}:event_type='web'
    elif event_type in {'flow','netflow','conn','connection','firewall','vpn','tls'} or dst:event_type='network'
    if not src:
        found=re.search(r'\bfrom\s+([0-9a-fA-F:.]+)',message)
        if found:src=ip(found[1])
    if not username:
        found=re.search(r'(?:for (?:invalid user )?|user[= ])([A-Za-z0-9_.@\\-]+)',message)
        if found:username=found[1][:200]
    fields={'dst_port':nested(data,'dest_port','dst_port','destination.port','id.resp_p','DestinationPort','dpt'),
            'src_port':nested(data,'src_port','source.port','id.orig_p','spt'),'protocol':nested(data,'proto','protocol','network.transport'),
            'query':nested(data,'dns.rrname','dns.query','query','query_name'),'url':nested(data,'url','http.url','request','uri','path'),
            'status':nested(data,'status','http.status','status_code'),'bytes_out':nested(data,'bytes_out','orig_bytes','flow.bytes_toserver','sent_bytes'),
            'process':nested(data,'process.command_line','CommandLine','command','process','Image'),'severity':nested(data,'alert.severity','severity','level')}
    return {'timestamp':timestamp,'timestamp_assumption':assumption,'event_type':event_type,'host':host,'src_ip':src,'dst_ip':dst,'username':username,
            'event_id':event_id,'message':message,'fields':fields,'raw':raw[:32768] or json.dumps(source,ensure_ascii=False)[:32768],
            'verification':'Recorded event observation; no attack outcome inferred.'}

SYSLOG=re.compile(r'^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<message>.*)$')
ACCESS=re.compile(r'^(?P<src>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^]]+)\]\s+"(?P<method>\S+)\s+(?P<url>.*?)\s+HTTP/[^\"]+"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)')

def parse_line(line,format='auto',year=None,zeek_fields=None):
    line=line.strip('\r\n')
    if not line.strip():return None
    if format in {'json','jsonl','suricata'} or format=='auto' and line.lstrip().startswith('{'):return normalize_event(json.loads(line),line,year)
    if format=='zeek':
        if not zeek_fields:raise ValueError('Zeek TSV requires a #fields header or JSON export')
        return normalize_event(dict(zip(zeek_fields,line.split('\t'))),line,year)
    match=ACCESS.match(line)
    if match:
        return normalize_event({'timestamp':match['time'],'src_ip':match['src'],'username':'' if match['user']=='-' else match['user'],'event_type':'web','url':match['url'],'status':int(match['status']),'message':line},line,year)
    match=SYSLOG.match(line)
    if match:return normalize_event({'timestamp':match['time'],'host':match['host'],'message':match['message']},line,year)
    # ISO/RFC5424-ish exports and firewall key=value records are retained as structured observations.
    timestamp_match=re.search(r'\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?',line)
    fields={key:value.strip('"') for key,value in re.findall(r'\b([\w.]+)=("[^"]*"|\S+)',line)}
    fields.update({'timestamp':timestamp_match[0] if timestamp_match else None,'message':line})
    if 'SRC' in fields:fields['src_ip']=fields['SRC']
    if 'DST' in fields:fields['dst_ip']=fields['DST']
    if 'DPT' in fields:fields['dst_port']=fields['DPT']
    return normalize_event(fields,line,year)

def iter_events(path,format='auto',year=None):
    suffix=path.suffix.lower()
    if suffix=='.json' and format in {'auto','json'}:
        with path.open(encoding='utf-8-sig',errors='replace') as probe:first=probe.read(256).lstrip()
        if first.startswith('['):
            if path.stat().st_size>MAX_EXPORT:raise ValueError('JSON array export exceeds 16 MiB; use streaming JSONL')
            rows=json.loads(path.read_text(encoding='utf-8-sig'))
            if not isinstance(rows,list):raise ValueError('Expected a JSON event array')
            for ordinal,row in enumerate(rows,1):
                try:yield ordinal,normalize_event(row,json.dumps(row),year),None
                except (ValueError,TypeError) as exc:yield ordinal,None,str(exc)[:200]
            return
    if format=='windows_xml' or suffix=='.xml':
        if path.stat().st_size>MAX_EXPORT:raise ValueError('Windows XML export exceeds 16 MiB; split it or use JSON/CSV')
        try:root=ET.fromstring(path.read_bytes())
        except Exception as exc:raise ValueError('Windows XML export is malformed or contains forbidden entities') from exc
        events=[root] if root.tag.endswith('Event') else list(root)
        for ordinal,event in enumerate(events,1):
            try:
                data={}
                for node in event.iter():
                    name=node.tag.rsplit('}',1)[-1]
                    if name=='TimeCreated':data['timestamp']=node.get('SystemTime')
                    elif name=='Data' and node.get('Name'):data[node.get('Name')]=node.text or ''
                    elif name in {'EventID','Computer'}:data[name]=node.text or ''
                yield ordinal,normalize_event(data,json.dumps(data),year),None
            except (ValueError,TypeError) as exc:yield ordinal,None,str(exc)
        return
    if format=='csv' or suffix=='.csv':
        csv.field_size_limit(MAX_LINE)
        with path.open(encoding='utf-8-sig',errors='replace',newline='') as stream:
            for ordinal,row in enumerate(csv.DictReader(stream),2):
                try:yield ordinal,normalize_event(row,json.dumps(row),year),None
                except (ValueError,TypeError) as exc:yield ordinal,None,str(exc)
        return
    if suffix=='.evtx':raise ValueError('Raw EVTX is not parsed. Export Windows events as JSON, CSV or XML.')
    with path.open(encoding='utf-8-sig',errors='replace') as stream:
        ordinal=0;zeek_fields=None
        while True:
            line=stream.readline(MAX_LINE+1)
            if not line:break
            ordinal+=1
            if len(line)>MAX_LINE:
                while line and not line.endswith('\n'):line=stream.readline(MAX_LINE+1)
                yield ordinal,None,'Line exceeds 128 KiB';continue
            if line.startswith('#fields'):zeek_fields=line.rstrip().split('\t')[1:];continue
            if line.startswith('#'):continue
            try:yield ordinal,parse_line(line,'zeek' if zeek_fields else format,year,zeek_fields),None
            except (ValueError,TypeError,OverflowError) as exc:yield ordinal,None,str(exc)[:200]

def ingest(db,value,format='auto',year=None,on_progress=None):
    if format not in {'auto','json','jsonl','suricata','zeek','csv','syslog','windows_xml'}:raise ValueError('Unsupported log export format')
    path=Path(value).expanduser().resolve(strict=True)
    if not path.is_file():raise ValueError('Select a regular log file')
    hasher=hashlib.sha256()
    with path.open('rb') as stream:
        while block:=stream.read(1024*1024):hasher.update(block)
    digest=hasher.hexdigest();source_id=str(uuid.uuid5(uuid.NAMESPACE_URL,'shadow-soc:'+digest+':'+format+':'+str(year)))
    counts={'imported':0,'duplicates':0,'invalid':0,'blank':0};batch=[];errors=[]
    def flush():
        if not batch:return
        with db.engine.begin() as connection:
            for ordinal,event in batch:
                event_hash=hashlib.sha256((source_id+':'+str(ordinal)).encode()).hexdigest();rid=str(uuid.uuid5(uuid.NAMESPACE_URL,event_hash))
                body={**event,'id':rid,'source_id':source_id,'source_file':path.name,'source_line':ordinal,'source_sha256':digest}
                added=connection.execute(text('INSERT OR IGNORE INTO soc_events(id,timestamp,source_id,event_hash,event_type,host,src_ip,dst_ip,username,body) VALUES (:id,:timestamp,:source_id,:hash,:event_type,:host,:src_ip,:dst_ip,:username,:body)'),{**{key:body[key] for key in ['id','timestamp','source_id','event_type','host','src_ip','dst_ip','username']},'hash':event_hash,'body':json.dumps(body,ensure_ascii=False)}).rowcount
                counts['imported' if added else 'duplicates']+=1
        batch.clear()
    for ordinal,event,error in iter_events(path,format,year):
        if error:
            counts['invalid']+=1
            if len(errors)<20:errors.append({'line':ordinal,'error':error})
        elif event is None:counts['blank']+=1
        else:batch.append((ordinal,event))
        if len(batch)>=500:flush()
        if on_progress and ordinal%1000==0:on_progress(ordinal,counts)
    flush()
    record=db.create('soc_ingestion',{'source_id':source_id,'name':path.name,'sha256':digest,'format':format,'year':year,**counts,'errors':errors,'notice':'Passive local import. Missing timestamps/timezones are explicitly marked; raw EVTX is unsupported.'})
    db.audit('soc.logs_ingested',{'id':record['id'],'source_id':source_id,**counts});return record

def events(db,search='',event_type='',src_ip='',host='',since=None,until=None,limit=100,offset=0,source_id=None):
    if not 1<=limit<=1000 or offset<0:raise ValueError('Event limit must be 1–1000 and offset nonnegative')
    clauses=[];params={'limit':limit,'offset':offset}
    for column,value in [('event_type',event_type),('src_ip',src_ip),('host',host),('source_id',source_id)]:
        if value:clauses.append(column+'=:'+column);params[column]=value
    if since:clauses.append('timestamp>=:since');params['since']=stamp(since)[0]
    if until:clauses.append('timestamp<=:until');params['until']=stamp(until)[0]
    if search:clauses.append("body LIKE :query ESCAPE '\\'");params['query']='%'+search.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
    where=' WHERE '+' AND '.join(clauses) if clauses else ''
    with db.engine.connect() as connection:
        rows=connection.execute(text('SELECT body FROM soc_events'+where+' ORDER BY timestamp,id LIMIT :limit OFFSET :offset'),params)
        return [json.loads(row[0]) for row in rows]

def event(db,rid):
    with db.engine.connect() as connection:body=connection.execute(text('SELECT body FROM soc_events WHERE id=:id'),{'id':rid}).scalar_one_or_none()
    if body is None:raise ValueError('SOC event not found')
    return json.loads(body)

def stats(db):
    with db.engine.connect() as connection:
        total=connection.execute(text('SELECT count(*) FROM soc_events')).scalar_one()
        types=dict(connection.execute(text('SELECT event_type,count(*) FROM soc_events GROUP BY event_type')).all())
        bounds=connection.execute(text('SELECT min(timestamp),max(timestamp) FROM soc_events')).one()
    return {'events':total,'event_types':types,'first_event':bounds[0],'last_event':bounds[1]}
