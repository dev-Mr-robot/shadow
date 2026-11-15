"""Bounded, scoped reconnaissance with one-use approvals and persistent history.

Only the root HTTP resource is requested. Discovered links are observations, never
followed. DNS resolution and HTTP probing are active operations requiring approval.
"""
import asyncio
import csv
import hashlib
import io
import ipaddress
import json
import os
import socket
import time
import uuid
import psutil
from datetime import datetime,timezone
from html.parser import HTMLParser
from urllib.parse import urljoin,urlsplit

import httpx
from sqlalchemy import text
from .scope import normalize as scope_normalize,check as scope_check

MAX_BODY=256*1024
MAX_LINE=4096

def now():return datetime.now(timezone.utc).isoformat()

class ScopePolicy:
    """Compile exact domains/IPs once for bulk imports instead of quadratic scans."""
    def __init__(self,engagement):
        self.exact=set();self.excluded=set();self.networks=[];self.excluded_networks=[]
        for source,exact,networks in [(engagement['scope'],self.exact,self.networks),(engagement['exclusions'],self.excluded,self.excluded_networks)]:
            for entry in source:
                if '/' in entry:networks.append(ipaddress.ip_network(entry,strict=False))
                else:exact.add(entry)
    def allows(self,host):
        if host in self.excluded:return False
        try:address=ipaddress.ip_address(host)
        except ValueError:return host in self.exact
        if any(address in network for network in self.excluded_networks):return False
        return host in self.exact or any(address in network for network in self.networks)

def allowed(host,engagement):
    try:return scope_check(host,engagement)['in_scope']
    except (ValueError,UnicodeError):return False

def normalize(value):
    value=value.strip()
    if not value or value.startswith('#'):return None
    if len(value)>2048:raise ValueError('Asset line exceeds 2048 characters')
    if '://' not in value and '/' in value:
        try:ipaddress.ip_network(value,strict=False)
        except ValueError:pass
        else:raise ValueError('Import individual IPs, not a CIDR range')
    # Literal IPv6 needs no URL parsing and may have no brackets.
    try:return str(ipaddress.ip_address(value.rstrip('.')))
    except ValueError:pass
    parsed=urlsplit(value if '://' in value else '//'+value)
    if parsed.username or parsed.password:raise ValueError('Credentials in an asset URL are not accepted')
    if parsed.scheme and parsed.scheme not in {'http','https'}:raise ValueError('Only HTTP URLs or hostnames are accepted')
    if not parsed.hostname:raise ValueError('Missing hostname')
    host=scope_normalize(parsed.hostname)
    if '/' in host:raise ValueError('Import individual hosts, not CIDRs')
    return host

def _query(db,sql,params=None):
    with db.engine.connect() as connection:return list(connection.execute(text(sql),params or {}).mappings())

def import_assets(db,eid,path):
    engagement=db.engagement(eid);policy=ScopePolicy(engagement)
    counts={'imported':0,'duplicates':0,'excluded':0,'invalid':0,'blank':0}
    path=__import__('pathlib').Path(path).expanduser().resolve(strict=True)
    if not path.is_file():raise ValueError('Select a regular input file')
    with path.open(encoding='utf-8-sig',errors='replace') as source:
        batch=[]
        def flush():
            if not batch:return
            with db.engine.begin() as connection:
                for host in batch:
                    body={'host':host,'state':'pending','addresses':[],'http':[],'errors':[],'interesting':[]}
                    result=connection.execute(text('INSERT OR IGNORE INTO recon_assets(id,engagement,host,state,body,updated) VALUES (:id,:eid,:host,:state,:body,:stamp)'),{'id':str(uuid.uuid4()),'eid':eid,'host':host,'state':'pending','body':json.dumps(body),'stamp':now()})
                    counts['imported' if result.rowcount else 'duplicates']+=1
            batch.clear()
        while True:
            line=source.readline(MAX_LINE+1)
            if not line:break
            if len(line)>MAX_LINE and not line.endswith('\n'):
                while True:
                    remainder=source.readline(MAX_LINE+1)
                    if not remainder or remainder.endswith('\n'):break
                counts['invalid']+=1;continue
            try:host=normalize(line)
            except (ValueError,UnicodeError):counts['invalid']+=1;continue
            if not host:counts['blank']+=1;continue
            if not policy.allows(host):counts['excluded']+=1;continue
            batch.append(host)
            if len(batch)>=500:flush()
        flush()
    db.audit('recon.imported',{'engagement_id':eid,'file_name':path.name,**counts})
    return counts

def list_assets(db,eid,search='',state='',limit=100,offset=0,sort='host'):
    policy=ScopePolicy(db.engagement(eid))
    if not 1<=limit<=1000 or offset<0:raise ValueError('Limit must be 1–1000; offset nonnegative')
    order={'host':'host','priority':"json_array_length(json_extract(body,'$.interesting')) DESC,host",'updated':'updated DESC'}.get(sort)
    if not order:raise ValueError('Sort must be host, priority or updated')
    rows=_query(db,'SELECT * FROM recon_assets WHERE engagement=:eid AND host LIKE :search ESCAPE \'\\\' AND (:state=\'\' OR state=:state) ORDER BY '+order+' LIMIT :limit OFFSET :offset',{'eid':eid,'search':'%'+search.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%','state':state,'limit':limit,'offset':offset})
    return [{**json.loads(r['body']),'id':r['id'],'updated':r['updated'],'in_scope':policy.allows(r['host'])} for r in rows]

def stats(db,eid):
    db.engagement(eid)
    row=_query(db,"SELECT COUNT(*) AS total_assets, SUM(CASE WHEN json_array_length(json_extract(body,'$.addresses'))>0 THEN 1 ELSE 0 END) AS resolved_assets, SUM(CASE WHEN json_array_length(json_extract(body,'$.http'))>0 THEN 1 ELSE 0 END) AS live_http_assets, SUM(CASE WHEN json_array_length(json_extract(body,'$.interesting'))>0 THEN 1 ELSE 0 END) AS interesting_assets, SUM(CASE WHEN state='failed' THEN 1 ELSE 0 END) AS failed_assets, SUM(CASE WHEN state='pending' THEN 1 ELSE 0 END) AS pending_assets FROM recon_assets WHERE engagement=:eid",{'eid':eid})[0]
    result={key:int(value or 0) for key,value in row.items()}
    # Distinct technology inventory stays SQL-side rather than collecting all assets.
    tech=_query(db,"SELECT COUNT(DISTINCT CAST(t.value AS TEXT)) AS count FROM recon_assets a, json_each(a.body,'$.http') h, json_each(h.value,'$.technologies') t WHERE a.engagement=:eid",{'eid':eid})
    result['unique_technologies']=int(tech[0]['count']);return result

def _eligible(db,eid,resume):
    last=''
    while True:
        rows=_query(db,"SELECT host FROM recon_assets WHERE engagement=:eid AND host>:last AND (:resume=0 OR state!='complete') ORDER BY host LIMIT 500",{'eid':eid,'last':last,'resume':int(resume)})
        if not rows:return
        for row in rows:last=row['host'];yield last

def _plan(db,eid,concurrency,timeout,retries,rate,resume):
    db.engagement(eid)
    if not 1<=concurrency<=32 or not 1<=timeout<=30 or not 0<=retries<=2 or not .1<=rate<=20:
        raise ValueError('Concurrency 1–32, timeout 1–30s, retries 0–2, rate 0.1–20 requests/s')
    hasher=hashlib.sha256();count=0
    for host in _eligible(db,eid,resume):hasher.update((host+'\n').encode());count+=1
    if not count:raise ValueError('No eligible assets; import first, or disable resume to repeat completed assets')
    engagement=db.engagement(eid)
    scope_digest=hashlib.sha256(json.dumps({'scope':engagement['scope'],'exclusions':engagement['exclusions'],'authorization':engagement['authorization'],'rules':engagement.get('rules','')},sort_keys=True).encode()).hexdigest()
    return {'engagement_id':eid,'count':count,'asset_digest':hasher.hexdigest(),'scope_digest':scope_digest,'concurrency':concurrency,'timeout':timeout,'retries':retries,'rate':rate,'resume':resume,
            'operations':'Resolve listed DNS names; GET / on HTTPS:443 and HTTP:80 only. No redirects, crawling, extra paths or certificate bypass. Response cap 256 KiB.',
            'scope_policy':'Both hostname and resolved destination IP/CIDR must be explicitly authorized; exclusions win. DNS requests use the system resolver. HTTP connects to one pinned allowed address with original Host/SNI.'}

def preview(db,eid,concurrency=8,timeout=8,retries=0,rate=4,resume=True):
    recover_stale(db)
    body=_plan(db,eid,concurrency,timeout,retries,rate,resume)
    body.update({'digest':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest(),'status':'pending_approval','expires':time.time()+600,'completed':0})
    rid=str(uuid.uuid4());stamp=now();body['id']=rid;body['created']=stamp;body['updated']=stamp
    with db.engine.begin() as c:
        c.execute(text('INSERT INTO recon_runs(id,engagement,status,body,created,updated) VALUES (:id,:eid,:status,:body,:created,:created)'),{'id':rid,'eid':eid,'status':body['status'],'body':json.dumps(body),'created':stamp})
        c.execute(text("INSERT INTO recon_targets(run_id,host) SELECT :rid,host FROM recon_assets WHERE engagement=:eid AND (:resume=0 OR state!='complete')"),{'rid':rid,'eid':eid,'resume':int(resume)})
    db.audit('recon.previewed',{'id':rid,'count':body['count'],'digest':body['digest']});return body

def get_run(db,rid):
    rows=_query(db,'SELECT body FROM recon_runs WHERE id=:id',{'id':rid})
    if not rows:raise ValueError('Reconnaissance run not found')
    return json.loads(rows[0]['body'])

def runs(db,eid,limit=50):
    if not 1<=limit<=500:raise ValueError('Limit must be 1–500')
    return [json.loads(r['body']) for r in _query(db,'SELECT body FROM recon_runs WHERE engagement=:eid ORDER BY created DESC LIMIT :limit',{'eid':eid,'limit':limit})]

def recover_stale(db):
    recovered=[]
    for record in _query(db,"SELECT id,body FROM recon_runs WHERE status='running'"):
        body=json.loads(record['body']);pid=body.get('owner_pid');started=body.get('owner_started')
        try:alive=bool(pid) and psutil.pid_exists(pid) and (started is None or abs(psutil.Process(pid).create_time()-started)<.01)
        except (psutil.Error,OSError):alive=False
        if not alive:_update_run(db,record['id'],{'status':'interrupted'});recovered.append(record['id'])
    return recovered

def _update_run(db,rid,patch):
    with db.engine.begin() as c:
        body=json.loads(c.execute(text('SELECT body FROM recon_runs WHERE id=:id'),{'id':rid}).scalar_one());body.update(patch);body['updated']=now()
        c.execute(text('UPDATE recon_runs SET body=:body,status=:status,updated=:stamp WHERE id=:id'),{'id':rid,'body':json.dumps(body),'status':body['status'],'stamp':body['updated']})
    return body

def cancel_preview(db,rid):
    row=get_run(db,rid)
    row.update({'status':'cancelled','updated':now()})
    with db.engine.begin() as c:
        changed=c.execute(text("UPDATE recon_runs SET body=:body,status='cancelled',updated=:stamp WHERE id=:id AND status='pending_approval'"),{'id':rid,'body':json.dumps(row),'stamp':row['updated']}).rowcount
        if changed!=1:raise ValueError('Only unstarted previews may be cancelled this way; interrupt the running process to cancel active work')
    db.audit('recon.preview_cancelled',{'id':rid});return row

class Page(HTMLParser):
    def __init__(self):super().__init__();self.in_title=False;self.title='';self.links=[]
    def handle_starttag(self,tag,attrs):
        if tag=='title':self.in_title=True
        if tag=='a':
            link=dict(attrs).get('href')
            if link and len(self.links)<100 and len(link)<=2048:self.links.append(link)
    def handle_endtag(self,tag):
        if tag=='title':self.in_title=False
    def handle_data(self,data):
        if self.in_title:self.title=(self.title+data)[:500]

class RateLimiter:
    def __init__(self,rate):self.interval=1/rate;self.next=0.;self.lock=asyncio.Lock()
    async def wait(self):
        async with self.lock:
            current=asyncio.get_running_loop().time();delay=max(0,self.next-current)
            if delay:await asyncio.sleep(delay)
            self.next=asyncio.get_running_loop().time()+self.interval

async def resolve(host,timeout):
    try:return [str(ipaddress.ip_address(host))]
    except ValueError:pass
    records=await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host,None,type=socket.SOCK_STREAM),timeout)
    return list(dict.fromkeys(r[4][0] for r in records))[:8]

def _destination(address,engagement):
    ip=ipaddress.ip_address(address)
    return not(ip.is_multicast or ip.is_unspecified or ip.is_reserved) and allowed(str(ip),engagement)

async def probe(host,addresses,timeout,limiter,engagement_check=None,transport=None):
    observations=[];errors=[]
    address=addresses[0];literal='['+address+']' if ':' in address else address
    host_header='['+host+']' if ':' in host else host
    for scheme,port in [('https',443),('http',80)]:
        try:
            await limiter.wait()
            if engagement_check and not engagement_check(address):raise ValueError('Scope changed; request cancelled before connection')
            async with asyncio.timeout(timeout),httpx.AsyncClient(timeout=timeout,trust_env=False,follow_redirects=False,transport=transport) as client:
                async with client.stream('GET',f'{scheme}://{literal}:{port}/',headers={'Host':host_header,'User-Agent':'SHADOW-authorized-research/0.2','Accept-Encoding':'identity'},extensions={'sni_hostname':host}) as response:
                    data=bytearray();truncated=False
                    async for part in response.aiter_raw():
                        data.extend(part[:max(0,MAX_BODY-len(data))])
                        if len(data)>=MAX_BODY:truncated=True;break
                    parser=Page()
                    encoded=bool(response.headers.get('content-encoding') and response.headers['content-encoding'].lower()!='identity')
                    if not encoded:parser.feed(bytes(data).decode('utf-8',errors='replace'))
                    technologies=[name+': '+response.headers[name][:300] for name in ['server','x-powered-by'] if response.headers.get(name)]
                    endpoints=[]
                    for link in parser.links:
                        parsed=urlsplit(urljoin(f'{scheme}://{host_header}/',link))
                        if parsed.scheme in {'http','https'} and parsed.hostname==host:endpoints.append(parsed.path or '/')
                    # Sensitive headers are never stored; response request IDs/cookies can contain secrets.
                    headers={k:v[:1000] for k,v in response.headers.items() if k.lower() in {'server','x-powered-by','content-type','content-length','content-encoding','cache-control','vary','access-control-allow-origin','strict-transport-security','content-security-policy','x-content-type-options'}}
                    observations.append({'scheme':scheme,'status':response.status_code,'title':parser.title.strip(),'technologies':technologies,'headers':headers,'endpoints':sorted(set(endpoints)),
                        'redirect':response.headers.get('location','')[:2000],'connected_ip':address,'body_truncated':truncated,'encoded_body_omitted':encoded})
        except asyncio.CancelledError:raise
        except Exception as exc:errors.append({'scheme':scheme,'error':type(exc).__name__,'detail':str(exc)[:300]})
    return observations,errors

def prioritize(observations):
    leads=[]
    for row in observations:
        if row['status'] in {401,403}:leads.append({'reason':f"{row['scheme'].upper()} returned {row['status']}; review intended access boundaries with authorized test identities.",'verification':'unverified lead'})
        if row['status']>=500:leads.append({'reason':f"{row['scheme'].upper()} server error {row['status']} observed; investigate reproducibility and context.",'verification':'observation'})
        for endpoint in row['endpoints']:
            if any(word in endpoint.lower() for word in ['admin','debug','api','upload','login']):leads.append({'reason':f'Observed link {endpoint}; useful manual review candidate. No vulnerability is confirmed.','verification':'unverified lead'})
    return leads[:30]

def _checkpoint(db,eid,rid,body):
    with db.engine.begin() as c:
        c.execute(text('UPDATE recon_assets SET body=:body,state=:state,updated=:stamp WHERE engagement=:eid AND host=:host'),{'body':json.dumps(body),'state':body['state'],'stamp':now(),'eid':eid,'host':body['host']})
        c.execute(text('INSERT INTO recon_snapshots(run_id,host,body) VALUES (:rid,:host,:body)'),{'rid':rid,'host':body['host'],'body':json.dumps(body)})

async def execute(db,run_id,digest,on_progress=None):
    recover_stale(db)
    plan=get_run(db,run_id)
    if plan['status']!='pending_approval' or plan['expires']<time.time() or plan['digest']!=digest:raise ValueError('Invalid, expired or already consumed reconnaissance preview')
    fresh=_plan(db,plan['engagement_id'],plan['concurrency'],plan['timeout'],plan['retries'],plan['rate'],plan['resume'])
    if hashlib.sha256(json.dumps(fresh,sort_keys=True).encode()).hexdigest()!=digest:raise ValueError('Scope or asset list changed; create and approve a new preview')
    approved_hash=hashlib.sha256();approved_count=0
    for host in _run_targets(db,run_id):approved_hash.update((host+'\n').encode());approved_count+=1
    if approved_hash.hexdigest()!=plan['asset_digest'] or approved_count!=plan['count']:raise ValueError('Preview target snapshot changed; create a new preview')
    with db.engine.begin() as c:
        # Serialize the decision so a second process cannot consume the same approval.
        body={**plan,'status':'running','owner_pid':os.getpid(),'owner_started':psutil.Process().create_time(),'updated':now()}
        changed=c.execute(text("UPDATE recon_runs SET status='running',body=:body,updated=:stamp WHERE id=:id AND status='pending_approval' AND NOT EXISTS (SELECT 1 FROM recon_runs WHERE status='running')"),{'id':run_id,'body':json.dumps(body),'stamp':body['updated']}).rowcount
        if changed!=1:raise ValueError('Preview was already consumed or another reconnaissance run is active')
    db.audit('recon.approved',{'id':run_id,'digest':digest});eid=plan['engagement_id'];completed=0;limiter=RateLimiter(plan['rate']);pending=set();status='completed'
    async def worker(host):
        nonlocal completed
        result={'host':host,'state':'failed','addresses':[],'http':[],'errors':[],'interesting':[],'observed_at':now(),'run_id':run_id}
        engagement=db.engagement(eid)
        if not allowed(host,engagement):result['errors']=[{'error':'ScopeChanged','detail':'Host is no longer in scope'}]
        else:
            for attempt in range(plan['retries']+1):
                try:
                    await limiter.wait()
                    # Recheck before DNS, not only before HTTP.
                    engagement=db.engagement(eid)
                    if not allowed(host,engagement):raise ValueError('Host removed from scope')
                    addresses=await resolve(host,plan['timeout']);result['addresses']=addresses
                    permitted=[a for a in addresses if _destination(a,engagement)]
                    if not permitted:raise ValueError('No resolved destination is explicitly covered by authorized IP/CIDR scope')
                    def still_allowed(address):
                        current=db.engagement(eid)
                        return allowed(host,current) and _destination(address,current)
                    result['http'],result['errors']=await probe(host,permitted,plan['timeout'],limiter,still_allowed)
                    result['state']='complete' if result['http'] else 'failed'
                    if result['http'] or attempt==plan['retries']:break
                except asyncio.CancelledError:raise
                except Exception as exc:result['errors']=[{'error':type(exc).__name__,'detail':str(exc)[:300]}]
                if attempt<plan['retries']:await asyncio.sleep(.5)
            result['interesting']=prioritize(result['http'])
        _checkpoint(db,eid,run_id,result);completed+=1
        _update_run(db,run_id,{'completed':completed})
        if on_progress:on_progress(completed,plan['count'],host)
    try:
        for host in _run_targets(db,run_id):
            pending.add(asyncio.create_task(worker(host)))
            if len(pending)>=plan['concurrency']:
                done,pending=await asyncio.wait(pending,return_when=asyncio.FIRST_COMPLETED)
                for task in done:task.result()
        if pending:await asyncio.gather(*pending)
    except asyncio.CancelledError:status='cancelled';raise
    except BaseException:status='failed';raise
    finally:
        for task in pending:task.cancel()
        if pending:await asyncio.gather(*pending,return_exceptions=True)
        _update_run(db,run_id,{'status':status,'completed':completed});db.audit('recon.finished',{'id':run_id,'status':status,'completed':completed})
    return get_run(db,run_id)

def _run_targets(db,rid):
    last=''
    while True:
        rows=_query(db,'SELECT host FROM recon_targets WHERE run_id=:rid AND host>:last ORDER BY host LIMIT 500',{'rid':rid,'last':last})
        if not rows:return
        for row in rows:last=row['host'];yield last

def compare(db,first_run,second_run,limit=1000):
    a,b=get_run(db,first_run),get_run(db,second_run)
    if a['engagement_id']!=b['engagement_id']:raise ValueError('Compare runs from the same engagement')
    if not 1<=limit<=10000:raise ValueError('Comparison limit must be 1–10000')
    rows=_query(db,"SELECT a.host AS host,a.body AS first_body,b.body AS second_body FROM recon_snapshots a LEFT JOIN recon_snapshots b ON b.run_id=:second AND a.host=b.host WHERE a.run_id=:first UNION ALL SELECT b.host AS host,NULL AS first_body,b.body AS second_body FROM recon_snapshots b LEFT JOIN recon_snapshots a ON a.run_id=:first AND a.host=b.host WHERE b.run_id=:second AND a.host IS NULL ORDER BY 1 LIMIT :limit",{'first':first_run,'second':second_run,'limit':limit+1})
    changes=[]
    def fingerprint(body):
        if body is None:return None
        item=json.loads(body)
        return {key:item[key] for key in ['state','addresses','http','interesting']}
    for row in rows[:limit]:
        left,right=fingerprint(row['first_body']),fingerprint(row['second_body'])
        if left!=right:changes.append({'host':row['host'],'change':'first_observation' if left is None else 'not_observed_in_second_run' if right is None else 'changed','first':left,'second':right})
    return {'first_run':first_run,'second_run':second_run,'changes':changes,'truncated':len(rows)>limit,'note':'Only observations recorded in these runs are compared; a resumed run may intentionally omit previously completed assets.'}

def export_assets(db,eid,format):
    if format not in {'json','csv','txt'}:raise ValueError('Use json, csv or txt')
    db.engagement(eid)
    if format=='json':yield '['
    if format=='csv':yield 'host,state,addresses,status_codes,title\n'
    first=True;last=''
    while True:
        rows=_query(db,'SELECT host,body FROM recon_assets WHERE engagement=:eid AND host>:last ORDER BY host LIMIT 500',{'eid':eid,'last':last})
        if not rows:break
        for record in rows:
            last=record['host'];row=json.loads(record['body'])
            if format=='json':yield ('' if first else ',')+json.dumps(row);first=False
            elif format=='txt':yield row['host']+'\n'
            else:
                buffer=io.StringIO();writer=csv.writer(buffer)
                # Prefix spreadsheet formulas in observed titles before CSV export.
                title='; '.join(h['title'] for h in row['http'])
                if title.startswith(('=','+','-','@','\t','\r')):title="'"+title
                writer.writerow([row['host'],row['state'],';'.join(row['addresses']),';'.join(str(h['status']) for h in row['http']),title]);yield buffer.getvalue()
    if format=='json':yield ']'
