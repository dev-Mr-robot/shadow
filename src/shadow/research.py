"""Static evidence analysis and operator-attested findings. Never replays requests or executes content."""
from __future__ import annotations
import ast
import base64
import difflib
import hashlib
import json
import re
import struct
from collections import Counter
from datetime import date
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from defusedxml import ElementTree as ET
from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator
from .scope import check

MAX_BYTES=8*1024*1024
MAX_TEXT=800000
SUSPICIOUS={
 'url':'May choose an outbound destination; inspect destination allowlists and SSRF controls.',
 'redirect':'May control navigation; verify allowed redirect destinations.',
 'next':'May control navigation; verify allowed redirect destinations.',
 'id':'May identify an object; compare authorization across owned test accounts.',
 'user_id':'May identify a user object; verify server-side authorization.',
 'file':'May select a file; inspect canonicalization and access controls.',
 'path':'May select a resource path; inspect canonicalization and access controls.',
 'query':'May influence a backend query; review parameterization.',
 'search':'May be reflected or used in a query; verify encoding and parameterization.',
 'callback':'May choose a callback or destination; inspect allowed values.'}
SECURITY_HEADERS={'content-security-policy','strict-transport-security','x-content-type-options','referrer-policy','permissions-policy'}

def read_file(path,limit=MAX_BYTES):
    selected=Path(path).expanduser().resolve(strict=True)
    if not selected.is_file():raise ValueError('Select a regular file')
    if selected.stat().st_size>limit:raise ValueError(f'File exceeds {limit} bytes')
    with selected.open('rb') as stream:data=stream.read(limit+1)
    if len(data)>limit:raise ValueError('File grew beyond the allowed limit')
    return selected,data

def _jwt(value):
    """Decode only. A decoded JWT is NOT authenticated and never marked verified."""
    if len(value)>32000:return {'error':'Token exceeds inspection limit','signature_verified':False}
    parts=value.split('.')
    if len(parts)!=3:return {'error':'Expected three JWT segments','signature_verified':False}
    try:
        decode=lambda part:json.loads(base64.urlsafe_b64decode(part+'='*(-len(part)%4)))
        header,payload=decode(parts[0]),decode(parts[1])
        if not isinstance(header,dict) or not isinstance(payload,dict):raise ValueError()
        notes=[]
        if str(header.get('alg','')).lower()=='none':notes.append('Header declares alg=none; acceptance by the server has not been tested.')
        if not payload.get('exp'):notes.append('No expiration claim observed; intended token lifetime is unknown.')
        return {'header':header,'claims':payload,'signature_verified':False,'notes':notes,
                'disclaimer':'Untrusted decoded claims only. No signature, issuer, audience, expiry or server acceptance verification was performed.'}
    except (ValueError,TypeError,UnicodeError,RecursionError):return {'error':'JWT header/payload is not decodable bounded JSON','signature_verified':False}

def analyze_http(raw):
    if not isinstance(raw,str) or not raw.strip():raise ValueError('Empty HTTP message')
    if len(raw)>MAX_TEXT:raise ValueError('HTTP text exceeds 800,000 characters')
    raw=raw.replace('\r\n','\n');head,_,body=raw.partition('\n\n');lines=head.splitlines()
    start=lines[0].strip();response=start.startswith('HTTP/');headers={};notes=[]
    for line in lines[1:]:
        key,sep,value=line.partition(':')
        if not sep or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",key):
            notes.append('Malformed/folded header line observed');continue
        headers.setdefault(key.lower(),[]).append(value.strip())
    method=path='';status=None;parameters={};uploads=[]
    if response:
        parts=start.split(' ',2)
        if len(parts)<2 or not parts[1].isdigit() or not 100<=int(parts[1])<=599:raise ValueError('Invalid HTTP status line')
        status=int(parts[1])
    else:
        parts=start.split(' ')
        if len(parts)!=3 or not parts[2].startswith('HTTP/') or not re.fullmatch('[A-Z]+',parts[0]):raise ValueError('Expected a raw HTTP request or response')
        method,path,_=parts
        parameters=parse_qs(urlsplit(path).query,keep_blank_values=True,max_num_fields=5000)
    content_type=' '.join(headers.get('content-type',[])).lower();json_body=None;xml_body=None
    if body.strip() and 'json' in content_type:
        try:
            json_body=json.loads(body)
            if isinstance(json_body,dict):
                for key,value in list(json_body.items())[:5000]:parameters.setdefault(key,[]).append(value)
        except (ValueError,RecursionError):notes.append('Body declares JSON but valid bounded JSON could not be parsed')
    elif body.strip() and 'xml' in content_type:
        try:
            root=ET.fromstring(body)
            xml_body={'root':root.tag,'elements':sum(1 for _ in root.iter())}
        except Exception:notes.append('XML could not be safely parsed; external entities are not allowed')
    elif 'application/x-www-form-urlencoded' in content_type:
        parameters.update(parse_qs(body,keep_blank_values=True,max_num_fields=5000))
    elif 'multipart/form-data' in content_type:
        boundary_match=re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))',' '.join(headers.get('content-type',[])),re.I)
        boundary=(boundary_match[1] or boundary_match[2]) if boundary_match else ''
        if not boundary or len(boundary)>200:notes.append('Multipart boundary missing or exceeds inspection limit')
        else:
            sections=body.split('--'+boundary)
            if len(sections)>1002:raise ValueError('Multipart inspection exceeds 1000 parts')
            for section in sections[1:]:
                part_head,sep,part_body=section.lstrip('\n').partition('\n\n')
                if not sep:continue
                disposition=next((line for line in part_head.splitlines() if line.lower().startswith('content-disposition:')),'')
                name_match=re.search(r'(?:^|;)\s*name="([^"]{1,500})"',disposition)
                file_match=re.search(r'(?:^|;)\s*filename="([^"]{0,500})"',disposition)
                if name_match:
                    if file_match:uploads.append({'parameter':name_match[1],'filename':file_match[1],'characters':len(part_body.rstrip('\n')),'note':'Metadata only; uploaded content is not executed or extracted.'})
                    else:parameters.setdefault(name_match[1],[]).append(part_body.rstrip('\n')[:10000])
    candidates=[{'parameter':key,'reason':SUSPICIOUS[key.lower()],'verification':'hypothesis'} for key in parameters if key.lower() in SUSPICIOUS]
    cookies=[]
    for line in headers.get('set-cookie',[]):
        parsed=SimpleCookie()
        try:parsed.load(line)
        except Exception:notes.append('A Set-Cookie header could not be parsed');continue
        for name,cookie in parsed.items():
            cookies.append({'name':name,'secure':bool(cookie['secure']),'httponly':bool(cookie['httponly']),'samesite':cookie['samesite'],
                            'missing_attributes':[attr for attr in ['secure','httponly','samesite'] if not cookie[attr]],
                            'note':'Appropriate attributes depend on the cookie purpose and HTTPS context; no vulnerability is confirmed.'})
    jwts=[]
    for line in headers.get('authorization',[]):
        if line.lower().startswith('bearer '):jwts.append(_jwt(line[7:].strip()))
    cors={key:headers[key] for key in ['access-control-allow-origin','access-control-allow-credentials','access-control-allow-methods','access-control-allow-headers'] if key in headers}
    if '*' in headers.get('access-control-allow-origin',[]) and 'true' in [x.lower() for x in headers.get('access-control-allow-credentials',[])]:
        notes.append('Wildcard CORS origin plus credentials observed. Browsers reject that combination; this alone does not establish data exposure.')
    duplicate_headers=[name for name,values in headers.items() if len(values)>1]
    if 'content-length' in duplicate_headers:notes.append('Duplicate Content-Length observed; parsing differences require controlled validation, not a confirmed request-smuggling claim.')
    return {'kind':'response' if response else 'request','start_line':start,'method':method,'path':path,'status':status,
      'headers':headers,'parameters':parameters,'uploads':uploads,'body':body,'json_body':json_body,'xml_body':xml_body,
      'authentication_present':bool(headers.get('authorization') or headers.get('cookie')),
      'request_cookie_names':[part.partition('=')[0].strip() for line in headers.get('cookie',[]) for part in line.split(';') if '=' in part],
      'cookies':cookies,'jwt':jwts,'cors':cors,'cache':{key:headers[key] for key in ['cache-control','vary','etag','age','expires'] if key in headers},
      'redirect':headers.get('location',[]),'missing_security_headers':sorted(SECURITY_HEADERS-set(headers)) if response else [],
      'duplicate_headers':duplicate_headers,'candidates':candidates,'parse_notes':notes,
      'disclaimer':'Static observations and investigation hypotheses only. No request was sent, replayed or verified against a server.'}

def compare_http(first,second):
    a,b=analyze_http(first),analyze_http(second)
    return {'first':a,'second':b,'status_changed':a['status']!=b['status'],
      'header_changes':{h:{'first':a['headers'].get(h),'second':b['headers'].get(h)} for h in sorted(set(a['headers'])|set(b['headers'])) if a['headers'].get(h)!=b['headers'].get(h)},
      'diff':'\n'.join(difflib.unified_diff(first.splitlines(),second.splitlines(),fromfile='first',tofile='second',lineterm='')),
      'verification':'observation','next_step':'Compare session identity, authorization and intended behavior before inferring a security flaw.'}

def _burp(text):
    root=ET.fromstring(text)
    if root.tag!='items':raise ValueError('Expected a Burp items XML export')
    exchanges=[]
    for item in root.findall('item')[:2000]:
        exchange={'url':item.findtext('url',''),'host':item.findtext('host',''),'analyses':[]}
        for kind in ['request','response']:
            element=item.find(kind)
            if element is None or not element.text:continue
            content=base64.b64decode(element.text,validate=True).decode('utf-8',errors='replace') if element.get('base64')=='true' else element.text
            exchange[kind]=content
            exchange['analyses'].append(analyze_http(content))
        exchanges.append(exchange)
    if not exchanges:raise ValueError('No request/response items in Burp XML export')
    return exchanges

def parse_nmap(name,text):
    """Structured open-port observations; heterogeneous JSON remains raw evidence."""
    services=[]
    if text.lstrip().startswith('<'):
        root=ET.fromstring(text)
        if root.tag!='nmaprun':raise ValueError('Expected Nmap XML with nmaprun root')
        for host in root.findall('host'):
            address=host.find('address')
            if address is None:continue
            asset=address.get('addr','')
            for port in host.findall('./ports/port'):
                state=port.find('state');service=port.find('service')
                if state is None or state.get('state')!='open':continue
                services.append({'asset':asset,'port':int(port.get('portid','0')),'protocol':port.get('protocol','tcp'),
                  'service':service.get('name','') if service is not None else '',
                  'version':' '.join(service.get(key,'') for key in ['product','version','extrainfo']).strip() if service is not None else '',
                  'verification':'Observed scanner output; service attribution may be a fingerprint hypothesis.'})
                if len(services)>20000:raise ValueError('Nmap import exceeds 20,000 services')
    elif name.lower().endswith('.json'):
        try:json.loads(text)
        except (ValueError,RecursionError) as exc:raise ValueError('Invalid Nmap JSON evidence') from exc
    else:
        asset=''
        for line in text.splitlines():
            if line.startswith('Nmap scan report for '):
                asset=line.removeprefix('Nmap scan report for ').strip();parenthesized=re.search(r'\(([^)]+)\)$',asset)
                if parenthesized:asset=parenthesized[1]
            match=re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$',line)
            if asset and match:services.append({'asset':asset,'port':int(match[1]),'protocol':match[2],'service':match[3],'version':match[4] or '',
                                                'verification':'Observed scanner output; no vulnerability has been verified.'})
    return services

def import_evidence(db,eid,path,source='http'):
    if not re.fullmatch(r'[a-z0-9_-]{1,50}',source):raise ValueError('Evidence source must be a short lowercase tool/type label')
    engagement=db.engagement(eid);selected,data=read_file(path);text=data.decode('utf-8-sig',errors='replace')
    if len(text)>MAX_TEXT:raise ValueError('Evidence text exceeds 800,000 characters')
    analyses=[];exchanges=[];services=[]
    if source=='nmap':
        try:services=parse_nmap(selected.name,text)
        except Exception as exc:raise ValueError('Nmap evidence could not be parsed safely') from exc
        for service in services:
            try:service['in_scope']=check(service['asset'],engagement)['in_scope']
            except ValueError:service['in_scope']=False
    if source in {'http','burp'}:
        if text.lstrip().startswith('<'):
            try:exchanges=_burp(text)
            except Exception as exc:raise ValueError('Invalid or unsafe Burp XML export') from exc
            analyses=[analysis for exchange in exchanges for analysis in exchange['analyses']]
        else:analyses=[analyze_http(text)]
    hosts=set()
    for analysis in analyses:
        for value in analysis['headers'].get('host',[]):
            host=urlsplit('//'+value).hostname
            if host:hosts.add(host)
        if analysis['path'].startswith(('http://','https://')):
            host=urlsplit(analysis['path']).hostname
            if host:hosts.add(host)
    for exchange in exchanges:
        if exchange['host']:hosts.add(exchange['host'])
    scope=[]
    for host in sorted(hosts):
        try:scope.append(check(host,engagement))
        except ValueError:scope.append({'target':host,'in_scope':False,'reason':'Invalid host representation'})
    record=db.create('import',{'engagement_id':eid,'name':selected.name,'source':source,'sha256':hashlib.sha256(data).hexdigest(),
      'text':text,'analyses':analyses,'exchanges':exchanges,'scope_checks':scope,'services':services,
      'warning':'Imports do not authorize targets. Original file bytes are not archived; retain originals for chain of custody.'},eid)
    db.audit('evidence.imported',{'id':record['id'],'engagement_id':eid,'source':source,'sha256':record['sha256']})
    return record

class FindingInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    engagement_id:str
    name:str=Field(min_length=1,max_length=250)
    asset:str=Field(min_length=1,max_length=2000)
    severity:Literal['Critical','High','Medium','Low','Informational']='Informational'
    cvss:float|None=Field(default=None,ge=0,le=10)
    cvss_justification:str=Field(default='',max_length=10000)
    cwe:str=Field(default='',max_length=100)
    description:str=Field(default='',max_length=100000)
    evidence:str=Field(default='',max_length=100000)
    evidence_ids:list[str]=Field(default_factory=list,max_length=100)
    reproduction:str=Field(default='',max_length=100000)
    impact:str=Field(default='',max_length=100000)
    remediation:str=Field(default='',max_length=100000)
    references:list[str]=Field(default_factory=list,max_length=100)
    verification:Literal['observation','hypothesis','unverified_lead','confirmed','false_positive','remediated']='hypothesis'
    workflow_status:Literal['needs_investigation','potential_vulnerability','verified_vulnerability','reported','resolved']='needs_investigation'
    @model_validator(mode='after')
    def validation(self):
        if not self.name.strip() or not self.asset.strip():raise ValueError('Name/asset must not be blank')
        if self.cvss is not None and not self.cvss_justification.strip():raise ValueError('CVSS requires a vector or documented justification')
        if self.verification in {'confirmed','remediated'} and not(self.evidence.strip() or self.evidence_ids):raise ValueError('Confirmed/remediated findings require technical evidence')
        if self.workflow_status in {'verified_vulnerability','reported','resolved'} and self.verification not in {'confirmed','remediated'}:raise ValueError('Verified/reported/resolved workflow requires a confirmed/remediated finding')
        if self.cwe and not re.fullmatch(r'CWE-\d+',self.cwe):raise ValueError('CWE must use CWE-NUMBER format')
        return self

def _finding_body(db,payload):
    body=FindingInput.model_validate(payload)
    engagement=db.engagement(body.engagement_id)
    parsed=urlsplit(body.asset) if '://' in body.asset else None
    if parsed and (parsed.username or parsed.password):raise ValueError('Affected asset URLs must not contain credentials')
    host=parsed.hostname if parsed else body.asset
    if not host or not check(host,engagement)['in_scope']:raise ValueError('Finding asset is outside the recorded engagement scope')
    for rid in body.evidence_ids:
        evidence=db.get('import',rid)
        if evidence.get('engagement_id')!=body.engagement_id:raise ValueError('Evidence belongs to another engagement')
    return body.model_dump()

def create_finding(db,payload):
    body=_finding_body(db,payload)
    # Duplicate candidates are shown as evidence-based matches, never silently merged.
    duplicates=[r['id'] for r in all_records(db,'finding',body['engagement_id']) if r['name'].strip().lower()==body['name'].strip().lower() and r['asset']==body['asset']]
    record=db.create('finding',{**body,'duplicate_candidates':duplicates},body['engagement_id'])
    db.audit('finding.created',{'id':record['id'],'verification':record['verification']});return record

def update_finding(db,rid,payload):
    old=db.get('finding',rid);merged={k:v for k,v in old.items() if k in FindingInput.model_fields};merged.update(payload)
    if merged.get('engagement_id')!=old['engagement_id']:raise ValueError('Cannot move findings across engagements')
    body=_finding_body(db,merged);record=db.update('finding',rid,body)
    db.audit('finding.updated',{'id':rid,'verification':record['verification']});return record

def all_records(db,kind,parent=None):
    offset=0
    while True:
        page=db.listing(kind,parent=parent,limit=200,offset=offset)
        if not page:return
        yield from page;offset+=len(page)

class AdvisoryInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    cve:str
    title:str=Field(min_length=1,max_length=500)
    product:str=Field(default='',max_length=1000)
    affected_versions:str=Field(default='',max_length=10000)
    description:str=Field(default='',max_length=100000)
    cvss:float|None=Field(default=None,ge=0,le=10)
    cvss_justification:str=Field(default='',max_length=10000)
    cwe:str=Field(default='',max_length=100)
    references:list[str]=Field(default_factory=list,max_length=100)
    detection:str=Field(default='',max_length=20000)
    reproduction:str=Field(default='',max_length=20000)
    remediation:str=Field(default='',max_length=20000)
    @model_validator(mode='after')
    def valid(self):
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}',self.cve):raise ValueError('Expected a CVE-YYYY-NNNN identifier')
        if self.cvss is not None and not self.cvss_justification.strip():raise ValueError('Imported CVSS needs a documented source vector/justification')
        return self

def import_advisory(db,path,source,observed_date):
    selected,data=read_file(path)
    parsed=urlsplit(source)
    if parsed.scheme not in {'https','http'} or not parsed.hostname or parsed.username or parsed.password:raise ValueError('Provide a source advisory HTTP(S) URL without embedded credentials; importing does not fetch it')
    stamp=date.fromisoformat(str(observed_date)).isoformat()
    body=AdvisoryInput.model_validate_json(data)
    record=db.create('advisory',{**body.model_dump(),'source':source,'source_date':stamp,'sha256':hashlib.sha256(data).hexdigest(),'name':selected.name,
        'verification':'Imported source claims; not independently verified. No network request was made.'})
    db.audit('advisory.imported',{'id':record['id'],'cve':body.cve,'source':source,'source_date':stamp});return record

def static_analyze(path,kind='auto'):
    selected,data=read_file(path);suffix=selected.suffix.lower()
    if kind=='auto':kind='python' if suffix=='.py' else 'pcap' if suffix=='.pcap' else 'binary' if data.startswith((b'\x7fELF',b'MZ')) else 'log' if suffix=='.log' else 'config'
    result={'name':selected.name,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'kind':kind,'observations':[],
      'verification':'Static heuristic leads only; no code/binary execution and no vulnerability confirmation.'}
    text=data.decode('utf-8',errors='replace')[:MAX_TEXT]
    if kind=='python':
        try:tree=ast.parse(text)
        except (SyntaxError,RecursionError) as exc:raise ValueError('Python source could not be safely parsed') from exc
        def call_name(node):
            if isinstance(node,ast.Name):return node.id
            if isinstance(node,ast.Attribute):return call_name(node.value)+'.'+node.attr
            return ''
        for node in ast.walk(tree):
            if isinstance(node,ast.Call):
                name=call_name(node.func)
                if name in {'eval','exec','pickle.loads','pickle.load','marshal.loads','yaml.load','os.system'} or any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords):
                    result['observations'].append({'line':node.lineno,'reason':f'{name or "call"} may cross a code/deserialization boundary; trace input trust and validate context.'})
    elif kind=='binary':
        result['format']='ELF' if data.startswith(b'\x7fELF') else 'PE/DOS signature' if data.startswith(b'MZ') else 'unknown'
        result['strings']=[m.group().decode('ascii') for m in re.finditer(rb'[ -~]{6,}',data)][:200]
        result['observations'].append({'reason':'Magic bytes and printable strings only; use an isolated static-analysis workflow for deeper research.'})
    elif kind=='pcap':
        if len(data)<24:raise ValueError('Truncated PCAP global header')
        magic=data[:4];endian='<' if magic in {b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'} else '>' if magic in {b'\xa1\xb2\xc3\xd4',b'\xa1\xb2\x3c\x4d'} else None
        if endian is None:raise ValueError('Only classic PCAP is supported; export PCAPNG as PCAP with your capture tool')
        count=0;offset=24
        while offset<len(data):
            if offset+16>len(data):raise ValueError('Truncated PCAP packet header')
            _,_,captured,_=struct.unpack_from(endian+'IIII',data,offset);offset+=16
            if captured>len(data)-offset:raise ValueError('Truncated PCAP packet data')
            offset+=captured;count+=1
        result['packet_count']=count;result['observations'].append({'reason':'PCAP framing/packet count inspected; payload protocol decoding is not implemented.'})
    elif kind=='log':
        counts=Counter(word.lower() for word in re.findall(r'\b(error|warning|failed|denied|exception)\b',text,re.I))
        result['keyword_counts']=dict(counts);result['observations'].append({'reason':'Keyword frequencies are triage hints; they do not establish an attack or compromise.'})
    elif kind=='config':
        for number,line in enumerate(text.splitlines(),1):
            if re.search(r'(?i)\b(password|secret|api[_-]?key|token)\b\s*[:=]\s*\S+',line):result['observations'].append({'line':number,'reason':'Potential embedded secret assignment. Value intentionally omitted; verify whether this is a real secret and rotate if exposed.'})
            if re.search(r'(?i)\b(debug|allow_anonymous)\b\s*[:=]\s*(true|yes|1)',line):result['observations'].append({'line':number,'reason':'Permissive/debug option observed; assess the deployment context.'})
    else:raise ValueError('Analysis kind must be auto, python, config, log, binary or pcap')
    result['observations']=result['observations'][:500];return result
