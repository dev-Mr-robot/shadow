"""Vetted adapters, immutable command previews and bounded subprocess execution."""
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import time
import psutil
from abc import ABC,abstractmethod
from pathlib import Path
from sqlalchemy import text
from .diagnostics import TOOLS
from .scope import check

class ToolAdapter(ABC):
    name:str
    @abstractmethod
    def build(self,target,ports): ...

def validate_target(db,eid,target):
    try:ip=ipaddress.ip_address(target)
    except ValueError:raise ValueError('Executable scans require one literal IP authorized by IP/CIDR scope')
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved or str(ip)=='255.255.255.255':raise ValueError('Reserved, multicast and unspecified targets are rejected')
    if not check(str(ip),db.engagement(eid))['in_scope']:raise ValueError('Target is outside the recorded scope or explicitly excluded')
    return str(ip)

def validate_ports(value):
    if len(value)>500 or not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*',value):raise ValueError('Use comma-separated numeric ports/ranges')
    total=0
    for part in value.split(','):
        bounds=[int(p) for p in part.split('-')];start,end=bounds[0],bounds[-1]
        if not 1<=start<=end<=65535:raise ValueError('Ports must be within 1–65535')
        total+=end-start+1
    if total>1024:raise ValueError('At most 1024 ports per approved job')
    return value

class NmapAdapter(ToolAdapter):
    name='nmap'
    def build(self,target,ports):
        args=['nmap','--unprivileged','-sT','-Pn','-n','--max-retries','1','--host-timeout','60s','-p',validate_ports(ports),'-oX','-']
        if ipaddress.ip_address(target).version==6:args+=['-6']
        return args+[target]

ADAPTERS={'nmap':NmapAdapter()}
VERSION_FLAGS={'nmap':['--version'],'subfinder':['-version'],'amass':['-version'],'httpx':['-version'],'nuclei':['-version'],
               'ffuf':['-V'],'gobuster':['version'],'whatweb':['--version'],'sqlmap':['--version'],'tshark':['--version'],
               'gdb':['--version'],'nikto':['-Version'],'testssl':['--version']}

def sandbox(argv):
    if os.name!='posix' or not shutil.which('bwrap'):raise ValueError('Linux bubblewrap is required; no unsandboxed fallback')
    exe=shutil.which(argv[0])
    if not exe or not str(Path(exe).resolve()).startswith('/usr/'):raise ValueError('Install Nmap under /usr before executing')
    args=[shutil.which('bwrap'),'--die-with-parent','--new-session','--unshare-user','--unshare-pid','--unshare-ipc','--unshare-uts','--cap-drop','ALL','--ro-bind','/usr','/usr']
    for path in ['/lib','/lib64','/etc/services','/etc/protocols','/etc/ld.so.cache']:
        if os.path.exists(path):args+=['--ro-bind',path,path]
    return args+['--proc','/proc','--dev','/dev','--tmpfs','/tmp','--chdir','/tmp','--clearenv','--setenv','PATH','/usr/bin:/bin','--',exe]+argv[1:]

class ToolManager:
    def __init__(self,state):self.state=state;self.db=state.database
    def preview(self,eid,target,ports='22,80,443',timeout=90,tool='nmap'):
        recover_stale(self.db)
        if tool not in ADAPTERS:raise ValueError('This integration supports output import only; no approved execution recipe is available')
        if not 5<=timeout<=300:raise ValueError('Timeout must be 5–300 seconds')
        target=validate_target(self.db,eid,target);argv=ADAPTERS[tool].build(target,ports)
        payload={'engagement_id':eid,'tool':tool,'target':target,'ports':ports,'timeout':timeout,'argv':argv}
        digest=hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()
        row=self.db.create('job',{**payload,'digest':digest,'command':shlex.join(argv),'expires':time.time()+600,'status':'pending','output':'','exit_code':None},eid)
        self.db.audit('tool.previewed',{'id':row['id'],'command':row['command']});return row

    def version_preview(self,tool):
        if tool not in VERSION_FLAGS:raise ValueError('No safe version-only recipe for this tool; inspect its manual installation')
        executable=shutil.which(TOOLS[tool][0])
        if not executable:raise ValueError('Tool not found. Install it manually using shadow tools instructions.')
        argv=[executable,*VERSION_FLAGS[tool]];digest=hashlib.sha256(json.dumps(argv).encode()).hexdigest()
        return self.db.create('job',{'tool':tool,'operation':'version','argv':argv,'command':shlex.join(argv),'digest':digest,'expires':time.time()+600,'status':'pending','output':'','timeout':10,'engagement_id':None})

    async def version_execute(self,rid,digest,approved=False):
        if approved is not True:raise ValueError('Explicit approval required for fixed version command')
        row=self.db.get('job',rid)
        if row.get('operation')!='version' or row['digest']!=digest or row['expires']<time.time():raise ValueError('Invalid version preview')
        executable=shutil.which(TOOLS[row['tool']][0]);expected=[executable,*VERSION_FLAGS[row['tool']]]
        if expected!=row['argv'] or hashlib.sha256(json.dumps(expected).encode()).hexdigest()!=digest:raise ValueError('Tool path or version recipe changed')
        if os.name!='posix' or not shutil.which('bwrap'):raise ValueError('Version execution requires Linux bubblewrap; imported transcripts remain available')
        args=[shutil.which('bwrap'),'--die-with-parent','--new-session','--unshare-all','--cap-drop','ALL','--ro-bind','/usr','/usr']
        for path in ['/lib','/lib64','/etc/ld.so.cache']:
            if os.path.exists(path):args+=['--ro-bind',path,path]
        destination=executable
        if not str(Path(executable).resolve()).startswith('/usr/'):
            args+=['--ro-bind',executable,'/tool'];destination='/tool'
        args+=['--proc','/proc','--dev','/dev','--tmpfs','/tmp','--chdir','/tmp','--clearenv','--setenv','PATH','/usr/bin:/bin','--',destination,*VERSION_FLAGS[row['tool']]]
        self.db.claim('job',rid);self.db.update('job',rid,{'owner_pid':os.getpid(),'owner_start':psutil.Process().create_time()})
        self.db.audit('tool.version_approved',{'id':rid,'command':row['command']})
        result=await self._capture(rid,args,10)
        return self.db.update('job',rid,{'identity_note':'Version output is evidence only; confirm the vendor, especially ProjectDiscovery httpx versus Python httpx.'})

    async def execute(self,rid,digest,approved=False,on_progress=None):
        if approved is not True:raise ValueError('Explicit approval is required before command execution')
        recover_stale(self.db)
        job=self.db.get('job',rid)
        if job['status']!='pending' or job['expires']<time.time() or digest!=job['digest']:raise ValueError('Expired, consumed or mismatched command preview')
        target=validate_target(self.db,job['engagement_id'],job['target'])
        expected=ADAPTERS[job['tool']].build(target,job['ports'])
        if expected!=job['argv']:raise ValueError('Stored command does not match its deterministic recipe')
        args=sandbox(expected)
        # Serialize approval consumption and the cross-process concurrency limit.
        with self.db.engine.connect() as c:
            c.exec_driver_sql('BEGIN IMMEDIATE')
            count=c.execute(text("SELECT count(*) FROM workspace_records WHERE kind='job' AND json_extract(body,'$.status') IN ('running','cancel_requested')")).scalar_one()
            if count>=2:c.rollback();raise ValueError('Two tool jobs are already running')
            changed=c.execute(text("UPDATE workspace_records SET body=json_set(body,'$.status','running','$.owner_pid',:pid,'$.owner_start',:started) WHERE id=:id AND kind='job' AND json_extract(body,'$.status')='pending'"),{'pid':os.getpid(),'started':psutil.Process().create_time(),'id':rid}).rowcount
            if changed!=1:c.rollback();raise ValueError('Command approval already consumed')
            c.commit()
        self.db.audit('tool.approved',{'id':rid,'digest':digest})
        return await self._capture(rid,args,job['timeout'],on_progress)

    async def _capture(self,rid,args,timeout,on_progress=None):
        process=None;output=bytearray();errors=bytearray();status='failed';code=None;readers=[];waiter=None
        overflow=asyncio.Event()
        async def drain(stream,buffer):
            while chunk:=await stream.read(8192):
                remaining=1024*1024-len(output)-len(errors)
                buffer.extend(chunk[:max(0,remaining)])
                if len(chunk)>remaining:overflow.set();return
                self.db.update('job',rid,{'output':output.decode('utf-8',errors='replace'),'stderr':errors.decode('utf-8',errors='replace')})
                if on_progress:on_progress(output.decode('utf-8',errors='replace'))
        try:
            process=await asyncio.create_subprocess_exec(*args,stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=os.name=='posix',env={'PATH':os.environ.get('PATH','/usr/bin:/bin')})
            readers=[asyncio.create_task(drain(process.stdout,output)),asyncio.create_task(drain(process.stderr,errors))];waiter=asyncio.create_task(process.wait())
            async with asyncio.timeout(timeout):
                while not waiter.done():
                    if self.db.get('job',rid)['status']=='cancel_requested':status='cancelled';break
                    if overflow.is_set():status='output_limit';break
                    await asyncio.sleep(.05)
                else:
                    code=await waiter;await asyncio.gather(*readers)
                    status='output_limit' if overflow.is_set() else 'completed' if code==0 else 'failed'
        except TimeoutError:status='timed_out'
        except asyncio.CancelledError:status='cancelled'
        except Exception as exc:errors.extend(('\nExecution failed: '+str(exc)[:500]).encode())
        finally:
            if process:
                if process.returncode is None:
                    try:
                        if os.name=='posix':os.killpg(process.pid,signal.SIGKILL)
                        else:process.kill()
                    except ProcessLookupError:pass
                await process.wait()
            for task in readers:
                if not task.done():task.cancel()
            if readers:await asyncio.gather(*readers,return_exceptions=True)
            if waiter and not waiter.done():waiter.cancel()
            row=self.db.update('job',rid,{'status':status,'output':output.decode('utf-8',errors='replace'),'stderr':errors.decode('utf-8',errors='replace'),'exit_code':code})
            self.db.audit('tool.finished',{'id':rid,'status':status,'exit_code':code})
        if status=='completed' and row.get('engagement_id') and row.get('operation')!='version':
            try:
                from .research import import_evidence
                # Import the captured XML through a private, generated temporary file.
                import tempfile
                fd,name=tempfile.mkstemp(suffix='.xml',dir=self.state.paths.data)
                try:
                    with os.fdopen(fd,'w',encoding='utf-8') as f:f.write(row['output'])
                    evidence=import_evidence(self.db,row['engagement_id'],Path(name),'nmap')
                    row=self.db.update('job',rid,{'evidence_id':evidence['id']})
                finally:Path(name).unlink(missing_ok=True)
            except (ValueError,OSError,ImportError) as exc:
                row=self.db.update('job',rid,{'evidence_import_error':str(exc)[:500]})
                self.db.audit('tool.evidence_import_failed',{'id':rid,'error':str(exc)[:500]})
        return row

    def cancel(self,rid):
        row=self.db.get('job',rid)
        if row['status']=='pending':self.db.claim('job',rid,'pending','cancelled')
        elif row['status']=='running':self.db.claim('job',rid,'running','cancel_requested')
        else:raise ValueError('Job is not pending/running')
        self.db.audit('tool.cancel_requested',{'id':rid});return self.db.get('job',rid)

def recover_stale(db):
    with db.engine.connect() as connection:
        rows=connection.execute(text("SELECT id,body FROM workspace_records WHERE kind='job' AND json_extract(body,'$.status') IN ('running','cancel_requested')")).all()
    for rid,body in rows:
        data=json.loads(body)
        try:live=psutil.Process(data.get('owner_pid',-1)).create_time()==data.get('owner_start')
        except (psutil.Error,ValueError):live=False
        if not live:
            db.update('job',rid,{'status':'interrupted'});db.audit('tool.recovered_interrupted',{'id':rid})

def register(app,runtime_factory,console):
    import typer
    from rich.text import Text
    group=typer.Typer(help='Vetted tool previews, approval-gated execution and captured history.')
    app.add_typer(group,name='tool')
    @group.command('preview')
    def preview(target:str,engagement:str|None=None,ports:str='22,80,443',timeout:int=90):
        with runtime_factory() as state:
            eid=engagement or state.settings.active_engagement
            if not eid:raise ValueError('Select an engagement first')
            console.print_json(data=ToolManager(state).preview(eid,target,ports,timeout))
    @group.command('run')
    def run(job_id:str):
        with runtime_factory() as state:
            manager=ToolManager(state);job=state.database.get('job',job_id)
            console.print(Text(job['command']));console.print(f"Timeout {job['timeout']}s; 1 MiB output cap; approved scope rechecked.",markup=False)
            if not typer.confirm('Execute exactly this command?',default=False):raise typer.Exit(1)
            operation=manager.version_execute(job_id,job['digest'],approved=True) if job.get('operation')=='version' else manager.execute(job_id,job['digest'],approved=True)
            console.print_json(data=asyncio.run(operation))
    @group.command('list')
    def listing():
        with runtime_factory() as state:console.print_json(data=state.database.listing('job'))
    @group.command('version')
    def version(tool:str):
        with runtime_factory() as state:
            manager=ToolManager(state);job=manager.version_preview(tool);console.print(Text(job['command']))
            console.print('Runs in a no-network Linux bubblewrap sandbox. Executable identity is not assumed from its filename.',markup=False)
            if not typer.confirm('Run this fixed version-only command?',default=False):raise typer.Exit(1)
            console.print_json(data=asyncio.run(manager.version_execute(job['id'],job['digest'],approved=True)))
    @group.command('cancel')
    def cancel(job_id:str):
        with runtime_factory() as state:console.print_json(data=ToolManager(state).cancel(job_id))
    @group.command('import')
    def import_output(tool:str,path:Path,engagement:str|None=None):
        if tool not in TOOLS:raise ValueError('Unknown integration')
        from .research import import_evidence
        with runtime_factory() as state:
            eid=engagement or state.settings.active_engagement
            if not eid:raise ValueError('Select an engagement first')
            console.print_json(data=import_evidence(state.database,eid,path,tool))
