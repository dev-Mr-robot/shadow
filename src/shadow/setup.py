"""First-run setup and diagnostic/repair actions, always inside the terminal."""
import asyncio
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
import httpx
from .config import Paths,Settings,load,save
from .diagnostics import collect
from .presentation import LOGO,safe
from rich.text import Text

def diagnose(paths=None):
    paths=paths or Paths();issues=[];config=None;database=None
    try:config=load(paths)
    except (OSError,ValueError) as exc:issues.append({'area':'configuration','severity':'error','detail':str(exc)[:500],'repair':'shadow setup --repair (backs up invalid config before an approved reset)'})
    if paths.database.exists():
        try:
            with sqlite3.connect(paths.database.as_uri()+'?mode=ro',uri=True,timeout=3) as c:
                database=c.execute('PRAGMA quick_check').fetchone()[0]
                if database!='ok':raise ValueError(database)
        except (OSError,ValueError,sqlite3.Error) as exc:issues.append({'area':'database','severity':'error','detail':str(exc)[:300],'repair':'Restore a reviewed backup; doctor never deletes/recreates a corrupt database.'})
    else:issues.append({'area':'database','severity':'info','detail':'Not initialized yet; shadow initializes it automatically.'})
    for path in [paths.data,paths.config]:
        parent=path if path.exists() else next((p for p in path.parents if p.exists()),None)
        if parent and not os.access(parent,os.W_OK):issues.append({'area':'permissions','severity':'error','detail':str(path)+' is not writable','repair':'Select an owned data/config directory or restore correct ownership with your administrator.'})
        if path.exists() and os.name=='posix' and path.stat().st_mode&0o077:issues.append({'area':'permissions','severity':'warning','detail':str(path)+' is accessible outside the owner','repair':'shadow setup --repair can restore private permissions.'})
    launcher=shutil.which('shadow')
    if not launcher:issues.append({'area':'PATH','severity':'warning','detail':'shadow is not on this shell PATH','repair':'Re-run install.sh (global launcher or approved shell PATH setup). Open a new terminal afterward.'})
    checked={}
    try:
        from packaging.requirements import Requirement
        for raw in importlib.metadata.requires('shadow-security-cli') or []:
            requirement=Requirement(raw)
            if requirement.marker and not requirement.marker.evaluate({'extra':''}):continue
            try:
                version=importlib.metadata.version(requirement.name);valid=not requirement.specifier or version in requirement.specifier
                checked[requirement.name]={'version':version,'valid':valid}
                if not valid:issues.append({'area':'dependencies','severity':'error','detail':requirement.name+' has incompatible version '+version,'repair':'shadow setup --repair'})
            except importlib.metadata.PackageNotFoundError:issues.append({'area':'dependencies','severity':'error','detail':requirement.name+' is missing','repair':'shadow setup --repair'})
    except (ImportError,importlib.metadata.PackageNotFoundError):pass
    return {'ready':not any(i['severity']=='error' for i in issues),'issues':issues,'python':sys.version.split()[0],'launcher':launcher,'database_check':database,'dependencies':checked,
            'data_directory':str(paths.data),'config_file':str(paths.settings),'automatic_optional_actions':False}

def repair(paths,console,confirm):
    report=diagnose(paths);actions=[]
    if any(i['area']=='configuration' and i['severity']=='error' for i in report['issues']):
        console.print('The configuration is invalid. A byte-for-byte backup will be saved before creating defaults.',markup=False)
        if confirm('Reset only the invalid configuration after saving its backup?'):
            backup=paths.settings.with_name('config.invalid-backup-'+uuid.uuid4().hex+'.json')
            if paths.settings.is_symlink():raise ValueError('Refusing symlink configuration repair')
            shutil.copy2(paths.settings,backup);save(paths,Settings());actions.append({'configuration_backup':str(backup),'action':'reset_to_defaults'})
    paths.initialize()
    if os.name=='posix':
        for path in [paths.settings,paths.database]:
            if path.exists() and not path.is_symlink():path.chmod(0o600)
        actions.append({'action':'restored_private_application_permissions'})
    executable=Path(sys.executable).absolute();runtime=executable.parents[2]
    lock=runtime/'requirements.lock.txt'
    if lock.is_file() and any(i['area']=='dependencies' for i in report['issues']):
        console.print('Repair will reinstall pinned Python dependencies only inside '+str(executable.parent.parent),markup=False)
        if confirm('Repair the application Python dependencies?'):
            subprocess.run([str(executable),'-m','pip','install','-r',str(lock)],check=True);actions.append({'action':'repaired_python_dependencies'})
    return {'actions':actions,'diagnosis':diagnose(paths)}

def install_ollama(console,confirm):
    if sys.platform!='linux':console.print('Install the local CLI runtime from https://ollama.com/download for this OS.',markup=False);return False
    console.print('Optional: install Ollama using its official Linux installer at https://ollama.com/install.sh. It can use sudo and create a system service. No model is downloaded by this step.',markup=False)
    if not confirm('Download and run the official Ollama installer with its normal system authorization?'):return False
    import hashlib
    with httpx.Client(timeout=60,trust_env=False,follow_redirects=False) as client:
        with client.stream('GET','https://ollama.com/install.sh') as response:
            response.raise_for_status();data=bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data)>2*1024*1024:raise ValueError('Official installer exceeds limit')
    with tempfile.TemporaryDirectory(prefix='shadow-ollama-setup-') as directory:
        script=Path(directory)/'install.sh';script.write_bytes(data)
        console.print('Official installer SHA256: '+hashlib.sha256(data).hexdigest(),markup=False)
        subprocess.run(['sh',str(script)],check=True)
    return bool(shutil.which('ollama'))

async def pull_model(settings,model,on_progress=None):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/+-]{0,199}',model):raise ValueError('Invalid local model name')
    async with httpx.AsyncClient(base_url=settings.ollama_url,timeout=httpx.Timeout(1800,connect=5),trust_env=False,follow_redirects=False) as client:
        async with client.stream('POST','/api/pull',json={'model':model,'stream':True}) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if len(line)>65536:raise ValueError('Model download status exceeded limit')
                if not line:continue
                item=json.loads(line)
                if item.get('error'):raise ValueError(str(item['error'])[:500])
                if on_progress:on_progress(item)

def first_run(state,console,confirm,prompt,force=False):
    if state.settings.setup_completed and not force:return
    console.print(Text(LOGO,style='#c86576'));console.print('SHADOW first-run setup — all questions are optional except preserving your existing configuration.',markup=False)
    status=asyncio.run(collect(state.settings,state.database));hardware=status['hardware'];ai=status['ollama']
    console.print(Text(f"{hardware['distribution']} · {hardware['cpu']} · {hardware['ram_available_bytes']/1024**3:.1f} GiB RAM available"))
    console.print(Text('NVIDIA: '+(', '.join(f"{g['name']} / {g['vram_mib']} MiB VRAM" for g in hardware['gpus']) or 'not detected; Ollama can use CPU')))
    if not ai['available']:
        if not shutil.which('ollama'):
            try:install_ollama(console,confirm)
            except (OSError,ValueError,httpx.HTTPError,subprocess.CalledProcessError) as exc:console.print(Text('Optional Ollama setup deferred: '+safe(exc)))
        if shutil.which('ollama') and confirm('Ollama is offline. Start its local model service now?'):
            log=state.paths.logs/'ollama-service.log'
            with log.open('ab') as stream:subprocess.Popen([shutil.which('ollama'),'serve'],stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,start_new_session=True)
            from .providers import OllamaProvider
            for _ in range(15):
                ai=asyncio.run(OllamaProvider(state.settings).status())
                if ai['available']:break
                time.sleep(1)
    if ai['available']:
        names=[m['name'] for m in ai['models']]
        if state.settings.model not in names:
            if names:
                for index,name in enumerate(names,1):console.print(Text(f'[{index}] {safe(name)}'))
                value=prompt('Select a local model number, or Enter to defer AI setup',default='').strip()
                if value:
                    if value.isdigit() and 1<=int(value)<=len(names):state.settings.model=names[int(value)-1]
                    else:console.print('Invalid selection; AI configuration deferred.',markup=False)
            else:
                model='qwen3:1.7b' if hardware['ram_available_bytes']<6*1024**3 else 'qwen3:4b'
                console.print('No model is installed. Suggested starting model: '+model+'. Source: https://ollama.com/library/qwen3 . Download size can exceed a gigabyte; runtime memory also needs room for context.',markup=False)
                if confirm('Download this large local model now?'):
                    try:
                        asyncio.run(pull_model(state.settings,model,lambda item:console.print(Text(str(item.get('status',''))+(' '+str(item.get('completed',''))+'/'+str(item.get('total','')) if item.get('total') else '')))))
                        state.settings.model=model
                    except (OSError,ValueError,httpx.HTTPError) as exc:console.print(Text('Optional model download failed: '+safe(exc)))
    else:console.print('Local AI is unavailable; SOC, imports, static analysis, engagements and reports still work. Run shadow setup later to enable AI.',markup=False)
    missing=[t['name'] for t in status['tools'] if not t['detected']]
    if missing:console.print('Optional tool integrations not installed: '+', '.join(missing)+'. They do not block startup. Use shadow tools and shadow setup --tools for reviewed installation options.',markup=False)
    state.settings.setup_completed=True;save(state.paths,state.settings)
    state.database.audit('setup.completed',{'model':state.settings.model,'ollama_available':ai['available']})
    console.print('Setup saved. Starting the terminal workstation.',markup=False)


def install_tools(console,confirm):
    """Fixed package list only; never accept arbitrary package-manager arguments."""
    if sys.platform!='linux' or not shutil.which('apt-get'):
        console.print('Use your distribution package manager to install optional nmap and bubblewrap.',markup=False);return
    packages=[package for executable,package in [('nmap','nmap'),('bwrap','bubblewrap')] if not shutil.which(executable)]
    if not packages:console.print('Nmap and bubblewrap are already installed.',markup=False);return
    console.print('Optional APT packages: '+', '.join(packages)+'. APT updates package indexes; sudo supplies system authorization. These packages enable the fixed sandboxed tool adapter.',markup=False)
    if not confirm('Install these exact optional system packages?'):return
    prefix=[] if os.geteuid()==0 else ['sudo']
    if prefix and not shutil.which('sudo'):raise ValueError('sudo is unavailable; ask your administrator to install these packages')
    subprocess.run(prefix+['apt-get','update'],check=True)
    subprocess.run(prefix+['apt-get','install','-y',*packages],check=True)
