"""Read-only hardware and executable inventory. No downloads, probes or scanners."""
import csv
import io
import os
import platform
import shutil
import subprocess
import sys
import psutil
from .providers import OllamaProvider

TOOLS={
 'nmap':('nmap','sudo apt install nmap'), 'subfinder':('subfinder','https://github.com/projectdiscovery/subfinder'),
 'amass':('amass','sudo apt install amass'), 'httpx':('httpx','https://github.com/projectdiscovery/httpx'),
 'nuclei':('nuclei','https://github.com/projectdiscovery/nuclei'), 'ffuf':('ffuf','sudo apt install ffuf'),
 'gobuster':('gobuster','sudo apt install gobuster'), 'whatweb':('whatweb','sudo apt install whatweb'),
 'sqlmap':('sqlmap','sudo apt install sqlmap'), 'tshark':('tshark','sudo apt install tshark'),
 'ghidra':('ghidra','https://github.com/NationalSecurityAgency/ghidra'), 'gdb':('gdb','sudo apt install gdb'),
 'nikto':('nikto','sudo apt install nikto'), 'testssl':('testssl.sh','https://github.com/testssl/testssl.sh')}

def inventory():
    return [{'name':name,'path':shutil.which(command),'detected':bool(shutil.which(command)), 'version':'not queried (availability only)',
             'installation':install,'execution_adapter':'planned; Phase 1 never executes security tools'} for name,(command,install) in TOOLS.items()]

def hardware():
    memory=psutil.virtual_memory();gpus=[];gpu_error=None
    executable=shutil.which('nvidia-smi')
    if executable:
        try:
            result=subprocess.run([executable,'--query-gpu=name,memory.total,memory.free,driver_version','--format=csv,noheader,nounits'],capture_output=True,text=True,timeout=4,check=True)
            for row in csv.reader(io.StringIO(result.stdout)):
                if len(row)>=4:gpus.append({'name':row[0].strip(),'vram_mib':int(row[1]),'free_vram_mib':int(row[2]),'driver':row[3].strip()})
        except (OSError,ValueError,subprocess.SubprocessError):gpu_error='NVIDIA diagnostics failed; GPU inference capability is unknown.'
    distro={}
    if sys.platform=='linux':
        try:distro=platform.freedesktop_os_release()
        except OSError:pass
    cpu_name=platform.processor() or platform.machine()
    if sys.platform=='linux':
        try:
            with open('/proc/cpuinfo',encoding='utf-8') as f:
                for line in f:
                    if line.startswith('model name'):cpu_name=line.partition(':')[2].strip();break
        except OSError:pass
    return {'os':platform.system(),'distribution':distro.get('PRETTY_NAME',platform.platform()),'kernel':platform.release(),
            'python':platform.python_version(),'cpu':cpu_name,'logical_cpus':psutil.cpu_count(),'physical_cores':psutil.cpu_count(logical=False),
            'ram_total_bytes':memory.total,'ram_available_bytes':memory.available,'ram_percent':memory.percent,
            'gpus':gpus,'gpu_error':gpu_error,'ollama_executable':shutil.which('ollama'),'bubblewrap':shutil.which('bwrap'),
            'virtualized_wsl':'microsoft' in platform.release().lower(), 'gpu_scope':'NVIDIA inventory only; AMD/Intel acceleration is not detected in Phase 1.'}

def recommendations(hw,ollama):
    available=hw['ram_available_bytes'];vram=max((g['free_vram_mib']*1024**2 for g in hw['gpus']),default=0)
    fit=[m['name'] for m in ollama['models'] if m.get('size') and m['size']<available*.5 and (not vram or m['size']<vram*.7)]
    return {'installed_candidates':fit,
            'suggestion':'Start with a 1.5B–4B local instruction model quantized to Q4, one request at a time and a 4096-token context. Benchmark before increasing context or model size.',
            'selection':'No model is downloaded, loaded, selected or switched automatically. Candidates are conservative size heuristics, not benchmark results.',
            'memory_note':'Model file size excludes KV cache, context, runtime and OS overhead. Shared GPU/system RAM is not added together for this estimate.',
            'fallback':'Ollama controls CPU fallback and GPU offload; Phase 1 does not run inference or configure acceleration.'}

async def collect(settings,database):
    # System calls run off the UI loop; Ollama only receives a read-only model-list request.
    import asyncio
    hw,ollama=await asyncio.gather(asyncio.to_thread(hardware),OllamaProvider(settings).status())
    return {'hardware':hw,'ollama':ollama,'database':{'status':'connected','revision':database.revision(),'path':str(database.paths.database)},
            'tools':inventory(),'recommendations':recommendations(hw,ollama),'config_path':str(database.paths.settings)}
