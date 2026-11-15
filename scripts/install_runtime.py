"""One-command Linux installer. Only explained, approved OS/PATH changes occur."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

APP='shadow-security-cli'

def confirm(question):
    try:return input(question+' [y/N] ').strip().lower() in {'y','yes'}
    except EOFError:return False

def run(argv):
    print('+ '+shlex.join([str(v) for v in argv]),flush=True)
    subprocess.run([str(v) for v in argv],check=True)

def install_system_packages(packages):
    if not packages:return
    if not shutil.which('apt-get'):raise RuntimeError('Install these required OS packages with your distribution package manager: '+', '.join(packages))
    print('Required system packages:',', '.join(packages))
    print('This uses APT and sudo authorization. SHADOW will not add repositories or change firewall/security settings.')
    if not confirm('Install exactly these system packages?'):raise RuntimeError('Required system packages were declined; no system changes made')
    prefix=[] if os.geteuid()==0 else ['sudo']
    if prefix and not shutil.which('sudo'):raise RuntimeError('sudo is unavailable; ask the system administrator to install the listed packages')
    run(prefix+['apt-get','update']);run(prefix+['apt-get','install','-y',*packages])

def root_paths():
    data=Path(os.environ.get('SHADOW_DATA_DIR','~/.local/share/shadow')).expanduser().absolute()
    config=Path(os.environ.get('SHADOW_CONFIG_DIR','~/.config/shadow')).expanduser().absolute()
    runtime=Path(os.environ.get('SHADOW_RUNTIME_DIR',str(data/'runtime'))).expanduser().absolute()
    for path in [data,config,runtime]:
        if any(ord(c)<32 for c in str(path)) or any(parent.is_symlink() for parent in [path,*path.parents]):raise ValueError('Unsafe/symlink installation path')
    if runtime in {Path('/'),Path.home(),data,config}:raise ValueError('Runtime must be its own subdirectory, never a user-data root')
    return data,config,runtime

def launcher_text(runtime):
    python=runtime/'venv'/'bin'/'python'
    return '#!/usr/bin/env bash\n# SHADOW managed launcher: '+str(runtime)+'\nset -e\nif [[ ! -x '+shlex.quote(str(python))+' ]]; then\n  printf "SHADOW runtime is missing. Re-run the SHADOW installer to repair it; your research data is preserved.\\n" >&2\n  exit 1\nfi\nexec '+shlex.quote(str(python))+' -I -m shadow.bootstrap "$@"\n'

def own_launcher(path,runtime):
    if not path.exists() and not path.is_symlink():return True
    if path.is_symlink():return path.resolve()==runtime/'venv'/'bin'/'shadow'
    try:return ('# SHADOW managed launcher: '+str(runtime)) in path.read_text(encoding='utf-8')[:2048]
    except (OSError,UnicodeError):return False

def configure_path(directory):
    if str(directory) in os.environ.get('PATH','').split(os.pathsep):return []
    shell=Path(os.environ.get('SHELL','/bin/bash')).name
    profiles=[Path.home()/'.profile',Path.home()/'.bashrc']
    if shell=='zsh':profiles.append(Path.home()/'.zshrc')
    if shell=='fish':profiles.append(Path.home()/'.config'/'fish'/'config.fish')
    print('To make shadow available in every new terminal, append a managed PATH entry to:')
    for path in profiles:print(' ',path,'(existing files are backed up first)')
    if not confirm('Authorize these PATH startup-file changes?'):raise RuntimeError('PATH changes declined. Choose the system-wide launcher option or authorize PATH setup to use plain shadow.')
    backups=[]
    for path in profiles:
        if path.is_symlink():raise ValueError('Refusing to edit symlink shell profile: '+str(path))
        path.parent.mkdir(parents=True,exist_ok=True)
        old=path.read_text(encoding='utf-8') if path.exists() else ''
        marker='# SHADOW managed PATH: '+str(directory)
        if marker in old:continue
        if path.exists():
            backup=path.with_name(path.name+'.shadow-backup-'+uuid.uuid4().hex[:12]);shutil.copy2(path,backup);backups.append(str(backup))
        line='fish_add_path -- '+shlex.quote(str(directory)) if path.suffix=='.fish' else 'export PATH='+shlex.quote(str(directory))+':"$PATH"'
        mode=stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
        fd,name=tempfile.mkstemp(prefix='.shadow-profile-',dir=path.parent)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:stream.write(old.rstrip()+'\n\n'+marker+'\n'+line+'\n')
        os.chmod(name,mode);os.replace(name,path)
    print('PATH is configured for new terminals. This installer does not alter the calling shell process.')
    return backups

def install(args):
    if sys.platform!='linux':raise RuntimeError('This installer targets Linux terminals')
    if sys.version_info<(3,11):raise RuntimeError('Python3.11+ is required; use the system package manager or provide SHADOW_PYTHON pointing to a supported interpreter. No third-party repository is added automatically.')
    source=Path(__file__).resolve().parents[1];data,config,runtime=root_paths()
    for module in ['venv','ssl','sqlite3']:
        if importlib.util.find_spec(module) is None:install_system_packages(['python3-full','python3-venv','ca-certificates']);break
    print('Installing SHADOW terminal runtime under:',runtime)
    if runtime.exists() and any(runtime.iterdir()) and not (runtime/'install.json').exists():raise ValueError('Runtime path contains unrecognized files; refusing to overwrite it')
    for path in [data,config,runtime]:path.mkdir(mode=0o700,parents=True,exist_ok=True);path.chmod(0o700)
    marker=runtime/'install.json'
    previous=json.loads(marker.read_text()) if marker.exists() else {}
    if previous and previous.get('application')!=APP:raise ValueError('Unrecognized installation marker')
    # Write ownership before bootstrap so interrupted installs remain safely repairable.
    marker.write_text(json.dumps({'application':APP,'source':str(source),'status':'installing',**{k:v for k,v in previous.items() if k in {'launcher','path_backups'}}},indent=2));marker.chmod(0o600)
    environment=runtime/'venv';python=environment/'bin'/'python'
    if environment.is_symlink():raise ValueError('Refusing symlink runtime environment')
    if python.exists() and not (environment/'pyvenv.cfg').is_file():raise ValueError('Unrecognized Python environment; refusing modification')
    if not python.exists():
        import venv
        venv.EnvBuilder(with_pip=False).create(environment)
    available=subprocess.run([str(python),'-m','pip','--version'],capture_output=True).returncode==0
    if not available:
        from bootstrap_pip import bootstrap
        bootstrap(python)
    run([python,'-m','pip','install','--disable-pip-version-check','-r',source/'requirements.lock.txt'])
    run([python,'-m','pip','install','--disable-pip-version-check','--no-deps','--upgrade',source])
    shutil.copy2(source/'requirements.lock.txt',runtime/'requirements.lock.txt')
    run([environment/'bin'/'shadow','init'])
    launcher=None;backups=previous.get('path_backups',[])
    if not args.no_link:
        selected=os.environ.get('SHADOW_BIN_DIR')
        use_system=not selected and not args.user
        directory=Path(selected).expanduser().absolute() if selected else Path('/usr/local/bin') if use_system else Path.home()/'.local'/'bin'
        if use_system and not os.access(directory,os.W_OK):
            print('A global terminal launcher can be installed at /usr/local/bin/shadow using sudo. No shell profile edit is then normally needed.')
            if not shutil.which('sudo') or not confirm('Authorize installation of this single global launcher using sudo?'):directory=Path.home()/'.local'/'bin';use_system=False
        directory.mkdir(parents=True,exist_ok=True) if not use_system or os.access(directory,os.W_OK) else None
        target=directory/'shadow'
        if not own_launcher(target,runtime):raise ValueError('Preserved an unrelated existing launcher: '+str(target))
        content=launcher_text(runtime)
        unchanged=target.is_file() and not target.is_symlink() and target.read_text(encoding='utf-8')==content
        if not unchanged:
            fd,name=tempfile.mkstemp(prefix='shadow-launcher-');os.close(fd)
            try:
                Path(name).write_text(content,encoding='utf-8');os.chmod(name,0o755)
                if os.access(directory,os.W_OK):
                    if target.is_symlink():target.unlink()
                    shutil.copyfile(name,target);target.chmod(0o755)
                else:run(['sudo','install','-m','755','--',name,target])
            finally:Path(name).unlink(missing_ok=True)
        launcher=str(target);backups+=configure_path(directory)
    info={'application':APP,'source':str(source),'runtime':str(runtime),'launcher':launcher,'path_backups':backups,'status':'ready'}
    marker.write_text(json.dumps(info,indent=2));marker.chmod(0o600)
    run([python,'-m','pip','check'])
    print('\nSHADOW installed. Open a new terminal and type: shadow')
    print('No activation, project-directory navigation or separate application service is required.')
    print('First launch offers local model setup. Optional tools never block the application.')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Install/repair SHADOW as one globally reachable terminal command.')
    parser.add_argument('--user',action='store_true',help='Use ~/.local/bin with authorized PATH setup instead of a sudo global launcher')
    parser.add_argument('--no-link',action='store_true',help='Explicitly omit the global launcher (advanced/packaging use)')
    parser.add_argument('--repair',action='store_true',help='Repair/upgrade the recognized isolated runtime, retaining data/configuration')
    args=parser.parse_args()
    try:install(args)
    except (OSError,ValueError,RuntimeError,subprocess.CalledProcessError) as exc:print('SHADOW installation:',exc,file=sys.stderr);sys.exit(1)
