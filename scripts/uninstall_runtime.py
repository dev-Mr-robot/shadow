"""Remove only a verified managed runtime. Research and configuration are preserved."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from install_runtime import root_paths,own_launcher

def uninstall():
    data,config,runtime=root_paths()
    marker=runtime/'install.json'
    if not marker.is_file() or marker.is_symlink():raise ValueError('No verified managed installation was found')
    info=json.loads(marker.read_text())
    if info.get('application')!='shadow-security-cli' or info.get('runtime')!=str(runtime):raise ValueError('Runtime ownership could not be verified')
    resolved=runtime.resolve()
    if resolved!=runtime or resolved in {Path('/'),Path.home().resolve(),data.resolve(),config.resolve()}:raise ValueError('Refusing unsafe runtime deletion')
    launcher=Path(info['launcher']) if info.get('launcher') else None
    if launcher and own_launcher(launcher,runtime) and (launcher.exists() or launcher.is_symlink()):
        if os.access(launcher.parent,os.W_OK):launcher.unlink()
        else:
            print('Removing only the verified global SHADOW launcher requires sudo authorization.')
            try:approved=input('Remove this launcher using sudo? [y/N] ').lower() in {'y','yes'}
            except EOFError:approved=False
            if not approved:raise ValueError('Uninstall deferred; no runtime files deleted')
            subprocess.run(['sudo','rm','--',str(launcher)],check=True)
    shutil.rmtree(resolved)
    print('Removed the managed runtime and matching launcher. Research, databases, reports, configuration and profile backups are preserved. Managed PATH entries are harmless and retained.')

if __name__=='__main__':
    try:uninstall()
    except (OSError,ValueError,subprocess.CalledProcessError) as exc:print('SHADOW uninstall:',exc,file=sys.stderr);sys.exit(1)
