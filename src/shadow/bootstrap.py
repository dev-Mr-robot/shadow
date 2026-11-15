"""Stdlib-only entry guard so missing Python packages have an actionable repair path."""
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

REQUIRED={'typer':'typer','textual':'textual','rich':'rich','httpx':'httpx','pydantic':'pydantic','psutil':'psutil','sqlalchemy':'sqlalchemy','alembic':'alembic','pypdf':'pypdf','defusedxml':'defusedxml','reportlab':'reportlab','yaml':'PyYAML'}

def main():
    missing=[name for module,name in REQUIRED.items() if importlib.util.find_spec(module) is None]
    runtime=Path(sys.executable).absolute().parents[2]
    lock=runtime/'requirements.lock.txt'
    if missing:
        if sys.argv[1:]==['doctor','--json']:
            print(json.dumps({'runtime_ready':False,'missing_dependencies':missing,'repair':'shadow setup --repair'}));return 1
        print('SHADOW is missing runtime packages:',', '.join(missing))
        explicit=sys.argv[1:]==['setup','--repair']
        approved=explicit
        if not approved and sys.stdin.isatty():
            try:approved=input('Repair these Python dependencies inside SHADOW’s private environment? [y/N] ').lower() in {'y','yes'}
            except EOFError:approved=False
        if not approved or not lock.is_file():
            print('Repair with: shadow setup --repair, or re-run the SHADOW installer. Your data is preserved.');return 1
        subprocess.run([sys.executable,'-m','pip','install','-r',str(lock)],check=True)
    from .main import main as cli_main
    cli_main();return 0

if __name__=='__main__':raise SystemExit(main())
