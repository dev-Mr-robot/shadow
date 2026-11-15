"""Official pip bootstrap confined to the application virtual environment."""
import hashlib
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

def bootstrap(python):
    url='https://bootstrap.pypa.io/get-pip.py'
    print('Bootstrapping pip from its official PyPA source:',url,flush=True)
    with urllib.request.urlopen(url,timeout=60) as response:data=response.read(4*1024*1024+1)
    if len(data)>4*1024*1024:raise ValueError('Official pip bootstrap exceeds supported size')
    print('Bootstrap SHA256:',hashlib.sha256(data).hexdigest(),flush=True)
    with tempfile.TemporaryDirectory(prefix='shadow-pip-') as directory:
        path=Path(directory)/'get-pip.py';path.write_bytes(data)
        subprocess.run([str(python),str(path),'--disable-pip-version-check'],check=True)

if __name__=='__main__':bootstrap(sys.argv[1])
