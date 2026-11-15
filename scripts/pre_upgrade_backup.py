"""Back up existing CLI data before package changes; requires only Python stdlib."""
import os
import sqlite3
import uuid
from pathlib import Path

def create_backup():
    data=Path(os.environ.get('SHADOW_DATA_DIR','~/.local/share/shadow')).expanduser()
    database=data/'shadow-cli.sqlite3'
    if not database.exists():print('No existing CLI database to back up.');return
    if data.is_symlink() or database.is_symlink():raise ValueError('Refusing symlink data/database during upgrade')
    folder=data/'backups'
    if folder.is_symlink():raise ValueError('Refusing symlink backup directory')
    folder.mkdir(mode=0o700,exist_ok=True)
    output=folder/('pre-upgrade-'+uuid.uuid4().hex+'.sqlite3')
    fd=os.open(output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
    with sqlite3.connect(database) as source,sqlite3.connect(output) as target:source.backup(target,pages=256)
    print('Pre-upgrade backup:',output)

if __name__=='__main__':create_backup()
