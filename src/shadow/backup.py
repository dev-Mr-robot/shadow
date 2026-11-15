"""Consistent SQLite backup/restore; restore always preserves a pre-restore snapshot."""
import os
import sqlite3
import uuid
from pathlib import Path

def validate_file(path):
    path=Path(path).expanduser()
    if path.is_symlink() or not path.is_file():raise ValueError('Select a regular SQLite file, not a symlink')
    if path.stat().st_size>2*1024**3:raise ValueError('Backup exceeds 2 GiB limit')
    return path.resolve()

def backup(state,output):
    output=Path(output).expanduser().absolute()
    if output.exists() or output.is_symlink():raise ValueError('Backup destination already exists')
    if not output.parent.is_dir():raise ValueError('Backup parent directory must exist')
    fd=os.open(output,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
    try:
        with sqlite3.connect(state.paths.database) as source,sqlite3.connect(output) as target:source.backup(target,pages=256)
    except BaseException:output.unlink(missing_ok=True);raise
    state.database.audit('database.backup',{'filename':output.name})
    return output

def restore(state,source,approved=False):
    if approved is not True:raise ValueError('Restoring requires explicit approval; stop other SHADOW sessions first')
    source=validate_file(source)
    if source==state.paths.database.resolve():raise ValueError('Cannot restore the live database onto itself')
    with sqlite3.connect(source.as_uri()+'?mode=ro',uri=True) as connection:
        if connection.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ValueError('Backup integrity check failed')
        tables={r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'alembic_version','audit_events','engagements'}<=tables:raise ValueError('This is not a SHADOW database backup')
        revision=connection.execute('SELECT version_num FROM alembic_version').fetchone()[0]
        from alembic.script import ScriptDirectory
        from alembic.config import Config
        cfg=Config();cfg.set_main_option('script_location',str(Path(__file__).parent/'migrations'))
        try:ScriptDirectory.from_config(cfg).get_revision(revision)
        except Exception as exc:raise ValueError('Backup has an unsupported schema revision') from exc
    folder=state.paths.data/'backups';folder.mkdir(mode=0o700,exist_ok=True)
    safety=backup(state,folder/('pre-restore-'+uuid.uuid4().hex+'.sqlite3'))
    state.database.engine.dispose()
    # SQLite's backup transaction updates the destination safely, without deleting a live WAL file.
    with sqlite3.connect(source.as_uri()+'?mode=ro',uri=True) as connection,sqlite3.connect(state.paths.database) as target:connection.backup(target,pages=256)
    state.database.migrate();state.database.audit('database.restored',{'source':source.name,'safety_backup':safety.name})
    return {'restored':source.name,'pre_restore_backup':str(safety)}
