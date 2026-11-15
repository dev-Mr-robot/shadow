"""Validated local configuration. No secrets or system configuration are changed."""
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from pydantic import BaseModel,ConfigDict,Field,field_validator

class Settings(BaseModel):
    model_config=ConfigDict(extra='forbid',validate_assignment=True)
    ollama_url: str='http://127.0.0.1:11434'
    model: str=Field(default='',max_length=200)
    embedding_model: str=Field(default='',max_length=200)
    context_length: int=Field(default=4096,ge=2048,le=32768)
    request_timeout: float=Field(default=5,ge=1,le=30)
    inference_timeout: float=Field(default=180,ge=5,le=600)
    active_engagement: str|None=None
    setup_completed: bool=False
    @field_validator('ollama_url')
    @classmethod
    def local_origin(cls,value):
        parsed=urlsplit(value)
        if parsed.scheme!='http' or parsed.hostname not in {'127.0.0.1','localhost','::1'} or parsed.username or parsed.password or parsed.path not in {'','/'} or parsed.query or parsed.fragment:
            raise ValueError('Ollama must use an HTTP loopback origin')
        # Access .port to validate malformed/out-of-range ports.
        _=parsed.port
        return value.rstrip('/')

class Paths:
    def __init__(self):
        self.data=Path(os.environ.get('SHADOW_DATA_DIR','~/.local/share/shadow')).expanduser().absolute()
        self.config=Path(os.environ.get('SHADOW_CONFIG_DIR','~/.config/shadow')).expanduser().absolute()
        self.settings=self.config/'config.json'
        # A dedicated new DB never mutates a previous web/experimental database.
        self.database=self.data/'shadow-cli.sqlite3'
        self.logs=self.data/'logs'

    def initialize(self):
        for path in [self.data,self.config,self.logs]:
            if path.is_symlink():raise ValueError(f'Refusing symlink data/config directory: {path}')
            path.mkdir(mode=0o700,parents=True,exist_ok=True)
            if os.name=='posix':path.chmod(0o700)
        if self.settings.is_symlink() or self.database.is_symlink():raise ValueError('Refusing symlink config/database files')

def load(paths):
    if not paths.settings.exists():return Settings()
    if paths.settings.is_symlink():raise ValueError('Refusing symlink configuration')
    if paths.settings.stat().st_size>65536:raise ValueError('Configuration exceeds 64 KiB')
    return Settings.model_validate_json(paths.settings.read_text(encoding='utf-8'))

def save(paths,settings):
    paths.initialize()
    fd,temporary=tempfile.mkstemp(prefix='.config-',dir=paths.config)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            f.write(settings.model_dump_json(indent=2)+'\n');f.flush();os.fsync(f.fileno())
        os.replace(temporary,paths.settings)
        if os.name=='posix':paths.settings.chmod(0o600)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    return settings
