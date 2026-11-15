"""Lifecycle composition without starting services or installing dependencies."""
import logging
import os
from logging.handlers import RotatingFileHandler
from .config import Paths,load,save
from .database import Database

class Runtime:
    def __init__(self,paths=None):
        self.paths=paths or Paths();self.paths.initialize();self.settings=load(self.paths)
        if not self.paths.settings.exists():save(self.paths,self.settings)
        self.database=Database(self.paths);self.database.migrate()
        self.logger=logging.getLogger('shadow.lifecycle')
        # A runtime can be created repeatedly in tests or embedded terminal sessions.
        for handler in list(self.logger.handlers):self.logger.removeHandler(handler);handler.close()
        log_path=self.paths.logs/'shadow.log'
        if log_path.is_symlink():raise ValueError('Refusing symlink log file')
        handler=RotatingFileHandler(log_path,maxBytes=512000,backupCount=3,encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        self.logger.addHandler(handler);self.logger.setLevel(logging.INFO);self.logger.propagate=False
        if os.name=='posix':log_path.chmod(0o600)
        self.logger.info('Phase 1 runtime initialized')

    def close(self):
        self.database.close()
        for handler in list(self.logger.handlers):self.logger.removeHandler(handler);handler.close()
