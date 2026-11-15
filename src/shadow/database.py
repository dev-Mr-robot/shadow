"""SQLAlchemy repository and packaged Alembic migrations for foundation data."""
import json
import os
import uuid
from datetime import datetime,timezone
from pathlib import Path
from sqlalchemy import create_engine,event,select,func
from sqlalchemy.orm import DeclarativeBase,Mapped,mapped_column,Session
from sqlalchemy import String,Text,Integer,URL,Index
from alembic import command
from alembic.config import Config

class Base(DeclarativeBase):pass

def now():return datetime.now(timezone.utc).isoformat()

class Audit(Base):
    __tablename__='audit_events'
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    timestamp:Mapped[str]=mapped_column(String(40),default=now)
    action:Mapped[str]=mapped_column(String(100))
    details:Mapped[str]=mapped_column(Text,default='{}')

class Engagement(Base):
    __tablename__='engagements'
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
    name:Mapped[str]=mapped_column(String(150))
    scope:Mapped[str]=mapped_column(Text)
    exclusions:Mapped[str]=mapped_column(Text,default='[]')
    authorization:Mapped[str]=mapped_column(Text)
    rules:Mapped[str]=mapped_column(Text,default='')
    created:Mapped[str]=mapped_column(String(40),default=now)

class Record(Base):
    __tablename__='workspace_records'
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
    kind:Mapped[str]=mapped_column(String(60),index=True)
    parent:Mapped[str|None]=mapped_column(String(36),nullable=True)
    body:Mapped[str]=mapped_column(Text)
    created:Mapped[str]=mapped_column(String(40),default=now)
    updated:Mapped[str]=mapped_column(String(40),default=now)
    __table_args__=(Index('ix_records_kind_parent_created','kind','parent','created'),)

class Database:
    def __init__(self,paths):
        self.paths=paths
        self.engine=create_engine(URL.create('sqlite+pysqlite',database=str(paths.database)),connect_args={'timeout':15})
        @event.listens_for(self.engine,'connect')
        def pragmas(connection,record):
            connection.execute('PRAGMA foreign_keys=ON');connection.execute('PRAGMA busy_timeout=15000')

    def migrate(self):
        self.paths.initialize()
        cfg=Config();cfg.set_main_option('script_location',str(Path(__file__).parent/'migrations'))
        with self.engine.begin() as connection:
            cfg.attributes['connection']=connection
            command.upgrade(cfg,'head')
        with self.engine.connect() as connection:connection.exec_driver_sql('PRAGMA journal_mode=WAL')
        if os.name=='posix':self.paths.database.chmod(0o600)

    def revision(self):
        with self.engine.connect() as connection:return connection.exec_driver_sql('SELECT version_num FROM alembic_version').scalar_one()

    def audit(self,action,details=None):
        with Session(self.engine) as s,s.begin():s.add(Audit(action=action,details=json.dumps(details or {})))

    def audit_rows(self,limit=30):
        with Session(self.engine) as s:
            return [{'id':a.id,'timestamp':a.timestamp,'action':a.action,'details':json.loads(a.details)} for a in s.scalars(select(Audit).order_by(Audit.id.desc()).limit(limit))]

    def create_engagement(self,body):
        with Session(self.engine) as s,s.begin():
            row=Engagement(name=body.name,scope=json.dumps(body.scope),exclusions=json.dumps(body.exclusions),authorization=body.authorization,rules=body.rules)
            s.add(row);s.flush();rid=row.id
            s.add(Audit(action='engagement.created',details=json.dumps({'id':rid,'name':body.name})))
        return self.engagement(rid)

    def engagement(self,rid):
        with Session(self.engine) as s:
            row=s.get(Engagement,rid)
            if not row:raise ValueError('Engagement not found')
            return {'id':row.id,'name':row.name,'scope':json.loads(row.scope),'exclusions':json.loads(row.exclusions),'authorization':row.authorization,'rules':row.rules,'created':row.created}

    def engagements(self):
        with Session(self.engine) as s:
            ids=list(s.scalars(select(Engagement.id).order_by(Engagement.created.desc())))
        return [self.engagement(rid) for rid in ids]

    def update_engagement(self,rid,body):
        with Session(self.engine) as s,s.begin():
            row=s.get(Engagement,rid)
            if not row:raise ValueError('Engagement not found')
            row.name=body.name;row.scope=json.dumps(body.scope);row.exclusions=json.dumps(body.exclusions)
            row.authorization=body.authorization;row.rules=body.rules
            s.add(Audit(action='engagement.updated',details=json.dumps({'id':rid})))
        return self.engagement(rid)

    @staticmethod
    def _record(row):
        if row is None:raise ValueError('Record not found')
        return {**json.loads(row.body),'id':row.id,'created':row.created,'updated':row.updated}

    def create(self,kind,body,parent=None):
        if not isinstance(body,dict):raise ValueError('Record body must be an object')
        clean={k:v for k,v in body.items() if k not in {'id','created','updated'}}
        with Session(self.engine) as s,s.begin():
            row=Record(kind=kind,parent=parent,body=json.dumps(clean));s.add(row);s.flush();result=self._record(row)
        return result

    def get(self,kind,rid):
        with Session(self.engine) as s:
            return self._record(s.scalar(select(Record).where(Record.id==rid,Record.kind==kind)))

    def listing(self,kind,parent=None,limit=200,offset=0):
        if not isinstance(limit,int) or not 1<=limit<=10000 or offset<0:raise ValueError('Invalid pagination')
        query=select(Record).where(Record.kind==kind)
        if parent is not None:query=query.where(Record.parent==parent)
        with Session(self.engine) as s:
            return [self._record(row) for row in s.scalars(query.order_by(Record.created.desc(),Record.id).limit(limit).offset(offset))]

    def update(self,kind,rid,patch):
        with Session(self.engine) as s,s.begin():
            row=s.scalar(select(Record).where(Record.id==rid,Record.kind==kind))
            if row is None:raise ValueError('Record not found')
            value=json.loads(row.body);value.update({k:v for k,v in patch.items() if k not in {'id','created','updated'}})
            row.body=json.dumps(value);row.updated=now();s.flush();result=self._record(row)
        return result

    def remove(self,kind,rid):
        with Session(self.engine) as s,s.begin():
            row=s.scalar(select(Record).where(Record.id==rid,Record.kind==kind))
            if row is None:raise ValueError('Record not found')
            s.delete(row);s.add(Audit(action=kind+'.removed',details=json.dumps({'id':rid})))

    def claim(self,kind,rid,status='pending',new_status='running'):
        """Atomic single-use approval transition across CLI/TUI processes."""
        from sqlalchemy import text
        with self.engine.begin() as c:
            result=c.execute(text("UPDATE workspace_records SET body=json_set(body,'$.status',:next),updated=:stamp WHERE id=:id AND kind=:kind AND json_extract(body,'$.status')=:old"),{'next':new_status,'stamp':now(),'id':rid,'kind':kind,'old':status})
            if result.rowcount!=1:raise ValueError('Approval has expired, was consumed or is no longer pending')
        return self.get(kind,rid)

    def close(self):self.engine.dispose()
