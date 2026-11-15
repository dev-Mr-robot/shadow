from pathlib import Path
from alembic.config import Config
from alembic import command
from shadow.database import Database
from shadow.scope import EngagementInput

def test_phase1_database_upgrades_without_losing_authorization(paths):
    paths.initialize();db=Database(paths)
    cfg=Config();cfg.set_main_option('script_location',str(Path(__file__).resolve().parents[1]/'src'/'shadow'/'migrations'))
    with db.engine.begin() as connection:
        cfg.attributes['connection']=connection;command.upgrade(cfg,'0001_foundation')
    body=EngagementInput(name='Existing Phase 1 lab',scope=['192.168.56.10'],authorization='Existing written authorization')
    row=db.create_engagement(body)
    assert db.revision()=='0001_foundation'
    db.migrate();db.migrate()
    assert db.revision()=='0004_soc' and db.engagement(row['id'])['authorization']==body.authorization
    note=db.create('note',{'content':'workspace migrated'},row['id'])
    assert db.get('note',note['id'])['content']=='workspace migrated'
    with db.engine.connect() as c:assert c.exec_driver_sql('SELECT count(*) FROM recon_assets').scalar_one()==0
    db.close()
