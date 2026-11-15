import json
from unittest.mock import AsyncMock
from shadow import setup
from shadow.config import save,Settings


def test_diagnose_invalid_config_without_overwrite(paths):
    paths.initialize();paths.settings.write_text('{broken')
    result=setup.diagnose(paths)
    assert not result['ready']
    assert any(i['area']=='configuration' for i in result['issues'])
    assert paths.settings.read_text()=='{broken'


def test_repair_config_requires_consent_and_saves_original(paths):
    from rich.console import Console
    paths.initialize();paths.settings.write_text('{broken')
    result=setup.repair(paths,Console(),lambda _:False)
    assert not result['diagnosis']['ready'] and paths.settings.read_text()=='{broken'
    result=setup.repair(paths,Console(),lambda _:True)
    assert result['diagnosis']['ready']
    backups=list(paths.config.glob('config.invalid-backup-*.json'))
    assert len(backups)==1 and backups[0].read_text()=='{broken'


def test_first_run_optional_ai_unavailable_does_not_block(runtime,monkeypatch):
    from rich.console import Console
    status={'hardware':{'distribution':'Linux','cpu':'test','ram_available_bytes':4*1024**3,'gpus':[]},'ollama':{'available':False,'models':[]},'tools':[{'name':'nmap','detected':False}]}
    monkeypatch.setattr(setup,'collect',AsyncMock(return_value=status))
    monkeypatch.setattr(setup.shutil,'which',lambda _:None)
    setup.first_run(runtime,Console(),lambda _:False,lambda *a,**k:'')
    assert runtime.settings.setup_completed
    assert json.loads(runtime.paths.settings.read_text())['setup_completed']
    assert runtime.database.revision()=='0004_soc'


def test_tools_declined_no_system_changes(monkeypatch):
    from rich.console import Console
    monkeypatch.setattr(setup.sys,'platform','linux')
    monkeypatch.setattr(setup.shutil,'which',lambda name:'/usr/bin/apt-get' if name=='apt-get' else None)
    monkeypatch.setattr(setup.subprocess,'run',lambda *a,**k:(_ for _ in ()).throw(AssertionError('must not run')))
    setup.install_tools(Console(),lambda _:False)
