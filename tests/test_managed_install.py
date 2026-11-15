"""Managed lifecycle boundaries without downloads or system changes."""
import importlib.util
import json
import sys
from pathlib import Path
import pytest

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'

def load(name,monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec=importlib.util.spec_from_file_location(name,SCRIPTS/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def test_managed_uninstall_preserves_research_and_config(tmp_path,monkeypatch):
    installer=load('install_runtime',monkeypatch);uninstaller=load('uninstall_runtime',monkeypatch)
    data=tmp_path/'data';config=tmp_path/'config';runtime=data/'runtime'
    runtime.mkdir(parents=True);config.mkdir();(data/'research.sqlite3').write_text('evidence');(config/'config.json').write_text('{}')
    launcher=tmp_path/'shadow';launcher.write_text(installer.launcher_text(runtime))
    (runtime/'install.json').write_text(json.dumps({'application':'shadow-security-cli','runtime':str(runtime),'launcher':str(launcher)}))
    monkeypatch.setattr(uninstaller,'root_paths',lambda:(data,config,runtime))
    uninstaller.uninstall()
    assert not runtime.exists() and not launcher.exists()
    assert (data/'research.sqlite3').read_text()=='evidence' and (config/'config.json').exists()


def test_unrecognized_runtime_is_never_removed(tmp_path,monkeypatch):
    module=load('uninstall_runtime',monkeypatch)
    runtime=tmp_path/'runtime';runtime.mkdir();(runtime/'keep').write_text('keep')
    (runtime/'install.json').write_text(json.dumps({'application':'other','runtime':str(runtime)}))
    monkeypatch.setattr(module,'root_paths',lambda:(tmp_path/'data',tmp_path/'config',runtime))
    with pytest.raises(ValueError):module.uninstall()
    assert (runtime/'keep').exists()
