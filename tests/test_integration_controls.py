import asyncio
import sys
import time
from pathlib import Path
import pytest
from shadow.integrations import ToolManager,validate_ports,validate_target
from shadow.scope import EngagementInput
from shadow.actions import ActionRunner
from shadow.backup import backup,restore

def engagement(state):return state.database.create_engagement(EngagementInput(name='Owned test lab',scope=['192.168.56.0/24','lab.test'],exclusions=['192.168.56.20'],authorization='Written authorization for an isolated test lab'))

def test_preview_scope_and_fixed_arguments(runtime):
    e=engagement(runtime);manager=ToolManager(runtime)
    row=manager.preview(e['id'],'192.168.56.10')
    assert row['status']=='pending' and row['argv'][-1]=='192.168.56.10'
    assert '-sT' in row['argv'] and '-sV' not in row['argv'] and '--script' not in row['argv']
    for target in ['8.8.8.8','192.168.56.20','lab.test','192.168.56.1;id','0.0.0.0']:
        with pytest.raises(ValueError):manager.preview(e['id'],target)
    for ports in ['22;id','0','1-65535','22,--script=all']:
        with pytest.raises(ValueError):validate_ports(ports)

async def test_tool_approval_and_single_use(runtime,monkeypatch):
    e=engagement(runtime);manager=ToolManager(runtime);row=manager.preview(e['id'],'192.168.56.10')
    with pytest.raises(ValueError):await manager.execute(row['id'],row['digest'])
    monkeypatch.setattr('shadow.integrations.sandbox',lambda argv:[sys.executable,'-c','print("test output")'])
    result=await manager.execute(row['id'],row['digest'],approved=True)
    assert result['status']=='completed' and 'test output' in result['output']
    with pytest.raises(ValueError):await manager.execute(row['id'],row['digest'],approved=True)

async def test_real_process_timeout_cancel_and_output_limit(runtime):
    e=engagement(runtime);manager=ToolManager(runtime)
    def job():return manager.preview(e['id'],'192.168.56.10')
    row=job();result=await manager._capture(row['id'],[sys.executable,'-c','import time;time.sleep(10)'],.1)
    assert result['status']=='timed_out'
    row=job();runtime.database.update('job',row['id'],{'status':'running'})
    task=asyncio.create_task(manager._capture(row['id'],[sys.executable,'-c','import time;time.sleep(10)'],10))
    await asyncio.sleep(.1);manager.cancel(row['id']);result=await task
    assert result['status']=='cancelled'
    row=job();result=await manager._capture(row['id'],[sys.executable,'-c','import sys;sys.stdout.write("x"*1100000)'],5)
    assert result['status']=='output_limit' and len(result['output'])<=1024*1024

async def test_tool_rechecks_scope_and_expiry(runtime,monkeypatch):
    e=engagement(runtime);manager=ToolManager(runtime);row=manager.preview(e['id'],'192.168.56.10')
    runtime.database.update('job',row['id'],{'expires':0})
    with pytest.raises(ValueError):await manager.execute(row['id'],row['digest'],approved=True)
    row=manager.preview(e['id'],'192.168.56.10')
    runtime.database.update_engagement(e['id'],EngagementInput(name=e['name'],scope=e['scope'],exclusions=['192.168.56.10'],authorization=e['authorization']))
    with pytest.raises(ValueError):await manager.execute(row['id'],row['digest'],approved=True)

async def test_natural_action_mutation_requires_separate_approval(runtime):
    e=engagement(runtime);runner=ActionRunner(runtime)
    preview=await runner.preview({'capability':'project_note','content':'A scoped test note'},e['id'])
    assert runtime.database.listing('note',e['id'])==[]
    with pytest.raises(ValueError):await runner.execute(preview['id'])
    result=await runner.execute(preview['id'],approved=True)
    assert result['content']=='A scoped test note'
    with pytest.raises(ValueError):await runner.execute(preview['id'],approved=True)

def test_backup_restore_is_consistent_and_preserves_safety_copy(runtime,tmp_path):
    e=engagement(runtime);destination=backup(runtime,tmp_path/'saved.sqlite3')
    runtime.database.create('note',{'content':'after backup'},e['id'])
    with pytest.raises(ValueError):backup(runtime,destination)
    with pytest.raises(ValueError):restore(runtime,destination)
    result=restore(runtime,destination,approved=True)
    assert Path(result['pre_restore_backup']).exists()
    assert runtime.database.engagement(e['id'])['name']==e['name']
    assert runtime.database.listing('note')==[]
