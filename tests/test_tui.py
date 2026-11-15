from textual.widgets import DataTable,Select,Input,TabbedContent,Static
from shadow.tui import ShadowApp
from shadow.config import load

async def test_tui_keyboard_navigation_and_settings(runtime,monkeypatch):
    import shadow.tui as module
    snapshot={
      'hardware':{'distribution':'Test Linux','python':'3.14','cpu':'Test CPU','ram_available_bytes':4*1024**3,'ram_total_bytes':8*1024**3,'gpus':[]},
      'ollama':{'available':True,'selected_model':'','selected_available':False,'models':[{'name':'small:local','size':1000,'parameters':'3B','quantization':'Q4'}]},
      'database':{'status':'connected','revision':'0001_foundation'},
      'tools':[{'name':'nmap','detected':False,'path':None,'installation':'manual'}]}
    async def collect(*args):return snapshot
    monkeypatch.setattr(module,'collect',collect)
    app=ShadowApp(runtime)
    async with app.run_test(size=(120,45)) as pilot:
        await app.workers.wait_for_complete();await pilot.pause()
        assert app.query_one('#tools-table',DataTable).row_count==1
        await pilot.press('f3');await pilot.pause()
        assert app.query_one('#tabs',TabbedContent).active=='models'
        app.query_one('#model-select',Select).value='small:local'
        app.query_one('#context',Input).value='8192'
        await pilot.click('#save-settings');await pilot.pause()
        assert load(runtime.paths).model=='small:local'
        assert load(runtime.paths).context_length==8192
        app.query_one('#context',Input).value='1'
        await pilot.click('#save-settings');await pilot.pause()
        assert load(runtime.paths).context_length==8192
        # Function-key navigation remains available while an input has focus.
        app.query_one('#context',Input).focus()
        await pilot.pause()
        await pilot.press('f5');await pilot.pause()
        assert app.query_one('#tabs',TabbedContent).active=='roadmap'

async def test_tui_offline_is_an_explicit_error_state(runtime,monkeypatch):
    import shadow.tui as module
    async def failed(*args):raise RuntimeError('diagnostic fixture failure')
    monkeypatch.setattr(module,'collect',failed)
    app=ShadowApp(runtime)
    async with app.run_test(size=(90,35)) as pilot:
        await app.workers.wait_for_complete();await pilot.pause()
        assert 'Diagnostics failed' in str(app.query_one('#message',Static).render())
