from textual.widgets import Input,Select,TabbedContent,DataTable,Static
from shadow.tui import ShadowApp
from test_soc import dataset

async def test_soc_terminal_ingest_detect_and_select_alert(runtime,tmp_path,monkeypatch):
    import shadow.tui as module
    async def offline(settings,database):
        return {'hardware':{'distribution':'Synthetic Linux fixture','python':'3.14','cpu':'Fixture CPU','ram_available_bytes':4*1024**3,'ram_total_bytes':8*1024**3,'gpus':[]},
                'ollama':{'available':False,'error':'Fixture Ollama offline','selected_model':'','selected_available':False,'models':[]},
                'database':{'status':'connected','revision':database.revision()},'tools':[]}
    monkeypatch.setattr(module,'collect',offline)
    path=dataset(tmp_path);app=ShadowApp(runtime)
    async with app.run_test(size=(150,58)) as pilot:
        await app.workers.wait_for_complete();await pilot.pause()
        app.query_one('#tabs',TabbedContent).active='soc-center';await pilot.pause();await app.workers.wait_for_complete()
        app.query_one('#soc-file',Input).value=str(path)
        await pilot.click('#soc-ingest');await app.workers.wait_for_complete();await pilot.pause()
        assert 'failed' not in str(app.query_one('#message',Static).render()).lower()
        await pilot.click('#soc-detect');await app.workers.wait_for_complete();await pilot.pause()
        app.query_one('#soc-section',Select).value='Alert Management';await pilot.pause();await app.workers.wait_for_complete();await pilot.pause()
        assert app.query_one('#soc-table',DataTable).row_count>=3
        app.query_one('#soc-section',Select).value='MITRE ATT&CK Explorer';await pilot.pause();await app.workers.wait_for_complete()
        assert app.query_one('#soc-table',DataTable).row_count>=4
        await pilot.click('#soc-ask');await pilot.pause()
        assert app.query_one('#tabs',TabbedContent).active=='assistant' and app.query_one('#research-mode',Select).value=='soc'
