from textual.widgets import Input,Markdown,TabbedContent
from shadow.tui import ShadowApp

async def test_expert_tab_uses_shared_offline_investigation(runtime,monkeypatch):
    import shadow.tui as module
    async def offline(*args):raise ValueError('offline fixture')
    monkeypatch.setattr(module,'collect',offline)
    app=ShadowApp(runtime)
    async with app.run_test(size=(120,45)) as pilot:
        await app.workers.wait_for_complete()
        app.query_one('#tabs',TabbedContent).active='experts'
        app.query_one('#expert-question',Input).value='Which evidence is needed to confirm IDOR?'
        app.expert_investigate()
        await app.workers.wait_for_complete();await pilot.pause()
        cases=runtime.database.listing('expert_case')
        assert len(cases)==1
        assert 'offline' in cases[0]['inference_status']
        assert 'Missing evidence' in app.query_one('#expert-answer',Markdown).source
