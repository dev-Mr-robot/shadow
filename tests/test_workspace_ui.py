"""Headless end-to-end terminal workflows using real services and mocked local HTTP."""
import json

import httpx
import pytest
from textual.widgets import Button, Input, Markdown, RichLog, Select, Static, TabbedContent, TextArea

from shadow.intelligence import InferenceProvider
from shadow.scope import EngagementInput
from shadow.tui import ShadowApp


def status_snapshot():
    return {
        'hardware': {'distribution': 'Fixture Linux', 'python': '3.14', 'cpu': 'Fixture CPU',
                     'ram_available_bytes': 4 * 1024**3, 'ram_total_bytes': 8 * 1024**3, 'gpus': []},
        'ollama': {'available': True, 'selected_model': 'fixture:local', 'selected_available': True,
                   'models': [{'name': 'fixture:local', 'size': 1000, 'parameters': '3B', 'quantization': 'Q4'}]},
        'database': {'status': 'connected', 'revision': 'fixture'}, 'tools': []}


@pytest.fixture
def local_transport(runtime, monkeypatch):
    """Mock only the local model boundary; UI/database/actions remain real."""
    import shadow.intelligence as intelligence
    import shadow.tui as tui
    runtime.settings.model = 'fixture:local'; runtime.settings.context_length = 8192
    requests = []; state = {'plan': 'remember', 'fail': False}

    def handler(request):
        if state['fail']:
            raise httpx.ConnectError('fixture Ollama unavailable')
        body = json.loads(request.content) if request.content else {}
        requests.append({'path': request.url.path, 'body': body})
        if request.url.path == '/api/show':
            return httpx.Response(200, json={'capabilities': ['completion']})
        if request.url.path == '/api/embed':
            return httpx.Response(200, json={'embeddings': [[1., 0.] for _ in body['input']]})
        if body.get('stream'):
            content = ('Approved result recorded. Its contents are observations, not a verified vulnerability.'
                       if 'most recent approved application result' in body['messages'][-1]['content']
                       else '1. Observed HTTP behavior.\n2. An identifier is an investigation lead, not a verified authorization flaw.')
            encoded = json.dumps({'message': {'content': content}}) + '\n' + json.dumps({'done': True}) + '\n'
            return httpx.Response(200, content=encoded.encode())
        actions = [{'capability': 'remember', 'content': 'The owned lab uses test identity one',
                    'explanation': 'Save only the explicitly requested local research memory'}] if state['plan'] == 'remember' else []
        plan = {'intent': 'project' if actions else 'continuation', 'objective': 'Handle the requested research task',
                'entities': ['owned lab'], 'actions': actions}
        return httpx.Response(200, json={'message': {'content': json.dumps(plan)}})

    original = InferenceProvider
    monkeypatch.setattr(intelligence, 'InferenceProvider', lambda settings: original(settings, httpx.MockTransport(handler)))
    async def diagnostics(*args):return status_snapshot()
    monkeypatch.setattr(tui, 'collect', diagnostics)
    return requests, state


async def settled(app, pilot):
    # Let button/select messages create their workers before awaiting completion.
    await pilot.pause()
    await app.workers.wait_for_complete()
    await pilot.pause()


async def click_visible(app, pilot, selector):
    app.query_one(selector).scroll_visible(animate=False)
    await pilot.pause()
    await pilot.click(selector)
    await settled(app, pilot)


async def switch(app, pilot, pane):
    app.action_tab(pane)
    await pilot.pause()


def log_text(log):
    return '\n'.join(line.text for line in log.lines)


async def test_workspace_create_select_engagement_and_passive_http_inspection(runtime, local_transport):
    requests, _ = local_transport
    app = ShadowApp(runtime)
    async with app.run_test(size=(120, 50)) as pilot:
        await settled(app, pilot)
        assert app.query_one('#tabs', TabbedContent).active == 'assistant'
        await switch(app, pilot, 'research-workspace')
        app.query_one('#engagement-name', Input).value = 'Terminal workflow lab'
        app.query_one('#engagement-scope', TextArea).load_text('lab.test\n192.168.56.10')
        app.query_one('#engagement-authorization', Input).value = 'Written authorization for the isolated owned lab'
        await click_visible(app, pilot, '#engagement-create')
        rows = runtime.database.engagements()
        assert len(rows) == 1 and runtime.settings.active_engagement == rows[0]['id']
        assert app.query_one('#active-engagement', Select).value == rows[0]['id']
        await switch(app, pilot, 'http-lab')
        app.query_one('#http-raw', TextArea).load_text('GET /api/users?id=42 HTTP/1.1\r\nHost: lab.test\r\nCookie: session=test-only\r\n\r\n')
        await click_visible(app, pilot, '#http-inspect')
        result = log_text(app.query_one('#http-result', RichLog))
        assert '42' in result and 'lab.test' in result
        assert runtime.database.listing('import') == []
        assert requests == []  # No model call or HTTP replay for static inspection.
        # Explicitly selecting another recorded engagement refreshes active context.
        second = runtime.database.create_engagement(EngagementInput(name='Second lab', scope=['second.test'], authorization='Written authorization for a second owned lab'))
        app.refresh_engagement_options(); await pilot.pause()
        await switch(app, pilot, 'assistant')
        app.query_one('#active-engagement', Select).value = second['id']
        await settled(app, pilot)
        assert runtime.settings.active_engagement == second['id'] and app.cid is None


async def test_workspace_semantic_chat_requires_separate_review_and_approval_then_resumes(runtime, local_transport):
    requests, state = local_transport
    eid = runtime.database.create_engagement(EngagementInput(name='Owned lab', scope=['lab.test'], authorization='Written permission for this owned lab'))['id']
    runtime.settings.active_engagement = eid
    app = ShadowApp(runtime)
    async with app.run_test(size=(120, 50)) as pilot:
        await settled(app, pilot)
        app.query_one('#chat-input', Input).value = 'Please remember that the owned lab uses test identity one'
        await click_visible(app, pilot, '#chat-send')
        cid = app.cid
        assert cid and len(runtime.database.listing('message', parent=cid)) == 2
        assert runtime.database.listing('memory') == []
        assert runtime.database.listing('action_preview') == []
        assert not app.query_one('#action-review', Button).disabled
        assert app.query_one('#action-approve', Button).disabled
        await click_visible(app, pilot, '#action-review')
        assert app.pending_action and runtime.database.listing('memory') == []
        assert runtime.database.get('action_preview', app.pending_action['id'])['status'] == 'pending'
        assert not app.query_one('#action-approve', Button).disabled
        await click_visible(app, pilot, '#action-approve')
        memories = runtime.database.listing('memory')
        assert len(memories) == 1 and memories[0]['content'] == 'The owned lab uses test identity one'
        assert runtime.database.listing('action_result', parent=cid)
        assert app.query_one('#action-approve', Button).disabled
        assert any('approved_application_action' in item['body'].get('messages', [{}])[-1].get('content', '') for item in requests if item['body'].get('stream'))
        await click_visible(app, pilot, '#new-chat')
        assert app.cid is None
        app.query_one('#conversation-select', Select).value = cid
        await settled(app, pilot)
        assert app.cid == cid and len(app.query('#chat-transcript Markdown')) >= 4
        state['plan'] = 'none'
        app.query_one('#chat-input', Input).value = 'Explain the second observation and the saved result'
        await click_visible(app, pilot, '#chat-send')
        last_prompt = [item['body']['messages'] for item in requests if item['body'].get('stream')][-1]
        assert any('identifier is an investigation lead' in message['content'] for message in last_prompt if message['role'] == 'assistant')
        assert 'approved_application_action' in last_prompt[-1]['content']


async def test_workspace_rejects_proposed_mutation_and_surfaces_worker_errors(runtime, local_transport):
    _, state = local_transport
    app = ShadowApp(runtime)
    async with app.run_test(size=(100, 40)) as pilot:
        await settled(app, pilot)
        app.query_one('#chat-input', Input).value = 'Please remember this explicit research note'
        await click_visible(app, pilot, '#chat-send')
        await click_visible(app, pilot, '#action-review')
        preview_id = app.pending_action['id']
        await click_visible(app, pilot, '#action-reject')
        assert runtime.database.get('action_preview', preview_id)['status'] == 'cancelled'
        assert runtime.database.listing('memory') == []
        state['fail'] = True
        app.query_one('#chat-input', Input).value = 'Explain the most recent observation'
        await click_visible(app, pilot, '#chat-send')
        assert not app.query_one('#chat-send', Button).disabled
        assert 'failed' in str(app.query_one('#message', Static).render()).lower()
        assert runtime.database.listing('memory') == []
        await pilot.press('f3'); await pilot.pause()
        assert app.query_one('#tabs', TabbedContent).active == 'models'
        await pilot.press('f5'); await pilot.pause()
        assert app.query_one('#tabs', TabbedContent).active == 'roadmap'
