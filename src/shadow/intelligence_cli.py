"""Natural conversational CLI and explicit memory/knowledge management."""
import asyncio
import json
from pathlib import Path

import typer
from rich.live import Live
from rich.markdown import Markdown
from rich.text import Text

from .intelligence import ConversationService, MODES
from .knowledge import KnowledgeService
from .presentation import safe


def register(app, runtime_factory, console):
    conversations = typer.Typer(help='Persistent conversation history, continuation and summaries.')
    memories = typer.Typer(help='Explicit, inspectable research memory. Nothing is inferred or saved automatically.')
    knowledge = typer.Typer(help='Local notes/documents, semantic retrieval and lexical fallback.')
    app.add_typer(conversations, name='conversation')
    app.add_typer(memories, name='memory')
    app.add_typer(knowledge, name='kb')

    async def turn(state, service, cid, text, route):
        plan = await service.plan(cid, text) if route else None
        if plan is not None and plan.clarification:
            service.record_clarification(cid, text, plan.clarification)
            console.print(Text(plan.clarification))
            return
        output = ''
        with Live(Markdown('Waiting for local model…'), console=console, refresh_per_second=10, transient=False) as live:
            async for token in service.stream(cid, text, plan):
                output += token
                live.update(Markdown(safe(output)))
        if plan is None or not plan.actions:
            return
        from .actions import ActionRunner
        runner = ActionRunner(state)
        conversation = state.database.get('conversation', cid)
        for action in plan.actions:
            preview = await runner.preview(action, engagement_id=conversation.get('engagement_id'))
            console.print(Text(str(preview.get('title', action.capability))))
            details = preview.get('details', {})
            console.print_json(data=details if isinstance(details, dict) else {'details': details})
            # No --yes shortcut: every proposed operation is concretely reviewable.
            if not typer.confirm('Approve this exact application action?', default=False):
                console.print('Action declined. Nothing executed.', markup=False)
                continue
            result = await runner.execute(preview['id'], approved=True)
            service.record_result(cid, result)
            console.print_json(data=result)
            explanation = ''
            with Live(Markdown('Explaining the approved action result…'), console=console, refresh_per_second=10) as live:
                async for token in service.stream(cid, 'Explain the most recent approved application result. Distinguish observed facts, hypotheses and next steps. Do not propose another action unless I ask.'):
                    explanation += token; live.update(Markdown(safe(explanation)))

    @app.command('chat')
    def chat(prompt: str | None = typer.Argument(None), conversation: str | None = typer.Option(None, '--conversation', '-c'),
             engagement: str | None = typer.Option(None, '--engagement', '-e'), mode: str = typer.Option('assistant', '--mode'),
             model: str | None = typer.Option(None, '--model'), no_routing: bool = typer.Option(False, '--no-routing')):
        """Talk naturally with local Ollama, optionally resuming a conversation ID."""
        with runtime_factory() as state:
            if model:
                state.settings.model = model
            service = ConversationService(state)
            if conversation:
                record = state.database.get('conversation', conversation)
                if engagement and engagement != record.get('engagement_id'):
                    raise ValueError('Cannot resume a conversation under another engagement')
                cid = conversation
            else:
                eid = engagement or getattr(state.settings, 'active_engagement', None)
                cid = service.new(mode, eid, (prompt or 'Terminal investigation')[:120])['id']
            console.print(Text('Conversation: ' + cid))
            console.print('Messages persist locally. Do not paste secrets. Durable research memory is explicit only.', markup=False)
            if prompt is not None:
                asyncio.run(turn(state, service, cid, prompt, not no_routing))
                return
            console.print('Speak naturally. Controls: :quit, :summary, :history. Ctrl+C cancels the current turn.', markup=False)
            while True:
                try:
                    text = typer.prompt('shadow >', prompt_suffix=' ')
                except (EOFError, KeyboardInterrupt, typer.Abort):
                    break
                if text.strip() == ':quit':
                    break
                if text.strip() == ':summary':
                    console.print(Markdown(safe(asyncio.run(service.summarize(cid)))))
                    continue
                if text.strip() == ':history':
                    for message in service.history(cid):
                        console.print(Text(message['role'].upper() + ' · ' + message.get('status', '')))
                        console.print(Markdown(safe(message['content'])))
                    continue
                try:
                    asyncio.run(turn(state, service, cid, text, not no_routing))
                except KeyboardInterrupt:
                    console.print('Turn cancelled; any partial response is saved.', markup=False)
                except Exception as exc:
                    console.print(Text('Local research request failed: ' + safe(exc), style='red'))

    @conversations.command('list')
    def conversation_list(engagement: str | None = typer.Option(None, '--engagement')):
        with runtime_factory() as state:
            console.print_json(data=ConversationService(state).conversations(engagement))

    @conversations.command('show')
    def conversation_show(conversation_id: str):
        with runtime_factory() as state:
            console.print_json(data={'conversation': state.database.get('conversation', conversation_id),
                                     'messages': ConversationService(state).history(conversation_id)})

    @conversations.command('summarize')
    def conversation_summarize(conversation_id: str):
        with runtime_factory() as state:
            console.print(Markdown(safe(asyncio.run(ConversationService(state).summarize(conversation_id)))))

    @memories.command('list')
    def memory_list(engagement: str | None = typer.Option(None, '--engagement')):
        with runtime_factory() as state:
            console.print_json(data=ConversationService(state).memory_list(engagement))

    @memories.command('search')
    def memory_search(query: str, engagement: str | None = typer.Option(None, '--engagement')):
        with runtime_factory() as state:
            console.print_json(data=ConversationService(state).memory_search(query, engagement))

    @memories.command('save')
    def memory_save(content: str, engagement: str | None = typer.Option(None, '--engagement')):
        """Explicitly save the text you provide; no secret or personal inference."""
        with runtime_factory() as state:
            console.print_json(data=ConversationService(state).memory_save(content, engagement))

    @memories.command('edit')
    def memory_edit(memory_id: str, content: str):
        with runtime_factory() as state:
            console.print_json(data=ConversationService(state).memory_update(memory_id, content))

    @memories.command('remove')
    def memory_remove(memory_id: str):
        with runtime_factory() as state:
            record = state.database.get('memory', memory_id)
            console.print_json(data=record)
            if not typer.confirm('Permanently remove this saved research memory?', default=False):
                raise typer.Abort()
            ConversationService(state).memory_remove(memory_id)
            console.print('Memory removed.', markup=False)

    @knowledge.command('import')
    def kb_import(file: Path):
        with runtime_factory() as state:
            console.print_json(data=asyncio.run(KnowledgeService(state).import_file(file)))

    @knowledge.command('list')
    def kb_list():
        with runtime_factory() as state:
            console.print_json(data=KnowledgeService(state).list())

    @knowledge.command('search')
    def kb_search(query: str, limit: int = typer.Option(5, min=1, max=20)):
        with runtime_factory() as state:
            console.print_json(data=asyncio.run(KnowledgeService(state).search(query, limit)))

    @knowledge.command('reindex')
    def kb_reindex(document_id: str):
        with runtime_factory() as state:
            console.print_json(data=asyncio.run(KnowledgeService(state).reindex(document_id)))

    @knowledge.command('remove')
    def kb_remove(document_id: str):
        with runtime_factory() as state:
            console.print_json(data=state.database.get('document', document_id))
            if not typer.confirm('Permanently remove this document and its chunks?', default=False):
                raise typer.Abort()
            KnowledgeService(state).remove(document_id)
            console.print('Document and chunks removed.', markup=False)
