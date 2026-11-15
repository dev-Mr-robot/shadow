"""Terminal expert investigation over shared services and evidence."""
from textual import on,work
from textual.widgets import TabPane,Static,Input,Button,Markdown
from textual.containers import VerticalScroll
from .presentation import safe

class ExpertMixin:
    def expert_panels(self):
        with TabPane('Experts',id='experts'):
            yield Static('Shared evidence, specialist routing, competing hypotheses and missing evidence. Review suggestions before taking action.',classes='intro')
            yield Input(placeholder='Describe the security question or evidence to investigate…',id='expert-question')
            yield Button('Investigate with specialists',id='expert-investigate')
            with VerticalScroll():yield Markdown('Ask a question to begin. CLI: shadow expert, shadow learn, shadow research topic.',id='expert-answer',open_links=False)

    @on(Button.Pressed,'#expert-investigate')
    def expert_pressed(self):self.expert_investigate()

    @work(exclusive=True,group='expert-investigation')
    async def expert_investigate(self):
        from .experts import ExpertService,render_case
        text=self.query_one('#expert-question',Input).value.strip()
        if not text:return
        answer=self.query_one('#expert-answer',Markdown)
        await answer.update('Reviewing available local evidence and selecting specialists…')
        try:
            result=await ExpertService(self.runtime).investigate(text,engagement_id=self.selected_engagement(False))
            await answer.update(safe(render_case(result)))
        except Exception as exc:await answer.update('Expert investigation unavailable: '+safe(exc)+'. Use shadow expert --help for offline analysis options.')
