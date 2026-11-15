import io
import json
from contextlib import contextmanager
import pytest
import typer
from rich.console import Console
from typer.testing import CliRunner
from shadow.experts import ExpertService,ExpertProfile,PROFILES,render_case
from shadow.knowledge import KnowledgeService
from shadow.scope import EngagementInput

class NeverInfer:
    async def complete(self,*args,**kwargs):raise AssertionError('Offline expert must not call inference')
    async def embed(self,*args,**kwargs):raise AssertionError('Offline expert must not call embeddings')

def engagement(runtime,name='Owned lab'):
    return runtime.database.create_engagement(EngagementInput(name=name,scope=['lab.test'],authorization='Written authorization for this owned lab'))['id']

async def test_offline_expert_uses_actual_evidence_and_preserves_verification(runtime):
    eid=engagement(runtime)
    finding=runtime.database.create('finding',{'name':'Object access lead','asset':'lab.test','verification':'hypothesis','evidence':'HTTP403 observed for one owned test identity'},eid)
    service=ExpertService(runtime,NeverInfer())
    result=await service.investigate('I think this may be an IDOR',specialist='web',engagement_id=eid,offline=True)
    assert len(service.catalog())==15
    assert result['inference_status'].startswith('offline deterministic')
    assert finding['id'] in {value for item in result['analysis']['observations'] for value in item['source_ids']}
    assert all(item['classification']!='operator_confirmed' for item in result['analysis']['observations'])
    assert len(result['analysis']['competing_hypotheses'])==2
    assert result['analysis']['missing_evidence'] and result['analysis']['validation_steps']
    assert len(service.conversations.history(result['conversation_id']))==2
    assert runtime.database.listing('memory')==[]
    assert 'offline deterministic' in render_case(result)

async def test_offline_teaching_is_curated_and_does_not_fake_answer_grading(runtime):
    result=await ExpertService(runtime,NeverInfer()).teach('API authorization',level='intermediate',answer='Authentication identifies the caller',offline=True)
    assert result['lesson']['exercises'] and result['lesson']['learning_path']
    assert 'not correctness grading' in result['lesson']['answer_feedback']
    assert result['inference_status'].startswith('offline curated')
    assert runtime.database.listing('memory')==[]

async def test_research_cites_imported_local_versions_without_external_lookup(runtime,tmp_path):
    file=tmp_path/'tls-notes.md';file.write_text('TLS certificate validation and PKI research notes')
    await KnowledgeService(runtime,NeverInfer()).import_file(file)
    service=ExpertService(runtime,NeverInfer())
    result=await service.research('TLS certificate validation',specialist='cryptography',offline=True)
    sources=result['evidence_packet']['sources']
    assert sources and len(sources[0]['version_sha256'])==64 and sources[0]['published_at']=='unknown'
    assert sources[0]['id'] in result['analysis']['source_ids']
    assert 'No external sources' in result['external_retrieval']
    assert 'not train' in result['evidence_packet']['knowledge_effect'] or 'no model training' in result['evidence_packet']['knowledge_effect']

class Structured:
    def __init__(self,unknown=False):self.unknown=unknown
    async def complete(self,model,messages,context,**kwargs):
        title=kwargs['format'].get('title') if isinstance(kwargs['format'],dict) else ''
        if title=='ExpertRoute':payload={'primary':'web','supporting':['api'],'reason':'The supplied question concerns an object-authorization boundary','entities':['object42']}
        else:payload={'observations':[{'statement':'The user reports an unusual endpoint','source_ids':['invented-id' if self.unknown else 'user_input'],'classification':'reported'}],'competing_hypotheses':[{'explanation':'Expected access control or a boundary defect remain alternatives','supporting_ids':['user_input'],'missing_evidence':['Two owned test identities'],'validation':['Compare expected ownership with observed response']}],'missing_evidence':['A reproducible request/response pair'],'validation_steps':['Use owned test identities within scope'],'recommendations':['Check program authorization constraints'],'conclusion':'The supplied assertion is unverified','uncertainty':'No validation test has run','source_ids':['user_input']}
        return {'content':json.dumps(payload)}
    async def embed(self,*args):return [[1.,0.]]

async def test_configured_model_routes_multiple_specialists_and_validates_claims(runtime):
    runtime.settings.model='fixture:local';runtime.settings.context_length=8192
    result=await ExpertService(runtime,Structured()).investigate('Analyze an unusual endpoint with object42')
    assert result['route']['primary']=='web' and result['route']['supporting']==['api']
    assert result['inference_status']=='local structured model analysis'
    assert result['analysis']['observations'][0]['classification']=='reported'

async def test_model_cannot_fabricate_evidence_reference(runtime):
    runtime.settings.model='fixture:local';runtime.settings.context_length=8192
    with pytest.raises(ValueError,match='unknown evidence'):
        await ExpertService(runtime,Structured(unknown=True)).investigate('Explain this endpoint',specialist='web')
    assert runtime.database.listing('expert_case')==[]

async def test_context_continuation_and_engagement_boundary(runtime):
    first=engagement(runtime);second=engagement(runtime,'Second lab')
    service=ExpertService(runtime,NeverInfer())
    case=await service.investigate('Analyze available evidence',engagement_id=first,offline=True)
    continued=await service.investigate('What evidence is still missing?',conversation_id=case['conversation_id'],offline=True)
    assert continued['conversation_id']==case['conversation_id'] and continued['engagement_id']==first
    with pytest.raises(ValueError,match='another engagement'):
        await service.investigate('Continue',conversation_id=case['conversation_id'],engagement_id=second,offline=True)
    with pytest.raises(ValueError):await service.teach('TLS',level='expert-certified',offline=True)

def test_expert_and_learn_cli_extend_existing_research_group(runtime):
    from shadow.experts_cli import register
    @contextmanager
    def factory():yield runtime
    app=typer.Typer();research=typer.Typer();app.add_typer(research,name='research')
    @research.command('existing')
    def existing():pass
    output=io.StringIO();register(app,factory,Console(file=output,width=100))
    runner=CliRunner()
    assert runner.invoke(app,['expert','--list']).exit_code==0
    assert runner.invoke(app,['expert','Review an IDOR lead','--offline']).exit_code==0
    assert runner.invoke(app,['learn','API authorization','--offline']).exit_code==0
    assert runner.invoke(app,['research','topic','TLS PKI','--offline']).exit_code==0
    assert runner.invoke(app,['research','existing']).exit_code==0
    assert runtime.database.listing('expert_case') and runtime.database.listing('expert_lesson')

def test_profiles_are_extensible_without_spawning_agents(runtime):
    service=ExpertService(runtime,NeverInfer())
    service.register_profile(ExpertProfile('custom','Custom Review','web_security','Review supplied lab evidence',('custom lab',),'No actions execute'))
    assert len(service.catalog())==16
    with pytest.raises(ValueError):service.register_profile(ExpertProfile('bad','Bad','not_a_mode','',(),''))
