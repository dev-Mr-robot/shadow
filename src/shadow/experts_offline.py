"""Versioned deterministic specialist checklists; never presented as LLM reasoning."""
import json

VERSION='2026-11-15-v1'
CHECKS={
 'network':('Service exposure does not by itself establish exploitability.', ['Original service/packet evidence and timestamps','Expected network flows and segmentation','Actual service configuration'], ['Compare observed and documented allowed flows','Review reachability from authorized network positions','Correlate configuration and packet/service observations']),
 'web':('A suspicious parameter is a lead; controlled identity/resource comparisons establish whether a boundary fails.', ['Raw request/response pairs','Expected authorization and test identities','Repeatable impact evidence'], ['Hold other request conditions constant while comparing authorized test identities','Check the intended server-side permission rule','Record redacted reproduction evidence before changing verification status']),
 'api':('Authentication identifies a caller; authorization decides which objects and operations are allowed.', ['API contract and ownership rules','Two authorized identities and owned test objects','JWT signature/issuer/audience validation evidence'], ['Build an identity/object/operation matrix','Compare expected and observed access to owned test resources','Distinguish decoded JWT claims from verified signature and policy checks']),
 'pentest':('Assessment conclusions require scope, a falsifiable hypothesis and reproducible evidence.', ['Written scope and exclusions','Acquisition context and evidence IDs','Reproduction, impact and remediation criteria'], ['Check authorization before active validation','Choose a minimally intrusive discriminating test','Preserve operator verification labels and source IDs']),
 'bounty':('Program rules, demonstrated security boundaries and impact determine reportability.', ['Program rules and scope','Affected identities/resources','Reproducible impact and duplicate review'], ['Review program constraints','Prioritize leads with an explicit boundary and missing discriminating evidence','Write an evidence-linked report without upgrading hypotheses']),
 'red_team':('Adversary simulation needs authorization, safety limits and measurable defensive observations.', ['Rules of engagement','Approved objectives/techniques','Expected telemetry and success criteria'], ['Tie proposed activity to an approved objective','Review safety and observability with defenders','Treat missing telemetry as a measurement limitation']),
 'soc':('A detection match is an observation, not proof of compromise or attack success.', ['Original event/alert IDs','Timestamp/time-zone and source coverage','Related identity/asset activity and benign alternatives'], ['Correlate time, identity and asset','Compare administrative/test activity against the detection hypothesis','Record missing telemetry and escalation criteria']),
 'blue_team':('A control must be evaluated against its policy and observed preventive/detective behavior.', ['Control objective and configuration','Expected behavior and actual telemetry','Coverage and false-positive evidence'], ['Trace documented risk to controls and telemetry','Validate changes in an owned test environment','Define verification and rollback criteria']),
 'threat_hunter':('A hunt hypothesis must state the telemetry that could support or contradict it.', ['Falsifiable hypothesis','Telemetry coverage/retention','Benign explanations'], ['State what would disprove the hypothesis','Query actual retained events','Separate absent retained evidence from evidence of absence']),
 'incident_response':('Preserve evidence while testing incident scope and competing explanations.', ['UTC timeline and acquisition context','Affected asset/account ownership','Containment authority and preservation needs'], ['Build a source-linked timeline','Separate observed impact from suspected scope','Review evidence preservation and containment risk before changes']),
 'malware':('Strings and metadata suggest leads; behavior and attribution require further isolated evidence.', ['Sample hash and origin','Static tool output','Isolated behavioral observations if available'], ['Inspect metadata/strings/imports without executing samples','Compare independent observations and benign explanations','Plan dynamic analysis only in an approved disposable environment']),
 'reverse_engineering':('Disassembly/decompiler output must be checked against binary structure and execution evidence.', ['Binary hash/format','Architecture and address context','Relevant disassembly/debugger observations'], ['Establish architecture/sections/symbols','Trace the supplied control/data flow','Separate inferred behavior from observed execution']),
 'cloud':('Effective permissions depend on identity, policy and resource context together.', ['Provider/service/version context','Identity/resource/policy documents','Effective-access and audit evidence'], ['Map principals/resources/trust relationships','Compare intended and effective permissions','Review least privilege and rollback constraints without changing live resources']),
 'cryptography':('Algorithm, protocol, validation, keys and threat assumptions determine cryptographic security together.', ['Protocol/algorithm/version','Key lifecycle and peer-validation configuration','Threat model and handshake/test evidence'], ['Separate encryption/integrity/authentication claims','Review certificate and peer-identity policy against supplied evidence','Do not declare a primitive broken from naming/configuration alone']),
 'secure_code':('A static pattern is a hypothesis until untrusted flow reaches a sensitive sink without its required boundary.', ['Source/configuration/version','Trust boundary and data/control flow','Reachability, mitigations and tests'], ['Trace input to the sensitive sink','Check framework assumptions and mitigations','Propose a targeted regression test and boundary-level fix'])}

class NoInference:
 async def embed(self,*args):raise ValueError('Offline review uses lexical retrieval only')

def route(question,profiles,prefix=''):
 from .experts import ExpertRoute
 text=question.casefold();scores={}
 for key,profile in profiles.items():
  terms={key.replace('_',' '),*[value.casefold() for value in profile.domains]}
  scores[key]=sum(1 for value in terms if len(value)>2 and value in text)
 ranked=sorted(profiles,key=lambda key:(-scores[key],list(profiles).index(key)))
 primary=ranked[0] if scores[ranked[0]] else 'pentest'
 return ExpertRoute(primary=primary,supporting=[key for key in ranked if key!=primary and scores[key]>0][:2],reason=prefix+'Offline taxonomy matching and explicit specialist checklists; not semantic model understanding.')

def analyze(packet,selected):
 from .experts import ExpertAnalysis,Observation,Hypothesis
 principle,missing,validation=CHECKS.get(selected.primary,CHECKS['pentest'])
 observations=[];ids=[]
 for item in packet['evidence']:
  if item['id']=='user_input':
   observations.append(Observation(statement='User-supplied assertion/question: '+item['text'],source_ids=[item['id']],classification='reported'))
  else:
   ids.append(item['id'])
   observations.append(Observation(statement=f"Saved {item['kind']} {item.get('name','')}: {item.get('text','')[:700]}",source_ids=[item['id']],classification='operator_confirmed' if item.get('operator_confirmed') else 'observed'))
 hypotheses=[]
 if ids:
  hypotheses=[Hypothesis(explanation='Intended or benign behavior remains one possible explanation; this checklist has not diagnosed the cause.',supporting_ids=ids[:5],missing_evidence=missing,validation=validation),Hypothesis(explanation='A security control/boundary defect is an alternative hypothesis, not a confirmed vulnerability or compromise.',supporting_ids=ids[:5],missing_evidence=missing,validation=validation)]
 return ExpertAnalysis(observations=observations,competing_hypotheses=hypotheses,missing_evidence=missing,validation_steps=validation,recommendations=[principle,'Review authorization before active tests; this service executes no test.','Verify source publication dates/current applicability.'],conclusion=f'Offline evidence review: {len(ids)} saved evidence records and {len(packet["sources"])} local source chunks. No successful model reasoning or external investigation ran.',uncertainty='Deterministic checklist hypotheses require human validation. No new vulnerability, compromise, source freshness or model expertise is established.',source_ids=[item['id'] for item in packet['sources']])

def teach(topic,level,answer,packet,profiles):
 from .experts import Lesson
 selected=route(topic,profiles);profile=profiles[selected.primary]
 principle,missing,validation=CHECKS.get(selected.primary,CHECKS['pentest'])
 mentioned=[term for term in profile.domains if answer and term.casefold() in answer.casefold()]
 omitted=[term for term in profile.domains if not answer or term.casefold() not in answer.casefold()]
 feedback='' if answer is None else 'Lexical concept-coverage review only, not correctness grading. Mentioned terms: '+(', '.join(mentioned) or 'none from the selected taxonomy')+'. Missing terms do not prove lack of understanding; review actual reasoning with qualified sources.'
 return Lesson(explanation=f'Offline foundational study checklist for {profile.name} at {level} level. {principle} {profile.boundaries}',key_points=[principle,*profile.domains],examples=['In an owned lab: '+validation[0]],exercises=['Explain in your own words: '+principle,'Identify evidence that supports or contradicts a hypothesis: '+'; '.join(missing)],answer_feedback=feedback,knowledge_gaps=['Not mentioned in the submitted answer; review if relevant: '+term for term in omitted[:6]] if answer else [],learning_path=[*validation,'Read retrieved source versions and verify their applicability.'],source_ids=[item['id'] for item in packet['sources']],uncertainty='This curated checklist is not a comprehensive lesson, correctness certification or a claim that the model learned anything. Source freshness may be unknown.')
