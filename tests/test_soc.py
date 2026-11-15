"""Synthetic SOC fixtures only; no actual user events or network actions."""
import json
from pathlib import Path
import pytest
from typer.testing import CliRunner
from shadow import soc,soc_logs,soc_detection
from shadow.main import app
from shadow.actions import ActionRunner
from shadow.intelligence import ConversationService,Action

def dataset(tmp_path,name='synthetic.jsonl',count=7):
    path=tmp_path/name
    rows=[{'timestamp':f'2026-11-15T00:00:{i:02d}Z','event_type':'auth_failure','src_ip':'198.51.100.10','host':'synthetic-host','username':'test-user-'+str(i),'message':'Failed password for test user'} for i in range(count)]
    rows.append({'timestamp':'2026-11-15T00:00:30Z','event_type':'auth_success','src_ip':'198.51.100.10','host':'synthetic-host','username':'test-user-0','message':'Accepted password for test-user-0'})
    path.write_text('\n'.join(json.dumps(r) for r in rows),encoding='utf-8');return path

@pytest.mark.parametrize('raw,kind,user',[
 ('Nov 15 01:02:03 synthetic-host sshd[7]: Failed password for invalid user alice from 198.51.100.10 port 22 ssh2','auth_failure','alice'),
 ('Nov 15 01:02:04 synthetic-host sshd[7]: Accepted publickey for alice from 198.51.100.10 port 22 ssh2','auth_success','alice'),
 ('Nov 15 01:03:00 synthetic-host sudo: alice : COMMAND=/usr/bin/cat /etc/shadow','sudo',''),
 ('198.51.100.10 - bob [15/Nov/2026:01:02:03 +0000] "GET /api?id=1 HTTP/1.1" 200 123','web','bob'),
 ('2026-11-15T01:02:03Z firewall SRC=198.51.100.10 DST=192.0.2.10 DPT=443 PROTO=TCP','network',''),
])
def test_syslog_auth_access_firewall_parsers(raw,kind,user):
    row=soc_logs.parse_line(raw,year=2026)
    assert row['event_type']==kind and row['username']==user
    assert row['timestamp'].startswith('2026-11-15')
    if 'from ' in raw or raw.startswith('198.51.100.10') or 'SRC=' in raw:assert row['src_ip']=='198.51.100.10'

def test_windows_json_xml_csv_suricata_and_zeek(runtime,tmp_path):
    nested={'Event':{'System':{'EventID':4625,'Computer':'synthetic-win','TimeCreated':{'@SystemTime':'2026-11-15T00:00:00Z'}},'EventData':{'TargetUserName':'alice','IpAddress':'198.51.100.10'}}}
    assert soc_logs.normalize_event(nested)['event_type']=='auth_failure'
    xml=tmp_path/'synthetic.xml';xml.write_text('<Events><Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-11-15T00:00:00Z"/><Computer>synthetic-win</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">198.51.100.10</Data></EventData></Event></Events>')
    assert soc_logs.ingest(runtime.database,xml)['imported']==1
    csv=tmp_path/'synthetic.csv';csv.write_text('timestamp,EventID,TargetUserName,IpAddress\n2026-11-15T00:01:00Z,4625,bob,198.51.100.11\n')
    assert soc_logs.ingest(runtime.database,csv)['imported']==1
    zeek=tmp_path/'synthetic.conn.log';zeek.write_text('#separator \\x09\n#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tproto\n1794700800.0\t198.51.100.12\t192.0.2.10\t443\ttcp\n')
    assert soc_logs.ingest(runtime.database,zeek)['imported']==1
    eve={'timestamp':'2026-11-15T00:02:00Z','event_type':'alert','src_ip':'198.51.100.10','dest_ip':'192.0.2.10','alert':{'signature':'SYNTHETIC malware indicator','severity':2}}
    assert soc_logs.normalize_event(eve)['event_type']=='ids_alert'
    assert soc_logs.stats(runtime.database)['events']==3

def test_timestamp_timezone_and_missing_assumptions():
    value,assumption=soc_logs.stamp('15/Nov/2026:01:02:03 -0700')
    assert '08:02:03' in value and not assumption
    assert soc_logs.parse_line('unstructured synthetic message')['timestamp_assumption']
    with pytest.raises(ValueError):soc_logs.stamp('not-a-time')

def test_stream_ingestion_dedup_search_and_blank_invalid(runtime,tmp_path):
    path=dataset(tmp_path);first=soc_logs.ingest(runtime.database,path);second=soc_logs.ingest(runtime.database,path)
    assert first['imported']==8 and second['duplicates']==8 and second['imported']==0
    assert soc_logs.stats(runtime.database)['events']==8
    assert len(soc_logs.events(runtime.database,event_type='auth_failure'))==7
    rows=soc_logs.events(runtime.database,src_ip='198.51.100.10',since='2026-11-15T00:00:25Z')
    assert len(rows)==1 and rows[0]['event_type']=='auth_success'
    broken=tmp_path/'synthetic-bad.jsonl';broken.write_text('{invalid\n\n'+json.dumps({'timestamp':'bad','message':'x'}))
    result=soc_logs.ingest(runtime.database,broken)
    assert result['invalid']==2 and result['blank']==1

def test_alerts_evidence_dedup_false_positives_and_lifecycle(runtime,tmp_path):
    soc_logs.ingest(runtime.database,dataset(tmp_path));run=soc_detection.detect(runtime.database)
    assert run['processed']==8 and run['alerts_created']>=3
    selected=soc.alerts(runtime.database);assert all(a['event_ids'] and 'hypothesis' in a['verification'] for a in selected)
    assert any(a['rule']=='Password spraying pattern' and 'T1110.003' in a['attack'] for a in selected)
    assert soc_detection.detect(runtime.database)['alerts_created']==0
    rid=selected[0]['id']
    with pytest.raises(ValueError):soc.update_alert(runtime.database,rid,status='CLOSED')
    for status in soc.STATES[1:]:soc.update_alert(runtime.database,rid,status=status,note='Synthetic test analyst transition')
    assert runtime.database.get('soc_alert',rid)['status']=='CLOSED'
    other=next(a for a in selected if a['id']!=rid)
    soc.update_alert(runtime.database,other['id'],status='CLOSED',false_positive=True,note='Synthetic authorized scanner fixture')
    assert runtime.database.get('soc_alert',other['id'])['classification']=='false_positive'
    assert soc.related(runtime.database,rid)['related']

def test_incident_timeline_report_and_no_response_execution(runtime,tmp_path):
    soc_logs.ingest(runtime.database,dataset(tmp_path));soc_detection.detect(runtime.database)
    alert=soc.alerts(runtime.database)[0]
    incident=soc.create_incident(runtime.database,'Synthetic incident',[alert['id']],incident_type='brute_force')
    timeline=soc.incident_timeline(runtime.database,incident['id'])
    assert timeline['events'] and timeline['events']==sorted(timeline['events'],key=lambda e:(e['timestamp'],e['id']))
    soc.update_incident(runtime.database,incident['id'],status='TRIAGED',note='Synthetic investigation',action_taken='Operator recorded an external review; nothing executed')
    output=tmp_path/'synthetic-soc.md';report=soc.report(runtime.database,incident['id'],'md',output)
    assert output.exists() and 'No attack outcome is inferred automatically' in output.read_text()
    assert timeline['events'][0]['id'] in output.read_text()
    with pytest.raises(FileExistsError):soc.report(runtime.database,incident['id'],'md',output)
    pdf=tmp_path/'synthetic-soc.pdf';soc.report(runtime.database,incident['id'],'pdf',pdf)
    from pypdf import PdfReader
    assert 'SOC Incident Report' in PdfReader(pdf).pages[0].extract_text()
    html=tmp_path/'synthetic-soc.html';soc.report(runtime.database,incident['id'],'html',html)
    assert '<script>' not in html.read_text()

def test_rule_import_versioning_sigma_subset_and_tuning(runtime,tmp_path):
    path=tmp_path/'synthetic-rule.json';path.write_text(json.dumps({'name':'Synthetic command rule','field':'fields.process','contains':['synthetic-command'],'attack':['T1046']}))
    rule=soc_detection.import_rule(runtime.database,path)
    assert rule['version']==1 and soc_detection.import_rule(runtime.database,path)['version']==2
    with pytest.raises(ValueError):soc_detection.Rule(name='Unsafe expression',field='__import__(os)')
    unsupported=tmp_path/'synthetic-sigma.json';unsupported.write_text(json.dumps({'title':'Unsupported Sigma','detection':{'selection':{'message|contains':'x'},'condition':'selection or other'}}))
    with pytest.raises(ValueError):soc_detection.import_rule(runtime.database,unsupported)
    supported=tmp_path/'synthetic-sigma-ok.json';supported.write_text(json.dumps({'title':'Sigma subset fixture','detection':{'selection':{'CommandLine|contains':'synthetic-command'},'condition':'selection'}}))
    assert soc_detection.import_rule(runtime.database,supported)['field']=='fields.process'
    disabled=soc_detection.set_rule_enabled(runtime.database,'builtin-0',False)
    assert not next(r for r in soc_detection.rules(runtime.database) if r['name']=='Repeated authentication failures')['enabled']
    assert disabled['version']==2

def test_attack_sourced_versioned_import_and_ioc_local_enrichment(runtime,tmp_path):
    known=soc_detection.attack_search(runtime.database,'T1110.001')[0]
    assert known['version']=='1.7' and known['source'].startswith('https://attack.mitre.org/')
    bundle=tmp_path/'synthetic-stix.json';bundle.write_text(json.dumps({'type':'bundle','objects':[{'type':'attack-pattern','name':'Synthetic test bundle technique','external_references':[{'source_name':'mitre-attack','external_id':'T1059','url':'https://attack.mitre.org/techniques/T1059/'}],'x_mitre_version':'test-fixture-version','modified':'2026-11-15'}]}))
    assert soc_detection.attack_import(runtime.database,bundle,'https://github.com/mitre/cti','synthetic-test-bundle')['imported']==1
    indicator=soc.add_ioc(runtime.database,'ip','198.51.100.10','Synthetic local test feed','2026-11-15',.8,'suspicious')
    soc_logs.ingest(runtime.database,dataset(tmp_path))
    result=soc.enrich(runtime.database,'198.51.100.10')
    assert not result['external_requests'] and result['sources'][0]['id']==indicator['id'] and result['events']
    with pytest.raises(ValueError):soc.add_ioc(runtime.database,'hash','not-a-hash','Synthetic','2026-11-15')

def test_network_periodicity_and_flow_summary(runtime,tmp_path):
    file=tmp_path/'synthetic-flows.jsonl'
    file.write_text('\n'.join(json.dumps({'timestamp':f'2026-11-15T00:00:{i*10:02d}Z','event_type':'network','src_ip':'192.0.2.10','dst_ip':'198.51.100.20','dst_port':443,'proto':'tcp'}) for i in range(6)))
    soc_logs.ingest(runtime.database,file);result=soc.network_summary(runtime.database)
    assert result['protocols']['tcp']==6 and result['periodicity_indicators'][0]['interval_seconds']==10
    assert 'encrypted payload' in result['notice']

def test_large_stream_ingestion_and_retention_requires_approval(runtime,tmp_path):
    path=tmp_path/'synthetic-large.jsonl'
    with path.open('w') as f:
        for i in range(20000):f.write(json.dumps({'timestamp':'2026-11-15T00:00:00Z','message':'Synthetic benign event '+str(i),'host':'synthetic-host'})+'\n')
    assert soc_logs.ingest(runtime.database,path)['imported']==20000
    preview=soc.retention(runtime.database,'2026-11-16T00:00:00Z')
    assert preview['affected_events']==20000 and soc_logs.stats(runtime.database)['events']==20000
    assert soc.retention(runtime.database,'2026-11-16T00:00:00Z',approved=True)['deleted']
    assert soc_logs.stats(runtime.database)['events']==0

async def test_soc_ai_context_and_actions_use_real_ids_with_separate_approval(runtime,tmp_path):
    soc_logs.ingest(runtime.database,dataset(tmp_path));soc_detection.detect(runtime.database)
    service=ConversationService(runtime);conversation=service.new('soc')
    context=service.context(conversation['id'])
    assert context['soc_statistics']['events']==8 and context['soc_alerts'][0]['id']
    runner=ActionRunner(runtime);preview=await runner.preview(Action(capability='soc_query',soc_view='alerts',severity='High'))
    with pytest.raises(ValueError):await runner.execute(preview['id'])
    result=await runner.execute(preview['id'],approved=True)
    assert result and all(a['severity']=='High' for a in result)

def test_soc_cli_ingest_alerts_and_terminal_help(paths,tmp_path):
    runner=CliRunner();file=dataset(tmp_path)
    assert runner.invoke(app,['soc','--help']).exit_code==0
    result=runner.invoke(app,['soc','ingest',str(file)])
    assert result.exit_code==0,result.output
    assert runner.invoke(app,['soc','detect']).exit_code==0
    assert runner.invoke(app,['soc','logs','--json']).exit_code==0
    assert runner.invoke(app,['soc','alerts','list','--severity','High']).exit_code==0
    assert runner.invoke(app,['soc','attack','search','T1110']).exit_code==0
    assert runner.invoke(app,['soc','playbook','brute_force']).exit_code==0
