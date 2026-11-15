import json
import pytest
from shadow import soc_logs,soc_detection,soc
from shadow.main import app
from typer.testing import CliRunner

def test_yaml_rules_and_forbidden_tags(runtime,tmp_path):
    file=tmp_path/'synthetic.yaml';file.write_text('title: Synthetic YAML selection\ndetection:\n  selection:\n    CommandLine|contains: synthetic-command\n  condition: selection\nlevel: high\n')
    assert soc_detection.import_rule(runtime.database,file)['severity']=='High'
    file.write_text('!!python/object/apply:os.system ["not-executed"]')
    with pytest.raises(Exception):soc_detection.import_rule(runtime.database,file)

def test_xml_entities_are_rejected_and_oversized_lines_are_counted(runtime,tmp_path):
    xml=tmp_path/'synthetic.xml';xml.write_text('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///must-not-read">]><Events>&e;</Events>')
    with pytest.raises(ValueError):soc_logs.ingest(runtime.database,xml)
    file=tmp_path/'synthetic.txt';file.write_text('x'*(soc_logs.MAX_LINE+100)+'\nNov 15 00:00:00 host synthetic event\n')
    result=soc_logs.ingest(runtime.database,file,year=2026)
    assert result['invalid']==1 and result['imported']==1

def test_soc_retention_and_rule_cli_confirmation(paths,tmp_path):
    runner=CliRunner();file=tmp_path/'synthetic.jsonl';file.write_text(json.dumps({'timestamp':'2026-11-15T00:00:00Z','message':'Synthetic test'}))
    assert runner.invoke(app,['soc','ingest',str(file)]).exit_code==0
    result=runner.invoke(app,['soc','retention','2026-11-16T00:00:00Z'],input='n\n')
    assert result.exit_code==1
    assert json.loads(runner.invoke(app,['soc','stats']).stdout)['events']==1
    assert runner.invoke(app,['soc','rule','coverage']).exit_code==0
    assert runner.invoke(app,['soc','rule','history']).exit_code==0
    assert runner.invoke(app,['soc','sensors']).exit_code==0
