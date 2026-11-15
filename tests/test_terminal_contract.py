"""The application interface remains entirely terminal native."""
import ast
from pathlib import Path
from typer.testing import CliRunner
from shadow.main import app

def test_no_website_gui_or_batch_components_in_application():
    root=Path(__file__).resolve().parents[1]
    forbidden_modules={'fastapi','flask','uvicorn','webbrowser','tkinter','PyQt5','PyQt6','PySide6','eel'}
    for source in (root/'src'/'shadow').rglob('*.py'):
        tree=ast.parse(source.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            names=[n.name for n in node.names] if isinstance(node,ast.Import) else [node.module or ''] if isinstance(node,ast.ImportFrom) else []
            assert not any(name.split('.')[0] in forbidden_modules for name in names),source
    for pattern in ['*.bat','*.cmd','*.tsx','*.jsx','package.json','vite.config.*','index.html']:
        assert not list((root/'src').rglob(pattern))
    assert not (root/'frontend').exists() and not (root/'backend').exists()

def test_required_terminal_commands_and_passive_analyze(paths,tmp_path):
    runner=CliRunner()
    for name in ['chat','recon','bounty','analyze','report','tools','settings','soc','workflow']:
        result=runner.invoke(app,[name,'--help']);assert result.exit_code==0,(name,result.output)
    file=tmp_path/'synthetic-request.txt';file.write_text('GET /api?id=1 HTTP/1.1\r\nHost: synthetic.test\r\n\r\n')
    result=runner.invoke(app,['analyze',str(file),'--kind','http'])
    assert result.exit_code==0 and 'parameters' in result.stdout
