from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from . import __version__

LOGO=r'''███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝'''

def safe(value):
    import unicodedata
    return ''.join(ch if ch in '\n\t' or unicodedata.category(ch) not in {'Cc','Cf'} else '?' for ch in str(value))

def startup(status):
    hw=status['hardware'];ai=status['ollama'];tools=status['tools']
    table=Table.grid(padding=(0,2));table.add_column(style='#788da9');table.add_column()
    selected=ai['selected_model'] or 'not selected'
    values=[('VERSION',__version__+' / INTEGRATED'),('PLATFORM',hw['distribution']),('PYTHON',hw['python']),
      ('AI ENGINE','ONLINE · local endpoint' if ai['available'] else 'OFFLINE'),('MODEL',selected),('MODEL AVAILABLE',str(ai['selected_available'])),
      ('DATABASE',status['database']['status']+' / '+status['database']['revision']),('TOOLS',str(sum(t['detected'] for t in tools))+' of '+str(len(tools))+' detected'),
      ('CPU',hw['cpu']),('RAM',f"{hw['ram_available_bytes']/1024**3:.1f} GiB available / {hw['ram_total_bytes']/1024**3:.1f} GiB total"),
      ('GPU',', '.join(f"{g['name']} ({g['vram_mib']} MiB)" for g in hw['gpus']) or 'NVIDIA not detected; CPU mode available through Ollama')]
    for label,value in values:table.add_row(label,Text(safe(value)))
    return Panel(table,title='PERSONAL SECURITY INTELLIGENCE',border_style='#83404e')

PHASES=[
 ('1','Foundation','Delivered: diagnostics, configuration, migrations, authorization records, scope checks, terminal shell'),
 ('2','Terminal workflows','Planned: full keyboard workspace, results tables, progress and natural-language input'),
 ('3','Local AI orchestration','Planned: semantic routing, typed plans, validated tool calls and streamed conversation'),
 ('4','Context and explicit memory','Planned: summaries, inspect/edit/delete, engagement retrieval and reference tests'),
 ('5','Reconnaissance','Planned: streaming imports, DNS/IP pinning, approved probes, rate limits, checkpoints, history'),
 ('6','Bug bounty engagements','Planned: evidence lifecycle, rules, observations, candidates, status and timeline'),
 ('7','HTTP/API laboratory','Planned: requests/responses, cookies, CORS, cache, JWT, Burp exports and comparison'),
 ('8','Tool adapters','Planned: vetted recipes, approval digests, scope rechecks, sandbox, cancellation and parsers'),
 ('9','Vulnerability intelligence / KB','Planned: local RAG, source/date-aware advisory cache, explicit external opt-in'),
 ('10','Reports','Planned: evidence-preserving Markdown, HTML and PDF'),
 ('11','Advanced research modules','Planned after core gates: changes, clustering, deduplication, code/log/static analysis'),
 ('12','Hardening and release','Planned: adversarial testing, clean Linux installs, packaging and compatibility matrix')]

def roadmap_table():
    table=Table(title='SHADOW engineering roadmap',expand=True)
    for label in ['Phase','Area','Status']:table.add_column(label)
    for phase,name,status in PHASES:table.add_row(phase,name,status)
    return table
