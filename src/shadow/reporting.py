"""Deterministic, immutable evidence snapshots and safe Markdown/HTML/PDF exports."""
from __future__ import annotations
import base64
import hashlib
import html
import io
import json
import os
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from uuid import uuid4

from .research import all_records

def _snapshot(db,eid):
    engagement=db.engagement(eid);findings=[];evidence=[]
    for row in all_records(db,'finding',eid):
        if len(findings)>=2000:raise ValueError('A report is limited to 2000 findings; split the engagement report')
        findings.append(row)
    for row in all_records(db,'import',eid):
        if len(evidence)>=2000:raise ValueError('A report is limited to 2000 evidence imports')
        evidence.append({k:row.get(k) for k in ['id','name','source','sha256','created','scope_checks']})
    snapshot={'engagement':engagement,'findings':findings,'evidence':evidence,'generated':datetime.now(timezone.utc).isoformat(),
      'methodology':'Report assembled from operator-recorded findings and imported evidence. Static observations and operator verification labels are preserved. SHADOW does not independently attest that a vulnerability was reproduced.',
      'scope_note':'Recorded authorization is an operator attestation. Imported evidence never expands scope.'}
    encoded=json.dumps(snapshot,ensure_ascii=False)
    if len(encoded)>5_000_000:raise ValueError('Report evidence snapshot exceeds 5,000,000 characters; reduce report scope')
    return snapshot

def _sections(snapshot):
    engagement=snapshot['engagement'];findings=snapshot['findings'];counts=Counter(f['severity'] for f in findings)
    confirmed=sum(f['verification'] in {'confirmed','remediated'} for f in findings)
    yield 'SHADOW Security Assessment',engagement['name']
    yield 'Executive summary',f"{len(findings)} findings recorded; {confirmed} have operator-supplied confirmed/remediated status. "+'; '.join(f'{severity}: {counts.get(severity,0)}' for severity in ['Critical','High','Medium','Low','Informational'])+'.'
    yield 'Report metadata',f"Generated (UTC): {snapshot['generated']}\nEngagement ID: {engagement['id']}\nAll labels reflect the evidence and operator attestations at snapshot time."
    yield 'Authorized scope','\n'.join('- '+s for s in engagement['scope'])
    yield 'Out-of-scope assets','\n'.join('- '+s for s in engagement['exclusions']) or 'No explicit exclusions recorded.'
    yield 'Authorization and program rules',engagement['authorization']+'\n\n'+(engagement.get('rules') or 'No additional program rules recorded.')
    yield 'Methodology',snapshot['methodology']+'\n'+snapshot['scope_note']
    for index,f in enumerate(findings,1):
        yield f"Finding {index}: {f['name']}",f"Asset / endpoint: {f['asset']}\nSeverity: {f['severity']}\nVerification: {f['verification']}\nWorkflow: {f.get('workflow_status','needs_investigation')}"
        if f.get('cwe'):yield 'Classification',f['cwe']
        if f.get('cvss') is not None:yield 'CVSS',f"{f['cvss']} — {f['cvss_justification']}"
        for key,label in [('description','Technical description'),('evidence','Technical evidence'),('reproduction','Reproduction steps / proof of concept'),('impact','Business impact'),('remediation','Remediation')]:
            yield label,f.get(key) or 'Not supplied.'
        if f.get('evidence_ids'):yield 'Evidence links','\n'.join(f['evidence_ids'])
        if f.get('references'):yield 'References','\n'.join(f['references'])
    yield 'Evidence inventory','\n'.join(f"{e['id']} | {e['name']} | {e['source']} | SHA-256 {e['sha256']}" for e in snapshot['evidence']) or 'No imported evidence files recorded.'

def _markdown(snapshot):
    parts=[]
    for index,(heading,body) in enumerate(_sections(snapshot)):
        parts.extend([('# ' if index==0 else '## ')+heading,'',str(body),''])
    return '\n'.join(parts)

def _html(snapshot):
    parts=['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SHADOW Security Assessment</title>',
      '<style>body{font:15px/1.6 system-ui;color:#202735;max-width:900px;margin:36px auto;padding:24px}h1{border-bottom:3px solid #9e3549;padding-bottom:12px}h2{font-size:18px;margin-top:28px}p{white-space:pre-wrap;overflow-wrap:anywhere}@media print{body{margin:0;padding:0}h2{break-after:avoid}}</style><body>']
    for index,(heading,body) in enumerate(_sections(snapshot)):
        tag='h1' if index==0 else 'h2'
        parts.extend([f'<{tag}>{html.escape(heading)}</{tag}>','<p>'+html.escape(str(body))+'</p>'])
    return '\n'.join(parts)+'</body></html>'

def _pdf(snapshot):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer
    font='Helvetica'
    for path in ['/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf','C:/Windows/Fonts/arial.ttf']:
        if Path(path).is_file():
            if 'ShadowReport' not in pdfmetrics.getRegisteredFontNames():pdfmetrics.registerFont(TTFont('ShadowReport',path))
            font='ShadowReport';break
    normal=ParagraphStyle('Body',fontName=font,fontSize=9,leading=14,textColor=colors.HexColor('#263241'),spaceAfter=9,wordWrap='CJK')
    heading_style=ParagraphStyle('Heading',parent=normal,fontSize=13,leading=18,spaceBefore=14,spaceAfter=8,textColor=colors.HexColor('#8e3044'),keepWithNext=True)
    title=ParagraphStyle('Title',parent=heading_style,fontSize=22,leading=28,spaceAfter=16)
    buffer=io.BytesIO();document=SimpleDocTemplate(buffer,pagesize=A4,rightMargin=48,leftMargin=48,topMargin=48,bottomMargin=48,title='SHADOW Security Assessment',author='SHADOW')
    story=[]
    for index,(heading,body) in enumerate(_sections(snapshot)):
        story.append(Paragraph(html.escape(heading),title if index==0 else heading_style))
        # Paragraph bounds keep very large evidence from becoming a single unsplittable flowable.
        text=str(body)
        if font=='Helvetica':text=text.encode('latin-1',errors='replace').decode('latin-1')
        for line in text.splitlines() or ['']:
            for start in range(0,max(1,len(line)),4000):
                story.append(Paragraph(html.escape(line[start:start+4000]) or ' ',normal))
    def footer(canvas,doc):
        canvas.saveState();canvas.setFont(font,8);canvas.setFillColor(colors.HexColor('#697487'))
        canvas.drawString(48,26,'SHADOW | Operator-recorded evidence and verification labels')
        canvas.drawRightString(A4[0]-48,26,str(doc.page));canvas.restoreState()
    document.build(story,onFirstPage=footer,onLaterPages=footer)
    return buffer.getvalue()

def _write_exclusive(path,data):
    selected=Path(path).expanduser().absolute()
    if selected.is_symlink():raise ValueError('Refusing symbolic-link output')
    parent=selected.parent.resolve(strict=True)
    if not parent.is_dir():raise ValueError('Output directory must exist')
    selected=parent/selected.name
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    if hasattr(os,'O_NOFOLLOW'):flags|=os.O_NOFOLLOW
    fd=os.open(selected,flags,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data)
    return selected

def generate_report(db,eid,format='md',output=None):
    if format not in {'md','html','pdf'}:raise ValueError('Report format must be md, html or pdf')
    snapshot=_snapshot(db,eid)
    content=_pdf(snapshot) if format=='pdf' else (_html(snapshot) if format=='html' else _markdown(snapshot)).encode('utf-8')
    filename=f'shadow-report-{uuid4().hex[:12]}.{format}'
    if output is None:
        directory=db.paths.data/'reports'
        if directory.is_symlink():raise ValueError('Refusing symbolic-link report directory')
        directory.mkdir(mode=0o700,exist_ok=True)
        output=directory/filename
    path=_write_exclusive(output,content)
    record=db.create('report',{'engagement_id':eid,'format':format,'filename':path.name,'path':str(path),'snapshot':snapshot,
      'content':base64.b64encode(content).decode('ascii') if format=='pdf' else content.decode('utf-8'),'encoding':'base64' if format=='pdf' else 'utf-8',
      'sha256':hashlib.sha256(content).hexdigest(),'warning':'Immutable report snapshot; later finding changes are not reflected in this report.'},eid)
    db.audit('report.generated',{'id':record['id'],'engagement_id':eid,'format':format,'sha256':record['sha256']});return record

def export_report(db,rid,output):
    report=db.get('report',rid)
    data=base64.b64decode(report['content'],validate=True) if report['encoding']=='base64' else report['content'].encode('utf-8')
    if hashlib.sha256(data).hexdigest()!=report['sha256']:raise ValueError('Stored report hash mismatch; export refused')
    path=_write_exclusive(output,data);db.audit('report.exported',{'id':rid,'sha256':report['sha256']});return path
