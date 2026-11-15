"""Natural-language proposals cross a separate deterministic approval boundary."""
import hashlib
import json
import time

class ActionRunner:
    def __init__(self,state):self.state=state;self.db=state.database
    async def preview(self,action,engagement_id=None):
        data=action.model_dump() if hasattr(action,'model_dump') else dict(action)
        capability=data.get('capability');eid=engagement_id or self.state.settings.active_engagement
        supported={'recon_probe','kb_search','report_generate','remember','project_note','http_review','nmap_preview','soc_query','soc_report'}
        if capability not in supported:raise ValueError('Unsupported action proposal')
        if capability in {'recon_probe','report_generate','project_note','nmap_preview'}:
            if not eid:raise ValueError('Select an authorized engagement before this action')
            self.db.engagement(eid)
        details={'action':data,'engagement_id':eid};title=data.get('explanation') or capability
        if capability=='recon_probe':
            from .recon import preview
            run=preview(self.db,eid);details['recon_run_id']=run['id'];details['recon_digest']=run.get('digest');details['network_preview']=run
        elif capability=='nmap_preview':
            from .integrations import ToolManager
            job=ToolManager(self.state).preview(eid,data.get('target',''),data.get('ports','22,80,443'))
            details['job_id']=job['id'];details['command']=job['command']
            title='Create a scoped Nmap command preview; execution requires another approval'
        elif capability=='remember' and not data.get('content','').strip():raise ValueError('Memory content is required')
        elif capability=='kb_search' and not data.get('query','').strip():raise ValueError('Search query is required')
        elif capability=='soc_report':self.db.get('soc_incident',data.get('target',''))
        token=hashlib.sha256(json.dumps(details,sort_keys=True).encode()).hexdigest()
        row=self.db.create('action_preview',{'title':title,'details':details,'digest':token,'expires':time.time()+600,'status':'pending'},eid)
        self.db.audit('action.previewed',{'id':row['id'],'capability':capability});return row

    async def execute(self,preview_id,approved=False,on_progress=None):
        if approved is not True:raise ValueError('Explicit user approval required')
        row=self.db.get('action_preview',preview_id)
        if row['expires']<time.time():raise ValueError('Action preview expired')
        details=row['details'];data=details['action'];eid=details['engagement_id'];capability=data['capability']
        digest=hashlib.sha256(json.dumps(details,sort_keys=True).encode()).hexdigest()
        if digest!=row['digest']:raise ValueError('Action preview changed')
        self.db.claim('action_preview',preview_id)
        try:
            if capability=='recon_probe':
                from .recon import execute
                result=await execute(self.db,details['recon_run_id'],details['recon_digest'],on_progress=on_progress)
            elif capability=='kb_search':
                from .knowledge import KnowledgeService
                result=await KnowledgeService(self.state).search(data['query'])
            elif capability=='report_generate':
                from .reporting import generate_report
                result=generate_report(self.db,eid,data.get('format','md'))
            elif capability=='remember':
                from .intelligence import ConversationService
                result=ConversationService(self.state).memory_save(data['content'],engagement_id=eid)
            elif capability=='project_note':result=self.db.create('note',{'content':data.get('content',''),'engagement_id':eid},eid)
            elif capability=='http_review':
                from .research import analyze_http
                result=analyze_http(data.get('content',''))
            elif capability=='soc_query':
                from . import soc,soc_logs,soc_detection
                view=data.get('soc_view','alerts')
                if view=='alerts':result=soc.alerts(self.db,data.get('severity',''),data.get('status',''),data.get('query',''),limit=30)
                elif view=='events':result=soc_logs.events(self.db,search=data.get('query',''),since=data.get('since') or None,limit=30)
                elif view=='incidents':result=self.db.listing('soc_incident',limit=30)
                elif view=='techniques':result=soc_detection.attack_search(self.db,data.get('query',''))
                elif view=='related_alerts':result=soc.related(self.db,data.get('target',''))
                else:raise ValueError('Unsupported SOC query view')
            elif capability=='soc_report':
                from .soc import report
                result=report(self.db,data['target'],data.get('format','md'))
            else:result=self.db.get('job',details['job_id'])
            if capability in {'report_generate','soc_report'}:
                result={k:v for k,v in result.items() if k not in {'content','snapshot','base64'}}
            self.db.update('action_preview',preview_id,{'status':'completed','result':result});self.db.audit('action.completed',{'id':preview_id,'capability':capability})
            return result
        except BaseException:
            self.db.update('action_preview',preview_id,{'status':'failed'});raise
