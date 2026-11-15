"""Read-only local model discovery contract. No inference starts during diagnostics."""
from abc import ABC,abstractmethod
import asyncio
import json
import httpx

class ModelProvider(ABC):
    @abstractmethod
    async def status(self): ...

class OllamaProvider(ModelProvider):
    def __init__(self,settings,transport=None):self.settings=settings;self.transport=transport
    async def status(self):
        try:
            async with asyncio.timeout(self.settings.request_timeout),httpx.AsyncClient(base_url=self.settings.ollama_url,timeout=self.settings.request_timeout,trust_env=False,follow_redirects=False,transport=self.transport) as client:
                async with client.stream('GET','/api/tags') as r:
                    r.raise_for_status();data=bytearray()
                    async for chunk in r.aiter_bytes():
                        data.extend(chunk)
                        if len(data)>2*1024*1024:raise ValueError('Model listing exceeds 2 MiB')
                payload=json.loads(data)
                if not isinstance(payload,dict):raise ValueError('Expected an object')
                models=payload.get('models')
                if not isinstance(models,list):raise ValueError('Unexpected model list')
                # Avoid unbounded or unvalidated status data from a different loopback service.
                clean=[]
                for item in models[:200]:
                    if isinstance(item,dict) and isinstance(item.get('name'),str):
                        details=item.get('details') if isinstance(item.get('details'),dict) else {}
                        clean.append({'name':item['name'][:200],'size':item.get('size') if isinstance(item.get('size'),int) else None,
                                      'quantization':str(details.get('quantization_level','unknown'))[:50],'parameters':str(details.get('parameter_size','unknown'))[:50]})
                selected=next((m for m in clean if m['name']==self.settings.model),None)
                return {'available':True,'models':clean,'selected_model':self.settings.model,'selected_available':bool(selected),'error':None}
        except (httpx.HTTPError,ValueError,TypeError,KeyError,TimeoutError):
            return {'available':False,'models':[],'selected_model':self.settings.model,'selected_available':False,'error':'Local Ollama is unavailable or returned an invalid model list. No inference was attempted.'}
