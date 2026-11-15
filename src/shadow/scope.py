"""Fail-closed target policy; analysis never becomes authorization."""
import ipaddress
import re
from pydantic import BaseModel,ConfigDict,Field,field_validator

def normalize(value):
    value=value.strip().lower().rstrip('.')
    try:return str(ipaddress.ip_network(value,strict=False)) if '/' in value else str(ipaddress.ip_address(value))
    except ValueError:
        value=value.encode('idna').decode('ascii')
        if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',value):
            raise ValueError('Scope accepts exact hostname/IP/CIDR only; no wildcards, URLs or command syntax')
        return value

class EngagementInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    name:str=Field(min_length=1,max_length=150)
    scope:list[str]=Field(min_length=1,max_length=100000)
    exclusions:list[str]=Field(default_factory=list,max_length=100000)
    authorization:str=Field(min_length=10,max_length=10000)
    rules:str=Field(default='',max_length=20000)
    @field_validator('name','authorization')
    @classmethod
    def nonblank(cls,value):
        if not value.strip():raise ValueError('Must not be blank')
        return value.strip()
    @field_validator('scope','exclusions')
    @classmethod
    def valid_scope(cls,values):return list(dict.fromkeys(normalize(v) for v in values))

def matches(target,entry):
    try:return ipaddress.ip_address(target) in ipaddress.ip_network(entry,strict=False)
    except ValueError:return target==entry

def check(target,engagement):
    target=normalize(target)
    if '/' in target:raise ValueError('Check one exact asset, not a target range')
    denied=any(matches(target,e) for e in engagement['exclusions'])
    included=any(matches(target,e) for e in engagement['scope'])
    return {'target':target,'in_scope':included and not denied,'reason':'Explicit exclusion' if denied else 'Included in recorded scope' if included else 'Not in recorded scope',
            'engagement_id':engagement['id'],'note':'Scope check only. No DNS lookup, HTTP request or scan was performed.'}
