#!/usr/bin/env python3
"""Tenant-scoped authorization policy for investigators, reviewers, collectors and admins."""
from __future__ import annotations
import json
ROLE_ACTIONS={
 'collector':{'evidence:create','task:read','task:complete'},
 'investigator':{'case:read','evidence:read','evidence:annotate','report:generate','task:create'},
 'reviewer':{'case:read','evidence:read','review:approve','review:reject','report:read'},
 'case_admin':{'case:read','case:write','evidence:read','evidence:hold','task:create','report:generate','review:approve'},
 'platform_admin':{'*'},
}
def authorize(principal,tenant_id,action):
    tenants=set(principal.get('tenant_ids') or ([principal.get('tenant_id')] if principal.get('tenant_id') else []))
    roles=set(principal.get('roles') or [])
    if tenant_id not in tenants and 'platform_admin' not in roles:
        return {'allowed':False,'reason':'cross_tenant_denied','tenant_id':tenant_id,'action':action}
    allowed=any('*' in ROLE_ACTIONS.get(r,set()) or action in ROLE_ACTIONS.get(r,set()) for r in roles)
    return {'allowed':allowed,'reason':'role_allowed' if allowed else 'role_denied','tenant_id':tenant_id,'action':action,'roles':sorted(roles)}
def require(principal,tenant_id,action):
    r=authorize(principal,tenant_id,action)
    if not r['allowed']:raise PermissionError(json.dumps(r,sort_keys=True))
    return r
