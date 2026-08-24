#!/usr/bin/env python3
"""
A2A RFC 8785 JSON Canonicalization wrapper.

Preferred engine:
  python package `rfc8785`

Validated fallback:
  bundled Node.js canonicalizer using ECMAScript JSON number/string
  serialization and UTF-16 property ordering, as required by RFC 8785.

The wrapper rejects:
- duplicate JSON object member names,
- lone UTF-16 surrogate code points,
- integers outside the interoperable IEEE-754 integer range,
- non-finite floating-point values.

It never silently falls back to ordinary Python json.dumps for JCS.
"""
from __future__ import annotations
import json, math, shutil, subprocess
from pathlib import Path

MAX_SAFE_INTEGER=(1<<53)-1
HERE=Path(__file__).resolve().parent
NODE_HELPER=HERE/"a2a_jcs_node.js"

class DuplicateKeyError(ValueError): pass
class JCSUnavailable(RuntimeError): pass

def _pairs(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise DuplicateKeyError(f"duplicate JSON member: {k!r}")
        out[k]=v
    return out

def strict_loads(text:str):
    obj=json.loads(text,object_pairs_hook=_pairs,
                   parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"invalid JSON number {x}")))
    validate_i_json(obj)
    return obj

def strict_load(path):
    return strict_loads(Path(path).read_text(encoding="utf-8",errors="strict"))

def validate_i_json(obj,path="$"):
    if obj is None or isinstance(obj,bool): return
    if isinstance(obj,str):
        for i,ch in enumerate(obj):
            cp=ord(ch)
            if 0xD800<=cp<=0xDFFF:
                raise ValueError(f"lone surrogate at {path}[{i}]")
        return
    if isinstance(obj,int):
        if abs(obj)>MAX_SAFE_INTEGER:
            raise ValueError(f"integer outside interoperable IEEE-754 range at {path}")
        return
    if isinstance(obj,float):
        if not math.isfinite(obj):
            raise ValueError(f"non-finite number at {path}")
        return
    if isinstance(obj,list):
        for i,x in enumerate(obj): validate_i_json(x,f"{path}[{i}]")
        return
    if isinstance(obj,dict):
        for k,v in obj.items():
            if not isinstance(k,str): raise TypeError(f"non-string JSON key at {path}")
            validate_i_json(k,f"{path}.<key>")
            validate_i_json(v,f"{path}.{k}")
        return
    raise TypeError(f"unsupported JSON type at {path}: {type(obj).__name__}")

def canonicalize(obj):
    validate_i_json(obj)
    try:
        import rfc8785
        return rfc8785.dumps(obj), "python-rfc8785"
    except Exception:
        pass
    node=shutil.which("node")
    if not node or not NODE_HELPER.exists():
        raise JCSUnavailable(
            "RFC 8785 canonicalization requires the `rfc8785` Python package "
            "or Node.js plus bundled a2a_jcs_node.js; refusing approximate canonicalization."
        )
    proc=subprocess.run(
        [node,str(NODE_HELPER)],
        input=json.dumps(obj,ensure_ascii=False,separators=(",",":"),allow_nan=False),
        text=True,capture_output=True,encoding="utf-8"
    )
    if proc.returncode:
        raise ValueError("Node JCS canonicalization failed: "+proc.stderr.strip())
    return proc.stdout.encode("utf-8"), "node-rfc8785-compatible"

def b64u(data:bytes):
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64u_decode(s:str):
    import base64
    if not isinstance(s,str): raise TypeError("base64url value must be a string")
    pad="="*((4-len(s)%4)%4)
    return base64.urlsafe_b64decode(s+pad)

# A2A v1.0 AgentCard fields whose empty repeated/map values must be retained
# because the field is REQUIRED.
_REQUIRED_TOP={
    "name","description","supportedInterfaces","version","capabilities",
    "defaultInputModes","defaultOutputModes","skills"
}
_REQUIRED_NESTED={
    "provider":{"url","organization"},
    "skill":{"id","name","description","tags"},
    "interface":{"url","protocolBinding","protocolVersion"},
}
_OPTIONAL_PRESENCE={
    "documentationUrl","iconUrl",
}
_OPTIONAL_CAPABILITY_PRESENCE={"streaming","pushNotifications","extendedAgentCard"}
_OPTIONAL_INTERFACE_PRESENCE={"tenant"}

def _drop_default_scalar(v):
    return v in ("",0,False,None)

def _clean_generic(v):
    if isinstance(v,list):
        vals=[_clean_generic(x) for x in v]
        return [x for x in vals if x is not _DROP]
    if isinstance(v,dict):
        o={}
        for k,x in v.items():
            y=_clean_generic(x)
            if y is not _DROP:o[k]=y
        return o
    return v

class _Drop: pass
_DROP=_Drop()

def prepare_agent_card(card:dict):
    """
    Apply A2A v1.0 AgentCard signature pre-canonicalization rules.

    `signatures` is excluded. Repeated/map fields not REQUIRED are omitted when
    empty. Proto scalar defaults are omitted unless the field is REQUIRED or
    uses explicit optional presence semantics.
    """
    if not isinstance(card,dict): raise TypeError("Agent Card must be a JSON object")
    out={}
    for k,v in card.items():
        if k=="signatures": continue
        if k in _REQUIRED_TOP:
            out[k]=_clean_required_top(k,v); continue
        if k in _OPTIONAL_PRESENCE:
            # proto optional: explicit default is preserved
            out[k]=_clean_generic(v); continue
        if k=="provider":
            if isinstance(v,dict) and v:
                out[k]=_clean_provider(v)
            continue
        if k=="securitySchemes":
            if isinstance(v,dict) and v:
                out[k]=_clean_generic(v)
            continue
        if k=="securityRequirements":
            if isinstance(v,list) and v:
                out[k]=_clean_generic(v)
            continue
        # Forward-compatible unknown fields: preserve non-default values.
        # A verifier cannot infer future proto presence annotations safely.
        if isinstance(v,(list,dict)) and not v: continue
        if _drop_default_scalar(v): continue
        out[k]=_clean_generic(v)
    validate_i_json(out)
    return out

def _clean_required_top(k,v):
    if k=="capabilities":
        return _clean_capabilities(v if isinstance(v,dict) else {})
    if k=="supportedInterfaces":
        return [_clean_interface(x) if isinstance(x,dict) else x for x in (v or [])]
    if k=="skills":
        return [_clean_skill(x) if isinstance(x,dict) else x for x in (v or [])]
    return _clean_generic(v)

def _clean_provider(v):
    out={}
    for k,x in v.items():
        if k in _REQUIRED_NESTED["provider"]:
            out[k]=_clean_generic(x)
        elif isinstance(x,(list,dict)) and not x: continue
        elif _drop_default_scalar(x): continue
        else: out[k]=_clean_generic(x)
    return out

def _clean_capabilities(v):
    out={}
    for k,x in v.items():
        if k in _OPTIONAL_CAPABILITY_PRESENCE:
            out[k]=_clean_generic(x)  # explicit false preserved
        elif k=="extensions":
            if isinstance(x,list) and x:
                out[k]=[_clean_extension(y) if isinstance(y,dict) else y for y in x]
        elif isinstance(x,(list,dict)) and not x: continue
        elif _drop_default_scalar(x): continue
        else: out[k]=_clean_generic(x)
    return out

def _clean_extension(v):
    # AgentExtension scalar fields are proto3 non-optional; default values are omitted.
    out={}
    for k,x in v.items():
        if k=="params":
            if isinstance(x,dict) and x:out[k]=_clean_generic(x)
        elif isinstance(x,(list,dict)) and not x: continue
        elif _drop_default_scalar(x): continue
        else: out[k]=_clean_generic(x)
    return out

def _clean_skill(v):
    out={}
    for k,x in v.items():
        if k in _REQUIRED_NESTED["skill"]:
            out[k]=_clean_generic(x)
        elif isinstance(x,(list,dict)):
            if x:out[k]=_clean_generic(x)
        elif _drop_default_scalar(x): continue
        else: out[k]=_clean_generic(x)
    return out

def _clean_interface(v):
    out={}
    for k,x in v.items():
        if k in _REQUIRED_NESTED["interface"] or k in _OPTIONAL_INTERFACE_PRESENCE:
            out[k]=_clean_generic(x)
        elif isinstance(x,(list,dict)) and not x: continue
        elif _drop_default_scalar(x): continue
        else: out[k]=_clean_generic(x)
    return out
