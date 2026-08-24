#!/usr/bin/env python3
from __future__ import annotations
import json, shutil, subprocess, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec,rsa,ed25519
from cryptography.hazmat.primitives import serialization

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))

from a2a_jcs import prepare_agent_card,canonicalize
from a2a_agent_card_crypto import sign_card,verify_card,public_jwk_from_key
from a2a_trust_store import init_store,import_jwks,sign_store,load_store
from a2a_card_history import compare as history_compare
from a2a_execution_binding import analyze as binding_analyze
from fleet_crypto import generate
from evidence_pack_engine import load_packs
from case_model import full_case

def writej(p,o):p.write_text(json.dumps(o,indent=2,sort_keys=True),encoding="utf-8")
def pem_private(priv,p):
    p.write_bytes(priv.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))

def card():
    return {
      "name":"Claims Review Agent",
      "description":"Reviews claims and routes approved actions.",
      "supportedInterfaces":[{"url":"https://claims-agent.example/a2a","protocolBinding":"HTTP+JSON","protocolVersion":"1.0","tenant":"TENANT-A"}],
      "provider":{"url":"https://example.com","organization":"Example Corp"},
      "version":"1.0.0",
      "capabilities":{"streaming":False,"pushNotifications":False,"extensions":[]},
      "securitySchemes":{"oauth":{"oauth2SecurityScheme":{"flows":{}}}},
      "securityRequirements":[{"oauth":[]}],
      "defaultInputModes":["application/json"],
      "defaultOutputModes":["application/json"],
      "skills":[{"id":"review_claim","name":"Review claim","description":"Review a claim","tags":["claims"]}]
    }

def main():
    import argparse
    ap=argparse.ArgumentParser();ap.add_argument("--out",required=True);a=ap.parse_args()
    out=Path(a.out).resolve();shutil.rmtree(out,ignore_errors=True);out.mkdir(parents=True)
    result={}

    # 1. A2A JCS pre-processing semantics.
    c=card();prepared=prepare_agent_card(c);body,engine=canonicalize(prepared)
    assert b'"streaming":false' in body
    assert b'"extensions"' not in body
    assert b'"signatures"' not in body
    assert b'"skills"' in body
    result["rfc8785_agentcard_canonicalization"]="PASS"

    # 2. Create ES256, RSA and Ed25519 signing keys.
    es=ec.generate_private_key(ec.SECP256R1());rs=rsa.generate_private_key(public_exponent=65537,key_size=2048);ed=ed25519.Ed25519PrivateKey.generate()
    es_p=out/"es.pem";rs_p=out/"rs.pem";ed_p=out/"ed.pem"
    for k,p in ((es,es_p),(rs,rs_p),(ed,ed_p)):pem_private(k,p)
    jwks={"keys":[
      public_jwk_from_key(es.public_key(),"es-key","ES256"),
      public_jwk_from_key(rs.public_key(),"rsa-key","RS256"),
      public_jwk_from_key(ed.public_key(),"ed-key","EdDSA"),
    ]}

    store=init_store()
    store=import_jwks(store,jwks,source_url="https://keys.example/a2a-jwks.json",
                      provider_org="Example Corp",provider_url="https://example.com",
                      allowed_origins=["https://claims-agent.example"],assurance="ENTERPRISE_PINNED")
    trust_priv=out/"trust.pem";trust_pub=out/"trust.pub.pem";generate(trust_priv,trust_pub)
    signed_store=out/"a2a_trust_store.signed.json";sign_store(store,trust_priv,signed_store)
    loaded,meta=load_store(signed_store,trust_pub,False)
    assert meta["verified"] and len(loaded["keys"])==3
    result["signed_offline_trust_store"]="PASS"

    # 3. Multi-signature JWS verification across ES256/RS256/EdDSA.
    signed,_=sign_card(c,es_p,"es-key","ES256","https://keys.example/a2a-jwks.json")
    signed,_=sign_card(signed,rs_p,"rsa-key","RS256","https://keys.example/a2a-jwks.json")
    signed,_=sign_card(signed,ed_p,"ed-key","EdDSA","https://keys.example/a2a-jwks.json")
    ver=verify_card(signed,loaded)
    assert ver["policy_satisfied"] and ver["valid_signature_count"]==3 and ver["trusted_signature_count"]==3
    result["agent_card_multisignature_verification"]="PASS"

    # 4. Tamper detection.
    tampered=json.loads(json.dumps(signed));tampered["description"]="Tampered description"
    tv=verify_card(tampered,loaded)
    assert not tv["policy_satisfied"] and tv["valid_signature_count"]==0
    result["agent_card_tamper_rejected"]="PASS"

    # 5. Revoked-key trust failure even with a cryptographically valid JWS.
    revoked=init_store()
    revoked=import_jwks(revoked,{"keys":[jwks["keys"][0]]},source_url="https://keys.example/a2a-jwks.json",
                        provider_org="Example Corp",provider_url="https://example.com",
                        allowed_origins=["https://claims-agent.example"])
    revoked["keys"][0]["revoked"]=True;revoked["keys"][0]["revocation_reason"]="incident response revocation"
    es_only,_=sign_card(c,es_p,"es-key","ES256","https://keys.example/a2a-jwks.json")
    rv=verify_card(es_only,revoked)
    assert rv["valid_signature_count"]==1 and rv["trusted_signature_count"]==0 and not rv["policy_satisfied"]
    assert any(x["type"]=="a2a_signing_key_revoked" for x in rv["findings"])
    result["revoked_signing_key_rejected"]="PASS"

    # 6. Provider/interface trust binding.
    wrong=json.loads(json.dumps(es_only));wrong["provider"]["organization"]="Other Corp"
    pv=verify_card(wrong,revoked)
    # Signature will fail because signed content changed; separately test valid signature under mismatched policy.
    other=card();other["provider"]["organization"]="Other Corp"
    other_signed,_=sign_card(other,es_p,"es-key","ES256","https://keys.example/a2a-jwks.json")
    unrev=json.loads(json.dumps(revoked));unrev["keys"][0]["revoked"]=False
    ov=verify_card(other_signed,unrev)
    assert ov["valid_signature_count"]==1 and not ov["trusted"]
    assert any(x["type"]=="a2a_provider_binding_mismatch" for x in ov["findings"])
    result["provider_interface_policy_binding"]="PASS"

    # 7. jku trust-source mismatch.
    badjku,_=sign_card(c,es_p,"es-key","ES256","https://evil.example/jwks.json")
    jv=verify_card(badjku,unrev)
    assert jv["valid_signature_count"]==1 and not jv["trusted"]
    assert any(x["type"]=="a2a_jku_trust_source_mismatch" for x in jv["findings"])
    result["jku_trust_bootstrap_protection"]="PASS"

    # 8. History/key rotation + same-version content mutation.
    rotated,_=sign_card(c,ed_p,"ed-key","EdDSA","https://keys.example/a2a-jwks.json")
    hist=history_compare(es_only,rotated)
    assert any(x["type"]=="a2a_card_signing_key_rotation" for x in hist["findings"])
    changed=card();changed["skills"].append({"id":"delete_claim","name":"Delete","description":"Delete claim","tags":["claims"]})
    changed_signed,_=sign_card(changed,ed_p,"ed-key","EdDSA","https://keys.example/a2a-jwks.json")
    hist2=history_compare(rotated,changed_signed)
    htypes={x["type"] for x in hist2["findings"]}
    assert "a2a_card_content_changed_without_version_change" in htypes and "a2a_card_skill_expansion" in htypes
    result["agent_card_history_and_rotation"]="PASS"

    # 9. Execution/delegation binding.
    trusted_es=verify_card(es_only,unrev)
    events=[{
      "event_id":"E1","task_id":"T1","context_id":"C1","principal":"alice","agent_id":"claims",
      "skill_id":"delete_claim","tenant":"TENANT-B",
      "agent_card_sha256":"deadbeef","authority_before":["claims.read"],"authority_after":["claims.read","claims.delete"],
      "authority_elevation_approved":False
    }]
    bind=binding_analyze(events,trusted_es)
    btypes={x["type"] for x in bind["findings"]}
    assert {"a2a_undeclared_skill_invoked","a2a_tenant_binding_mismatch","a2a_execution_card_hash_mismatch","a2a_unapproved_authority_escalation"}.issubset(btypes)
    result["execution_delegation_binding"]="PASS"

    # 10. Evidence Pack catalog.
    packs=load_packs();ids={x["id"] for x in packs}
    assert len(packs)>=68
    for pid in ("a2a.signed_agent_card_trust","a2a.signing_key_lifecycle","a2a.execution_identity_binding","a2a.push_callback_identity"):
        assert pid in ids
    result["a2a_v13_evidence_packs"]="PASS"

    # 11. End-to-end orchestrator attaches trust/delegation pack.
    case=out/"case";case.mkdir();writej(case/"case.json",{"case_id":"A2A-13","tool_version":"1.3"})
    card_path=out/"card.json";writej(card_path,es_only)
    events_path=out/"events.jsonl";events_path.write_text("".join(json.dumps(e)+"\n" for e in events))
    cp=subprocess.run([sys.executable,str(HERE/"a2a_trust_analyze.py"),"--case",str(case),"--card",str(card_path),
                       "--trust-store",str(signed_store),"--trust-public-key",str(trust_pub),"--events",str(events_path)],
                      capture_output=True,text=True)
    assert cp.returncode==0,(cp.stdout,cp.stderr)
    profile=json.loads((case/"incident_profile.json").read_text())
    attached=set(profile.get("additional_evidence_pack_ids") or [])
    assert "a2a.execution_identity_binding" in attached
    result["a2a_case_orchestrator"]="PASS"

    # 12. Case/workbench integration.
    fc=full_case(case)
    assert fc["a2a_trust"]["presence"]["verification"] and fc["a2a_trust"]["presence"]["execution_binding"]
    dash=(HERE/"analyst_dashboard.py").read_text()
    assert "A2A Identity, Signed Agent Cards & Delegation Trust" in dash
    assert "version':'1.3" in dash
    result["workbench_a2a_trust_integration"]="PASS"

    final={"status":"PASS","evidence_pack_count":len(packs),"components":result}
    writej(out/"V1.3_SELFTEST.json",final);print(json.dumps(final,indent=2,sort_keys=True))

if __name__=="__main__":main()
