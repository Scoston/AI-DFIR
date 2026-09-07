#!/usr/bin/env python3
"""Validate generated synthetic exchange graphs with pinned CASE/UCO tools.

This acceptance command takes no input graph, URL, or ontology argument. It
never loads user JSON-LD. Exporting and comparing real cases need no RDF tools.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
import socket
import sys
import tempfile
import urllib.request
import warnings
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ONTOLOGY_SHA256 = "d246cfba2dbb8a521a97015c41c973a861a4906f6017d0e5f6c0b17487b63a7f"
VERSIONS = {"case-utils": "0.18.0", "rdflib": "7.6.0", "pyshacl": "0.40.1"}


def main():
    import case_utils
    from case_utils.case_validate import validate
    from rdflib import BNode, Graph, URIRef
    from rdflib.compare import isomorphic
    from rdflib.namespace import RDF, XSD

    from v17_case_exchange import export_exchange
    from v17_case_exchange_selftest import CASE_ID, TENANT_ID, exchange_fixture
    from v17_integrity import canonical_json_bytes

    versions = {name: importlib.metadata.version(name) for name in VERSIONS}
    assert versions == VERSIONS, "CASE validation tool versions changed"
    ontology = Path(case_utils.__file__).parent / "ontology/case-1.5.0.ttl"
    assert hashlib.sha256(ontology.read_bytes()).hexdigest() == ONTOLOGY_SHA256, "CASE ontology changed"
    with tempfile.TemporaryDirectory(prefix="ai-dfir-case-conformance-") as temporary, ExitStack() as guard:
        root = Path(temporary)
        for owner, attr in ((socket.socket, "connect"), (socket, "create_connection"),
                            (socket, "getaddrinfo"), (urllib.request, "urlopen")):
            guard.enter_context(patch.object(owner, attr, side_effect=AssertionError("network forbidden")))
        raw, public = exchange_fixture(root)
        graph = export_exchange(raw, public, expected_tenant=TENANT_ID, expected_case=CASE_ID)
        path = root / "synthetic.jsonld"
        path.write_bytes(canonical_json_bytes(graph))
        result = validate(str(path), case_version="1.5.0", do_owl_imports=False,
                          allow_warnings=False, allow_infos=False)
        assert result.conforms and not result.undefined_concepts, result.text
        rdf = Graph().parse(data=path.read_bytes(), format="json-ld")
        roundtrip = Graph().parse(data=rdf.serialize(format="nt"), format="nt")
        assert isomorphic(rdf, roundtrip), "RDF round trip changed triples"
        assert not any(isinstance(term, BNode) for triple in rdf for term in triple)
        assert len(set(rdf.subjects(RDF.type, URIRef("https://ontology.caseontology.org/case/investigation/Investigation")))) == 1
        assert len(set(rdf.subjects(RDF.type, URIRef("https://ontology.unifiedcyberontology.org/uco/observable/ObservableObject")))) == 3
        sizes = list(rdf.objects(None, URIRef("https://ontology.unifiedcyberontology.org/uco/observable/sizeInBytes")))
        assert len(sizes) == 3 and all(value.datatype == XSD.integer and int(value) >= 0 for value in sizes)

        rejected = 0
        for name in ("hash-datatype", "missing-target", "size-datatype", "unknown-concept"):
            bad = copy.deepcopy(graph)
            if name == "hash-datatype":
                node = next(n for n in bad["@graph"] if n["@type"] == "uco-types:Hash")
                node["uco-types:hashValue"]["@type"] = "xsd:string"
            elif name == "missing-target":
                node = next(n for n in bad["@graph"] if n["@type"] == "uco-core:Relationship")
                del node["uco-core:target"]
            elif name == "size-datatype":
                node = next(n for n in bad["@graph"] if n["@type"] == "uco-observable:ContentDataFacet")
                node["uco-observable:sizeInBytes"] = "123"
            else:
                bad["@graph"][0]["uco-core:misspelledProperty"] = "synthetic"
            path.write_bytes(canonical_json_bytes(bad))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = validate(str(path), case_version="1.5.0", do_owl_imports=False,
                                  allow_warnings=False, allow_infos=False)
            assert not result.conforms, "invalid CASE graph accepted: " + name
            rejected += 1
    print(json.dumps({"status": "PASS", "case_version": "1.5.0", "uco_version": "1.5.0",
                      "versions": versions, "ontology_sha256": ONTOLOGY_SHA256,
                      "valid_graphs": 1, "invalid_graphs_rejected": rejected,
                      "rdf_roundtrip": "PASS", "triples": len(rdf), "network_required": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
