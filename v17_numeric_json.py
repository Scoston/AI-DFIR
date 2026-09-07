"""Bounded strict JSON with exact number tokens and collision-free tagged hashes."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_log_analytics import MAX_INPUT_BYTES, _bounded
from v17_provenance import ProvenanceError

MAX_NUMBER_CHARS = 128
NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
TOKEN_ENCODING = "ai-dfir/json-number-token-tree/v1"


@dataclass(frozen=True)
class NumberToken:
    text: str

    def __post_init__(self):
        if not isinstance(self.text, str) or len(self.text) > MAX_NUMBER_CHARS or NUMBER_RE.fullmatch(self.text) is None:
            raise ProvenanceError("invalid or excessive JSON number token")


def document(raw: bytes, *, limit=MAX_INPUT_BYTES):
    if not isinstance(raw, bytes) or not raw or len(raw) > limit:
        raise ProvenanceError("numeric JSON document is empty or exceeds byte limit")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProvenanceError("duplicate numeric JSON key")
            result[key] = value
        return result
    def constant(_):
        raise ProvenanceError("unsupported non-JSON numeric constant")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant,
                            parse_int=NumberToken, parse_float=NumberToken)
        # The shared walk bounds keys, strings, depth and nodes. NumberToken is
        # a single leaf with its own lexical budget; no float conversion occurs.
        _bounded(result)
        return result
    except (ValueError, TypeError, RecursionError):
        raise ProvenanceError("invalid or excessive numeric JSON") from None


def token_tree(value):
    """Tag every JSON kind; an evidence object cannot impersonate a number tag.

    Input must come from document(), whose depth/node/string limits are checked
    before this recursive encoding. Object key canonicalization remains RFC8785.
    """
    if isinstance(value, NumberToken):
        return ["number", value.text]
    if value is None:
        return ["null"]
    if type(value) is bool:
        return ["boolean", value]
    if isinstance(value, str):
        return ["string", value]
    if isinstance(value, list):
        return ["array", [token_tree(item) for item in value]]
    if isinstance(value, dict):
        return ["object", {key: token_tree(item) for key, item in value.items()}]
    raise ProvenanceError("unsupported numeric JSON value")


def token_bytes(value):
    return canonical_json_bytes(token_tree(value))


def token_digest(value):
    return sha256_bytes(token_bytes(value))
