"""Synthetic structure-preserving ZIP builders and a pinned, committed corpus."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import zlib

from v17_docx_intake_selftest import DOCUMENT, font_table, relationships

PROFILES = ("docx-document-xml", "docx-font-relationships", "zip-member-name")
MAX_PAYLOAD_BYTES = 16 * 1024
MAX_GENERATED_BYTES = 32 * 1024
CORPUS_PATH = "tests/fixtures/fuzz/v17/structured_cases.json"
CORPUS_SHA256 = "bc01aa0fc7429f45eec4843e751373e3e52a71126be3644d77ecb6e1b4824b51"
CORPUS_SCHEMA = "ai-dfir/synthetic-structured-fuzz-corpus/v1.7"


def require(condition):
    if not condition: raise ValueError("invalid or excessive synthetic fuzz structure/corpus")


def zip32(parts):
    """Small stored ZIP32, built in memory without member I/O or extraction APIs."""
    local, central = bytearray(), bytearray()
    require(type(parts) in (list, tuple) and 1 <= len(parts) <= 4)
    for part in parts:
        require(type(part) in (list, tuple) and len(part) == 2)
        name, data = part
        require(isinstance(name, str) and 0 < len(name) <= 4096)
        encoded = name.encode("utf-8", errors="strict")
        require(0 < len(encoded) <= 4096 and type(data) is bytes and len(data) <= MAX_PAYLOAD_BYTES)
        require(len(local) + len(central) + 98 + 2 * len(encoded) + len(data) <= MAX_GENERATED_BYTES)
        offset = len(local); crc = zlib.crc32(data); size = len(data)
        local.extend(struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0x800, 0, 0, 33, crc, size, size, len(encoded), 0))
        local.extend(encoded); local.extend(data)
        central.extend(struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 0x314, 20, 0x800, 0, 0, 33,
                                   crc, size, size, len(encoded), 0, 0, 0, 0, (stat.S_IFREG | 0o600) << 16, offset))
        central.extend(encoded)
    end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, len(parts), len(parts), len(central), len(local), 0)
    output = bytes(local + central) + end
    require(len(output) <= MAX_GENERATED_BYTES)
    return output


def build(raw, *, profile):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_PAYLOAD_BYTES and profile in PROFILES)
    if profile == "docx-document-xml":
        parts = [("word/document.xml", raw)]
    elif profile == "docx-font-relationships":
        parts = [("word/document.xml", DOCUMENT), ("word/fontTable.xml", font_table()),
                 ("word/_rels/fontTable.xml.rels", raw), ("word/fonts/synthetic.ttf", b"synthetic opaque font")]
    else:
        parts = [(raw.decode("utf-8", errors="strict"), b"synthetic member content")]
    return zip32(parts)


def seeds():
    return DOCUMENT, relationships(), b"safe/synthetic.txt"


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result); result[key] = value
    return result


def load_corpus():
    path = Path(__file__).resolve().parent / CORPUS_PATH
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 65536)
        raw = stream.read(65537)
    require(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == CORPUS_SHA256)
    obj = json.loads(raw, object_pairs_hook=_object)
    require(isinstance(obj, dict) and set(obj) == {"schema", "cases"} and obj["schema"] == CORPUS_SCHEMA)
    require(isinstance(obj["cases"], list) and len(obj["cases"]) == 8)
    rows, names = [], set()
    for row in obj["cases"]:
        require(isinstance(row, dict) and set(row) == {"id", "profile", "payload_base64", "expected"})
        name, profile, payload = row["id"], row["profile"], row["payload_base64"]
        require(isinstance(name, str) and re.fullmatch(r"[a-z0-9-]{1,64}", name) and name not in names)
        require(isinstance(profile, str) and profile in PROFILES and isinstance(row["expected"], str)
                and row["expected"] in {"ACCEPT", "REJECT"})
        require(isinstance(payload, str) and len(payload) <= 22000)
        data = base64.b64decode(payload, validate=True)
        require(base64.b64encode(data).decode() == payload and 0 < len(data) <= MAX_PAYLOAD_BYTES)
        names.add(name); rows.append({"id": name, "profile": profile, "payload": data, "expected": row["expected"]})
    return tuple(rows)
