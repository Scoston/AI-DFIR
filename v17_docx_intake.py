"""Bounded, selected-part DOCX intake from one immutable ZIP32 snapshot."""
from __future__ import annotations

import io
import struct
import zipfile
import zlib
from xml.etree.ElementTree import TreeBuilder

from defusedxml.ElementTree import DefusedXMLParser
from defusedxml.common import DefusedXmlException

from v17_archive_intake import inspect_archive, name_risks, read_archive
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_provenance import ProvenanceError

SCHEMA = "ai-dfir/bounded-docx-intake/v1.7"
WORD = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
REL = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
XML_PARTS = {
    "word/document.xml": f"{{{WORD}}}document",
    "word/fontTable.xml": f"{{{WORD}}}fonts",
    "word/_rels/fontTable.xml.rels": f"{{{REL}}}Relationships",
}
MAX_MEMBERS = 512
MAX_XML_BYTES = 2 * 1024**2
MAX_FONT_BYTES = 4 * 1024**2
MAX_SELECTED_BYTES = 16 * 1024**2
MAX_FONTS = 32
MAX_XML_NODES = 50000
MAX_XML_DEPTH = 64
MAX_TEXT_CHARS = 1024**2
MAX_OUTPUT_BYTES = 2 * 1024**2


def require(condition, reason="invalid, unsupported, ambiguous, or excessive DOCX"):
    if not condition:
        raise ProvenanceError(reason)


class _Tree(TreeBuilder):
    def __init__(self):
        super().__init__()
        self.depth = self.nodes = self.text_chars = 0

    def start(self, tag, attrs):
        self.depth += 1
        self.nodes += 1
        require(self.depth <= MAX_XML_DEPTH and self.nodes <= MAX_XML_NODES and len(attrs) <= 128)
        require(len(tag) <= 4096 and all(len(k) <= 4096 and len(v) <= 4096 for k, v in attrs.items()))
        return super().start(tag, attrs)

    def end(self, tag):
        self.depth -= 1
        return super().end(tag)

    def data(self, data):
        self.text_chars += len(data)
        require(self.text_chars <= MAX_TEXT_CHARS)
        return super().data(data)


def xml_root(raw, expected):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_XML_BYTES)
    try:
        parser = DefusedXMLParser(target=_Tree(), forbid_dtd=True, forbid_entities=True, forbid_external=True)
        parser.feed(raw)
        root = parser.close()
        require(root.tag == expected)
        return root
    except (DefusedXmlException, ValueError, SyntaxError, RecursionError) as exc:
        raise ProvenanceError("invalid, forbidden, or excessive DOCX XML") from exc


def font_relationships(parts):
    raw = parts.get("word/_rels/fontTable.xml.rels")
    if raw is None:
        return {}
    root = xml_root(raw, XML_PARTS["word/_rels/fontTable.xml.rels"])
    result = {}
    for rel in root:
        require(rel.tag == f"{{{REL}}}Relationship" and len(result) < 256)
        rid, target = rel.get("Id"), rel.get("Target")
        mode = rel.get("TargetMode", "Internal")
        require(bool(rid) and rid not in result and bool(target) and mode in {"Internal", "External"})
        result[rid] = {"target": target, "mode": mode, "type": rel.get("Type")}
    return result


def font_part(rel):
    """Restricted literal package keys only; never a filesystem or URL lookup."""
    if not rel or rel["mode"] != "Internal" or rel["type"] != OFFICE_REL + "/font":
        return None
    target = rel["target"]
    if (any(c in target for c in "\\:%?#") or any(ord(c) < 32 or ord(c) == 127 for c in target)
            or any(p in {"", ".", ".."} for p in target.split("/"))):
        return None
    return "word/" + target


def _inflate(raw, info, limit):
    require(info.file_size <= limit and info.file_size <= max(1, info.compress_size) * 1000)
    name_len, extra_len = struct.unpack_from("<HH", raw, info.header_offset + 26)
    start = info.header_offset + 30 + name_len + extra_len
    payload = raw[start:start + info.compress_size]
    if info.compress_type == zipfile.ZIP_STORED:
        value = payload
    else:
        decoder = zlib.decompressobj(-15)
        value = decoder.decompress(payload, limit + 1)
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail)
    require(len(value) <= limit and len(value) == info.file_size and zlib.crc32(value) == info.CRC)
    return value


class DocxParts(dict):
    """Selected byte parts with a separate, bounded intake receipt."""
    intake: dict


def load_docx(raw):
    require(type(raw) is bytes)
    archive = inspect_archive(raw, input_format="zip")
    require(archive["member_count"] <= MAX_MEMBERS)
    aliases = set()
    for row in archive["members"]:
        absolute, traversal, _, _, ambiguous, alias = name_risks(row["name"])
        require(not (absolute or traversal or ambiguous or "\\" in row["name"] or alias in aliases))
        aliases.add(alias)
        require(not (row["is_symlink"] or row["special_type"] or row["encrypted"]))
        require(row["compression_method"] in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
        require(not row["is_directory"] or row["size"] == 0)
    parts, selected, used = DocxParts(), [], 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as container:
            infos = {info.orig_filename: info for info in container.infolist()}
            require("word/document.xml" in infos and not infos["word/document.xml"].is_dir())

            def retain(name, limit, role):
                nonlocal used
                if name in parts:
                    return
                info = infos[name]
                require(not info.is_dir() and used + info.file_size <= MAX_SELECTED_BYTES)
                value = _inflate(raw, info, limit)
                used += len(value)
                parts[name] = value
                selected.append({"name": name, "role": role, "size_bytes": len(value), "sha256": sha256_bytes(value)})

            for name, expected in XML_PARTS.items():
                if name in infos:
                    retain(name, MAX_XML_BYTES, "xml")
                    xml_root(parts[name], expected)
            relmap = font_relationships(parts)
            if "word/fontTable.xml" in parts:
                fonts = xml_root(parts["word/fontTable.xml"], XML_PARTS["word/fontTable.xml"]).findall(f".//{{{WORD}}}font")
                require(len(fonts) <= MAX_FONTS)
                for font in fonts:
                    embedded = font.find(f"{{{WORD}}}embedRegular")
                    if embedded is None:
                        continue
                    target = font_part(relmap.get(embedded.get(f"{{{OFFICE_REL}}}id")))
                    if target in infos:
                        retain(target, MAX_FONT_BYTES, "regular-font")
    except (zipfile.BadZipFile, zlib.error, struct.error, ValueError, KeyError, RecursionError) as exc:
        raise ProvenanceError("invalid, unsupported, ambiguous, or excessive DOCX") from exc
    findings = list(archive["findings"])
    for row in archive["members"]:
        name = row["name"].lower()
        if name.endswith("vbaproject.bin") or name.startswith(("word/activex/", "word/embeddings/")):
            findings.append({"type": "docx_active_or_embedded_content", "severity": "high", "part": row["name"]})
    parts.intake = {
        "schema": SCHEMA, "source_sha256": sha256_bytes(raw), "source_size_bytes": len(raw),
        "member_count": archive["member_count"], "selected_parts": selected, "selected_bytes": used,
        "uninspected_member_count": archive["member_count"] - len(selected),
        "selected_part_size_crc_checked": True, "all_member_payloads_verified": False,
        "external_resources_loaded": False, "filesystem_extraction": False,
        "source_authenticity_verified": False, "complete_visible_rendering_verified": False,
        "collection_complete": None, "network_required": False, "findings": findings,
    }
    require(len(canonical_json_bytes(parts.intake)) <= MAX_OUTPUT_BYTES)
    return parts


def read_docx(path):
    return load_docx(read_archive(path))
