"""Bounded static ZIP32 and TAR metadata inspection; never extract members."""
from __future__ import annotations

import bz2
import io
import lzma
import os
import posixpath
import re
import stat
import struct
import tarfile
import unicodedata
import zipfile
import zlib
from pathlib import Path

from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_provenance import ProvenanceError

SCHEMA = "ai-dfir/bounded-archive-intake/v1.7"
FORMATS = ("zip", "tar", "tar-gzip", "tar-bzip2", "tar-xz")
MAX_INPUT_BYTES = 16 * 1024**2
MAX_TAR_BYTES = 32 * 1024**2
MAX_MEMBERS = 4096
MAX_HEADERS = 8192
MAX_MEMBER_BYTES = 32 * 1024**2
MAX_LOGICAL_BYTES = 128 * 1024**2
MAX_NAME_BYTES = 4096
MAX_NAMES_BYTES = 1024**2
MAX_PAX_BYTES = 64 * 1024
MAX_PAX_RECORDS = 256
MAX_EXTENSION_CHAIN = 8
MAX_OUTPUT_BYTES = 8 * 1024**2
MAX_EXPANSION_RATIO = 1000
LZMA_MEMORY_LIMIT = 64 * 1024**2
CONTROL_NAMES = frozenset({"claude.md", "claude.local.md", "agents.md", ".mcp.json", "package.json", "makefile"})
CONTROL_DIRS = frozenset({".cursor", ".claude", ".vscode", ".devcontainer", "skills", "tools"})
NESTED_SUFFIXES = (".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".whl", ".vsix")


def _require(condition, reason):
    if not condition:
        raise ProvenanceError(reason)


def read_archive(path):
    fd = os.open(Path(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_INPUT_BYTES,
                 "archive must be a bounded regular file")
        raw = stream.read(MAX_INPUT_BYTES + 1)
    _require(0 < len(raw) <= MAX_INPUT_BYTES, "archive exceeds input byte limit")
    return raw


def detect_format(raw):
    if raw.startswith((b"PK\x03\x04", b"PK\x05\x06")): return "zip"
    if raw.startswith(b"\x1f\x8b"): return "tar-gzip"
    if raw.startswith(b"BZh"): return "tar-bzip2"
    if raw.startswith(b"\xfd7zXZ\x00"): return "tar-xz"
    return "tar"


def name_risks(name):
    """Literal names stay data; portable ambiguity is a conservative finding."""
    clean = name.replace("\\", "/")
    parts = clean.split("/")
    folded = [part.casefold() for part in parts]
    absolute = clean.startswith("/") or re.match(r"^[A-Za-z]:", clean) is not None
    traversal = ".." in parts
    control = (folded[-1] in CONTROL_NAMES or any(part in CONTROL_DIRS for part in folded)
               or ".github/workflows/" in clean.casefold()
               or ".git/hooks/" in clean.casefold()
               or clean.casefold().endswith(".github/copilot-instructions.md"))
    nested = clean.casefold().endswith(NESTED_SUFFIXES)
    ambiguous = (not clean or any(ord(c) < 32 or ord(c) == 127 for c in clean)
                 or any(p in {"", "."} for p in parts[:-1])
                 or any(p.endswith((".", " ")) for p in parts if p)
                 or any(re.fullmatch(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p) for p in folded))
    alias = "/".join(unicodedata.normalize("NFC", p).casefold().rstrip(" .") for p in parts)
    alias = posixpath.normpath(alias)
    return absolute, traversal, bool(control), nested, ambiguous, alias


def _zip_rows(raw):
    # Check and count the complete central directory before ZipFile allocates
    # member objects. EOCD's declared count alone is not a resource bound.
    end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
    _require(end >= 0 and end + 22 <= len(raw), "missing ZIP end record")
    _, disk, cd_disk, count_disk, count, size, offset, comment = struct.unpack_from("<4s4H2IH", raw, end)
    _require(disk == cd_disk == 0 and count_disk == count and count != 65535
             and size != 0xffffffff and offset != 0xffffffff,
             "split and ZIP64 archives are outside the bounded ZIP32 profile")
    _require(count <= MAX_MEMBERS and end + 22 + comment == len(raw)
             and offset + size == end, "invalid or excessive ZIP directory")
    cursor, actual = offset, 0
    while cursor < end:
        _require(cursor + 46 <= end and raw[cursor:cursor + 4] == b"PK\x01\x02", "invalid ZIP directory entry")
        name_len, extra_len, comment_len, member_disk = struct.unpack_from("<4H", raw, cursor + 28)
        _require(member_disk == 0 and name_len <= MAX_NAME_BYTES, "unsupported ZIP entry scope or name")
        stop = cursor + 46 + name_len + extra_len + comment_len
        _require(stop <= end, "truncated ZIP directory entry")
        extra, extra_end = cursor + 46 + name_len, cursor + 46 + name_len + extra_len
        while extra < extra_end:
            _require(extra + 4 <= extra_end, "truncated ZIP extra field")
            tag, length = struct.unpack_from("<HH", raw, extra)
            _require(tag != 1 and extra + 4 + length <= extra_end, "ZIP64 or malformed ZIP extra field")
            extra += 4 + length
        actual += 1
        _require(actual <= MAX_MEMBERS, "ZIP member limit exceeded")
        cursor = stop
    _require(actual == count and cursor == end, "ZIP directory count mismatch")
    intervals = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        _require(len(archive.infolist()) == count, "ZIP directory interpretation mismatch")
        rows = []
        for info in archive.infolist():
            _require(0 <= info.header_offset < offset and info.header_offset + 30 <= offset
                     and raw[info.header_offset:info.header_offset + 4] == b"PK\x03\x04",
                     "invalid ZIP local header reference")
            local_name, local_extra = struct.unpack_from("<HH", raw, info.header_offset + 26)
            data_start = info.header_offset + 30 + local_name + local_extra
            _require(data_start + info.compress_size <= offset,
                     "ZIP declared payload extends into directory")
            local_flags, local_method = struct.unpack_from("<HH", raw, info.header_offset + 6)
            local_text = raw[info.header_offset + 30:info.header_offset + 30 + local_name].decode(
                "utf-8" if local_flags & 0x800 else "cp437")
            _require(local_flags == info.flag_bits and local_method == info.compress_type
                     and local_text == info.orig_filename, "ZIP local and central metadata disagree")
            if not local_flags & 8:
                local_crc, compressed, expanded = struct.unpack_from("<III", raw, info.header_offset + 14)
                _require((local_crc, compressed, expanded) == (info.CRC, info.compress_size, info.file_size),
                         "ZIP local and central sizes or CRC disagree")
            extra = info.header_offset + 30 + local_name
            while extra < data_start:
                _require(extra + 4 <= data_start, "truncated local ZIP extra field")
                tag, length = struct.unpack_from("<HH", raw, extra)
                _require(tag != 1 and extra + 4 + length <= data_start, "ZIP64 or malformed local ZIP extra field")
                extra += 4 + length
            intervals.append((info.header_offset, data_start + info.compress_size))
            mode = (info.external_attr >> 16) & 0xffff
            rows.append({"name": info.orig_filename, "size": info.file_size, "compressed_size": info.compress_size,
                         "compression_ratio": round(info.file_size / max(1, info.compress_size), 2) if info.file_size else 1.0,
                         "is_symlink": stat.S_ISLNK(mode), "is_hardlink": False, "linkname": None,
                         "is_directory": info.is_dir(), "special_type": stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK},
                         "encrypted": bool(info.flag_bits & 1), "compression_method": info.compress_type})
    intervals.sort()
    _require((not intervals and offset == 0) or (intervals and intervals[0][0] == 0), "prefixed ZIP is outside this profile")
    _require(all(first[1] <= second[0] for first, second in zip(intervals, intervals[1:])), "overlapping ZIP members")
    return rows, actual


def _tar_bytes(raw, input_format):
    if input_format == "tar":
        _require(len(raw) <= MAX_TAR_BYTES, "TAR stream exceeds byte limit")
        return raw
    if input_format == "tar-gzip":
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        result = decoder.decompress(raw, MAX_TAR_BYTES + 1)
    elif input_format == "tar-bzip2":
        decoder = bz2.BZ2Decompressor()
        result = decoder.decompress(raw, max_length=MAX_TAR_BYTES + 1)
    else:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=LZMA_MEMORY_LIMIT)
        result = decoder.decompress(raw, max_length=MAX_TAR_BYTES + 1)
    _require(len(result) <= MAX_TAR_BYTES and decoder.eof and not decoder.unused_data,
             "truncated, concatenated, trailing, or excessive compressed TAR stream")
    _require(len(result) <= MAX_EXPANSION_RATIO * len(raw), "compressed TAR expansion ratio exceeds limit")
    return result


def _pax(raw):
    _require(len(raw) <= MAX_PAX_BYTES, "PAX header exceeds byte limit")
    cursor, fields = 0, set()
    while cursor < len(raw):
        space = raw.find(b" ", cursor, min(len(raw), cursor + 12))
        _require(space > cursor and raw[cursor:space].isdigit(), "invalid PAX record length")
        length = int(raw[cursor:space])
        _require(length >= 5 and cursor + length <= len(raw) and raw[cursor + length - 1] == 10,
                 "invalid PAX record framing")
        key, equals, value = raw[space + 1:cursor + length - 1].partition(b"=")
        _require(bool(key) and equals == b"=" and len(key) <= 256 and key not in fields,
                 "invalid or duplicate PAX key")
        _require(key not in {b"size", b"SCHILY.realsize", b"SCHILY.filetype"}
                 and not key.startswith(b"GNU.sparse.") and not (key == b"hdrcharset" and value == b"BINARY"),
                 "PAX size, sparse, and binary-name overrides are outside this profile")
        key.decode("utf-8"); value.decode("utf-8")
        fields.add(key)
        _require(len(fields) <= MAX_PAX_RECORDS, "PAX record limit exceeded")
        cursor += length


def _tar_preflight(raw):
    _require(len(raw) >= 1024 and len(raw) % 512 == 0, "TAR requires complete blocks and terminator")
    cursor, headers, extensions, members = 0, 0, 0, 0
    extension_types = {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                       tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}
    while cursor + 512 <= len(raw):
        block = raw[cursor:cursor + 512]
        if block == bytes(512):
            _require(cursor + 1024 <= len(raw) and not any(raw[cursor:]) and not extensions,
                     "TAR has missing terminator, trailing data, or orphan extensions")
            return headers, members
        info = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        headers += 1
        _require(headers <= MAX_HEADERS and 0 <= info.size <= MAX_MEMBER_BYTES,
                 "TAR header or member size limit exceeded")
        _require(info.type != tarfile.GNUTYPE_SPARSE, "GNU sparse TAR is outside this profile")
        stop = cursor + 512 + ((info.size + 511) // 512) * 512
        _require(stop <= len(raw), "TAR member extends beyond retained stream")
        if info.type in extension_types:
            extensions += 1
            _require(extensions <= MAX_EXTENSION_CHAIN, "TAR extension chain exceeds limit")
            data = raw[cursor + 512:cursor + 512 + info.size]
            if info.type in {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE}:
                _pax(data)
            else:
                _require(0 < len(data) <= MAX_NAME_BYTES + 1 and data.endswith(b"\0")
                         and b"\0" not in data[:-1], "invalid or excessive GNU long name")
                data[:-1].decode("utf-8")
        else:
            extensions = 0
            members += 1
            _require(members <= MAX_MEMBERS and (info.isfile() or info.size == 0),
                     "excessive TAR members or data on a non-file member")
        cursor = stop
    raise ProvenanceError("TAR end marker missing")


def _tar_rows(raw):
    headers, members = _tar_preflight(raw)
    rows = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", encoding="utf-8", errors="strict") as archive:
        for info in archive:
            _require(len(rows) < MAX_MEMBERS and not info.issparse(), "excessive or sparse TAR members")
            rows.append({"name": info.name, "size": info.size, "is_symlink": info.issym(),
                         "is_hardlink": info.islnk(), "linkname": info.linkname if info.issym() or info.islnk() else None,
                         "is_directory": info.isdir(), "special_type": not (info.isfile() or info.isdir() or info.issym() or info.islnk())})
    _require(len(rows) == members, "TAR header interpretation mismatch")
    return rows, headers


def inspect_archive(raw, *, input_format):
    _require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_INPUT_BYTES, "archive requires bounded immutable bytes")
    _require(isinstance(input_format, str) and input_format in FORMATS, "unsupported archive format")
    try:
        stream = raw if input_format == "zip" else _tar_bytes(raw, input_format)
        rows, headers = _zip_rows(stream) if input_format == "zip" else _tar_rows(stream)
        findings, aliases, names_bytes, logical_bytes = [], {}, 0, 0
        for ordinal, row in enumerate(rows):
            name = row["name"]
            _require(isinstance(name, str) and len(name.encode("utf-8")) <= MAX_NAME_BYTES, "member name exceeds limit")
            names_bytes += len(name.encode("utf-8"))
            link = row["linkname"]
            if link is not None:
                _require(len(link.encode("utf-8")) <= MAX_NAME_BYTES, "link name exceeds limit")
                names_bytes += len(link.encode("utf-8"))
            logical_bytes += row["size"]
            _require(type(row["size"]) is int and 0 <= row["size"] <= MAX_MEMBER_BYTES
                     and logical_bytes <= MAX_LOGICAL_BYTES and names_bytes <= MAX_NAMES_BYTES,
                     "archive logical size or names budget exceeded")
            absolute, traversal, control, nested, ambiguous, alias = name_risks(name)
            row.update(ordinal=ordinal, control_surface=control, nested_archive=nested)
            def finding(kind, severity):
                findings.append({"type": kind, "severity": severity, "member": row})
            if absolute or traversal: finding("archive_path_escape", "critical")
            if ambiguous: finding("archive_ambiguous_member_path", "high")
            if alias in aliases: finding("archive_member_path_collision", "high")
            aliases.setdefault(alias, ordinal)
            if row["is_symlink"] or row["is_hardlink"]: finding("archive_symlink_member", "high")
            if link is not None and any(name_risks(link)[i] for i in (0, 1, 4)):
                finding("archive_link_target_escape_or_ambiguity", "critical")
            if row["special_type"]: finding("archive_special_member", "high")
            if row.get("encrypted"): finding("archive_encrypted_member", "high")
            if row.get("compression_ratio", 0) >= 100 and row["size"] >= 1024**2:
                finding("archive_extreme_compression_ratio", "high")
            if control: finding("archive_contains_agent_autoload_control", "high")
            if nested: finding("archive_contains_nested_archive", "medium")
        result = {"schema": SCHEMA, "input_format": input_format, "source_sha256": sha256_bytes(raw),
                  "source_size_bytes": len(raw), "container_stream_bytes": len(stream), "header_count": headers,
                  "member_count": len(rows), "declared_logical_bytes": logical_bytes, "names_bytes": names_bytes,
                  "members": rows, "findings": findings, "metadata_only": True, "members_extracted": False,
                  "member_payload_integrity_verified": False, "source_authenticity_verified": False,
                  "archive_safety_verified": False, "extraction_authorized": False, "collection_complete": None,
                  "network_required": False}
        _require(len(canonical_json_bytes(result)) <= MAX_OUTPUT_BYTES, "archive report exceeds output limit")
        return result
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError, OSError, NotImplementedError, struct.error,
            tarfile.TarError, zipfile.BadZipFile, zlib.error, lzma.LZMAError) as exc:
        raise ProvenanceError("invalid, unsupported, ambiguous, or excessive archive metadata") from exc
