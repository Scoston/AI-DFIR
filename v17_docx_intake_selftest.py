#!/usr/bin/env python3
"""Synthetic selected-part DOCX acceptance/rejection checks; not a renderer."""
import io
import json
import stat
import zipfile
from contextlib import ExitStack
from unittest.mock import patch

import v17_docx_intake as intake
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_provenance import ProvenanceError

DOCUMENT = (f'<w:document xmlns:w="{intake.WORD}"><w:body><w:p><w:r><w:t>'
            'Synthetic evidence</w:t></w:r></w:p></w:body></w:document>').encode()


def package(parts=None, compression=zipfile.ZIP_DEFLATED):
    if parts is None:
        parts = {"word/document.xml": DOCUMENT, "word/media/uninspected.bin": b"synthetic media"}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as container:
        for name, raw in parts.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.compress_type = compression
            container.writestr(info, raw)
    return stream.getvalue()


def font_table(count=1, key=None):
    key_attr = '' if key is None else f' w:fontKey="{key}"'
    body = ''.join(f'<w:font w:name="Synthetic {i}"><w:embedRegular r:id="r{i}"{key_attr}/></w:font>' for i in range(count))
    return f'<w:fonts xmlns:w="{intake.WORD}" xmlns:r="{intake.OFFICE_REL}">{body}</w:fonts>'.encode()


def relationships(target="fonts/synthetic.ttf", count=1, mode="Internal", kind=None):
    kind = kind or intake.OFFICE_REL + "/font"
    body = ''.join(f'<Relationship Id="r{i}" Target="{target}" TargetMode="{mode}" Type="{kind}"/>' for i in range(count))
    return f'<Relationships xmlns="{intake.REL}">{body}</Relationships>'.encode()


def synthetic_font():
    from fontTools.fontBuilder import FontBuilder
    from fontTools.pens.ttGlyphPen import TTGlyphPen
    builder = FontBuilder(1000, isTTF=True)
    builder.setupGlyphOrder([".notdef", "box"])
    builder.setupCharacterMap({cp: "box" for cp in range(32, 127)})
    empty, box = TTGlyphPen(None), TTGlyphPen(None)
    box.moveTo((100, 100)); box.lineTo((500, 100)); box.lineTo((500, 700)); box.lineTo((100, 700)); box.closePath()
    builder.setupGlyf({".notdef": empty.glyph(), "box": box.glyph()})
    builder.setupHorizontalMetrics({".notdef": (600, 0), "box": (600, 100)})
    builder.setupHorizontalHeader(ascent=800, descent=-200)
    builder.setupNameTable({"familyName": "Synthetic", "styleName": "Regular", "uniqueFontIdentifier": "Synthetic-Regular",
                           "fullName": "Synthetic Regular", "psName": "Synthetic-Regular"})
    builder.setupOS2(sTypoAscender=800, sTypoDescender=-200, usWinAscent=800, usWinDescent=200)
    builder.setupPost(); builder.setupMaxp()
    builder.font["head"].created = builder.font["head"].modified = 2082844800
    builder.font.recalcTimestamp = False
    output = io.BytesIO(); builder.save(output)
    return output.getvalue()


def check():
    seeds = [package(compression=method) for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)]
    hostile = [b"", seeds[1][:-1], package({"word/document.xml": b"<wrong/>"}),
               package({"word/document.xml": b'<!DOCTYPE x [<!ENTITY a "x">]><x>&a;</x>'}),
               package({"word/document.xml": DOCUMENT, "../escape": b"x"}),
               package({"word/document.xml": DOCUMENT, "WORD/DOCUMENT.XML": DOCUMENT})]
    rows = []
    with ExitStack() as guards:
        for name in ("open", "extract", "extractall"):
            guards.enter_context(patch.object(zipfile.ZipFile, name, side_effect=AssertionError("member I/O forbidden")))
        for raw in seeds:
            parts = intake.load_docx(raw)
            assert parts.intake == intake.load_docx(raw).intake and parts["word/document.xml"] == DOCUMENT
            assert parts.intake["source_sha256"] == sha256_bytes(raw)
            assert parts.intake["selected_part_size_crc_checked"] is True
            assert parts.intake["all_member_payloads_verified"] is False
            rows.append({"input_sha256": sha256_bytes(raw), "output_sha256": sha256_bytes(canonical_json_bytes(parts.intake))})
        for raw in hostile:
            try:
                intake.load_docx(raw)
            except ProvenanceError:
                continue
            raise AssertionError("invalid DOCX accepted")
    return {"status": "PASS", "valid_packages": len(seeds), "invalid_packages_rejected": len(hostile),
            "receipt_manifest_sha256": sha256_bytes(canonical_json_bytes(rows)),
            "network_required": False, "independent_rendering_verified": False}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
