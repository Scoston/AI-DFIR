#!/usr/bin/env python3
"""
AI-DFIR v1.2 Evil Font / glyph-remapping forensics.

Defensive analyzer for DOCX/PDF/font artifacts. It never executes document
content and never modifies the source file.

Detection layers:
1. Tool-agnostic font geometry: many Unicode codepoints collapsing to the same
   glyph outline / blank glyph.
2. DOCX OOXML font embedding, per-character font switching, and machine-text
   vs font-name reconstructed visible-text disagreement.
3. EvilFontTool-specific low-confidence IOCs such as font-family suffixes that
   are UTF-8 hex bytes or " 0" stealth variants.
4. PDF embedded-font glyph-collapse and two-layer image + invisible-text signals.

The tool-specific IOCs are never required for the generic remapped-glyph finding.
"""
from __future__ import annotations
import argparse, hashlib, io, json, re, time
from collections import Counter, defaultdict
from pathlib import Path
import v17_docx_intake as docx_intake
import v17_html_intake as html_intake
import v17_content_intake as bounded_content
from v17_docx_font import analyze as bounded_docx_font
from v17_integrity import canonical_json_bytes

NS={
 "w":"http://schemas.openxmlformats.org/wordprocessingml/2006/main",
 "r":"http://schemas.openxmlformats.org/officeDocument/2006/relationships",
 "pr":"http://schemas.openxmlformats.org/package/2006/relationships",
}
HEX_SUFFIX=re.compile(r"^(?P<prefix>.+) (?P<suffix>0|[0-9a-fA-F]{2,8})$")

def sha256(data:bytes): return hashlib.sha256(data).hexdigest()

def font_name_suffix_visible(name):
    m=HEX_SUFFIX.match(name or "")
    if not m:return None
    suffix=m.group("suffix")
    if suffix=="0":return ""
    try:
        b=bytes.fromhex(suffix);s=b.decode("utf-8")
        return s if len(s)==1 else None
    except Exception:return None

def deobfuscate_odttf(data:bytes,font_key:str):
    """Reverse OOXML font obfuscation for defensive inspection."""
    key=(font_key or "").strip("{}").replace("-","")
    if len(key)!=32:return data
    try:guid=bytes.fromhex(key)
    except Exception:return data
    out=bytearray(data)
    for i in range(min(32,len(out))):
        out[i] ^= guid[15-(i%16)]
    return bytes(out)

def glyph_signature(glyphset,name):
    try:
        from fontTools.pens.recordingPen import RecordingPen
        pen=RecordingPen();glyphset[name].draw(pen)
        # RecordingPen output is deterministic enough for same-font equality.
        return hashlib.sha256(repr(pen.value).encode()).hexdigest(), len(pen.value)
    except Exception:
        return None,None

def analyze_font_bytes(data:bytes,label="font"):
    try:
        from fontTools.ttLib import TTFont
    except Exception as e:
        return {"label":label,"available":False,"error":"fontTools unavailable","findings":[]}
    findings=[]
    try:
        font=TTFont(io.BytesIO(data),lazy=False)
        cmap=font.getBestCmap() or {}
        glyphset=font.getGlyphSet()
        printable=[cp for cp in range(32,127) if cp in cmap]
        sigs=[];blank=0;widths=[]
        for cp in printable:
            gn=cmap[cp];sig,ncmd=glyph_signature(glyphset,gn)
            if sig:sigs.append((cp,gn,sig,ncmd))
            if ncmd==0:blank+=1
            try:widths.append(font["hmtx"].metrics[gn][0])
            except Exception:pass
        counts=Counter(x[2] for x in sigs)
        max_cluster=max(counts.values(),default=0)
        n=len(sigs)
        collapse=max_cluster/n if n else 0.0
        unique_ratio=len(counts)/n if n else 1.0
        blank_ratio=blank/max(1,len(printable))
        layout={tag:(tag in font) for tag in ("GSUB","GPOS","GDEF","kern")}
        names=[]
        if "name" in font:
            for rec in font["name"].names:
                if rec.nameID in (1,4,6):
                    try:nm=rec.toUnicode()
                    except Exception:continue
                    if nm not in names:names.append(nm)
        if n>=20 and collapse>=0.70:
            findings.append({"type":"font_glyph_outline_collapse","severity":"critical",
                             "printable_codepoints":n,"largest_identical_outline_cluster":max_cluster,
                             "collapse_ratio":round(collapse,4),"unique_outline_ratio":round(unique_ratio,4)})
        if len(printable)>=20 and blank_ratio>=0.70:
            findings.append({"type":"font_mass_blank_glyph_mapping","severity":"critical",
                             "printable_codepoints":len(printable),"blank_ratio":round(blank_ratio,4)})
        if n>=20 and collapse>=0.70 and not any(layout.values()):
            findings.append({"type":"remapped_font_with_layout_tables_removed","severity":"high",
                             "layout_tables":layout})
        return {"label":label,"available":True,"sha256":sha256(data),"font_names":names,
                "printable_codepoints":len(printable),"glyph_collapse_ratio":round(collapse,4),
                "blank_ratio":round(blank_ratio,4),"unique_outline_ratio":round(unique_ratio,4),
                "layout_tables":layout,"findings":findings}
    except Exception as e:
        return {"label":label,"available":True,"sha256":sha256(data),"error":repr(e),"findings":[]}

def docx_parts(path):
    return docx_intake.read_docx(path)

def parse_docx_runs(parts):
    xml=docx_intake.xml_root(parts["word/document.xml"],docx_intake.XML_PARTS["word/document.xml"])
    runs=[];machine=[]
    for r in xml.findall(".//w:r",NS):
        texts=[t.text or "" for t in r.findall(".//w:t",NS)]
        text="".join(texts)
        if not text:continue
        rf=r.find("./w:rPr/w:rFonts",NS)
        font=None
        if rf is not None:
            font=rf.attrib.get("{%s}ascii"%NS["w"]) or rf.attrib.get("{%s}hAnsi"%NS["w"])
        runs.append({"text":text,"font":font})
        machine.append(text)
    return runs,"".join(machine)

def embedded_docx_fonts(parts):
    out=[];findings=[]
    ft=parts.get("word/fontTable.xml")
    if not ft:return out,findings
    root=docx_intake.xml_root(ft,docx_intake.XML_PARTS["word/fontTable.xml"])
    relmap=docx_intake.font_relationships(parts)
    fonts=root.findall(".//w:font",NS)
    docx_intake.require(len(fonts)<=docx_intake.MAX_FONTS)
    cache={};deadline=time.monotonic()+20
    for f in fonts:
        name=f.attrib.get("{%s}name"%NS["w"])
        emb=f.find("w:embedRegular",NS)
        if emb is None:continue
        rid=emb.attrib.get("{%s}id"%NS["r"]);key=emb.attrib.get("{%s}fontKey"%NS["w"])
        relationship=relmap.get(rid)
        target=relationship["target"] if relationship else None
        part=docx_intake.font_part(relationship)
        raw=parts.get(part) if part else None
        item={"font_name":name,"relationship_id":rid,"target":target,"font_key":key,
              "font_sha256":sha256(raw) if raw else None}
        if raw:
            decoded=deobfuscate_odttf(raw,key)
            digest=sha256(decoded)
            key_ok=not key or re.fullmatch(r"[0-9a-fA-F]{32}",key.strip("{}").replace("-",""))
            if key_ok and digest not in cache and time.monotonic()<deadline:
                cache[digest]=bounded_docx_font(decoded)
            result=cache.get(digest) if key_ok else None
            item["decoded_font"]=result or {"available":False,"error":"embedded font analysis unavailable, unsupported, or resource-limited","findings":[]}
            if item["decoded_font"].get("available") is not True:
                findings.append({"type":"docx_font_analysis_incomplete","severity":"high","font_name":name})
        else:
            findings.append({"type":"docx_font_reference_unresolved","severity":"high","font_name":name,
                             "note":"Missing, external, or unsupported regular-font relationship; no external resource was loaded."})
        out.append(item)
    if len(out)>=8:
        findings.append({"type":"unusually_many_embedded_fonts","severity":"high","count":len(out)})
    return out,findings

def analyze_docx(path):
    parts=docx_parts(path);findings=list(parts.intake["findings"])
    runs,machine=parse_docx_runs(parts)
    embedded,ef=embedded_docx_fonts(parts);findings+=ef
    fonts=[r["font"] for r in runs if r.get("font")]
    one_char=sum(1 for r in runs if len(r["text"])==1)
    if len(runs)>=20 and one_char/len(runs)>=0.70 and len(set(fonts))>=8:
        findings.append({"type":"per_character_font_switching","severity":"critical",
                         "run_count":len(runs),"one_char_run_ratio":round(one_char/len(runs),4),
                         "unique_fonts":len(set(fonts))})
    reconstructed=[];mapped=0;stealth=0;mismatch=0
    for r in runs:
        vis=font_name_suffix_visible(r.get("font"))
        for ch in r["text"]:
            if vis is None:
                reconstructed.append(ch)
            elif vis=="":
                stealth+=1;mapped+=1
            else:
                reconstructed.append(vis);mapped+=1
                if ch!=vis:mismatch+=1
    visible="".join(reconstructed)
    if mapped>=10 and mismatch/max(1,mapped-stealth)>=0.30:
        findings.append({"type":"machine_visible_text_disagreement_via_font_mapping","severity":"critical",
                         "mapped_characters":mapped,"stealth_characters":stealth,
                         "disagreement_ratio":round(mismatch/max(1,mapped-stealth),4),
                         "machine_text_sha256":hashlib.sha256(machine.encode()).hexdigest(),
                         "reconstructed_visible_text_sha256":hashlib.sha256(visible.encode()).hexdigest()})
    if stealth:
        findings.append({"type":"stealth_font_machine_only_characters","severity":"critical","count":stealth})
    tool_ioc_fonts=[x for x in set(fonts) if font_name_suffix_visible(x) is not None]
    if len(tool_ioc_fonts)>=8:
        findings.append({"type":"evilfonttool_style_font_family_pattern","severity":"high",
                         "font_count":len(tool_ioc_fonts),
                         "note":"Tool-specific IOC; generic glyph/remapping findings carry greater evidentiary weight."})
    for e in embedded:
        findings += [{**x,"font_name":e["font_name"]} for x in (e.get("decoded_font") or {}).get("findings",[])]
    report={"schema":"ai-dfir/evil-font-docx-analysis/v1.2","path":str(Path(path).absolute()),
            "intake":parts.intake,"independent_rendering_verified":False,
            "source_authenticity_verified":False,"collection_complete":None,
            "machine_text_sha256":hashlib.sha256(machine.encode()).hexdigest(),
            "tool_reconstructed_visible_text_sha256":hashlib.sha256(visible.encode()).hexdigest(),
            "run_count":len(runs),"unique_run_fonts":len(set(fonts)),"embedded_fonts":embedded,
            "findings":findings,
            "note":"Reconstructed visible text uses only a tool-specific hex-suffix signal; generic glyph-collapse detection does not depend on EvilFontTool naming."}
    docx_intake.require(len(canonical_json_bytes(report))<=docx_intake.MAX_OUTPUT_BYTES)
    return report


def analyze_html(path, *, captured=None):
    """Static bounded HTML/CSS only; no JavaScript or independent rendering."""
    p=Path(path).absolute()
    captured=html_intake.capture(p) if captured is None else captured
    text=captured["text"]
    findings=list(captured["findings"]);families=[];machine=[];reconstructed=[];mapped=stealth=mismatch=styled_chars=0
    font_faces=captured["font_faces"]

    # EvilFont-style HTML uses single-character spans with a font family whose
    # suffix encodes the human-visible character; family suffix 0 hides
    # machine-only characters.
    for span in captured["spans"]:
        body=span["text"];family=span["font"]
        machine.append(body)
        if family:families.append(family)
        vis=font_name_suffix_visible(family)
        if len(body)==1 and family:styled_chars+=1
        for ch in body:
            if vis is None:reconstructed.append(ch)
            elif vis=="":
                mapped+=1;stealth+=1
            else:
                reconstructed.append(vis);mapped+=1
                if ch!=vis:mismatch+=1

    machine_text="".join(machine)
    visible_text="".join(reconstructed)
    suffix_families=[f for f in set(families) if font_name_suffix_visible(f) is not None]
    if styled_chars>=20 and len(suffix_families)>=8:
        findings.append({"type":"html_per_character_font_switching","severity":"critical",
                         "styled_single_character_spans":styled_chars,
                         "unique_encoded_font_families":len(suffix_families)})
    denom=max(1,mapped-stealth)
    if mapped>=10 and mismatch/denom>=0.30:
        findings.append({"type":"machine_visible_text_disagreement_via_font_mapping","severity":"critical",
                         "mapped_characters":mapped,"stealth_characters":stealth,
                         "disagreement_ratio":round(mismatch/denom,4),
                         "machine_text_sha256":hashlib.sha256(machine_text.encode()).hexdigest(),
                         "reconstructed_visible_text_sha256":hashlib.sha256(visible_text.encode()).hexdigest()})
    if stealth:
        findings.append({"type":"stealth_font_machine_only_characters","severity":"critical","count":stealth})
    if len(suffix_families)>=8:
        findings.append({"type":"evilfonttool_style_font_family_pattern","severity":"high",
                         "font_count":len(suffix_families),
                         "note":"Tool-specific IOC; generic glyph/remapping findings carry greater evidentiary weight."})
    for face in font_faces:
        findings += [{**x,"font_family":face.get("font_family"),"font_file":face.get("font_file")}
                     for x in (face.get("font_analysis") or {}).get("findings",[])]

    report={"schema":"ai-dfir/evil-font-html-analysis/v1.2","path":str(p),
            "html_sha256":hashlib.sha256(captured["raw"]).hexdigest(),
            "decoded_html_sha256":hashlib.sha256(text.encode()).hexdigest(),
            "intake":captured["intake"],"independent_rendering_verified":False,
            "font_faces":font_faces,"unique_run_fonts":len(set(families)),
            "machine_text_sha256":hashlib.sha256(machine_text.encode()).hexdigest() if machine_text else None,
            "tool_reconstructed_visible_text_sha256":hashlib.sha256(visible_text.encode()).hexdigest() if visible_text else None,
            "findings":findings,
            "note":"Static span and top-level font-face observations only; no CSS cascade, JavaScript, or independent rendering."}
    html_intake.require(len(canonical_json_bytes(report))<=html_intake.MAX_OUTPUT_BYTES)
    return report

def analyze_pdf(path):
    return bounded_content.pdf_file(path)

def main():
    ap=argparse.ArgumentParser();ap.add_argument("path");ap.add_argument("--out")
    a=ap.parse_args();ext=Path(a.path).suffix.lower()
    try:
        if ext==".docx":obj=analyze_docx(a.path)
        elif ext in (".html",".htm"):obj=analyze_html(a.path)
        elif ext==".pdf":obj=analyze_pdf(a.path)
        elif ext in (".ttf",".otf",".woff",".woff2"):
            obj={"schema":"ai-dfir/font-analysis/v1.2","font":bounded_content.font_file(a.path)}
        else:raise ValueError("unsupported document")
        bounded_content.output_report(obj,a.out)
    except KeyboardInterrupt:raise SystemExit(130)
    except Exception:
        print(json.dumps({"status":"FAIL","error":"invalid, unsupported, excessive document or unavailable output"}))
        raise SystemExit(1)
if __name__=="__main__":main()
