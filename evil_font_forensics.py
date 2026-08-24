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
import argparse, hashlib, io, json, re, tempfile, zipfile
from collections import Counter, defaultdict
from pathlib import Path
from xml.etree import ElementTree as ET

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
    with zipfile.ZipFile(path) as z:
        return {n:z.read(n) for n in z.namelist()}

def parse_docx_runs(parts):
    xml=ET.fromstring(parts.get("word/document.xml",b"<x/>"))
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
    try:root=ET.fromstring(ft)
    except Exception:return out,findings
    relmap={}
    rels=parts.get("word/_rels/fontTable.xml.rels")
    if rels:
        try:
            rr=ET.fromstring(rels)
            for rel in rr:
                relmap[rel.attrib.get("Id")]=rel.attrib.get("Target")
        except Exception:pass
    for f in root.findall(".//w:font",NS):
        name=f.attrib.get("{%s}name"%NS["w"])
        emb=f.find("w:embedRegular",NS)
        if emb is None:continue
        rid=emb.attrib.get("{%s}id"%NS["r"]);key=emb.attrib.get("{%s}fontKey"%NS["w"])
        target=relmap.get(rid)
        raw=parts.get("word/"+target) if target else None
        item={"font_name":name,"relationship_id":rid,"target":target,"font_key":key,
              "font_sha256":sha256(raw) if raw else None}
        if raw:
            decoded=deobfuscate_odttf(raw,key)
            item["decoded_font"]=analyze_font_bytes(decoded,name or target)
        out.append(item)
    if len(out)>=8:
        findings.append({"type":"unusually_many_embedded_fonts","severity":"high","count":len(out)})
    return out,findings

def analyze_docx(path):
    parts=docx_parts(path);findings=[]
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
    return {"schema":"ai-dfir/evil-font-docx-analysis/v1.2","path":str(Path(path).resolve()),
            "machine_text_sha256":hashlib.sha256(machine.encode()).hexdigest(),
            "tool_reconstructed_visible_text_sha256":hashlib.sha256(visible.encode()).hexdigest(),
            "run_count":len(runs),"unique_run_fonts":len(set(fonts)),"embedded_fonts":embedded,
            "findings":findings,
            "note":"Reconstructed visible text uses only a tool-specific hex-suffix signal; generic glyph-collapse detection does not depend on EvilFontTool naming."}


def _css_font_faces(css_text,base_dir:Path):
    faces=[]
    block_re=re.compile(r"@font-face\s*\{(.*?)\}",re.I|re.S)
    fam_re=re.compile(r"font-family\s*:\s*['\"]?([^;'\"\}]+)",re.I)
    src_re=re.compile(r"url\((?:['\"])?([^)'\"\s]+)",re.I)
    for b in block_re.findall(css_text or ""):
        fm=fam_re.search(b);sm=src_re.search(b)
        if not fm:continue
        family=fm.group(1).strip()
        src=sm.group(1).strip() if sm else None
        item={"font_family":family,"src":src}
        if src and not re.match(r"^[a-z]+://",src,re.I) and not src.startswith("data:"):
            fp=(base_dir/src).resolve()
            try:
                if fp.exists() and fp.is_file():
                    raw=fp.read_bytes()
                    item["font_file"]=str(fp)
                    item["font_analysis"]=analyze_font_bytes(raw,fp.name)
            except Exception as e:item["font_error"]=repr(e)
        faces.append(item)
    return faces

def analyze_html(path):
    """
    Detect EvilFont-style HTML and generic remapped-font abuse.

    The implementation parses static HTML/CSS only. It never loads remote
    resources, runs JavaScript, or renders the page.
    """
    p=Path(path).resolve();text=p.read_text(encoding="utf-8",errors="replace")
    findings=[];families=[];machine=[];reconstructed=[];mapped=stealth=mismatch=styled_chars=0

    # Collect inline styles and linked local CSS only.
    css_chunks=[]
    css_chunks += re.findall(r"<style\b[^>]*>(.*?)</style>",text,re.I|re.S)
    for href in re.findall(r"<link\b[^>]*href=['\"]([^'\"]+\.css(?:\?[^'\"]*)?)['\"][^>]*>",text,re.I|re.S):
        if re.match(r"^[a-z]+://",href,re.I):continue
        css_path=(p.parent/href.split("?",1)[0]).resolve()
        try:
            if css_path.exists() and css_path.is_file():css_chunks.append(css_path.read_text(encoding="utf-8",errors="replace"))
        except Exception:pass

    font_faces=[]
    for css in css_chunks:
        font_faces += _css_font_faces(css,p.parent)

    # EvilFont-style HTML uses single-character spans with a font family whose
    # suffix encodes the human-visible character; family suffix 0 hides
    # machine-only characters.
    span_re=re.compile(r"<span\b([^>]*)>(.*?)</span>",re.I|re.S)
    fam_attr=re.compile(r"font-family\s*:\s*['\"]?([^;'\"\}]+)",re.I)
    tag_strip=re.compile(r"<[^>]+>")
    for attrs,body in span_re.findall(text):
        body=tag_strip.sub("",body)
        body=__import__("html").unescape(body)
        machine.append(body)
        fm=fam_attr.search(attrs)
        family=fm.group(1).strip() if fm else None
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

    return {"schema":"ai-dfir/evil-font-html-analysis/v1.2","path":str(p),
            "html_sha256":hashlib.sha256(text.encode()).hexdigest(),
            "font_faces":font_faces,"unique_run_fonts":len(set(families)),
            "machine_text_sha256":hashlib.sha256(machine_text.encode()).hexdigest() if machine_text else None,
            "tool_reconstructed_visible_text_sha256":hashlib.sha256(visible_text.encode()).hexdigest() if visible_text else None,
            "findings":findings,
            "note":"Static analysis only; remote fonts/resources are not fetched."}

def analyze_pdf(path):
    findings=[];fonts=[];text=""
    raw=Path(path).read_bytes()
    if re.search(rb"(?<!\d)3\s+Tr\b",raw):
        findings.append({"type":"pdf_invisible_text_render_mode_3","severity":"critical"})
    image_markers=len(re.findall(rb"/Subtype\s*/Image\b",raw))
    try:
        import fitz
        doc=fitz.open(path);pages=len(doc)
        for page in doc:
            text += page.get_text()
            for f in page.get_fonts(full=True):
                xref=f[0]
                if not xref:continue
                if any(x.get("xref")==xref for x in fonts):continue
                try:
                    name,ext,ftype,content=doc.extract_font(xref)
                    item={"xref":xref,"name":name,"ext":ext,"type":ftype,
                          "analysis":analyze_font_bytes(content,name)}
                    fonts.append(item)
                    findings += [{**x,"font_name":name,"font_xref":xref} for x in item["analysis"].get("findings",[])]
                except Exception as e:
                    fonts.append({"xref":xref,"error":repr(e)})
        if pages and image_markers>=pages and len(text.strip())>=50:
            findings.append({"type":"pdf_image_dominant_with_machine_text_layer","severity":"high",
                             "pages":pages,"image_markers":image_markers,"extracted_text_chars":len(text)})
    except Exception as e:
        pages=None
    return {"schema":"ai-dfir/evil-font-pdf-analysis/v1.2","path":str(Path(path).resolve()),
            "pdf_sha256":hashlib.sha256(raw).hexdigest(),"image_markers":image_markers,
            "extracted_text_sha256":hashlib.sha256(text.encode()).hexdigest() if text else None,
            "embedded_fonts":fonts,"findings":findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("path");ap.add_argument("--out")
    a=ap.parse_args();ext=Path(a.path).suffix.lower()
    if ext==".docx":obj=analyze_docx(a.path)
    elif ext==".pdf":obj=analyze_pdf(a.path)
    elif ext in (".html",".htm"):obj=analyze_html(a.path)
    elif ext in (".ttf",".otf",".woff",".woff2"):
        obj={"schema":"ai-dfir/font-analysis/v1.2","font":analyze_font_bytes(Path(a.path).read_bytes(),Path(a.path).name)}
    else:raise SystemExit("supported: DOCX, PDF, TTF/OTF/WOFF/WOFF2")
    txt=json.dumps(obj,indent=2,sort_keys=True,default=str)
    if a.out:Path(a.out).write_text(txt)
    else:print(txt)
if __name__=="__main__":main()
