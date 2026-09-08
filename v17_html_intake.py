"""Bounded static HTML/CSS observations and descriptor-confined local resources."""
from __future__ import annotations

from html.parser import HTMLParser
import os
from pathlib import Path
import stat
import time

import tinycss2

from v17_docx_font import analyze as font_analysis
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_provenance import ProvenanceError

SCHEMA = "ai-dfir/contained-html-intake/v1.7"
MAX_HTML_BYTES = 256 * 1024
MAX_CSS_BYTES = 64 * 1024
MAX_FONT_BYTES = 4 * 1024**2
MAX_SELECTED_BYTES = 8 * 1024**2
MAX_RESOURCES = 64
MAX_STYLESHEETS = 32
MAX_FONTS = 32
MAX_NODES = 8192
MAX_DEPTH = 64
MAX_CSS_TOKENS = 32768
MAX_SPAN_CHARS = 256 * 1024
MAX_OUTPUT_BYTES = 2 * 1024**2
VOID = frozenset("area base br col embed hr img input link meta param source track wbr".split())


def require(condition):
    if not condition:
        raise ProvenanceError("invalid, unsupported, ambiguous, or excessive HTML/CSS intake")


def path_parts(value, base=()):
    """Normalize literal relative segments before any descriptor-relative open."""
    require(isinstance(value, str) and 0 < len(value) <= 4096)
    require(not value.startswith("/") and not any(c in value for c in "\\:%?#")
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    result = list(base)
    for part in value.split("/"):
        require(bool(part))
        if part == ".":
            continue
        if part == "..":
            require(bool(result)); result.pop()
        else:
            require(not part.endswith((".", " ")))
            result.append(part)
        require(len(result) <= MAX_DEPTH)
    require(bool(result))
    return tuple(result)


class Resources:
    """Anchor to the caller-selected parent directory; reject all resource symlinks."""
    def __init__(self, root):
        require(os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"))
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        self.cache, self.rows, self.total, self.attempts = {}, [], 0, 0

    def close(self):
        os.close(self.fd)

    def read(self, parts, limit, role):
        require(isinstance(parts, tuple) and 0 < len(parts) <= MAX_DEPTH
                and all(isinstance(p, str) and p not in {"", ".", ".."}
                        and "/" not in p and "\\" not in p and "\x00" not in p for p in parts))
        if parts in self.cache:
            raw = self.cache[parts]
            require(len(raw) <= limit)
            return raw
        self.attempts += 1
        require(self.attempts <= MAX_RESOURCES + 1)
        descriptor = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor); descriptor = child
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_size <= limit
                        and self.total + info.st_size <= MAX_SELECTED_BYTES)
                raw = stream.read(limit + 1)
            require(len(raw) <= limit and self.total + len(raw) <= MAX_SELECTED_BYTES)
        finally:
            os.close(descriptor)
        self.total += len(raw)
        self.cache[parts] = raw
        self.rows.append({"path": "/".join(parts), "role": role, "size_bytes": len(raw), "sha256": sha256_bytes(raw)})
        return raw


def read_text_snapshot(path):
    path = Path(path).absolute()
    resources = Resources(path.parent)
    try:
        raw = resources.read((path.name,), MAX_HTML_BYTES, "text")
        return raw, raw.decode("utf-8", errors="strict")
    finally:
        resources.close()


def tokens_ok(tokens):
    stack = [(tokens, 1)]; count = 0
    while stack:
        values, depth = stack.pop(); require(depth <= MAX_DEPTH)
        for token in values:
            count += 1; require(count <= MAX_CSS_TOKENS and token.type != "error")
            for attr in ("content", "prelude", "arguments", "value"):
                child = getattr(token, attr, None)
                if isinstance(child, list): stack.append((child, depth + 1))


def significant(tokens):
    return [t for t in tokens if t.type not in {"whitespace", "comment"}]


def family(tokens):
    values = significant(tokens)
    if len(values) == 1 and values[0].type == "string": return values[0].value
    if values and all(t.type == "ident" for t in values): return " ".join(t.value for t in values)
    return None


def declarations(value):
    result = tinycss2.parse_declaration_list(value, skip_comments=True, skip_whitespace=True)
    tokens_ok(result)
    require(all(t.type == "declaration" for t in result))
    return result


class Document(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.spans, self.styles, self.links, self.findings = [], [], [], [], []
        self.nodes = self.span_chars = 0
        self.style = None
        self.has_base = False

    def handle_starttag(self, tag, attrs):
        self.nodes += 1
        require(self.nodes <= MAX_NODES and len(attrs) <= 64 and len(tag) <= 4096)
        require(len({k for k, v in attrs}) == len(attrs)
                and all(len(k) <= 4096 and (v is None or len(v) <= 4096) for k, v in attrs))
        attrs = dict(attrs); span = None
        if tag == "base":
            self.has_base = True
            self.findings.append({"type": "html_base_unresolved", "severity": "high"})
        if tag == "link" and "stylesheet" in (attrs.get("rel") or "").lower().split():
            require(len(self.links) < MAX_STYLESHEETS)
            self.links.append(attrs.get("href"))
        if tag == "style":
            require(self.style is None and len(self.styles) < MAX_STYLESHEETS)
            self.style = []
        if tag == "span":
            name = None
            for declaration in declarations(attrs.get("style") or ""):
                if declaration.lower_name == "font-family":
                    name = family(declaration.value)
                    if name is None: self.findings.append({"type": "html_font_style_unsupported", "severity": "high"})
            span = {"font": name, "chunks": []}
            self.spans.append(span)
        if tag not in VOID:
            self.stack.append((tag, span)); require(len(self.stack) <= MAX_DEPTH)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID: self.handle_endtag(tag)

    def handle_endtag(self, tag):
        require(bool(self.stack) and self.stack[-1][0] == tag)
        self.stack.pop()
        if tag == "style":
            css = "".join(self.style)
            require(len(css.encode("utf-8")) <= MAX_CSS_BYTES)
            self.styles.append(css); self.style = None

    def handle_data(self, data):
        if self.style is not None:
            self.style.append(data)
        # Retain each span's static text, including descendants, under one budget.
        for _, span in self.stack:
            if span is not None:
                self.span_chars += len(data); require(self.span_chars <= MAX_SPAN_CHARS)
                span["chunks"].append(data)

    def unknown_decl(self, data):
        raise ProvenanceError("unsupported HTML declaration")


def parse_html(raw):
    require(type(raw) is bytes and len(raw) <= MAX_HTML_BYTES)
    text = raw.decode("utf-8", errors="strict")
    parser = Document(); parser.feed(text); parser.close()
    require(not parser.stack and parser.style is None)
    spans = [{"font": row["font"], "text": "".join(row["chunks"])} for row in parser.spans]
    return {"text": text, "spans": spans, "styles": parser.styles, "links": parser.links,
            "findings": parser.findings, "has_base": parser.has_base}


def parse_css(text):
    require(type(text) is str and len(text.encode("utf-8")) <= MAX_CSS_BYTES)
    rules = tinycss2.parse_stylesheet(text, skip_comments=True, skip_whitespace=True)
    tokens_ok(rules)
    faces, findings = [], []
    for rule in rules:
        if rule.type != "at-rule": continue
        if rule.lower_at_keyword != "font-face":
            findings.append({"type": "html_css_rule_uninspected", "severity": "high", "rule": rule.lower_at_keyword})
            continue
        require(rule.content is not None and not significant(rule.prelude) and len(faces) < MAX_FONTS)
        props = {}
        for declaration in declarations(rule.content):
            require(declaration.lower_name not in props)
            props[declaration.lower_name] = declaration.value
        name = family(props.get("font-family", []))
        values = significant(props.get("src", []))
        target = None
        if values:
            token = values.pop(0)
            if token.type == "url": target = token.value
            elif token.type == "function" and token.lower_name == "url":
                args = significant(token.arguments)
                if len(args) == 1 and args[0].type == "string": target = args[0].value
        if not name or not target or any(t.type != "function" or t.lower_name != "format" for t in values):
            target = None
        faces.append({"font_family": name, "src": target})
    return faces, findings


def capture(path):
    path = Path(path).absolute(); resources = Resources(path.parent)
    try:
        raw = resources.read((path.name,), MAX_HTML_BYTES, "html")
        parsed = parse_html(raw)
        findings = list(parsed["findings"])
        css_sources = [(css, ()) for css in parsed["styles"]]
        for target in parsed["links"]:
            try:
                require(not parsed["has_base"])
                parts = path_parts(target)
                css_sources.append((resources.read(parts, MAX_CSS_BYTES, "stylesheet").decode("utf-8", errors="strict"), parts[:-1]))
            except (ProvenanceError, OSError, UnicodeError):
                findings.append({"type": "html_stylesheet_unresolved", "severity": "high", "target": target})
        faces, cache = [], {}
        deadline = time.monotonic() + 20
        for css, base in css_sources:
            try:
                selected, extra = parse_css(css)
                require(len(faces) + len(selected) <= MAX_FONTS)
                findings.extend(extra)
            except (ProvenanceError, ValueError, RecursionError):
                findings.append({"type": "html_stylesheet_unparsed", "severity": "high"})
                continue
            for face in selected:
                try:
                    require(not parsed["has_base"])
                    parts = path_parts(face["src"], base)
                    font = resources.read(parts, MAX_FONT_BYTES, "font")
                    face["font_file"] = "/".join(parts)
                    digest = sha256_bytes(font)
                    if digest not in cache and time.monotonic() < deadline:
                        cache[digest] = font_analysis(font)
                    report = cache.get(digest)
                    if not report or report.get("available") is not True:
                        findings.append({"type": "html_font_analysis_incomplete", "severity": "high"})
                    face["font_analysis"] = report or {"available": False, "findings": []}
                except (ProvenanceError, OSError):
                    findings.append({"type": "html_font_reference_unresolved", "severity": "high"})
                faces.append(face)
        receipt = {"schema": SCHEMA, "source_sha256": sha256_bytes(raw), "source_size_bytes": len(raw),
                   "selected_resources": resources.rows, "selected_bytes": resources.total,
                   "external_resources_loaded": False, "resource_symlinks_followed": False,
                   "source_authenticity_verified": False, "complete_visible_rendering_verified": False,
                   "atomic_resource_snapshot_verified": False, "collection_complete": None, "network_required": False}
        require(len(canonical_json_bytes({"intake": receipt, "font_faces": faces, "findings": findings})) <= MAX_OUTPUT_BYTES)
        return {**parsed, "raw": raw, "font_faces": faces, "findings": findings, "intake": receipt}
    finally:
        resources.close()
