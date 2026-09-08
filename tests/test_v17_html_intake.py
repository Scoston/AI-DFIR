"""Directory-handle containment, static parser, resource, and source-binding tests."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import content_intake_gate as gate
import evil_font_forensics as legacy
import v17_html_intake as intake
from v17_docx_intake_selftest import synthetic_font
from v17_html_intake_selftest import HTML, CSS, VALID_HTML, INVALID_HTML, VALID_CSS, INVALID_CSS, check
from v17_integrity import sha256_bytes
from v17_provenance import ProvenanceError

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def site(tmp_path):
    root = tmp_path / 'evidence'; root.mkdir()
    (root / 'styles').mkdir(); (root / 'fonts').mkdir()
    (root / 'source.html').write_bytes(HTML)
    (root / 'styles/site.css').write_text(CSS)
    (root / 'fonts/demo.ttf').write_bytes(synthetic_font())
    return root


@pytest.mark.parametrize('raw', VALID_HTML)
def test_valid_static_html(raw):
    parsed = intake.parse_html(raw)
    assert parsed['spans'] and parsed['text'].encode() == raw


@pytest.mark.parametrize('raw', INVALID_HTML + [None, 'text', bytearray(b'x'), b'x' * (intake.MAX_HTML_BYTES + 1)])
def test_rejected_html(raw):
    with pytest.raises((ProvenanceError, UnicodeError)): intake.parse_html(raw)


@pytest.mark.parametrize('css', VALID_CSS)
def test_valid_css(css):
    assert intake.parse_css(css)[1] == []


@pytest.mark.parametrize('css', INVALID_CSS + [None, b'css', 'x' * (intake.MAX_CSS_BYTES + 1)])
def test_rejected_css(css):
    with pytest.raises(ProvenanceError): intake.parse_css(css)


@pytest.mark.parametrize('target', ['../escape', '/absolute', '//host/file', 'https://example.invalid/a', 'file:///a', 'data:x',
                                     'C:font', 'font\\name', 'a%2fb', 'a?x', 'a#x', 'a//b', 'a\x00b', 'a\x01b', 'a.', 'a ', '', None])
def test_unsafe_root_references_reject_before_open(target):
    with pytest.raises(ProvenanceError): intake.path_parts(target)


@pytest.mark.parametrize('target,base,expected', [('a.css', (), ('a.css',)), ('./a.css', (), ('a.css',)),
    ('../fonts/font.ttf', ('styles',), ('fonts', 'font.ttf')), ('nested/../a.css', (), ('a.css',))])
def test_relative_normalization_stays_inside_root(target, base, expected):
    assert intake.path_parts(target, base) == expected


def test_selected_byte_receipts_and_geometry(site):
    report = legacy.analyze_html(site / 'source.html')
    receipt = report['intake']
    assert receipt['source_sha256'] == sha256_bytes(HTML) == report['html_sha256']
    for row in receipt['selected_resources']:
        raw = (site / row['path']).read_bytes()
        assert row['sha256'] == sha256_bytes(raw) and row['size_bytes'] == len(raw)
    assert receipt['collection_complete'] is None
    for flag in ('external_resources_loaded', 'resource_symlinks_followed', 'source_authenticity_verified',
                 'complete_visible_rendering_verified', 'atomic_resource_snapshot_verified', 'network_required'):
        assert receipt[flag] is False
    types = {f['type'] for f in report['findings']}
    assert ('font_glyph_outline_collapse' if sys.platform == 'linux' else 'html_font_analysis_incomplete') in types


@pytest.mark.parametrize('kind', ['stylesheet', 'font', 'directory', 'source'])
def test_symlinks_never_read_external_bytes(kind, site, tmp_path, monkeypatch):
    outside = tmp_path / 'outside'; outside.mkdir()
    (outside / 'site.css').write_text('@font-face{font-family:outside;src:url(outside.ttf)}')
    (outside / 'source.html').write_text('<span>outside</span>')
    (outside / 'demo.ttf').write_bytes(b'outside font')
    if kind == 'stylesheet':
        p = site / 'styles/site.css'; p.unlink(); p.symlink_to(outside / 'site.css')
    elif kind == 'font':
        p = site / 'fonts/demo.ttf'; p.unlink(); p.symlink_to(outside / 'demo.ttf')
    elif kind == 'directory':
        (site / 'styles/site.css').unlink(); (site / 'styles').rmdir(); (site / 'styles').symlink_to(outside, target_is_directory=True)
    else:
        p = site / 'source.html'; p.unlink(); p.symlink_to(outside / 'source.html')
    monkeypatch.setattr(intake, 'font_analysis', lambda raw: pytest.fail('outside bytes reached font worker'))
    result = gate.scan(site / 'source.html')
    assert result['verdict'] == 'REVIEW'
    assert 'outside font' not in json.dumps(result)


@pytest.mark.parametrize('target', ['../../outside.css', 'https://example.invalid/font.css', '/outside.css', 'styles/site.css?x'])
def test_unresolved_stylesheet_does_not_read(target, site, monkeypatch):
    (site / 'source.html').write_text(f'<link rel="stylesheet" href="{target}">')
    calls = []
    original = intake.Resources.read
    def read(self, parts, limit, role):
        calls.append(role)
        return original(self, parts, limit, role)
    monkeypatch.setattr(intake.Resources, 'read', read)
    result = gate.scan(site / 'source.html')
    assert calls == ['html'] and result['verdict'] == 'REVIEW'


@pytest.mark.parametrize('src', ['url(../../outside.ttf)', 'url(https://example.invalid/font.ttf)',
                               'local("Arial")', 'url(a.ttf),url(b.ttf)', 'url(\\2e\\2e /\\2e\\2e /outside.ttf)'])
def test_font_reference_rejection(site, src, monkeypatch):
    (site / 'styles/site.css').write_text(f'@font-face{{font-family:Synthetic;src:{src}}}')
    monkeypatch.setattr(intake, 'font_analysis', lambda raw: pytest.fail('unresolved font analyzed'))
    result = gate.scan(site / 'source.html')
    assert result['verdict'] == 'REVIEW' and any(f['type'] == 'html_font_reference_unresolved' for f in result['findings'])


def test_escaped_css_identifiers_and_safe_paths(site, monkeypatch):
    (site / 'styles/site.css').write_text('@font-\\66 ace{font-family:"Demo 41";src:url("../fonts/\\64 emo.ttf")}')
    monkeypatch.setattr(intake, 'font_analysis', lambda raw: {'available': True, 'findings': []})
    result = intake.capture(site / 'source.html')
    assert result['font_faces'][0]['font_file'] == 'fonts/demo.ttf' and result['findings'] == []


def test_base_disables_all_relative_resource_reads(site, monkeypatch):
    (site / 'source.html').write_bytes(b'<base href="https://example.invalid/">' + HTML)
    monkeypatch.setattr(intake, 'font_analysis', lambda raw: pytest.fail('base ignored'))
    result = intake.capture(site / 'source.html')
    assert len(result['intake']['selected_resources']) == 1
    assert {'html_base_unresolved', 'html_stylesheet_unresolved'}.issubset({f['type'] for f in result['findings']})


@pytest.mark.parametrize('css', ['@import "outside.css";', '@media print {@font-face{font-family:x;src:url(x.ttf)}}'])
def test_import_and_nested_rules_are_explicitly_uninspected(css):
    faces, findings = intake.parse_css(css)
    assert faces == [] and findings[0]['type'] == 'html_css_rule_uninspected'


@pytest.mark.parametrize('limit,value', [('MAX_NODES', 1), ('MAX_DEPTH', 1), ('MAX_SPAN_CHARS', 1)])
def test_html_tree_and_text_budgets(limit, value, monkeypatch):
    monkeypatch.setattr(intake, limit, value)
    with pytest.raises(ProvenanceError): intake.parse_html(b'<div><span>data</span></div>')


@pytest.mark.parametrize('attrs', [' '.join(f'a{i}="v"' for i in range(65)), 'a="' + 'v' * 4097 + '"'])
def test_attribute_budgets(attrs):
    with pytest.raises(ProvenanceError): intake.parse_html(f'<span {attrs}></span>'.encode())


@pytest.mark.parametrize('limit,value', [('MAX_CSS_TOKENS', 2), ('MAX_DEPTH', 1)])
def test_css_token_budgets(limit, value, monkeypatch):
    monkeypatch.setattr(intake, limit, value)
    with pytest.raises(ProvenanceError): intake.parse_css('@font-face{font-family:Synthetic;src:url("font.ttf")}')


@pytest.mark.parametrize('limit,value', [('MAX_CSS_BYTES', 5), ('MAX_FONT_BYTES', 5), ('MAX_SELECTED_BYTES', len(HTML) + 1), ('MAX_RESOURCES', 0)])
def test_resource_budget_failure_is_review(limit, value, site, monkeypatch):
    monkeypatch.setattr(intake, limit, value)
    assert gate.scan(site / 'source.html')['verdict'] == 'REVIEW'


def test_fonts_are_deduplicated_by_bytes(site, monkeypatch):
    (site / 'styles/site.css').write_text(CSS + CSS.replace('Synthetic', 'Other'))
    calls = []
    monkeypatch.setattr(intake, 'font_analysis', lambda raw: calls.append(raw) or {'available': True, 'findings': []})
    result = intake.capture(site / 'source.html')
    assert len(calls) == 1 and len(result['font_faces']) == 2 and len(result['intake']['selected_resources']) == 3


def test_elapsed_font_budget_is_unknown(site, monkeypatch):
    ticks = iter([0, 21]); monkeypatch.setattr(intake.time, 'monotonic', lambda: next(ticks))
    monkeypatch.setattr(intake, 'font_analysis', lambda raw: pytest.fail('budget ignored'))
    assert any(f['type'] == 'html_font_analysis_incomplete' for f in intake.capture(site / 'source.html')['findings'])


@pytest.mark.parametrize('available', [False, None])
def test_font_failure_not_promoted_to_pass(available, site, monkeypatch):
    monkeypatch.setattr(intake, 'font_analysis', lambda raw: {'available': available, 'findings': []})
    assert gate.scan(site / 'source.html')['verdict'] == 'REVIEW'


def test_resource_snapshot_cache_prevents_reopening(site):
    resources = intake.Resources(site)
    try:
        first = resources.read(('source.html',), intake.MAX_HTML_BYTES, 'html')
        (site / 'source.html').write_bytes(b'replaced')
        assert resources.read(('source.html',), intake.MAX_HTML_BYTES, 'html') == first == HTML
    finally: resources.close()


def test_anchored_root_survives_path_replacement(site, tmp_path):
    resources = intake.Resources(site)
    try:
        moved = tmp_path / 'moved'; site.rename(moved); site.mkdir()
        (site / 'source.html').write_bytes(b'replacement tree')
        assert resources.read(('source.html',), intake.MAX_HTML_BYTES, 'html') == HTML
    finally: resources.close()


def test_gate_uses_the_same_html_snapshot(site, monkeypatch):
    original = intake.parse_html
    def parse(raw):
        (site / 'source.html').write_bytes(b'replaced')
        return original(raw)
    monkeypatch.setattr(intake, 'parse_html', parse)
    result = gate.scan(site / 'source.html')
    assert result['analyses']['text_intake']['source_sha256'] == sha256_bytes(HTML)
    assert result['analyses']['document_font']['html_sha256'] == sha256_bytes(HTML)


def test_named_pipe_source_fails_without_waiting(site):
    if not hasattr(os, 'mkfifo'): return
    p = site / 'pipe.html'; os.mkfifo(p)
    assert gate.scan(p)['verdict'] == 'REVIEW'


@pytest.mark.parametrize('raw', [b'\xff', b'x' * (intake.MAX_HTML_BYTES + 1)])
def test_text_gate_size_and_encoding_failures(raw, site):
    p = site / 'text.txt'; p.write_bytes(raw)
    result = gate.scan(p)
    assert result['verdict'] == 'REVIEW' and result['findings'][0]['type'] == 'text_parse_failure'


def test_existing_html_deception_findings_remain(site):
    from v12_selftest import make_html
    p = site / 'source.html'; make_html(p)
    result = gate.scan(p)
    assert result['verdict'] == 'QUARANTINE'
    assert {'html_per_character_font_switching', 'machine_visible_text_disagreement_via_font_mapping',
            'stealth_font_machine_only_characters', 'evilfonttool_style_font_family_pattern'}.issubset({f['type'] for f in result['findings']})


@pytest.mark.parametrize('kind', ['new', 'existing', 'symlink', 'source'])
def test_html_cli_exclusive_output(kind, site):
    source = site / 'source.html'; output = site / 'report.json'
    if kind == 'existing': output.write_bytes(b'keep')
    if kind == 'symlink': output.symlink_to(source)
    if kind == 'source': output = source
    result = subprocess.run([sys.executable, str(ROOT / 'evil_font_forensics.py'), str(source), '--out', str(output)], capture_output=True, timeout=15)
    assert source.read_bytes() == HTML
    if kind == 'new':
        assert result.returncode == 0 and output.stat().st_mode & 0o777 == 0o600
        assert json.loads(output.read_bytes())['intake']['source_sha256'] == sha256_bytes(HTML)
    else:
        assert result.returncode == 1 and json.loads(result.stdout)['status'] == 'FAIL'
        if kind == 'existing': assert output.read_bytes() == b'keep'


def test_selftest():
    assert check()['contained_resource_fixture'] == 'PASS'
