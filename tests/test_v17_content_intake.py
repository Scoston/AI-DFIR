"""Resource-worker protocol, native boundary, and intake output regressions."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from types import SimpleNamespace

import pytest

import content_intake_gate as gate
import evil_font_forensics as legacy
from scripts import content_worker_v17 as child
import v17_content_intake as intake
from v17_content_intake_selftest import TEXT, check, pdf_fixture
from v17_docx_intake_selftest import synthetic_font
from v17_integrity import sha256_bytes
from v17_provenance import ProvenanceError

ROOT = Path(__file__).resolve().parents[1]
PDF = pdf_fixture()
FONT = synthetic_font()


@pytest.mark.parametrize('mode', ['plain', 'markup'])
def test_real_text_workers(mode):
    report = intake.run_worker(TEXT, mode=mode)
    if sys.platform != 'linux':
        assert report['available'] is False; return
    assert report['available'] is True and report['source_sha256'] == sha256_bytes(TEXT)
    assert report['source_size_bytes'] == len(TEXT) and report['collection_complete'] is None
    assert all(report[k] is False for k in intake.FALSE_FLAGS)
    assert 'unicode_bidi' in {f['type'] for f in report['analyses']['unicode']['findings']}
    assert 'terminal_cursor_or_display_control' in {f['type'] for f in report['analyses']['terminal']['findings']}
    assert ('markup' in report['analyses']) == (mode == 'markup')


@pytest.mark.parametrize('mode', [None, '', 'shell', '../worker.py', [], 1, True])
def test_invalid_modes_do_not_spawn(mode, monkeypatch):
    monkeypatch.setattr(intake.subprocess, 'Popen', lambda *a, **kw: pytest.fail('spawned'))
    assert intake.run_worker(TEXT, mode=mode)['available'] is False


@pytest.mark.parametrize('raw', [None, 'text', bytearray(TEXT), memoryview(TEXT), b'x' * (intake.TEXT_BYTES + 1)])
def test_invalid_text_input_does_not_spawn(raw, monkeypatch):
    monkeypatch.setattr(intake.subprocess, 'Popen', lambda *a, **kw: pytest.fail('spawned'))
    assert intake.run_worker(raw, mode='plain')['available'] is False


@pytest.mark.parametrize('raw', [b'not PDF', b'', b'%PDF-' + b'x' * intake.PDF_BYTES])
def test_pdf_parent_preflight(raw, monkeypatch):
    monkeypatch.setattr(intake.subprocess, 'Popen', lambda *a, **kw: pytest.fail('spawned'))
    assert intake.run_worker(raw, mode='pdf')['available'] is False


def test_unsupported_platform_is_unknown(monkeypatch):
    monkeypatch.setattr(intake.sys, 'platform', 'unsupported')
    monkeypatch.setattr(intake.subprocess, 'Popen', lambda *a, **kw: pytest.fail('spawned'))
    assert intake.run_worker(TEXT, mode='plain')['available'] is False


def valid_reply(raw=TEXT, mode='plain'):
    from unicode_forensics import analyze as unicode_analyze
    from terminal_render_forensics import analyze as terminal_analyze
    return {'schema': intake.SCHEMA, 'mode': mode, 'available': True, 'source_sha256': sha256_bytes(raw),
            'source_size_bytes': len(raw), 'collection_complete': None, **{k: False for k in intake.FALSE_FLAGS},
            'analyses': {'unicode': unicode_analyze(raw.decode()), 'terminal': terminal_analyze(raw.decode())}}


@pytest.fixture
def fake_worker(monkeypatch):
    monkeypatch.setattr(intake.sys, 'platform', 'linux')
    class Process:
        pid = 123456789
        returncode = 0
        reply = json.dumps(valid_reply()).encode()
        def __init__(self, argv, **kwargs):
            assert argv == [sys.executable, str(intake.WORKER), 'plain']
            assert kwargs['start_new_session'] is True and 'shell' not in kwargs
        def communicate(self, data=None, timeout=None): return self.reply, None
    monkeypatch.setattr(intake.subprocess, 'Popen', Process)
    return Process


@pytest.mark.parametrize('field,value', [('schema', 'wrong'), ('mode', 'markup'), ('available', False), ('error', 'failed'),
    ('source_sha256', '0' * 64), ('source_size_bytes', True), ('source_size_bytes', 0), ('collection_complete', True),
    ('source_authenticity_verified', True), ('independent_rendering_verified', True), ('network_required', True),
    ('analyses', {}), ('analyses', {'unicode': {'findings': []}, 'terminal': {'findings': []}})])
def test_forged_child_claims_are_unknown(field, value, fake_worker):
    reply = valid_reply(); reply[field] = value; fake_worker.reply = json.dumps(reply).encode()
    assert intake.run_worker(TEXT, mode='plain')['available'] is False


@pytest.mark.parametrize('reply', [b'', b'[]', b'{}', b'not JSON', b'{"x":1,"x":2}', b'{"x":NaN}', b'x' * (intake.OUTPUT_BYTES + 1)])
def test_invalid_child_json_is_unknown(reply, fake_worker):
    fake_worker.reply = reply
    assert intake.run_worker(TEXT, mode='plain')['available'] is False


@pytest.mark.parametrize('mutation', [lambda r: r.pop('collection_complete'),
    lambda r: r['analyses']['unicode'].update(findings=[False]),
    lambda r: r['analyses']['unicode'].update(findings=[{'type': 'x', 'severity': 'safe'}]),
    lambda r: r['analyses']['unicode'].update(length=999)])
def test_incomplete_domain_results_fail(mutation, fake_worker):
    reply = valid_reply(); mutation(reply); fake_worker.reply = json.dumps(reply).encode()
    assert intake.run_worker(TEXT, mode='plain')['available'] is False


@pytest.mark.parametrize('code', [-9, -11, 1, 2])
def test_nonzero_child_exit_is_unknown(code, fake_worker):
    fake_worker.returncode = code
    assert intake.run_worker(TEXT, mode='plain')['available'] is False


def test_timeout_kills_child_group(fake_worker, monkeypatch):
    calls = []
    def communicate(self, data=None, timeout=None):
        if timeout is not None: raise subprocess.TimeoutExpired('redacted', timeout)
        return b'', None
    monkeypatch.setattr(fake_worker, 'communicate', communicate)
    monkeypatch.setattr(intake.os, 'killpg', lambda pid, sig: calls.append((pid, sig)))
    assert intake.run_worker(TEXT, mode='plain')['available'] is False
    assert calls == [(fake_worker.pid, signal.SIGKILL)]


@pytest.mark.parametrize('mode', ['plain', 'markup', 'pdf'])
def test_actual_child_limits(mode):
    if sys.platform != 'linux': return
    code = '''import resource,sys
import unicode_forensics
from scripts import content_worker_v17 as child
def probe(*args):
    return {"findings": [], "limits": {k: resource.getrlimit(getattr(resource,"RLIMIT_"+k)) for k in ("CPU","AS","FSIZE","CORE")}}
unicode_forensics.analyze = probe
child.pdf_projection = probe
raise SystemExit(child.main())
'''
    raw = PDF if mode == 'pdf' else TEXT
    result = subprocess.run([sys.executable, '-c', code, mode], input=raw, capture_output=True, cwd=ROOT, timeout=15)
    assert result.returncode == 0
    profile = json.loads(result.stdout)['analyses']['pdf' if mode == 'pdf' else 'unicode']
    _, cpu, memory, _ = intake.MODES[mode]
    assert profile['limits'] == {'CPU': [cpu, cpu], 'AS': [memory * 1024**2] * 2, 'FSIZE': [0, 0], 'CORE': [0, 0]}


def test_actual_excessive_text_report_fails_closed():
    raw = ('a\u200b' * 60000).encode()
    assert len(raw) <= intake.TEXT_BYTES
    assert intake.run_worker(raw, mode='plain')['available'] is False


def test_optional_real_pdf_backend():
    result = intake.run_worker(PDF, mode='pdf')
    if sys.platform != 'linux' or importlib.util.find_spec('pymupdf') is None:
        assert result['available'] is False; return
    assert result['available'] is True
    projection = result['analyses']['pdf']
    assert projection['pages'] == 1 and projection['extracted_text_sha256'] == sha256_bytes(b'Synthetic evidence\n')
    assert any(f['type'] == 'pdf_font_analysis_incomplete' for f in projection['findings'])


@pytest.fixture
def pdf_backend(monkeypatch):
    class Page:
        text = 'synthetic'
        references = [(4,)]
        def get_text(self, kind): assert kind == 'text'; return self.text
        def get_fonts(self, full): assert full; return self.references
    class Document:
        is_pdf = True; needs_pass = False; is_repaired = False; page_count = 1
        data = FONT
        closed = False
        def __enter__(self): return self
        def __exit__(self, *args): self.closed = True
        def load_page(self, number): return page
        def extract_font(self, xref): return 'Synthetic', 'ttf', 'TrueType', self.data
    page, document = Page(), Document()
    def open_pdf(**kwargs):
        assert kwargs == {'stream': PDF, 'filetype': 'pdf'}
        return document
    tools = SimpleNamespace(mupdf_display_errors=lambda flag: None, mupdf_display_warnings=lambda flag: None)
    monkeypatch.setitem(sys.modules, 'pymupdf', SimpleNamespace(open=open_pdf, TOOLS=tools))
    return document, page


def test_pdf_stream_and_font_geometry(pdf_backend):
    result = child.pdf_projection(PDF)
    assert result['pages'] == 1 and result['embedded_fonts'][0]['analysis']['sha256'] == sha256_bytes(FONT)
    assert any(f['type'] == 'font_glyph_outline_collapse' for f in result['findings'])
    assert pdf_backend[0].closed


@pytest.mark.parametrize('field,value', [('is_pdf', False), ('needs_pass', True), ('is_repaired', True), ('page_count', 65)])
def test_pdf_document_preflight(field, value, pdf_backend):
    setattr(pdf_backend[0], field, value)
    with pytest.raises(ProvenanceError): child.pdf_projection(PDF)
    assert pdf_backend[0].closed


@pytest.mark.parametrize('kind', ['text', 'references', 'unique-fonts'])
def test_pdf_projection_budgets(kind, pdf_backend):
    _, page = pdf_backend
    if kind == 'text': page.text = 'x' * (intake.TEXT_BYTES + 1)
    if kind == 'references': page.references = [(4,)] * 4097
    if kind == 'unique-fonts': page.references = [(i,) for i in range(1, 34)]
    with pytest.raises(ProvenanceError): child.pdf_projection(PDF)


@pytest.mark.parametrize('data', [b'', b'wOFF' + b'x' * 30, b'bad font', b'x' * (intake.FONT_BYTES + 1)])
def test_unavailable_pdf_fonts_remain_high(data, pdf_backend):
    pdf_backend[0].data = data
    result = child.pdf_projection(PDF)
    assert result['embedded_fonts'][0]['analysis_available'] is False
    assert result['findings'][0]['type'] == 'pdf_font_analysis_incomplete'


def test_pdf_dependency_missing_is_failure(monkeypatch):
    monkeypatch.setitem(sys.modules, 'pymupdf', None)
    with pytest.raises(ModuleNotFoundError): child.pdf_projection(PDF)


def test_pdf_static_findings_survive_unavailable_backend(tmp_path, monkeypatch):
    p = tmp_path / 'source.pdf'; raw = b'%PDF-1.7\n3 Tr /Subtype /Image\n%%EOF'; p.write_bytes(raw)
    monkeypatch.setattr(intake, 'run_worker', lambda *a, **kw: {'available': False})
    result = gate.scan(p)
    assert result['verdict'] == 'QUARANTINE'
    assert {'pdf_invisible_text_render_mode_3', 'pdf_analysis_incomplete'}.issubset({f['type'] for f in result['findings']})
    assert result['analyses']['document_font']['pdf_sha256'] == sha256_bytes(raw)


@pytest.mark.parametrize('raw', [b'not PDF', b'%PDF-' + b'x' * intake.PDF_BYTES])
def test_pdf_source_failure_is_review(raw, tmp_path):
    p = tmp_path / 'source.pdf'; p.write_bytes(raw)
    result = gate.scan(p)
    assert result['verdict'] == 'REVIEW' and result['findings'][0]['type'] == 'pdf_parse_failure'


def test_real_standalone_font_geometry(tmp_path):
    p = tmp_path / 'source.ttf'; p.write_bytes(FONT)
    result = gate.scan(p)
    assert result['verdict'] == ('QUARANTINE' if sys.platform == 'linux' else 'REVIEW')
    assert result['analyses']['font']['source_sha256'] == sha256_bytes(FONT)


@pytest.mark.parametrize('suffix,raw', [('.ttf', b'bad'), ('.woff', b'wOFF' + b'x' * 20),
                                       ('.woff2', b'wOF2' + b'x' * 20), ('.otf', b'x' * (intake.FONT_BYTES + 1))])
def test_bad_or_unsupported_font_is_review(suffix, raw, tmp_path):
    p = tmp_path / ('source' + suffix); p.write_bytes(raw)
    assert gate.scan(p)['verdict'] == 'REVIEW'


@pytest.mark.parametrize('suffix', ['.ttf', '.pdf', '.txt'])
def test_symlink_sources_rejected(suffix, tmp_path):
    target = tmp_path / 'outside'; target.write_bytes(PDF if suffix == '.pdf' else FONT)
    p = tmp_path / ('source' + suffix); p.symlink_to(target)
    assert gate.scan(p)['verdict'] == 'REVIEW'


def test_text_worker_unknown_is_review(tmp_path, monkeypatch):
    p = tmp_path / 'source.txt'; p.write_bytes(TEXT)
    monkeypatch.setattr(intake, 'run_worker', lambda *a, **kw: {'available': False})
    result = gate.scan(p)
    assert result['verdict'] == 'REVIEW' and result['findings'][0]['type'] == 'text_analysis_incomplete'
    assert result['analyses']['text_intake']['source_sha256'] == sha256_bytes(TEXT)


def test_unknown_extension_is_review(tmp_path):
    p = tmp_path / 'source.unknown'; p.write_bytes(b'unknown')
    result = gate.scan(p)
    assert result['verdict'] == 'REVIEW' and result['findings'][0]['type'] == 'unsupported_content_type'


@pytest.mark.parametrize('critical', [False, True])
def test_gate_output_limit_preserves_quarantine(critical, tmp_path, monkeypatch):
    p = tmp_path / 'source.txt'; p.write_bytes(TEXT if critical else b'plain')
    monkeypatch.setattr(intake, 'GATE_OUTPUT_BYTES', 1)
    result = gate.scan(p)
    assert result['verdict'] == ('QUARANTINE' if critical and sys.platform == 'linux' else 'REVIEW')
    assert result['findings'][0]['type'] == 'intake_output_limit'


@pytest.mark.parametrize('kind', ['new', 'existing', 'symlink', 'source'])
def test_gate_cli_exclusive_output(kind, tmp_path):
    source = tmp_path / 'source.txt'; source.write_bytes(b'plain')
    output = tmp_path / 'report.json'
    if kind == 'existing': output.write_bytes(b'keep')
    if kind == 'symlink': output.symlink_to(source)
    if kind == 'source': output = source
    result = subprocess.run([sys.executable, str(ROOT / 'content_intake_gate.py'), str(source), '--out', str(output)], capture_output=True, timeout=10)
    assert source.read_bytes() == b'plain'
    if kind == 'new':
        assert result.returncode == (0 if sys.platform == 'linux' else 1)
        assert output.stat().st_mode & 0o777 == 0o600
        assert json.loads(output.read_bytes())['analyses']['text_intake']['source_sha256'] == sha256_bytes(b'plain')
    else:
        assert result.returncode == 1 and json.loads(result.stdout)['status'] == 'FAIL'
        if kind == 'existing': assert output.read_bytes() == b'keep'


@pytest.mark.parametrize('suffix,raw', [('.pdf', PDF), ('.ttf', FONT)])
def test_pdf_font_cli_refuses_source_overwrite(suffix, raw, tmp_path):
    path = tmp_path / ('source' + suffix); path.write_bytes(raw)
    result = subprocess.run([sys.executable, str(ROOT / 'evil_font_forensics.py'), str(path), '--out', str(path)], capture_output=True, timeout=20)
    assert result.returncode == 1 and path.read_bytes() == raw


def test_private_output_limit_precedes_creation(tmp_path):
    output = tmp_path / 'report.json'
    with pytest.raises(ProvenanceError): intake.output_report({'large': 'x' * 100}, output, limit=20)
    assert not output.exists()


def test_selftest():
    assert check()['pdf_failure_preserves_static_finding'] is True
