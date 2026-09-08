#!/usr/bin/env python3
"""Fixed synthetic HTML/CSS parser and contained-resource acceptance."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import v17_html_intake as intake
from v17_fuzz_targets import blocked_actions
from v17_integrity import sha256_bytes
from v17_provenance import ProvenanceError

HTML = b'<html><head><link rel="stylesheet" href="styles/site.css"></head><body><span style="font-family: Synthetic">sample</span></body></html>'
CSS = '@font-face {font-family: Synthetic; src: url("../fonts/demo.ttf") format("truetype");}'
VALID_HTML = [b'<span style="font-family: \'Demo 41\'">x</span>', b'<html><body><br><span>a&amp;b</span></body></html>']
INVALID_HTML = [b'\xff', b'<span>x', b'<span></div>', b'<span style="x" style="y"></span>',
                b'<style>' + b'x' * (intake.MAX_CSS_BYTES + 1) + b'</style>', b'<div>' * 65 + b'</div>' * 65]
VALID_CSS = [CSS, 'body {color: blue}']
INVALID_CSS = [']', '@font-face;', '@font-face{font-family:x;font-family:y;src:url(a)}', '@font-face{src:url("bad\n")}']


def check():
    with blocked_actions():
        for raw in VALID_HTML: intake.parse_html(raw)
        for text in VALID_CSS: intake.parse_css(text)
        for parse, values in ((intake.parse_html, INVALID_HTML), (intake.parse_css, INVALID_CSS)):
            for value in values:
                try: parse(value)
                except (ProvenanceError, UnicodeError): continue
                raise AssertionError("invalid HTML/CSS accepted")
        with TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'styles').mkdir(); (root / 'fonts').mkdir()
            (root / 'source.html').write_bytes(HTML)
            (root / 'styles/site.css').write_text(CSS, encoding='utf-8')
            (root / 'fonts/demo.ttf').write_bytes(b'synthetic opaque font')
            with patch.object(intake, 'font_analysis', lambda raw: {'available': True, 'sha256': sha256_bytes(raw), 'findings': []}):
                captured = intake.capture(root / 'source.html')
            assert captured['intake']['source_sha256'] == sha256_bytes(HTML)
            assert [r['path'] for r in captured['intake']['selected_resources']] == ['source.html', 'styles/site.css', 'fonts/demo.ttf']
            assert captured['findings'] == []
            assert captured['intake']['atomic_resource_snapshot_verified'] is False
    return {'status': 'PASS', 'valid_html': 2, 'invalid_html_rejected': 6, 'valid_css': 2,
            'invalid_css_rejected': 4, 'contained_resource_fixture': 'PASS',
            'network_required': False, 'independent_rendering_verified': False}


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
