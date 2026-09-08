#!/usr/bin/env python3
"""Synthetic bounded worker acceptance and unknown-result preservation."""
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

import v17_content_intake as intake

TEXT = 'synthetic \u202eabc\u202c <!-- hidden --> \x1b[2J'.encode()


def pdf_fixture():
    stream = b'BT /F1 12 Tf 72 220 Td (Synthetic evidence) Tj ET\n'
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        b'<< /Length ' + str(len(stream)).encode() + b' >>\nstream\n' + stream + b'endstream']
    raw = b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'; offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(raw)); raw += str(number).encode() + b' 0 obj\n' + obj + b'\nendobj\n'
    xref = len(raw)
    raw += b'xref\n0 6\n0000000000 65535 f \n'
    raw += b''.join(f'{offset:010d} 00000 n \n'.encode() for offset in offsets[1:])
    return raw + b'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n' + str(xref).encode() + b'\n%%EOF\n'


def check():
    accepted = 0
    for mode in ('plain', 'markup'):
        result = intake.run_worker(TEXT, mode=mode)
        if sys.platform == 'linux':
            assert result['available'] is True
            assert any(f['type'] == 'unicode_bidi' for f in result['analyses']['unicode']['findings'])
            accepted += 1
        else: assert result['available'] is False
    for raw in (b'\xff', b'x' * (intake.TEXT_BYTES + 1)):
        assert intake.run_worker(raw, mode='plain')['available'] is False
    with TemporaryDirectory() as folder:
        path = Path(folder) / 'synthetic.pdf'
        path.write_bytes(b'%PDF-1.7\n3 Tr\n%%EOF\n')
        result = intake.pdf_file(path)
        assert {'pdf_invisible_text_render_mode_3', 'pdf_analysis_incomplete'}.issubset({f['type'] for f in result['findings']})
    return {'status': 'PASS', 'text_worker_profiles': accepted, 'invalid_text_rejected': 2,
            'pdf_failure_preserves_static_finding': True, 'network_required': False,
            'independent_rendering_verified': False}


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
