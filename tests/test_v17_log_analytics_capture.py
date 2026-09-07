"""Automatic acquisition binding, transport boundaries, and output failure tests."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import zipfile

import pytest
import requests
from urllib3.response import HTTPResponse
from urllib3.exceptions import ReadTimeoutError

import provider_collectors_v15 as collectors
import v17_log_analytics_capture as acquisition
from case_export_v17 import verify_case
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_log_analytics_capture_selftest import (
    SYNTHETIC_TOKEN, captured_case, synthetic_adapter, synthetic_params,
)
from v17_log_analytics_context import compare_replay
from v17_log_analytics_context_selftest import export_fixture
from v17_log_analytics_selftest import synthetic_response


@pytest.fixture(autouse=True)
def no_live_acquisition(monkeypatch):
    monkeypatch.setenv(acquisition.TOKEN_ENV, SYNTHETIC_TOKEN)
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected live network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def install(monkeypatch, *, raw=None, partial=False, status=200, headers=None):
    raw = json.dumps(synthetic_response(partial=partial), indent=3).encode() + b'\n' if raw is None else raw
    adapter = synthetic_adapter(raw, status=status, headers=headers)
    monkeypatch.setattr(requests.adapters, "HTTPAdapter", adapter)
    return raw, adapter


def capture(tmp_path, params=None):
    return acquisition.capture(canonical_json_bytes(synthetic_params() if params is None else params), tmp_path / 'capture')


@pytest.mark.parametrize('partial', [False, True])
def test_capture_preserves_exact_body_actual_request_and_distinct_response_header_names(tmp_path, monkeypatch, partial):
    raw, adapter = install(monkeypatch, partial=partial, headers={'x-request-id': 'third-id', 'Set-Cookie': SYNTHETIC_TOKEN})
    receipt = capture(tmp_path)
    folder = tmp_path / 'capture'
    ctx = json.loads((folder / 'context.json').read_bytes())
    assert (folder / 'response.json').read_bytes() == raw
    assert ctx['request']['body'] == json.loads(adapter.sent[0][0].body)
    assert ctx['request']['url'] == adapter.sent[0][0].url
    assert ctx['request']['headers'] == {'content-type': 'application/json', 'prefer': 'wait=30', 'x-ms-client-request-id': 'synthetic-client-request'}
    assert ctx['response']['headers'] == {'content-type': 'application/json', 'x-ms-request-id': 'synthetic-ms-request',
                                           'request-id': 'synthetic-other-request', 'x-request-id': 'third-id'}
    assert ctx['response']['body_sha256'] == sha256_bytes(raw) and ctx['response']['body_size_bytes'] == len(raw)
    assert receipt['status'] == 'CAPTURED' and receipt['artifact_set_complete']
    assert receipt['collection_complete'] is (False if partial else None)
    assert receipt['partial_error_recorded'] is partial and receipt['response_error_recorded'] is partial
    assert not receipt['source_authenticity_verified'] and not receipt['request_scope_verified'] and not receipt['query_execution_verified']
    assert json.loads((folder / 'receipt.json').read_bytes()) == receipt
    assert not (folder / 'receipt.pending.json').exists()
    for entry in receipt['files']:
        preserved = (folder / entry['path']).read_bytes()
        assert entry['sha256'] == sha256_bytes(preserved) and entry['size_bytes'] == len(preserved)
    assert SYNTHETIC_TOKEN not in (folder / 'context.json').read_text()
    assert 'authorization' not in (folder / 'context.json').read_text().lower()
    assert 'SYNTHETIC-PRIVATE-CAPTURE-QUERY' not in json.dumps(receipt) and 'wait=30' not in json.dumps(receipt)
    assert len(adapter.sent) == 1 and adapter.closed and adapter.response.raw.closed


@pytest.mark.parametrize('partial', [False, True])
def test_automatically_captured_artifacts_replay_in_a_signed_case_offline(tmp_path, monkeypatch, partial):
    install(monkeypatch, partial=partial)
    capture(tmp_path)
    fixture = captured_case(tmp_path / 'case', tmp_path / 'capture')
    def forbidden(*args, **kwargs):
        pytest.fail('unexpected acquisition, process execution, or extraction during replay')
    monkeypatch.setattr(acquisition, 'capture', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(zipfile.ZipFile, 'extractall', forbidden)
    result = verify_case(fixture['package'], fixture['public'], require_provenance=True, replay_transforms=True)
    transform = result['reconstruction']['deterministic_replay']['transforms'][0]
    assert result['valid'] and transform['status'] == 'PASS' and transform['request_context_bound']
    assert transform['partial_error_recorded'] is partial and not transform['query_reexecuted']


def test_request_has_explicit_tls_no_proxies_no_retries_and_no_ambient_session_credentials(tmp_path, monkeypatch):
    _, adapter = install(monkeypatch)
    monkeypatch.setenv('HTTPS_PROXY', 'https://synthetic-proxy.invalid')
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', '/synthetic/untrusted-ca.pem')
    monkeypatch.setenv('NETRC', '/synthetic/netrc')
    monkeypatch.setattr(requests.sessions.Session, 'send', lambda *a, **k: pytest.fail('Session must not buffer redirect bodies'))
    capture(tmp_path)
    prepared, kwargs = adapter.sent[0]
    assert kwargs == {'stream': True, 'timeout': (10, 45), 'verify': True, 'cert': None, 'proxies': {}}
    assert prepared.headers['Authorization'] == 'Bearer ' + SYNTHETIC_TOKEN
    assert prepared.headers['Accept-Encoding'] == 'identity' and 'Cookie' not in prepared.headers
    assert prepared.method == 'POST' and prepared.url.startswith('https://api.loganalytics.io/v1/workspaces/')


def test_real_http_adapter_disables_redirects_preloading_and_decoding_before_bounded_read(tmp_path, monkeypatch):
    calls = []
    body = io.BytesIO(b'x' * 1000)
    class Pool:
        def urlopen(self, **kwargs):
            calls.append(kwargs)
            return HTTPResponse(body=body, status=302, headers={'Location': 'https://other.example.invalid'},
                                preload_content=False, decode_content=False)
    pool = Pool()
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'get_connection_with_tls_context', lambda *a, **k: pool)
    monkeypatch.setattr(acquisition, 'MAX_INPUT_BYTES', 32)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert len(calls) == 1
    assert calls[0]['redirect'] is False and calls[0]['preload_content'] is False and calls[0]['decode_content'] is False
    assert calls[0]['retries'].total == 0 and pool.cert_reqs == 'CERT_REQUIRED'
    assert not (tmp_path / 'capture/receipt.json').exists() and body.closed


@pytest.mark.parametrize('mutate', [
    lambda r: setattr(r, 'url', 'https://different.example.invalid'),
    lambda r: setattr(r, 'method', 'GET'),
    lambda r: setattr(r, 'body', b'{"query":"substituted"}'),
    lambda r: r.headers.update({'prefer': 'wait=99'}),
])
def test_changed_prepared_request_is_not_recorded_as_the_original_capture(tmp_path, monkeypatch, mutate):
    _, adapter = install(monkeypatch)
    send = adapter.send
    def altered(self, request, **kwargs):
        response = send(self, request, **kwargs)
        mutate(response.request)
        return response
    monkeypatch.setattr(adapter, 'send', altered)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert not (tmp_path / 'capture/receipt.json').exists() and adapter.closed and adapter.response.raw.closed


@pytest.mark.parametrize('status', [204, 301, 302, 307, 400, 401, 403, 429, 500])
def test_http_failure_or_redirect_preserves_bounded_observations_without_a_replay_context(tmp_path, monkeypatch, status):
    raw, adapter = install(monkeypatch, raw=b'{"error":{"code":"synthetic-failure"}}', status=status)
    result = capture(tmp_path)
    folder = tmp_path / 'capture'
    assert result['status'] == 'FAILED' and not result['artifact_set_complete'] and result['collection_complete'] is False
    assert result['http_status'] == status and not result['request_context_bound']
    assert (folder / 'response.json').read_bytes() == raw
    observation = json.loads((folder / 'capture-observation.json').read_bytes())
    assert observation['schema'] == acquisition.OBSERVATION_SCHEMA and not observation['replay_context_available']
    assert observation['response']['status'] == status and len(adapter.sent) == 1
    assert not (folder / 'context.json').exists() and not (folder / 'projection.json').exists()


@pytest.mark.parametrize('raw,complete,error', [
    (b'', None, None), (b'not-json', None, None), (b'\xff', None, None), (b'{}', None, False),
    (b'{"tables":[],"tables":[]}', None, None), (b'{"tables":[],"error":null}', False, True),
    (b'{"tables":[],"error":{"code":"FatalError"}}', False, True),
    (b'{"tables":[{"name":"x","columns":[{"name":"a","type":"decimal"}],"rows":[[2]]}]}', None, False),
])
def test_unsupported_responses_retain_exact_bytes_and_explicit_unknown_or_incomplete_state(tmp_path, monkeypatch, raw, complete, error):
    install(monkeypatch, raw=raw)
    result = capture(tmp_path)
    assert result['status'] == 'FAILED' and not result['artifact_set_complete']
    assert result['collection_complete'] is complete and result['response_error_recorded'] is error
    assert (tmp_path / 'capture/response.json').read_bytes() == raw
    assert not (tmp_path / 'capture/projection.json').exists()


def test_empty_supported_results_stay_unknown(tmp_path, monkeypatch):
    install(monkeypatch, raw=b'{"tables":[]}')
    result = capture(tmp_path)
    assert result['status'] == 'CAPTURED' and result['row_count'] == 0 and result['collection_complete'] is None


@pytest.mark.parametrize('change', [
    lambda p: p.update(token=SYNTHETIC_TOKEN), lambda p: p.update(headers={'Authorization': 'secret'}),
    lambda p: p.update(url='https://elsewhere.invalid'), lambda p: p.update(command='run'),
    lambda p: p.pop('workspace_id'), lambda p: p.update(workspace_id=None),
    lambda p: p.update(workspace_id='not-a-guid'), lambda p: p.update(workspace_id='id/query?timespan=PT1H'),
    lambda p: p.pop('kql'), lambda p: p.update(kql=None), lambda p: p.update(kql=''),
    lambda p: p.update(kql='q\x00'), lambda p: p.update(timespan=None),
    lambda p: p.update(workspaces=['workspace-name']), lambda p: p.update(workspaces=['00000000-0000-0000-0000-000000000001'] * 33),
    lambda p: p.update(prefer='wait=30\r\nAuthorization: secret'), lambda p: p.update(client_request_id=[]),
])
def test_invalid_request_parameters_fail_before_network_and_output_creation(tmp_path, monkeypatch, change):
    _, adapter = install(monkeypatch)
    params = synthetic_params()
    change(params)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path, params)
    assert not adapter.sent and not (tmp_path / 'capture').exists()


@pytest.mark.parametrize('raw', [b'', b'[]', b'null', b'{}', b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}',
    b'{"a":9007199254740992}', b'{"a":"\\ud800"}', b'\xff', b'{} {}', b' ' * (128 * 1024 + 1)])
def test_parameter_documents_are_strict_and_bounded(tmp_path, monkeypatch, raw):
    _, adapter = install(monkeypatch)
    with pytest.raises(acquisition.CaptureError):
        acquisition.capture(raw, tmp_path / 'capture')
    assert not adapter.sent and not (tmp_path / 'capture').exists()


@pytest.mark.parametrize('key', ['kql', 'prefer', 'client_request_id'])
def test_configured_credential_cannot_be_copied_into_request_context(tmp_path, monkeypatch, key):
    _, adapter = install(monkeypatch)
    params = synthetic_params()
    params[key] = 'prefix-' + SYNTHETIC_TOKEN
    with pytest.raises(acquisition.CaptureError) as exc:
        capture(tmp_path, params)
    assert SYNTHETIC_TOKEN not in str(exc.value) and not adapter.sent and not (tmp_path / 'capture').exists()


@pytest.mark.parametrize('token', ['', 'bad token', 'bad\r\nHeader', 'é', 'x' * 16385])
def test_missing_invalid_or_excessive_credential_fails_before_acquisition(tmp_path, monkeypatch, token):
    _, adapter = install(monkeypatch)
    monkeypatch.setenv(acquisition.TOKEN_ENV, token)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert not adapter.sent and not (tmp_path / 'capture').exists()


@pytest.mark.parametrize('name,value', [('x-ms-request-id', SYNTHETIC_TOKEN), ('request-id', 'x' * 4097),
    ('x-request-id', 'bad\x00'), ('Content-Type', 'bad\r\nheader')])
def test_unsafe_selected_response_headers_never_enter_artifacts(tmp_path, monkeypatch, name, value):
    _, adapter = install(monkeypatch, headers={name: value})
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert list((tmp_path / 'capture').iterdir()) == [] and adapter.closed and adapter.response.raw.closed


@pytest.mark.parametrize('encoding', ['gzip', 'deflate', 'br', 'identity,gzip', ''])
def test_unsupported_content_encoding_fails_without_implicit_decoding(tmp_path, monkeypatch, encoding):
    _, adapter = install(monkeypatch, headers={'Content-Encoding': encoding})
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert not (tmp_path / 'capture/receipt.json').exists() and adapter.response.raw.closed


@pytest.mark.parametrize('length', ['-1', '+1', '1.0', '1, 1', '99999999999', str(8 * 1024 * 1024 + 1), ''])
def test_invalid_or_excessive_content_length_is_rejected_before_body_read(tmp_path, monkeypatch, length):
    _, adapter = install(monkeypatch, headers={'Content-Length': length})
    send = adapter.send
    def unread(self, request, **kwargs):
        response = send(self, request, **kwargs)
        response.raw.read = lambda *a, **k: pytest.fail('body read before length validation')
        return response
    monkeypatch.setattr(adapter, 'send', unread)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert adapter.closed and adapter.response.raw.closed


@pytest.mark.parametrize('delta', [-1, 1])
def test_body_length_mismatch_never_claims_a_complete_capture(tmp_path, monkeypatch, delta):
    raw = b'{"tables":[]}'
    install(monkeypatch, raw=raw, headers={'Content-Length': str(len(raw) + delta)})
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert not (tmp_path / 'capture/receipt.json').exists()


@pytest.mark.parametrize('extra', [0, 1])
def test_body_limit_is_enforced_without_content_length(tmp_path, monkeypatch, extra):
    raw = b'{"tables":[]}' + b' ' * extra
    _, adapter = install(monkeypatch, raw=raw)
    send = adapter.send
    def no_length(self, request, **kwargs):
        response = send(self, request, **kwargs)
        del response.headers['Content-Length']
        return response
    monkeypatch.setattr(adapter, 'send', no_length)
    monkeypatch.setattr(acquisition, 'MAX_INPUT_BYTES', len(raw) - extra)
    if extra:
        with pytest.raises(acquisition.CaptureError):
            capture(tmp_path)
        assert not (tmp_path / 'capture/receipt.json').exists()
    else:
        assert capture(tmp_path)['status'] == 'CAPTURED'


@pytest.mark.parametrize('error', [requests.exceptions.SSLError('private-transport-value'),
    requests.exceptions.ConnectionError('private-transport-value'), ReadTimeoutError(None, '/', 'private-transport-value')])
def test_transport_errors_are_redacted_and_close_adapter(tmp_path, monkeypatch, error):
    _, adapter = install(monkeypatch)
    def failed(*args, **kwargs):
        raise error
    monkeypatch.setattr(adapter, 'send', failed)
    with pytest.raises(acquisition.CaptureError) as exc:
        capture(tmp_path)
    assert 'private-transport-value' not in str(exc.value) and adapter.closed
    assert not (tmp_path / 'capture/receipt.json').exists()


def test_midstream_failure_closes_response_and_does_not_publish_partial_bytes_as_complete(tmp_path, monkeypatch):
    _, adapter = install(monkeypatch)
    send = adapter.send
    def broken(self, request, **kwargs):
        response = send(self, request, **kwargs)
        def fail(*args, **kwargs):
            raise ReadTimeoutError(None, '/', 'private-stream-content')
        response.raw.read = fail
        return response
    monkeypatch.setattr(adapter, 'send', broken)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert adapter.closed and adapter.response.raw.closed and not (tmp_path / 'capture/response.json').exists()


@pytest.mark.parametrize('kind', ['directory', 'file', 'symlink', 'dangling-symlink'])
def test_existing_output_targets_are_preserved_before_network(tmp_path, monkeypatch, kind):
    _, adapter = install(monkeypatch)
    output = tmp_path / 'capture'
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'existing').write_bytes(b'preserve')
    if kind == 'directory':
        output.mkdir()
        (output / 'existing').write_bytes(b'preserve')
    elif kind == 'file':
        output.write_bytes(b'preserve')
    else:
        output.symlink_to(target if kind == 'symlink' else tmp_path / 'missing', target_is_directory=True)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert not adapter.sent and (target / 'existing').read_bytes() == b'preserve'
    if kind == 'file':
        assert output.read_bytes() == b'preserve'
    elif kind == 'directory':
        assert (output / 'existing').read_bytes() == b'preserve'
    else:
        assert output.is_symlink()


@pytest.mark.parametrize('name', ['response.json', 'context.json', 'projection.json', 'receipt.pending.json'])
def test_member_write_failure_never_publishes_success_receipt(tmp_path, monkeypatch, name):
    install(monkeypatch)
    write = acquisition._write_new
    def fail(directory, filename, raw):
        if filename == name:
            raise OSError('synthetic write failure')
        return write(directory, filename, raw)
    monkeypatch.setattr(acquisition, '_write_new', fail)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert not (tmp_path / 'capture/receipt.json').exists()


def test_partial_write_and_interrupt_leave_no_complete_receipt(tmp_path, monkeypatch):
    install(monkeypatch)
    write = acquisition._write_new
    def interrupted(directory, name, raw):
        if name == 'context.json':
            write(directory, name, raw[:8])
            raise KeyboardInterrupt()
        return write(directory, name, raw)
    monkeypatch.setattr(acquisition, '_write_new', interrupted)
    with pytest.raises(KeyboardInterrupt):
        capture(tmp_path)
    assert not (tmp_path / 'capture/receipt.json').exists()
    assert (tmp_path / 'capture/context.json').stat().st_size == 8


def test_receipt_publication_does_not_replace_an_existing_file(tmp_path, monkeypatch):
    install(monkeypatch)
    link = os.link
    def blocked(source, destination):
        Path(destination).write_bytes(b'existing receipt')
        return link(source, destination)
    monkeypatch.setattr(acquisition.os, 'link', blocked)
    with pytest.raises(acquisition.CaptureError):
        capture(tmp_path)
    assert (tmp_path / 'capture/receipt.json').read_bytes() == b'existing receipt'
    assert (tmp_path / 'capture/receipt.pending.json').exists()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX permission bits')
def test_capture_directory_and_files_start_private(tmp_path, monkeypatch):
    install(monkeypatch)
    capture(tmp_path)
    folder = tmp_path / 'capture'
    assert folder.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in folder.iterdir())


@pytest.mark.parametrize('change', ['query', 'workspace', 'request-id', 'response'])
def test_captured_context_or_response_substitution_fails_signed_replay(tmp_path, monkeypatch, change):
    install(monkeypatch)
    capture(tmp_path)
    fixture = captured_case(tmp_path / 'case', tmp_path / 'capture')
    ctx = json.loads(fixture['context'])
    if change == 'query':
        ctx['request']['body']['query'] += ' | take 1'
    elif change == 'workspace':
        ctx['request']['body']['workspaces'] = []
    elif change == 'request-id':
        ctx['response']['headers']['request-id'] = 'changed-id'
    else:
        fixture['raw'] += b' '
    fixture['context'] = canonical_json_bytes(ctx)
    export_fixture(fixture)
    result = verify_case(fixture['package'], fixture['public'], replay_transforms=True)
    assert result['valid'] and result['reconstruction']['deterministic_replay']['status'] == 'FAIL'


def run_cli(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, 'argv', ['provider_collectors_v15.py', *map(str, args)])
    with pytest.raises(SystemExit) as exc:
        collectors.main()
    captured = capsys.readouterr()
    return exc.value.code, captured


@pytest.mark.parametrize('partial', [False, True])
def test_cli_explicit_capture_with_parameter_file_has_no_query_or_credentials_in_summary(tmp_path, monkeypatch, capsys, partial):
    install(monkeypatch, partial=partial)
    params = tmp_path / 'params.json'
    params.write_bytes(canonical_json_bytes(synthetic_params()))
    code, output = run_cli(monkeypatch, capsys, 'azure_foundry_logs', '--capture-context', '--params-file', params, '--out', tmp_path / 'capture')
    receipt = json.loads(output.out)
    assert code == 2 and receipt['status'] == 'CAPTURED' and not output.err
    assert SYNTHETIC_TOKEN not in output.out and 'SYNTHETIC-PRIVATE-CAPTURE-QUERY' not in output.out
    assert str(tmp_path) not in output.out and receipt['collection_complete'] is (False if partial else None)


@pytest.mark.parametrize('args', [
    ['aws_bedrock', '--capture-context'], ['azure_foundry_logs', '--capture-context', '--params-json', 'private-invalid-json'],
    ['azure_foundry_logs', '--capture-context', '--params-file', '/synthetic/missing-file'],
    ['azure_foundry_logs', '--capture-context', '--params-file', '/synthetic/missing-file', '--params-json', '{"extra":true}'],
])
def test_cli_bad_capture_arguments_are_redacted_and_do_not_acquire(tmp_path, monkeypatch, capsys, args):
    _, adapter = install(monkeypatch)
    code, output = run_cli(monkeypatch, capsys, *args, '--out', tmp_path / 'capture')
    assert code == 1 and json.loads(output.out)['artifact_set_complete'] is False and not output.err
    assert 'private-invalid-json' not in output.out and '/synthetic/missing-file' not in output.out
    assert not adapter.sent and not (tmp_path / 'capture').exists()


def test_legacy_response_only_cli_still_uses_existing_receipt_and_exit_contract(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(collectors, 'azure_foundry_logs', lambda **kwargs: ({'tables': []}, {'collection_complete': None}, []))
    code, output = run_cli(monkeypatch, capsys, 'azure_foundry_logs', '--out', tmp_path / 'response.json')
    receipt = json.loads(output.out)
    assert code == 2 and receipt['schema'] == 'ai-dfir/provider-collection-receipt/v1.5'
    assert receipt['collection_complete'] is False and (tmp_path / 'response.json').exists()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX FIFO')
def test_cli_fifo_parameter_file_is_rejected_without_network_or_blocking(tmp_path, monkeypatch, capsys):
    _, adapter = install(monkeypatch)
    pipe = tmp_path / 'pipe'
    os.mkfifo(pipe)
    code, output = run_cli(monkeypatch, capsys, 'azure_foundry_logs', '--capture-context', '--params-file', pipe, '--out', tmp_path / 'capture')
    assert code == 1 and json.loads(output.out)['status'] == 'FAILED' and not adapter.sent


def test_cli_interruption_has_nonzero_exit_and_no_complete_claim(tmp_path, monkeypatch, capsys):
    def interrupted(*args):
        raise KeyboardInterrupt()
    monkeypatch.setattr(acquisition, 'capture', interrupted)
    code, output = run_cli(monkeypatch, capsys, 'azure_foundry_logs', '--capture-context', '--out', tmp_path / 'capture')
    assert code == 130 and json.loads(output.out) == {'status': 'INTERRUPTED', 'artifact_set_complete': False}


def test_captured_projection_is_reproducible_directly(tmp_path, monkeypatch):
    install(monkeypatch)
    capture(tmp_path)
    folder = tmp_path / 'capture'
    compared = compare_replay((folder / 'response.json').read_bytes(), (folder / 'projection.json').read_bytes(),
                              context_raw=(folder / 'context.json').read_bytes(), input_format='workspace-post')
    assert compared['status'] == 'PASS' and compared['request_context_bound'] and not compared['query_execution_verified']
