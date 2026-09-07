#!/usr/bin/env python3
"""Synthetic bounded archive acceptance and deterministic hostile mutations."""
from __future__ import annotations

import base64
import io
import json
import random
import socket
import stat
import subprocess
import tarfile
import zipfile
from contextlib import ExitStack
from unittest.mock import patch

from v17_archive_intake import FORMATS, inspect_archive
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_provenance import ProvenanceError

COMPRESSED_SEEDS = {
    'tar-gzip': 'H4sIAAAAAAACA+3XTW7DIBRGUcZZhVeAHw4xK2ilSN0Esl8UVNdYgJumq68bVY2UDKIMcKP6OxMsTxigy0+0O5bpI4mMaFITnUa6HolUdf4+/TeaNqIgMYMxJhumKcUyxWOf9pxcsxKwQFKWHBs75NwE7u5fkdIV+kf/kL3/ZgzRhzKMHUf51j5I/8bg/Ef/kF3PMXErP93wh/f/qr68/xut0P8s6+9TEfj7EHDv3B2LwYbILbpYis71r7nnuNn/5bcirbQoqulx8vs+Qf95zv+9bf2hfN6+PGV7Ad5e//XV+ps19v85+J4FLNdP/zvX8SP1X6P/eaSDRwQAAAAAAAAA/9wXyQRVwQAoAAA=',
    'tar-bzip2': 'QlpoOTFBWSZTWf34i5YAAUZfgcuwQAH/gAMkbURvb9/wAIAIGDAA+NsIk0TyNBomCMEwABNqYIMpqajaIaNMQGENDammTQyARSVNkZTyTNTNTR6j1AG1DQHqHqZdvu9/CWGoZwhYJ63PxC8KEAbNlu2JW+y1LqFn3RszkpLMtKqQCxvYXHln6P65j5v2vNNjBFl48iA6VsWQoGHl44bzz0KB0t0UESkncyRThyr6DmFoMaKCbGEuMzpiCg3bU1gJtG+gTkt8FYTS7DDUCIQNFCy+5PIKnEZMoFASxeVFT8dHc+4kSyFgMxvQn8LEKJSrLK8YLaspE65szkFOkDSzM2sNFxkZQGuk503VNF6Af4u5IpwoSH78RcsA',
    'tar-xz': '/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4Cf/AQNdADmYSQaa5zjZBNMLIrlETD3/vTcNjCRdrYASJKwV/7qIpWwIgJRilDlZ4Jp2lAGH3SsSu2YiYN9eTiCdc0/s/aXbHIxKd4ydMqwpQvvlb28U2KYENHPC9fYjGhmWBx7sSt9lNqgHTUGobxoO+AZhaL46eJNMTQjSHuBYxkP/NrTRtyZdQXo2xBd2gtHoADtSHPDJgAheCYe/K5U7eWOFxcWsdbbO4TGLhiu2BrmHzXHuAWTvBQYNvV1Xaov9YIuisT9Er5z5hvROZ5ILma11/18N6MthbZFPZ4tD3t3wckbO1xXM1/6xq4gHavxwOm5s2B6JmraIOk9999cWKUyYH1NsMQAAAHoRKJaA/Nw1AAGfAoBQAACgu0DUscRn+wIAAAAABFla',
}

SEED = 17018
MUTATIONS = 128
ENTRIES = (
    ("safe.txt", "file", b"synthetic\n", ""),
    ("../escape.txt", "file", b"synthetic\n", ""),
    (".cursor/rules.md", "file", b"synthetic\n", ""),
    ("nested.zip", "file", b"not recursively parsed", ""),
    ("link", "symlink", b"", "../../escape"),
    ("shadow/FILE.txt", "file", b"one", ""),
    ("shadow/file.txt", "file", b"two", ""),
)


def zip_seed(entries=ENTRIES):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, kind, raw, link in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = stat.S_IFLNK if kind == "symlink" else stat.S_IFDIR if kind == "directory" else stat.S_IFREG
            info.external_attr = (mode | 0o600) << 16
            archive.writestr(info, link.encode() if kind == "symlink" else raw)
    return target.getvalue()


def tar_seed(entries=ENTRIES, *, format=tarfile.USTAR_FORMAT):
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w", format=format) as archive:
        for name, kind, raw, link in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o600
            info.mtime = 0
            info.type = {"file": tarfile.REGTYPE, "symlink": tarfile.SYMTYPE,
                         "hardlink": tarfile.LNKTYPE, "directory": tarfile.DIRTYPE,
                         "fifo": tarfile.FIFOTYPE}[kind]
            info.linkname = link
            info.size = len(raw) if kind == "file" else 0
            archive.addfile(info, io.BytesIO(raw) if kind == "file" else None)
    return target.getvalue()


def seeds():
    tar = tar_seed()
    return {"zip": zip_seed(), "tar": tar, **{key: base64.b64decode(value, validate=True) for key, value in COMPRESSED_SEEDS.items()}}


def _outcome(raw, selected):
    try:
        report = inspect_archive(raw, input_format=selected)
        assert report["source_sha256"] == sha256_bytes(raw)
        assert report["member_count"] == len(report["members"])
        assert report["metadata_only"] is True and report["collection_complete"] is None
        for flag in ("members_extracted", "member_payload_integrity_verified", "source_authenticity_verified",
                     "archive_safety_verified", "extraction_authorized", "network_required"):
            assert report[flag] is False
        return "ACCEPT", sha256_bytes(canonical_json_bytes(report))
    except ProvenanceError:
        return "REJECT", None


def campaign(*, mutations=MUTATIONS):
    """Fixed synthetic inputs only; failed invariants/crashes propagate."""
    if type(mutations) is not int or not 0 <= mutations <= 2048:
        raise ValueError("invalid archive mutation count")
    retained = seeds()  # Construct fixtures before disabling all member I/O.
    outcomes, corpus, accepted, rejected = [], [], 0, 0
    with ExitStack() as guard:
        for owner, name in ((socket.socket, "connect"), (socket, "create_connection"), (socket, "getaddrinfo"),
                            (subprocess, "Popen"), (zipfile.ZipFile, "open"), (zipfile.ZipFile, "extract"),
                            (zipfile.ZipFile, "extractall"), (tarfile.TarFile, "extractfile"),
                            (tarfile.TarFile, "extract"), (tarfile.TarFile, "extractall")):
            guard.enter_context(patch.object(owner, name, side_effect=AssertionError("external/member action forbidden")))
        for selected in FORMATS:
            raw = retained[selected]
            cases = [(raw, "ACCEPT"), (b"", "REJECT"), (raw[:16], "REJECT"), (raw[:-1], "REJECT"),
                     (b"prefix" + raw, "REJECT"), (raw + b"suffix", "REJECT"), (raw + raw, "REJECT"),
                     (bytes([raw[0] ^ 128]) + raw[1:], "REJECT")]
            rng = random.Random(SEED + FORMATS.index(selected))
            for _ in range(mutations):
                candidate = bytearray(raw)
                for _ in range(rng.randint(1, 4)):
                    candidate[rng.randrange(len(candidate))] = rng.randrange(256)
                cases.append((bytes(candidate), None))
            for ordinal, (data, expected) in enumerate(cases):
                first = _outcome(data, selected)
                assert first == _outcome(data, selected), "nondeterministic archive inspection"
                assert expected is None or first[0] == expected, "incorrect archive seed expectation"
                accepted += first[0] == "ACCEPT"; rejected += first[0] == "REJECT"
                corpus.append([selected, ordinal, sha256_bytes(data)])
                outcomes.append([selected, ordinal, *first])
    return {"status": "PASS", "profiles": len(FORMATS), "cases": len(corpus), "seed": SEED,
            "accepted": accepted, "rejected": rejected, "corpus_sha256": sha256_bytes(canonical_json_bytes(corpus)),
            "outcomes_sha256": sha256_bytes(canonical_json_bytes(outcomes)), "network_required": False,
            "member_content_apis_blocked": True, "coverage_guided": False, "exhaustive": False}


def main():
    report = campaign()
    assert report["cases"] == 680 and report["accepted"] >= 5 and report["rejected"] >= 35
    assert report["corpus_sha256"] == "a22b595655eb1b8b536cee3c4efa8544d0c4c0dafba1427a069349cb545e00e9"
    assert report["outcomes_sha256"] == "ea08648021310f6781a975e4529f64a3083e177c4e5fd0daef2210d0d60b07e1"
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
