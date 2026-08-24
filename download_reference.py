#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from huggingface_hub import HfApi, snapshot_download


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--revision", required=True,
                    help="Use the full approved commit SHA for forensic reference acquisition.")
    ap.add_argument("--out", required=True)
    ap.add_argument("--token", default=None)
    args = ap.parse_args()

    if len(args.revision) < 40:
        raise SystemExit("For forensic use, provide the full commit SHA, not a short hash or moving branch.")

    api = HfApi(token=args.token)
    info = api.model_info(args.repo, revision=args.revision)

    resolved = info.sha
    if resolved != args.revision:
        print(f"Requested revision resolved to: {resolved}")

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    path = snapshot_download(
        repo_id=args.repo,
        revision=args.revision,
        local_dir=str(out),
        token=args.token,
    )

    provenance = {
        "repo_id": args.repo,
        "requested_revision": args.revision,
        "resolved_commit_sha": resolved,
        "snapshot_path": path,
    }
    (out / "FORENSIC_REFERENCE_PROVENANCE.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps(provenance, indent=2))


if __name__ == "__main__":
    main()
