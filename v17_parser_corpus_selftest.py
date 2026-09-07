"""Pinned deterministic campaign for all twelve synthetic parser profiles."""
from __future__ import annotations

import json

from v17_parser_corpus import run_campaign

EXPECTED_CORPUS = "46862fe63d5a6023297894928161a35fa402ec6e521506dd5c13efc24ce7e5d6"
EXPECTED_OUTCOMES = "3f36fc1181e9cda17b02d10bfb9200272a1de295167356f27fa0330d56d26188"


def main():
    report = run_campaign()
    assert report["status"] == "PASS" and report["failure_count"] == 0
    assert report["profile_count"] == 12 and report["case_count"] == 3318
    assert report["corpus_sha256"] == EXPECTED_CORPUS and report["outcome_sha256"] == EXPECTED_OUTCOMES
    print(json.dumps({"status": "PASS", "profile_count": 12, "cases": 3318,
                      "corpus_sha256": EXPECTED_CORPUS, "outcome_sha256": EXPECTED_OUTCOMES,
                      "network_performed": False, "exhaustive": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
