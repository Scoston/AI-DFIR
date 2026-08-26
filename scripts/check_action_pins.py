from pathlib import Path
import re
import sys

WORKFLOW_DIR = Path(".github/workflows")
LOCAL_ACTION_DIR = Path(".github/actions")

USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
PINNED_RE = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")


def candidate_files():
    for path in sorted(WORKFLOW_DIR.glob("*")):
        if path.suffix in {".yml", ".yaml"}:
            yield path

    if LOCAL_ACTION_DIR.exists():
        for path in sorted(LOCAL_ACTION_DIR.rglob("*")):
            if path.name in {"action.yml", "action.yaml"}:
                yield path


def main() -> int:
    failures = []
    external_refs = 0

    for path in candidate_files():
        text = path.read_text(encoding="utf-8-sig")

        for line_number, line in enumerate(text.splitlines(), start=1):
            match = USES_RE.match(line)
            if not match:
                continue

            reference = match.group(1)

            # Repository-local actions do not require a remote commit SHA.
            if reference.startswith("./"):
                continue

            external_refs += 1

            if not PINNED_RE.fullmatch(reference):
                failures.append(
                    f"{path}:{line_number}: unpinned action reference: {reference}"
                )

    if failures:
        print("GitHub Actions SHA pin check: FAIL")
        for failure in failures:
            print(f"  {failure}")
        return 1

    print(
        f"GitHub Actions SHA pin check: PASS "
        f"({external_refs} external references pinned)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
