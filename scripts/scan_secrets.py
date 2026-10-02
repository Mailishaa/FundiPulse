#!/usr/bin/env python3
"""Secret scanner for this repository.

Runs before commit and in CI. Uses ``detect-secrets`` when available and falls
back to a built-in pattern scan when it is not, so the guard never silently
disappears because a dependency failed to install.

What it protects against, concretely:

* a real ``.env`` being committed,
* an API key, JWT secret, database password, cloud credential or private key
  appearing anywhere in the tree,
* a new high-entropy string being introduced without review.

Exit codes: ``0`` clean, ``1`` findings, ``2`` scanner error.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE = REPO_ROOT / ".secrets.baseline"

#: Paths that are expected to contain example credentials. Anything NOT in this
#: list that looks like a credential is a finding.
ALLOWED_EXAMPLE_FILES: frozenset[Path] = frozenset(
    {
        REPO_ROOT / ".env.example",
        REPO_ROOT / "docker-compose.yml",
        REPO_ROOT / ".secrets.baseline",
    }
)

#: Files never scanned: binary, vendored, or generated.
SKIP_SUFFIXES: frozenset[str] = frozenset(
    {".pyc", ".so", ".png", ".jpg", ".jpeg", ".pdf", ".zip", ".gz", ".whl"}
)
#: Test suites legitimately contain fake credentials ("password" fixtures). The
#: generic ``assigned_secret`` pattern is relaxed there, but the *specific* key
#: shapes (private keys, AWS/GitHub/Slack/Stripe/Google keys) are still enforced,
#: so a genuine credential pasted into a test is still a finding.
TEST_PATH_MARKERS: tuple[Path, ...] = (REPO_ROOT / "tests",)

SKIP_DIRS: frozenset[str] = frozenset(
    {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache"}
)

#: Assigns a high-entropy or credential-shaped value. Deliberately conservative
#: about what counts, because a scanner that cries wolf gets disabled.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "assigned_secret",
        re.compile(
            r"(?i)\b(secret|passwd|password|token|api[_-]?key|private[_-]?key|"
            r"access[_-]?key|db[_-]?password)\b\s*[:=]\s*"
            r"['\"]([A-Za-z0-9+/=_-]{20,})['\"]"
        ),
    ),
)


def _iter_files() -> list[Path]:
    """Every scannable file in the repository."""
    results: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        results.append(path)
    return results


def scan_with_detect_secrets() -> tuple[bool, str]:
    """Run detect-secrets against the baseline. Returns (ok, output)."""
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "detect_secrets",
                "scan",
                "--baseline",
                str(BASELINE),
                "--all-files",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return True, "detect-secrets not installed; ran pattern scan only."

    if completed.returncode != 0:
        return False, completed.stdout + completed.stderr
    return True, completed.stdout or "detect-secrets: no new findings."


def scan_with_patterns() -> list[str]:
    """Built-in scan. Returns a list of human-readable findings."""
    findings: list[str] = []

    real_env = REPO_ROOT / ".env"
    if real_env.exists():
        findings.append(
            f"BLOCKER: {real_env.relative_to(REPO_ROOT)} exists and must never be committed."
        )

    for path in _iter_files():
        relative = path
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        for name, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                matched = match.group(0)
                is_example_file = path in ALLOWED_EXAMPLE_FILES
                is_test_file = any(
                    REPO_ROOT in path.parents and marker in path.parents
                    for marker in TEST_PATH_MARKERS
                )

                # Concrete key shapes are findings everywhere, including examples
                # and tests. A real credential does not become safe because it
                # sits next to a placeholder.
                if name in {
                    "private_key",
                    "aws_access_key",
                    "github_token",
                    "slack_token",
                    "stripe_key",
                    "google_api_key",
                }:
                    findings.append(
                        f"{relative}: {name} - rotate this credential: {matched[:24]}..."
                    )
                    continue

                if is_example_file or is_test_file:
                    # Generic "assigned_secret" only; expected in these files.
                    continue
                if _is_documented_placeholder(matched):
                    continue
                findings.append(f"{relative}: possible {name} -> {matched[:40]}")
    return findings


def _is_documented_placeholder(value: str) -> bool:
    """Treat obvious filler as harmless.

    A scanner that flags every placeholder trains people to add blanket
    suppressions, which is how real secrets end up baselined later.
    """
    lowered = value.lower()
    markers = (
        "replace-me",
        "changeme",
        "change-me",
        "your-",
        "your_",
        "placeholder",
        "example",
        "xxxx",
        "not-used-anywhere",
        "dummy",
        "todo",
        "<",
    )
    return any(marker in lowered for marker in markers)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON for tooling.")
    args = parser.parse_args()

    ok, detector_output = scan_with_detect_secrets()
    findings = scan_with_patterns()

    if args.json:
        print(
            json.dumps(
                {
                    "detect_secrets_ok": ok,
                    "detect_secrets_output": detector_output,
                    "pattern_findings": findings,
                },
                indent=2,
            )
        )
        return 0 if (ok and not findings) else 1

    print(detector_output.strip())

    if findings:
        print("\nPOSSIBLE SECRETS FOUND:")
        for finding in findings:
            print(f"  - {finding}")
        print(
            "\nIf a finding is a false positive, remove the value rather than "
            "suppressing the scan. A real credential that reached git history "
            "must be ROTATED, not just deleted."
        )
        return 1

    if not ok:
        print("\nSecret scan FAILED.")
        return 1

    print("\nSecret scan clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
