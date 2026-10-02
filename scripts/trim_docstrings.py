#!/usr/bin/env python3
"""Collapse multi-paragraph docstrings to their summary line.

Coding standard for this repository: a docstring states *what* a thing is, in one
line. The *why* lives in ``docs/`` and the ADRs, and only genuinely surprising
inline comments stay in the code.

Mechanically, because doing it by hand across a few thousand lines is both slow
and inconsistent. Operates on exact line ranges located with ``ast``, so it
cannot corrupt code, and it is idempotent.

    python scripts/trim_docstrings.py app/db/seed.py app/core/storage.py ...

Use ``--check`` to report without writing, and ``--dry-run`` to preview.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
import sys

#: Sections kept even when the rest is collapsed, because they are structural
#: rather than expository.
KEPT_SECTIONS = ("Args:", "Returns:", "Yields:", "Raises:")


def _summary(docstring: str) -> str:
    """First paragraph, collapsed to one line, with any kept sections appended."""
    lines = docstring.expandtabs().splitlines()
    if not lines:
        return ""

    head = lines[0].strip()
    if not head.endswith((".", "!", "?")):
        head = f"{head}." if head else ""

    kept: list[str] = []
    collecting = False
    for raw in lines[1:]:
        stripped = raw.strip()
        if not stripped:
            collecting = False
            continue
        is_header = stripped.rstrip(":") in [s.rstrip(":") for s in KEPT_SECTIONS]
        if is_header:
            kept.append(stripped)
            collecting = True
            continue
        if collecting:
            kept.append(stripped)

    return " ".join([head, *kept]) if kept else head


def _docstring_line_ranges(tree: ast.AST) -> list[tuple[int, int, str]]:
    """Return ``(start_line, end_line, summary)`` for every docstring, 1-based."""
    ranges: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        doc = ast.get_docstring(node, clean=False)
        if not doc:
            continue
        body = node.body[0]
        assert isinstance(body, ast.Expr), "docstring must be a bare string expression"
        start = body.lineno - 1  # the opening quotes line
        end = body.end_lineno  # inclusive, 1-based
        summary = _summary(ast.get_docstring(node, clean=False) or "")
        if summary:
            ranges.append((start, end, summary))
    return ranges


def trim(path: Path, *, check: bool, dry_run: bool) -> int:
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    ranges = _docstring_line_ranges(ast.parse(source))

    replacements: list[tuple[int, int, str]] = []
    for start, end, summary in ranges:
        block = lines[start:end]
        if len(block) <= 1:
            continue
        indent = len(block[0]) - len(block[0].lstrip())
        summary = " ".join(summary.split())
        if len(summary) + indent + 3 > 100:
            summary = summary[: 97 - indent] + "..."
        quoted = f'"""{summary}"""'
        if block[-1].strip().endswith('"""') and block[-1].strip() != '"""':
            quoted = f'"""{summary}"""'
        replacements.append((start, end, " " * indent + quoted))

    if not replacements:
        return 0

    for start, end, text in sorted(replacements, reverse=True):
        lines[start:end] = [text]

    result = "\n".join(lines) + ("\n" if source.endswith("\n") else "")
    if check:
        print(f"{path}: {len(replacements)} docstring(s) could be trimmed")
        return len(replacements)
    if dry_run:
        print("\n".join(f"  {text}" for _, _, text in sorted(replacements)))
        return len(replacements)

    path.write_text(result, encoding="utf-8")
    print(f"{path}: trimmed {len(replacements)} docstring(s)")
    return len(replacements)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.paths:
        parser.error("no files given")

    total = 0
    for path in args.paths:
        total += trim(path, check=args.check, dry_run=args.dry_run)
    print(f"total: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
