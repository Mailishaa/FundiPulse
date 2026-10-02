#!/usr/bin/env python3
"""Generate the Mermaid ERD from live SQLAlchemy metadata.

Deriving the diagram from ``Base.metadata`` rather than maintaining it by hand
means the documentation cannot silently drift away from the schema. Run it after
any schema change:

    python scripts/generate_erd.py

Optionally write the result straight into ``docs/data-model.md`` between the
``<!-- ERD:BEGIN -->`` / ``<!-- ERD:END -->`` markers:

    python scripts/generate_erd.py --write
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import MetaData  # noqa: E402

from app.db.base import Base  # noqa: E402
import app.db.models  # noqa: E402,F401

DOC_PATH = REPO_ROOT / "docs" / "data-model.md"
BEGIN_MARKER = "<!-- ERD:BEGIN -->"
END_MARKER = "<!-- ERD:END -->"

#: Tables grouped for readability. Anything not listed falls into "other".
GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Identity & access", ("users", "refresh_sessions", "security_tokens")),
    ("Organizations", ("organizations", "organization_memberships")),
    (
        "Controlled catalogues",
        ("trades", "skills", "counties"),
    ),
    (
        "Work passport",
        (
            "worker_profiles",
            "worker_trades",
            "worker_skills",
            "worker_preferred_counties",
            "work_experiences",
            "projects",
            "credentials",
            "worker_references",
        ),
    ),
    ("Files & evidence", ("files", "evidence_items")),
    (
        "Verification",
        ("verification_requests", "verifications"),
    ),
    (
        "Jobs & applications",
        (
            "job_sources",
            "jobs",
            "job_skills",
            "job_source_events",
            "job_applications",
        ),
    ),
    ("Trust & safety", ("audit_logs", "reports", "notification_events")),
)

#: Relations that are worth drawing but that add clutter when auto-expanded.
_SKIP_RELATION_TABLES: frozenset[str] = frozenset()


_TYPE_MAP: dict[str, str] = {
    "UUID": "uuid",
    "BOOLEAN": "bool",
    "INTEGER": "int",
    "BIGINT": "bigint",
    "DATETIME": "datetime",
    "INET": "inet",
    "JSONB": "jsonb",
    "DATE": "date",
    "NUMERIC": "numeric",
    "TEXT": "text",
    "FLOAT": "float",
}


def _md_type(column: object) -> str:
    """Render a column type in a Mermaid-friendly way.

    Any variable-length string type collapses to ``string``: the exact length is
    an implementation detail that makes the diagram harder to read, and the
    authoritative definition is the migration, not the picture.
    """
    raw = str(getattr(column, "type", "")).upper().replace(" ", "")
    if raw.startswith(("VARCHAR(", "CHAR(", "TEXT")):
        return "string"
    if raw.startswith("NUMERIC("):
        return "numeric"
    return _TYPE_MAP.get(raw, raw.lower() or "string")


def _column_marker(column: object, pk_columns: set[str]) -> str:
    """Return the Mermaid key marker (``PK`` / ``FK``) for a column."""
    is_pk = column.name in pk_columns
    is_fk = bool(list(getattr(column, "foreign_keys", [])))
    if is_pk and is_fk:
        return "PK,FK"
    if is_pk:
        return "PK"
    return "FK" if is_fk else ""


def _render_table(name: str, table: object) -> list[str]:
    """Emit one Mermaid ``erDiagram`` entity."""
    pk = getattr(table, "primary_key", None)
    pk_columns = {c.name for c in pk.columns} if pk is not None else set()
    lines = [f"    {name} {{"]
    for column in table.columns:
        marker = _column_marker(column, pk_columns)
        rendered = f"        {_mermaid_type(_md_type(column))} {column.name} {marker}".rstrip()
        lines.append(rendered)
    lines.append("    }")
    return lines


def _mermaid_type(rendered: str) -> str:
    """Mermaid entity attribute types cannot contain punctuation."""
    return rendered.replace("(", "_").replace(")", "").replace(",", "_")


def _collect_relations() -> list[str]:
    """Emit relationship lines from foreign keys."""
    lines: list[str] = []
    for table_name in sorted(Base.metadata.tables):
        table = Base.metadata.tables[table_name]
        if table_name in _SKIP_RELATION_TABLES:
            continue
        for constraint in sorted(table.foreign_key_constraints, key=lambda c: str(c.elements)):
            for element in constraint.elements:
                target = element.column.table.name
                parent = element.parent
                # Cardinality is always one-to-many from the referenced side.
                lines.append(f'    {target} "1" ||--|.. {table_name} "{parent.name}"')
    return sorted(set(lines))


def generate() -> str:
    """Build the full Mermaid ERD document."""
    metadata: MetaData = Base.metadata
    all_names = set(metadata.tables)
    grouped: set[str] = set()
    out: list[str] = ["```mermaid", "erDiagram"]

    for title, tables in GROUPS:
        present = [t for t in tables if t in all_names]
        if not present:
            continue
        out.append(f"    %% {title}")
        for table_name in present:
            out.extend(_render_table(table_name, metadata.tables[table_name]))
            grouped.add(table_name)

    others = sorted(all_names - grouped)
    if others:
        out.append("    %% Other")
        for table_name in others:
            out.extend(_render_table(table_name, metadata.tables[table_name]))

    out.append("")
    out.extend(_collect_relations())
    out.append("```")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help=f"Replace the ERD block in {DOC_PATH.relative_to(REPO_ROOT)}.",
    )
    args = parser.parse_args()

    diagram = generate()
    if args.write:
        doc = DOC_PATH.read_text(encoding="utf-8")
        if BEGIN_MARKER not in doc or END_MARKER not in doc:
            print(
                f"error: {DOC_PATH} must contain {BEGIN_MARKER} and {END_MARKER}",
                file=sys.stderr,
            )
            return 1
        head, rest = doc.split(BEGIN_MARKER, 1)
        _, tail = rest.split(END_MARKER, 1)
        DOC_PATH.write_text(
            f"{head}{BEGIN_MARKER}\n{diagram}\n{END_MARKER}{tail}", encoding="utf-8"
        )
        print(f"wrote ERD into {DOC_PATH.relative_to(REPO_ROOT)}")
    else:
        print(diagram)
    return 0


if __name__ == "__main__":
    sys.exit(main())
