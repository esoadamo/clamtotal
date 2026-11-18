"""indexed relation tables for instant report pages

Rewrites how the report page finds related files: instead of loading every scan
row (plus its JSON columns) and intersecting IOCs in Python, the Relations tab
now joins two indexed association tables. This migration also backfills them
from existing scans, so previously scanned files open instantly too.

Revision ID: 0009_scan_relation_tables
Revises: 0008_scan_entropy
Create Date: 2025-01-05 00:00:00

"""

import json

import sqlalchemy as sa

from alembic import op

revision: str = "0009_scan_relation_tables"
down_revision: str | None = "0008_scan_entropy"
branch_labels = None
depends_on = None

_TOKEN_MAX = 255


def upgrade() -> None:
    op.create_table(
        "scan_iocs",
        sa.Column("sha256", sa.String(64), primary_key=True),
        sa.Column("token", sa.String(255), primary_key=True),
    )
    op.create_index("ix_scan_iocs_token", "scan_iocs", ["token"])
    op.create_table(
        "scan_embedded",
        sa.Column("parent_sha256", sa.String(64), primary_key=True),
        sa.Column("child_sha256", sa.String(64), primary_key=True),
    )
    op.create_index("ix_scan_embedded_child_sha256", "scan_embedded", ["child_sha256"])

    conn = op.get_bind()
    iocs_rows = conn.execute(sa.text("SELECT sha256, iocs FROM scans WHERE iocs IS NOT NULL"))
    ioc_batch: list[dict] = []
    for sha256, iocs_json in iocs_rows:
        try:
            iocs = json.loads(iocs_json) if iocs_json else {}
        except (TypeError, ValueError):
            iocs = {}
        tokens = {
            v[:_TOKEN_MAX] for values in (iocs or {}).values() for v in values if isinstance(v, str)
        }
        ioc_batch.extend({"sha256": sha256, "token": t} for t in sorted(tokens))
        if len(ioc_batch) >= 50_000:
            conn.execute(
                sa.text("INSERT INTO scan_iocs (sha256, token) VALUES (:sha256, :token)"),
                ioc_batch,
            )
            ioc_batch = []
    if ioc_batch:
        conn.execute(
            sa.text("INSERT INTO scan_iocs (sha256, token) VALUES (:sha256, :token)"),
            ioc_batch,
        )

    embedded_rows = conn.execute(
        sa.text("SELECT sha256, embedded FROM scans WHERE embedded IS NOT NULL")
    )
    child_batch: list[dict] = []
    for sha256, embedded_json in embedded_rows:
        try:
            embedded = json.loads(embedded_json) if embedded_json else []
        except (TypeError, ValueError):
            embedded = []
        children = {
            c.get("sha256")
            for c in embedded or []
            if isinstance(c, dict) and isinstance(c.get("sha256"), str)
        }
        child_batch.extend({"parent_sha256": sha256, "child_sha256": c} for c in sorted(children))
        if len(child_batch) >= 50_000:
            conn.execute(
                sa.text(
                    "INSERT INTO scan_embedded (parent_sha256, child_sha256) "
                    "VALUES (:parent_sha256, :child_sha256)"
                ),
                child_batch,
            )
            child_batch = []
    if child_batch:
        conn.execute(
            sa.text(
                "INSERT INTO scan_embedded (parent_sha256, child_sha256) "
                "VALUES (:parent_sha256, :child_sha256)"
            ),
            child_batch,
        )


def downgrade() -> None:
    op.drop_table("scan_embedded")
    op.drop_table("scan_iocs")
