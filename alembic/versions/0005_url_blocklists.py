"""url/domain scanning: blocklist entries + url scan cache

Revision ID: 0005_url_blocklists
Revises: 0004_alternative_names
Create Date: 2025-01-06 00:00:00

"""

import sqlalchemy as sa

from alembic import op

revision: str = "0005_url_blocklists"
down_revision: str | None = "0004_alt_names"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "blocklist_entries",
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("domain", "source"),
    )
    op.create_table(
        "url_scans",
        sa.Column("url_id", sa.String(128), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("matches", sa.JSON(), nullable=True),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("url_id"),
    )
    op.create_index("ix_url_scans_host", "url_scans", ["host"])


def downgrade() -> None:
    op.drop_index("ix_url_scans_host", table_name="url_scans")
    op.drop_table("url_scans")
    op.drop_table("blocklist_entries")
