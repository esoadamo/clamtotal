"""initial schema: scans table

Revision ID: 0001_initial
Revises:
Create Date: 2025-01-01 00:00:00

"""

import sqlalchemy as sa

from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("sha256", sa.String(64), primary_key=True),
        sa.Column("md5", sa.String(32), nullable=False),
        sa.Column("sha1", sa.String(40), nullable=False),
        sa.Column("file_name", sa.String(512), nullable=False),
        sa.Column("size", sa.Integer, nullable=False),
        sa.Column("file_type", sa.String(128), nullable=False),
        sa.Column("magic_hex", sa.String(64), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("signature", sa.String(256), nullable=True),
        sa.Column("engine", sa.String(128), nullable=False),
        sa.Column("urls", sa.JSON, nullable=False),
        sa.Column("raw_output", sa.Text, nullable=True),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scans_md5", "scans", ["md5"])
    op.create_index("ix_scans_sha1", "scans", ["sha1"])


def downgrade() -> None:
    op.drop_index("ix_scans_sha1", table_name="scans")
    op.drop_index("ix_scans_md5", table_name="scans")
    op.drop_table("scans")
