"""add offline-analysis fields (engines, iocs, behavior, embedded, sha512, crc32)

Revision ID: 0002_analysis_fields
Revises: 0001_initial
Create Date: 2025-01-02 00:00:00

"""

import sqlalchemy as sa

from alembic import op

revision: str = "0002_analysis_fields"
down_revision: str | None = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("sha512", sa.String(128), nullable=True))
    op.add_column("scans", sa.Column("crc32", sa.String(8), nullable=True))
    op.add_column("scans", sa.Column("engines", sa.JSON, nullable=True))
    op.add_column("scans", sa.Column("iocs", sa.JSON, nullable=True))
    op.add_column("scans", sa.Column("behavior", sa.JSON, nullable=True))
    op.add_column("scans", sa.Column("embedded", sa.JSON, nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "embedded")
    op.drop_column("scans", "behavior")
    op.drop_column("scans", "iocs")
    op.drop_column("scans", "engines")
    op.drop_column("scans", "crc32")
    op.drop_column("scans", "sha512")
