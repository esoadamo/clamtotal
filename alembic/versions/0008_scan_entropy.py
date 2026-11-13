"""add cached entropy column to scans (compute once at scan time)

Revision ID: 0008_scan_entropy
Revises: 0007_scan_ephemeral
Create Date: 2025-01-04 00:00:00

"""

import sqlalchemy as sa

from alembic import op

revision: str = "0008_scan_entropy"
down_revision: str | None = "0007_scan_ephemeral"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("entropy", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "entropy")
