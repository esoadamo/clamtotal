"""add names column (alternative file names per hash) for relations

Revision ID: 0004_alt_names
Revises: 0003_scan_status
Create Date: 2025-01-04 00:00:00

"""

import sqlalchemy as sa

from alembic import op

revision: str = "0004_alt_names"
down_revision: str | None = "0003_scan_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("names", sa.JSON, nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "names")
