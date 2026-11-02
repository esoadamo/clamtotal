"""add scan status column (pending/done) for async scanning

Revision ID: 0003_scan_status
Revises: 0002_analysis_fields
Create Date: 2025-01-03 00:00:00

"""

import sqlalchemy as sa

from alembic import op

revision: str = "0003_scan_status"
down_revision: str | None = "0002_analysis_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("status", sa.String(16), nullable=False, server_default="done"),
    )


def downgrade() -> None:
    op.drop_column("scans", "status")
