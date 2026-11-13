"""add ephemeral flag to scans (delete-once-viewed uploads)

Revision ID: 0007_scan_ephemeral
Revises: 0006_drop_feed_from_app_db
Create Date: 2025-01-03 00:00:00

"""

import sqlalchemy as sa

from alembic import op

revision: str = "0007_scan_ephemeral"
down_revision: str | None = "0006_drop_feed_from_app_db"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("ephemeral", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("scans", "ephemeral")
