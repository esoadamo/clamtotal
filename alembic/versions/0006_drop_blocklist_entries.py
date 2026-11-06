"""move the domain feed out of the app database (feed.db is separate now)

Revision ID: 0006_drop_feed_from_app_db
Revises: 0005_url_blocklists
Create Date: 2025-01-07 00:00:00

"""

from alembic import op

revision: str = "0006_drop_feed_from_app_db"
down_revision: str | None = "0005_url_blocklists"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # the feed entries now live in the feed daemon's own database (feed.db), not here
    op.drop_table("blocklist_entries")


def downgrade() -> None:
    import sqlalchemy as sa

    op.create_table(
        "blocklist_entries",
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("domain", "source"),
    )
