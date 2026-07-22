"""Add name column to route

Revision ID: 7c9e3af1c8a2
Revises: 3bfd13c165c0
Create Date: 2025-09-11 13:45:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7c9e3af1c8a2"
down_revision: Union[str, Sequence[str], None] = "3bfd13c165c0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add as NOT NULL with a server default to backfill existing rows automatically
    op.add_column(
        "route",
        sa.Column("name", sa.String(length=128), nullable=False, server_default=""),
    )
    # Drop the default so future inserts must explicitly provide a value
    op.alter_column(
        "route", "name", server_default=None, existing_type=sa.String(length=128)
    )


def downgrade() -> None:
    op.drop_column("route", "name")
