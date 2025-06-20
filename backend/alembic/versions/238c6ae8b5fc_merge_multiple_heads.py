"""Merge multiple heads

Revision ID: 238c6ae8b5fc
Revises: def456789abc, 0302dda856c9
Create Date: 2025-06-19 20:39:26.979913

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "238c6ae8b5fc"
down_revision = ("def456789abc", "0302dda856c9")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
