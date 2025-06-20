"""Merge all remaining heads

Revision ID: 60d9c38417be
Revises: 238c6ae8b5fc, add_user_document_crud
Create Date: 2025-06-19 18:48:21.987370

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '60d9c38417be'
down_revision = ('238c6ae8b5fc', 'add_user_document_crud')
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
