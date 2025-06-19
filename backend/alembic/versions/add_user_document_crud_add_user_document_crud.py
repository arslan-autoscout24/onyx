"""Add UserDocument table for CRUD operations

Revision ID: add_user_document_crud
Revises: ffc707a226b4
Create Date: 2024-12-19 16:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "add_user_document_crud"
down_revision = "ffc707a226b4" 
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    # Create the user_document table
    op.create_table(
        'user_document',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('content', sa.Text(), nullable=False, default=''),
        sa.Column('is_public', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['created_by'], ['user.id'], ),
        sa.ForeignKeyConstraint(['updated_by'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for performance
    op.create_index('ix_user_document_created_by', 'user_document', ['created_by'])
    op.create_index('ix_user_document_is_public', 'user_document', ['is_public'])
    op.create_index('ix_user_document_created_at', 'user_document', ['created_at'])
    op.create_index('ix_user_document_title', 'user_document', ['title'])


def downgrade() -> None:
    # Drop indexes
    op.drop_index('ix_user_document_title', table_name='user_document')
    op.drop_index('ix_user_document_created_at', table_name='user_document')
    op.drop_index('ix_user_document_is_public', table_name='user_document')
    op.drop_index('ix_user_document_created_by', table_name='user_document')
    
    # Drop table
    op.drop_table('user_document')
