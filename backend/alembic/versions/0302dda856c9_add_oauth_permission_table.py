"""Add OAuth permission tracking table

Revision ID: 0302dda856c9
Revises: 495cb26ce93e
Create Date: 2025-06-08 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '0302dda856c9'
down_revision = '495cb26ce93e'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Create oauth_permission table
    op.create_table(
        'oauth_permission',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('permission_level', sa.String(20), nullable=False),
        sa.Column('granted_by', sa.String(50), nullable=False),
        sa.Column('okta_groups', sa.Text(), nullable=True),
        sa.Column('granted_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
    )
    
    # Create indexes for performance
    op.create_index('idx_oauth_permission_user_id', 'oauth_permission', ['user_id'])
    op.create_index('idx_oauth_permission_level', 'oauth_permission', ['permission_level'])
    op.create_index('idx_oauth_permission_active', 'oauth_permission', ['is_active'])

def downgrade() -> None:
    op.drop_table('oauth_permission')