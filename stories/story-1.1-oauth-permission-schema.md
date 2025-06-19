# Story 1.1: Database Schema for OAuth Permissions

## 📊 Story Overview

**Story ID**: 1.1  
**Priority**: P0 - Critical Foundation  
**Estimate**: 2 days  
**Sprint**: 1 (Week 1)  
**Dependencies**: None  
**Assignee**: TBD  

## 🎯 Description

Create minimal database schema to track OAuth permissions granted through Okta groups. This is the foundation for the entire OAuth authorization system and must be deployed first.

## ✅ Acceptance Criteria

### Database Changes
- [ ] New `OAuthPermission` table created via Alembic migration
- [ ] Table includes all required fields with proper types
- [ ] Database indexes created on `user_id` and `permission_level` for performance
- [ ] Migration is backwards compatible (no existing data affected)
- [ ] Foreign key relationship to existing `User` table

### Code Changes  
- [ ] SQLAlchemy model added to `backend/onyx/db/models.py`
- [ ] Model properly integrated with existing user management
- [ ] Type hints and documentation added

### Testing
- [ ] Unit tests for database model created
- [ ] Migration test (up/down) works correctly
- [ ] Performance test for index usage

### Deployment
- [ ] Migration runs successfully on test database
- [ ] Existing authentication flows remain unaffected
- [ ] Database connection pool handles new table

## 🔧 Technical Implementation

### Files to Modify

#### 1. Create Migration File
**Path**: `backend/alembic/versions/xxx_add_oauth_permission_table.py`

```python
"""Add OAuth permission tracking table

Revision ID: xxx
Revises: [previous_revision]
Create Date: 2024-01-XX XX:XX:XX.XXXXXX
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = 'xxx'
down_revision = '[previous_revision]'
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
```

#### 2. Add SQLAlchemy Model
**Path**: `backend/onyx/db/models.py`

Add this class to the existing models:

```python
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

class OAuthPermission(SQLAlchemyBaseUserTable):
    """
    Track OAuth-granted permissions from Okta groups.
    
    This table stores permissions granted to users through OAuth providers
    (primarily Okta) based on their group memberships.
    """
    __tablename__ = "oauth_permission"
    
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="user.id", nullable=False)
    permission_level: str = Field(max_length=20, nullable=False)  # 'read', 'write', 'admin'
    granted_by: str = Field(max_length=50, nullable=False)  # 'okta_groups', 'manual', etc.
    okta_groups: Optional[str] = Field(default=None)  # JSON string of Okta groups
    granted_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    is_active: bool = Field(default=True, nullable=False)
    
    # Relationship to User table
    user: "User" = Relationship(back_populates="oauth_permissions")

    class Config:
        table = True
        
    def __repr__(self) -> str:
        return f"<OAuthPermission(user_id={self.user_id}, level={self.permission_level})>"
```

#### 3. Update User Model
**Path**: `backend/onyx/db/models.py`

Add this relationship to the existing `User` class:

```python
# Add this to the User class
oauth_permissions: List["OAuthPermission"] = Relationship(back_populates="user")
```

### Permission Levels

The system will use these three permission levels:

- **`read`**: Can view content and basic operations
- **`write`**: Can create, edit, and manage content  
- **`admin`**: Full administrative access

### Okta Groups Integration

The `okta_groups` field will store JSON data like:
```json
["onyx-users", "onyx-admins", "content-creators"]
```

## 🧪 Testing Requirements

### Unit Tests
**Path**: `backend/tests/unit/test_oauth_permission_model.py`

```python
import pytest
from datetime import datetime
from uuid import uuid4
from onyx.db.models import OAuthPermission, User

def test_oauth_permission_creation():
    """Test creating OAuth permission record"""
    user_id = uuid4()
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="write",
        granted_by="okta_groups",
        okta_groups='["onyx-users", "content-creators"]'
    )
    
    assert permission.user_id == user_id
    assert permission.permission_level == "write"
    assert permission.is_active == True
    assert permission.granted_at is not None

def test_oauth_permission_repr():
    """Test string representation"""
    user_id = uuid4()
    permission = OAuthPermission(
        user_id=user_id,
        permission_level="admin",
        granted_by="okta_groups"
    )
    
    expected = f"<OAuthPermission(user_id={user_id}, level=admin)>"
    assert repr(permission) == expected
```

### Migration Tests
**Path**: `backend/tests/integration/test_oauth_permission_migration.py`

```python
import pytest
from alembic import command
from alembic.config import Config

def test_oauth_permission_migration_up_down():
    """Test migration can be applied and reversed"""
    # Test upgrade
    config = Config("alembic.ini")
    command.upgrade(config, "head")
    
    # Verify table exists
    # Add verification logic
    
    # Test downgrade
    command.downgrade(config, "-1")
    
    # Verify table removed
    # Add verification logic
```

## 🚀 Deployment Checklist

### Pre-deployment
- [ ] Code review completed
- [ ] All tests passing
- [ ] Migration tested on staging database
- [ ] Performance impact assessed

### Deployment Steps
1. [ ] Deploy migration to staging environment
2. [ ] Verify existing auth flows work
3. [ ] Run performance tests on indexes
4. [ ] Deploy to production during maintenance window
5. [ ] Monitor database performance post-deployment

### Post-deployment Verification
- [ ] Table created successfully
- [ ] Indexes are being used (check query execution plans)
- [ ] No impact on existing user authentication
- [ ] Application logs show no new errors

### Rollback Plan
If issues occur:
1. Run migration downgrade: `alembic downgrade -1`
2. Verify existing functionality restored
3. Investigate and fix issues before re-deployment

## 📋 Definition of Done

- [ ] All acceptance criteria met
- [ ] Code reviewed and approved
- [ ] Unit tests written and passing
- [ ] Integration tests passing
- [ ] Migration tested on staging
- [ ] Performance impact assessed
- [ ] Documentation updated
- [ ] Deployed to production successfully
- [ ] Post-deployment verification completed

## 🔗 Related Stories

**Next Stories**:
- Story 1.2: Okta Token Parsing and Group Extraction
- Story 1.3: Basic Permission Checking Infrastructure

**Dependencies**:
- None (this is the foundation story)

## 📝 Notes

- This story establishes the data foundation for the entire OAuth authorization system
- The simple three-level permission model replaces the complex scope-based approach from the original plan
- The `okta_groups` field is stored as JSON text for flexibility
- Indexes are crucial for performance as this table will be queried frequently
- The migration must be backwards compatible to ensure zero-downtime deployment

## 🐛 Known Risks

1. **Database Performance**: New table will be queried on every request - indexes are critical
2. **Migration Timing**: Should be deployed during low-traffic period
3. **Backwards Compatibility**: Must not break existing authentication flows

## 💡 Success Metrics

- Migration completes in under 5 seconds
- No errors in application logs post-deployment
- Database query performance remains under 10ms for permission checks
- 100% test coverage for new model code
