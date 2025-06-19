import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session
from onyx.db.engine import get_session_context_manager


def test_oauth_permission_table_exists():
    """Test that oauth_permission table exists after migration"""
    with get_session_context_manager() as db_session:
        # Check if table exists
        result = db_session.execute(
            text("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'oauth_permission'")
        )
        table_count = result.scalar()
        assert table_count == 1, "oauth_permission table should exist"


def test_oauth_permission_table_structure():
    """Test that oauth_permission table has correct columns"""
    with get_session_context_manager() as db_session:
        # Check table columns
        result = db_session.execute(
            text("""
                SELECT column_name, data_type, is_nullable 
                FROM information_schema.columns 
                WHERE table_name = 'oauth_permission'
                ORDER BY column_name
            """)
        )
        columns = result.fetchall()
        
        expected_columns = {
            'id': ('uuid', 'NO'),
            'user_id': ('uuid', 'NO'),
            'permission_level': ('character varying', 'NO'),
            'granted_by': ('character varying', 'NO'),
            'okta_groups': ('text', 'YES'),
            'granted_at': ('timestamp with time zone', 'NO'),
            'is_active': ('boolean', 'NO')
        }
        
        actual_columns = {col[0]: (col[1], col[2]) for col in columns}
        
        for col_name, (expected_type, expected_nullable) in expected_columns.items():
            assert col_name in actual_columns, f"Column {col_name} should exist"
            actual_type, actual_nullable = actual_columns[col_name]
            assert actual_nullable == expected_nullable, f"Column {col_name} nullable mismatch"


def test_oauth_permission_indexes_exist():
    """Test that performance indexes are created"""
    with get_session_context_manager() as db_session:
        # Check for indexes
        result = db_session.execute(
            text("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename = 'oauth_permission'
                AND indexname LIKE 'idx_%'
            """)
        )
        indexes = [row[0] for row in result.fetchall()]
        
        expected_indexes = [
            'idx_oauth_permission_user_id',
            'idx_oauth_permission_level',
            'idx_oauth_permission_active'
        ]
        
        for expected_index in expected_indexes:
            assert expected_index in indexes, f"Index {expected_index} should exist"


def test_oauth_permission_foreign_key():
    """Test that foreign key constraint to user table exists"""
    with get_session_context_manager() as db_session:
        # Check foreign key constraint
        result = db_session.execute(
            text("""
                SELECT 
                    tc.constraint_name,
                    kcu.column_name,
                    ccu.table_name AS foreign_table_name,
                    ccu.column_name AS foreign_column_name,
                    rc.delete_rule
                FROM information_schema.table_constraints AS tc 
                JOIN information_schema.key_column_usage AS kcu
                  ON tc.constraint_name = kcu.constraint_name
                  AND tc.table_schema = kcu.table_schema
                JOIN information_schema.constraint_column_usage AS ccu
                  ON ccu.constraint_name = tc.constraint_name
                  AND ccu.table_schema = tc.table_schema
                JOIN information_schema.referential_constraints AS rc
                  ON tc.constraint_name = rc.constraint_name
                WHERE tc.constraint_type = 'FOREIGN KEY' 
                AND tc.table_name = 'oauth_permission'
                AND kcu.column_name = 'user_id'
            """)
        )
        fk_info = result.fetchone()
        
        assert fk_info is not None, "Foreign key constraint should exist"
        assert fk_info[2] == 'user', "Should reference user table"
        assert fk_info[3] == 'id', "Should reference user.id column"
        assert fk_info[4] == 'CASCADE', "Should have CASCADE delete rule"


def test_oauth_permission_crud_operations():
    """Test basic CRUD operations on oauth_permission table"""
    with get_session_context_manager() as db_session:
        # First, create a test user
        user_result = db_session.execute(
            text("""
                INSERT INTO "user" (id, email, hashed_password, is_active, is_superuser, is_verified, role)
                VALUES (gen_random_uuid(), 'test@example.com', 'hashed', true, false, true, 'BASIC')
                RETURNING id
            """)
        )
        user_id = user_result.scalar()
        
        try:
            # Insert oauth permission
            permission_result = db_session.execute(
                text("""
                    INSERT INTO oauth_permission (id, user_id, permission_level, granted_by, okta_groups, granted_at, is_active)
                    VALUES (gen_random_uuid(), :user_id, 'write', 'okta_groups', '["test-group"]', NOW(), true)
                    RETURNING id, permission_level, granted_by
                """),
                {'user_id': user_id}
            )
            permission_id, level, granted_by = permission_result.fetchone()
            
            assert level == 'write'
            assert granted_by == 'okta_groups'
            
            # Read the permission
            select_result = db_session.execute(
                text("SELECT permission_level, is_active FROM oauth_permission WHERE id = :perm_id"),
                {'perm_id': permission_id}
            )
            perm_data = select_result.fetchone()
            assert perm_data[0] == 'write'
            assert perm_data[1] == True
            
            # Update the permission
            db_session.execute(
                text("UPDATE oauth_permission SET is_active = false WHERE id = :perm_id"),
                {'perm_id': permission_id}
            )
            
            # Verify update
            updated_result = db_session.execute(
                text("SELECT is_active FROM oauth_permission WHERE id = :perm_id"),
                {'perm_id': permission_id}
            )
            assert updated_result.scalar() == False
            
            # Delete the permission
            db_session.execute(
                text("DELETE FROM oauth_permission WHERE id = :perm_id"),
                {'perm_id': permission_id}
            )
            
            # Verify deletion
            count_result = db_session.execute(
                text("SELECT COUNT(*) FROM oauth_permission WHERE id = :perm_id"),
                {'perm_id': permission_id}
            )
            assert count_result.scalar() == 0
            
        finally:
            # Clean up test user
            db_session.execute(
                text("DELETE FROM \"user\" WHERE id = :user_id"),
                {'user_id': user_id}
            )
            db_session.commit()