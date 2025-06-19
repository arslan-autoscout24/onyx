"""
Basic validation tests for permission management API.

These tests verify that the new permission management endpoints
are properly configured and can handle basic requests.
"""
import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from uuid import uuid4
from datetime import datetime

from onyx.main import get_application
from onyx.db.models import User, OAuthPermission, PermissionLevel


@pytest.fixture
def client():
    """Create a test client for the application."""
    app = get_application()
    return TestClient(app)


@pytest.fixture
def mock_admin_user():
    """Create a mock admin user."""
    user = Mock(spec=User)
    user.id = uuid4()
    user.email = "admin@test.com"
    return user


@pytest.fixture
def mock_regular_user():
    """Create a mock regular user."""
    user = Mock(spec=User)
    user.id = uuid4()
    user.email = "user@test.com"
    return user


@pytest.fixture
def mock_oauth_permission():
    """Create a mock OAuth permission."""
    permission = Mock(spec=OAuthPermission)
    permission.permission_level = PermissionLevel.READ
    permission.okta_groups = ["Onyx-Readers"]
    permission.granted_at = datetime.utcnow()
    permission.updated_at = datetime.utcnow()
    permission.source = "okta"
    permission.is_active = True
    return permission


def test_permissions_router_exists():
    """Test that the permissions router is properly imported."""
    from onyx.server.auth.permissions import router
    assert router is not None
    assert router.prefix == "/auth"


def test_permission_level_enum():
    """Test that PermissionLevel enum is properly defined."""
    from onyx.db.models import PermissionLevel
    
    assert PermissionLevel.READ == "read"
    assert PermissionLevel.WRITE == "write"
    assert PermissionLevel.ADMIN == "admin"


@patch('onyx.auth.users.current_user')
@patch('onyx.db.oauth_permissions.get_user_oauth_permission')
def test_get_current_user_permissions_endpoint_exists(
    mock_get_permission,
    mock_current_user,
    client,
    mock_regular_user,
    mock_oauth_permission
):
    """Test that the get current user permissions endpoint is accessible."""
    mock_current_user.return_value = mock_regular_user
    mock_get_permission.return_value = mock_oauth_permission
    
    # This should not raise an import error or 404
    response = client.get("/api/auth/permissions")
    
    # We expect some response, even if it's an auth error
    assert response.status_code in [200, 401, 403, 422]


@patch('onyx.server.auth_check.require_admin')
@patch('onyx.db.oauth_permissions.get_permission_summary')
def test_admin_permissions_summary_endpoint_exists(
    mock_get_summary,
    mock_require_admin,
    client,
    mock_admin_user
):
    """Test that the admin permissions summary endpoint is accessible."""
    mock_require_admin.return_value = mock_admin_user
    mock_get_summary.return_value = {
        "read": 5,
        "write": 3,
        "admin": 1,
        "no_oauth_permission": 2
    }
    
    # This should not raise an import error or 404
    response = client.get("/api/auth/admin/permissions/summary")
    
    # We expect some response, even if it's an auth error
    assert response.status_code in [200, 401, 403, 422]


def test_oauth_permissions_database_functions_exist():
    """Test that required database functions are importable."""
    from onyx.db.oauth_permissions import (
        get_user_oauth_permission,
        get_all_users_with_permissions,
        get_permission_history,
        log_permission_change,
        get_user_by_id,
        get_user_by_email
    )
    
    # Functions should be callable
    assert callable(get_user_oauth_permission)
    assert callable(get_all_users_with_permissions)
    assert callable(get_permission_history)
    assert callable(log_permission_change)
    assert callable(get_user_by_id)
    assert callable(get_user_by_email)


def test_permission_history_model_exists():
    """Test that PermissionHistory model is properly defined."""
    from onyx.db.models import PermissionHistory
    
    # Should be able to create the class
    assert PermissionHistory is not None
    assert hasattr(PermissionHistory, '__tablename__')
    assert PermissionHistory.__tablename__ == "permission_history"


def test_pydantic_models_exist():
    """Test that Pydantic models are properly defined."""
    from onyx.server.auth.permissions import (
        UserPermissionResponse,
        PermissionHistoryEntry,
        PermissionUpdate,
        BulkPermissionUpdate,
        PermissionSummary
    )
    
    # All models should be importable
    assert UserPermissionResponse is not None
    assert PermissionHistoryEntry is not None
    assert PermissionUpdate is not None
    assert BulkPermissionUpdate is not None
    assert PermissionSummary is not None


if __name__ == "__main__":
    pytest.main([__file__])
