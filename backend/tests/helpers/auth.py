import jwt
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from onyx.db.engine import get_async_session
from onyx.db.models import User, OAuthPermission, PermissionLevel


def create_okta_jwt_token(email: str, groups: List[str], expires_in: int = 3600) -> str:
    """Create a valid JWT token for testing."""
    now = datetime.utcnow()
    payload = {
        "iss": "https://test-org.okta.com/oauth2/default",
        "aud": "test_audience",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        "sub": f"test_user_{email}",
        "email": email,
        "groups": groups,
        "preferred_username": email
    }
    
    # Use test secret for JWT signing
    return jwt.encode(payload, "test_secret", algorithm="HS256")


def create_invalid_jwt_token() -> str:
    """Create an invalid JWT token for testing."""
    return "invalid.jwt.token"


def create_expired_jwt_token(email: str, groups: List[str]) -> str:
    """Create an expired JWT token for testing."""
    return create_okta_jwt_token(email, groups, expires_in=-3600)


def create_test_user_with_groups(email: str, groups: List[str]) -> Dict[str, Any]:
    """Create a test user with specific group memberships."""
    return {
        "email": email,
        "groups": groups,
        "token": create_okta_jwt_token(email, groups)
    }


def create_modified_jwt_token(email: str, groups: List[str]) -> str:
    """Create a JWT token and then modify it to make it invalid."""
    valid_token = create_okta_jwt_token(email, groups)
    # Modify the token payload by changing the last 10 characters
    modified_token = valid_token[:-10] + "modified123"
    return modified_token


def create_malicious_jwt_token(email: str, malicious_groups: List[str]) -> str:
    """Create a JWT token with potentially malicious group claims."""
    return create_okta_jwt_token(email, malicious_groups)


async def cleanup_test_data():
    """Clean up test data after each test."""
    try:
        async with get_async_session() as db_session:
            # Clean up test users and permissions
            # This is a placeholder - implement based on actual database schema
            await db_session.execute("DELETE FROM oauth_permissions WHERE email LIKE '%@test.com'")
            await db_session.execute("DELETE FROM users WHERE email LIKE '%@test.com'")
            await db_session.commit()
    except Exception as e:
        # Log error but don't fail tests
        print(f"Warning: Failed to cleanup test data: {e}")


async def create_test_user_in_db(
    email: str, 
    groups: List[str], 
    permission_level: Optional[str] = None
) -> User:
    """Create a test user in the database with specified permissions."""
    async with get_async_session() as db_session:
        # Create user if doesn't exist
        user = User(email=email)
        db_session.add(user)
        await db_session.flush()
        
        # Determine permission level from groups if not specified
        if not permission_level:
            if "Onyx-Admins" in groups:
                permission_level = "admin"
            elif "Onyx-Writers" in groups:
                permission_level = "write"
            elif "Onyx-Readers" in groups:
                permission_level = "read"
            else:
                permission_level = "read"  # default
        
        # Create OAuth permission
        oauth_permission = OAuthPermission(
            user_id=user.id,
            permission_level=PermissionLevel(permission_level),
            okta_groups=groups
        )
        db_session.add(oauth_permission)
        
        await db_session.commit()
        await db_session.refresh(user)
        return user


def get_test_users_data() -> List[Dict[str, Any]]:
    """Get standard test user configurations."""
    return [
        {
            "email": "admin@test.com",
            "groups": ["Onyx-Admins", "Onyx-Writers", "Onyx-Readers"],
            "expected_permission": "admin"
        },
        {
            "email": "writer@test.com", 
            "groups": ["Onyx-Writers", "Onyx-Readers"],
            "expected_permission": "write"
        },
        {
            "email": "reader@test.com",
            "groups": ["Onyx-Readers"],
            "expected_permission": "read"
        },
        {
            "email": "no-groups@test.com",
            "groups": [],
            "expected_permission": "read"  # default fallback
        }
    ]


class MockOktaResponse:
    """Mock Okta API responses for testing."""
    
    @staticmethod
    def successful_token_response(email: str, groups: List[str]) -> Dict[str, Any]:
        return {
            "access_token": create_okta_jwt_token(email, groups),
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid email groups"
        }
    
    @staticmethod
    def invalid_code_response() -> Dict[str, Any]:
        return {
            "error": "invalid_grant",
            "error_description": "Invalid authorization code"
        }
    
    @staticmethod
    def expired_token_response() -> Dict[str, Any]:
        return {
            "error": "invalid_token",
            "error_description": "Token has expired"
        }
