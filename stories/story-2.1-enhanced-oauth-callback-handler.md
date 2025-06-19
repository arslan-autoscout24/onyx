# Story 2.1: Enhanced OAuth Callback Handler

## 📊 Story Overview

**Story ID**: 2.1  
**Priority**: P0 - Critical  
**Estimate**: 2 days  
**Sprint**: 2 (Week 2)  
**Dependencies**: Stories 1.1, 1.2, 1.3  
**Assignee**: TBD  

## 🎯 Description

Enhance existing OAuth callback to process Okta groups and grant permissions. This story integrates the Okta token parser with the OAuth login flow to automatically assign permissions based on user's group memberships during authentication.

## ✅ Acceptance Criteria

### OAuth Callback Enhancement
- [ ] Enhanced `oauth_callback` method in `OAuthUserManager`
- [ ] Okta group processing only triggered for OIDC provider
- [ ] Permission granted/updated based on Okta groups in JWT token
- [ ] Backwards compatible with existing OAuth flow
- [ ] Error handling for token parsing failures
- [ ] Integration tests with mock Okta responses

### Security & Reliability
- [ ] Graceful fallback when token parsing fails
- [ ] Logging for security events and permission changes
- [ ] No impact on non-Okta OAuth providers (Google, etc.)
- [ ] Proper error boundaries to prevent login failures

### Performance
- [ ] OAuth login flow remains fast (<2 seconds additional processing)
- [ ] Token parsing doesn't block the authentication process
- [ ] Efficient database operations for permission updates

## 🔧 Technical Implementation

### Files to Modify

#### 1. Enhanced OAuth User Manager
**Path**: `backend/onyx/auth/users.py` (enhancement)

```python
# Add these imports at the top
from onyx.auth.okta_parser import OktaTokenParser, parse_okta_token_for_permissions
from onyx.db.oauth_permissions import update_user_oauth_permission
import logging

logger = logging.getLogger(__name__)

class OAuthUserManager(BaseUserManager[User, UUID]):
    """Enhanced OAuth User Manager with Okta group processing"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.okta_parser = OktaTokenParser()
    
    async def oauth_callback(
        self,
        oauth_name: str,
        access_token: str,
        account_id: str,
        account_email: str,
        expires_at: Optional[int] = None,
        refresh_token: Optional[str] = None,
        request: Optional[Request] = None,
        *,
        associate_by_email: bool = False,
        is_verified_by_default: bool = False,
    ) -> User:
        """
        Enhanced OAuth callback with Okta group processing.
        
        This method extends the base OAuth callback to process Okta groups
        and automatically assign permissions based on group memberships.
        """
        logger.info(f"OAuth callback for provider: {oauth_name}, user: {account_email}")
        
        try:
            # Call the existing OAuth callback logic
            user = await super().oauth_callback(
                oauth_name=oauth_name,
                access_token=access_token,
                account_id=account_id,
                account_email=account_email,
                expires_at=expires_at,
                refresh_token=refresh_token,
                request=request,
                associate_by_email=associate_by_email,
                is_verified_by_default=is_verified_by_default,
            )
            
            # Process Okta groups for OIDC provider only
            if oauth_name == 'oidc' and access_token:
                logger.info(f"Processing Okta groups for user {user.id}")
                await self._process_okta_groups(user, access_token)
            else:
                logger.debug(f"Skipping group processing for provider: {oauth_name}")
            
            return user
            
        except Exception as e:
            logger.error(f"Error in OAuth callback for {oauth_name}: {str(e)}")
            # Re-raise the exception to maintain existing error handling
            raise
    
    async def _process_okta_groups(self, user: User, access_token: str) -> None:
        """
        Process Okta groups from access token and update user permissions.
        
        Args:
            user: The authenticated user
            access_token: JWT access token from Okta
        """
        try:
            # Parse token and extract permission level
            permission_level, okta_groups = parse_okta_token_for_permissions(access_token)
            
            logger.info(
                f"Extracted permission '{permission_level}' from groups {okta_groups} for user {user.id}"
            )
            
            # Update user's OAuth permissions in database
            await update_user_oauth_permission(
                user_id=user.id,
                permission_level=permission_level,
                okta_groups=okta_groups,
                granted_by="okta_groups"
            )
            
            logger.info(f"Successfully updated OAuth permissions for user {user.id}")
            
        except Exception as e:
            logger.error(f"Failed to process Okta groups for user {user.id}: {str(e)}")
            # Don't raise exception - we don't want to break login for permission processing failures
            # User will get default 'read' permission from the permission service
    
    async def _handle_token_parsing_error(self, user: User, error: Exception) -> None:
        """
        Handle token parsing errors gracefully.
        
        Args:
            user: The authenticated user
            error: The exception that occurred during token parsing
        """
        logger.warning(
            f"Token parsing failed for user {user.id}, they will have default permissions: {str(error)}"
        )
        
        # Could optionally create a default permission record here
        # For now, we rely on the permission service's fallback behavior
```

#### 2. Enhanced OAuth Configuration
**Path**: `backend/onyx/auth/oauth.py` (enhancement if exists, or create)

```python
"""
OAuth configuration enhancements for Okta group processing.
"""
from onyx.configs.app_configs import OAUTH_PERMISSIONS_ENABLED

# Feature flag for OAuth permission processing
PROCESS_OKTA_GROUPS = OAUTH_PERMISSIONS_ENABLED and True

def should_process_okta_groups(oauth_name: str) -> bool:
    """
    Determine if we should process Okta groups for this OAuth provider.
    
    Args:
        oauth_name: Name of the OAuth provider
        
    Returns:
        True if groups should be processed, False otherwise
    """
    return PROCESS_OKTA_GROUPS and oauth_name == 'oidc'
```

#### 3. Configuration Updates
**Path**: `backend/onyx/configs/app_configs.py` (enhancement)

Add these configuration options:

```python
# OAuth Permissions Configuration
OAUTH_PERMISSIONS_ENABLED = env.bool("OAUTH_PERMISSIONS_ENABLED", default=False)
OKTA_GROUP_PROCESSING_ENABLED = env.bool("OKTA_GROUP_PROCESSING_ENABLED", default=True)
OAUTH_PERMISSION_LOGGING_LEVEL = env.str("OAUTH_PERMISSION_LOGGING_LEVEL", default="INFO")
```

#### 4. Error Handling and Monitoring
**Path**: `backend/onyx/auth/oauth_monitoring.py` (new file)

```python
"""
Monitoring and metrics for OAuth permission processing.
"""
import logging
from typing import Dict, Any
from datetime import datetime
from uuid import UUID

logger = logging.getLogger(__name__)

class OAuthPermissionMonitor:
    """Monitor OAuth permission processing events"""
    
    @staticmethod
    def log_permission_grant(
        user_id: UUID, 
        permission_level: str, 
        okta_groups: list, 
        processing_time_ms: float
    ) -> None:
        """Log successful permission grant"""
        logger.info(
            f"OAuth permission granted - User: {user_id}, Level: {permission_level}, "
            f"Groups: {okta_groups}, Processing time: {processing_time_ms:.2f}ms"
        )
    
    @staticmethod
    def log_permission_error(
        user_id: UUID, 
        error: str, 
        access_token_preview: str = None
    ) -> None:
        """Log permission processing error"""
        token_info = f", Token preview: {access_token_preview[:20]}..." if access_token_preview else ""
        logger.error(f"OAuth permission error - User: {user_id}, Error: {error}{token_info}")
    
    @staticmethod
    def log_oauth_callback_start(oauth_name: str, account_email: str) -> None:
        """Log start of OAuth callback processing"""
        logger.debug(f"OAuth callback started - Provider: {oauth_name}, Email: {account_email}")
    
    @staticmethod
    def log_oauth_callback_complete(oauth_name: str, user_id: UUID, had_groups: bool) -> None:
        """Log completion of OAuth callback"""
        groups_processed = "with groups" if had_groups else "without groups"
        logger.info(f"OAuth callback completed - Provider: {oauth_name}, User: {user_id}, {groups_processed}")
```

### Updated OAuth Flow Diagram

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   User Login    │───▶│  Okta OAuth      │───▶│   JWT Token with    │
│   via Okta      │    │  Authorization   │    │   Groups Claim      │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
                                                          │
                                                          ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│  User Created/  │◀───│   Enhanced       │◀───│  Parse Token &      │
│  Updated in DB  │    │ OAuth Callback   │    │  Extract Groups     │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
          │                       │                       │
          ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│ OAuth Permission│    │   Error Handling │    │  Permission Level   │
│ Record Created  │    │  & Monitoring    │    │   Determination     │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
```

## 🧪 Testing Requirements

### Unit Tests
**Path**: `backend/tests/unit/auth/test_enhanced_oauth_callback.py`

```python
"""
Unit tests for enhanced OAuth callback handler.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from uuid import uuid4

from onyx.auth.users import OAuthUserManager
from onyx.db.models import User


class TestEnhancedOAuthCallback:
    
    def setup_method(self):
        """Set up test fixtures"""
        self.oauth_manager = OAuthUserManager(MagicMock(), MagicMock())
        self.test_user = User(
            id=uuid4(),
            email="test@example.com",
            is_active=True,
            is_superuser=False,
            is_verified=True
        )
    
    @pytest.mark.asyncio
    async def test_oauth_callback_with_okta_groups(self):
        """Test OAuth callback with Okta group processing"""
        access_token = "mock.jwt.token"
        
        with patch.object(self.oauth_manager.__class__.__bases__[0], 'oauth_callback') as mock_super:
            mock_super.return_value = self.test_user
            
            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse:
                mock_parse.return_value = ("admin", ["Onyx-Admins"])
                
                with patch('onyx.auth.users.update_user_oauth_permission') as mock_update:
                    result = await self.oauth_manager.oauth_callback(
                        oauth_name="oidc",
                        access_token=access_token,
                        account_id="123",
                        account_email="test@example.com"
                    )
                    
                    assert result == self.test_user
                    mock_parse.assert_called_once_with(access_token)
                    mock_update.assert_called_once_with(
                        user_id=self.test_user.id,
                        permission_level="admin",
                        okta_groups=["Onyx-Admins"],
                        granted_by="okta_groups"
                    )
    
    @pytest.mark.asyncio
    async def test_oauth_callback_non_okta_provider(self):
        """Test OAuth callback with non-Okta provider (should skip group processing)"""
        with patch.object(self.oauth_manager.__class__.__bases__[0], 'oauth_callback') as mock_super:
            mock_super.return_value = self.test_user
            
            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse:
                result = await self.oauth_manager.oauth_callback(
                    oauth_name="google",
                    access_token="google-token",
                    account_id="123",
                    account_email="test@example.com"
                )
                
                assert result == self.test_user
                mock_parse.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_oauth_callback_with_token_parsing_error(self):
        """Test OAuth callback when token parsing fails"""
        access_token = "invalid.jwt.token"
        
        with patch.object(self.oauth_manager.__class__.__bases__[0], 'oauth_callback') as mock_super:
            mock_super.return_value = self.test_user
            
            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse:
                mock_parse.side_effect = ValueError("Invalid token")
                
                # Should not raise exception, just log error
                result = await self.oauth_manager.oauth_callback(
                    oauth_name="oidc",
                    access_token=access_token,
                    account_id="123",
                    account_email="test@example.com"
                )
                
                assert result == self.test_user
                mock_parse.assert_called_once_with(access_token)
    
    @pytest.mark.asyncio
    async def test_oauth_callback_with_permission_update_error(self):
        """Test OAuth callback when permission update fails"""
        access_token = "mock.jwt.token"
        
        with patch.object(self.oauth_manager.__class__.__bases__[0], 'oauth_callback') as mock_super:
            mock_super.return_value = self.test_user
            
            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse:
                mock_parse.return_value = ("write", ["Onyx-Writers"])
                
                with patch('onyx.auth.users.update_user_oauth_permission') as mock_update:
                    mock_update.side_effect = Exception("Database error")
                    
                    # Should not raise exception, just log error
                    result = await self.oauth_manager.oauth_callback(
                        oauth_name="oidc",
                        access_token=access_token,
                        account_id="123",
                        account_email="test@example.com"
                    )
                    
                    assert result == self.test_user
    
    @pytest.mark.asyncio
    async def test_oauth_callback_no_access_token(self):
        """Test OAuth callback without access token"""
        with patch.object(self.oauth_manager.__class__.__bases__[0], 'oauth_callback') as mock_super:
            mock_super.return_value = self.test_user
            
            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse:
                result = await self.oauth_manager.oauth_callback(
                    oauth_name="oidc",
                    access_token="",  # Empty token
                    account_id="123",
                    account_email="test@example.com"
                )
                
                assert result == self.test_user
                mock_parse.assert_not_called()
    
    @pytest.mark.asyncio 
    async def test_process_okta_groups_success(self):
        """Test successful Okta group processing"""
        access_token = "mock.jwt.token"
        
        with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse:
            mock_parse.return_value = ("admin", ["Onyx-Admins", "Other-Group"])
            
            with patch('onyx.auth.users.update_user_oauth_permission') as mock_update:
                await self.oauth_manager._process_okta_groups(self.test_user, access_token)
                
                mock_parse.assert_called_once_with(access_token)
                mock_update.assert_called_once_with(
                    user_id=self.test_user.id,
                    permission_level="admin",
                    okta_groups=["Onyx-Admins", "Other-Group"],
                    granted_by="okta_groups"
                )
```

### Integration Tests
**Path**: `backend/tests/integration/auth/test_oauth_callback_integration.py`

```python
"""
Integration tests for OAuth callback with database.
"""
import pytest
from uuid import uuid4
from unittest.mock import patch

from onyx.auth.users import OAuthUserManager
from onyx.db.oauth_permissions import get_user_permission_level


class TestOAuthCallbackIntegration:
    
    @pytest.mark.asyncio
    async def test_full_oauth_flow_with_permission_grant(self):
        """Test complete OAuth flow with permission grant"""
        # This would be a full integration test with test database
        # For now, we'll use mocks but structure for real integration
        pass
    
    @pytest.mark.asyncio
    async def test_oauth_callback_performance(self):
        """Test OAuth callback performance with group processing"""
        # Ensure the enhanced callback doesn't significantly slow down login
        import time
        
        # This would measure actual callback performance
        pass
```

## 🚀 Deployment Checklist

### Pre-deployment
- [ ] Code review completed
- [ ] All unit tests passing
- [ ] Integration tests with database passing
- [ ] Feature flag `OAUTH_PERMISSIONS_ENABLED` ready
- [ ] Backup plan for OAuth callback issues

### Deployment Steps
1. [ ] Deploy with feature flag disabled initially
2. [ ] Enable feature flag for test users
3. [ ] Monitor OAuth login success rates
4. [ ] Test permission assignment for Okta users
5. [ ] Gradually enable for all users

### Post-deployment Verification
- [ ] Okta OAuth login still works
- [ ] Non-Okta OAuth providers unaffected
- [ ] Permissions being assigned correctly
- [ ] No performance degradation in login flow
- [ ] Error handling working as expected

### Rollback Plan
If issues occur:
1. Disable feature flag `OAUTH_PERMISSIONS_ENABLED`
2. Verify standard OAuth login works
3. Check for any authentication failures
4. Fix issues and re-enable gradually

## 📋 Definition of Done

- [ ] All acceptance criteria met
- [ ] Enhanced OAuth callback working with Okta groups
- [ ] Backwards compatibility maintained
- [ ] Comprehensive unit tests (>95% coverage)
- [ ] Integration tests passing
- [ ] Error handling prevents login failures
- [ ] Performance impact minimal (<500ms)
- [ ] Feature flag controls ready
- [ ] Monitoring and logging in place
- [ ] Code reviewed and approved
- [ ] Deployed successfully

## 🔗 Related Stories

**Dependencies**:
- Story 1.1: Database Schema for OAuth Permissions
- Story 1.2: Okta JWT Token Parser  
- Story 1.3: OAuth Permission Database Operations

**Next Stories**:
- Story 2.2: Permission Retrieval Service
- Story 3.1: Permission Dependency Functions

## 📝 Notes

- The enhancement is designed to be backwards compatible
- Feature flags allow gradual rollout and quick rollback
- Error handling ensures token parsing failures don't break login
- Only OIDC (Okta) provider processes groups, others are unchanged
- Extensive logging for debugging and monitoring
- No signature verification initially (security enhancement for later)

## 🐛 Known Risks

1. **OAuth Login Failures**: Token parsing errors could affect login
2. **Performance Impact**: Additional processing during authentication
3. **Database Load**: Permission updates during login
4. **Token Format Changes**: Okta might change JWT structure

## 💡 Success Metrics

- OAuth login success rate remains >99%
- Permission assignment works for >95% of Okta users
- Login processing time increases by <500ms
- Zero authentication failures due to permission processing
- All Okta group mappings work correctly
