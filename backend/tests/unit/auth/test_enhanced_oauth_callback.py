"""
Unit tests for Enhanced OAuth Callback Handler (Story 2.1)

Tests the oauth_callback method enhancements for processing Okta groups
and assigning permissions during OAuth authentication.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from sqlalchemy.orm import Session
from fastapi import HTTPException

from onyx.auth.users import OAuthUserManager
from onyx.auth.oauth_monitoring import OAuthPermissionMonitor
from onyx.db.models import User
from onyx.configs.app_configs import (
    OAUTH_PERMISSIONS_ENABLED,
    OKTA_GROUP_PROCESSING_ENABLED,
    OAUTH_PERMISSION_LOGGING_LEVEL
)


class TestEnhancedOAuthCallback:
    """Test suite for enhanced OAuth callback handler."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session = Mock(spec=Session)
        self.oauth_manager = OAuthUserManager()
        self.mock_user = Mock(spec=User)
        self.mock_user.id = "test-user-id"
        self.mock_user.email = "test@example.com"

    @pytest.fixture
    def mock_oauth_account_info(self):
        """Mock OAuth account info for OIDC provider."""
        return {
            "sub": "test-sub-id",
            "email": "test@example.com",
            "name": "Test User",
            "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
        }

    @pytest.fixture
    def mock_google_oauth_account_info(self):
        """Mock OAuth account info for Google provider."""
        return {
            "sub": "google-sub-id",
            "email": "test@gmail.com",
            "name": "Google User"
        }

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True)
    @patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True)
    @patch('onyx.auth.users.parse_okta_token_for_permissions')
    @patch('onyx.auth.users.update_user_oauth_permission')
    @patch('onyx.auth.users.OAuthPermissionMonitor')
    def test_oauth_callback_with_okta_groups_success(
        self,
        mock_monitor,
        mock_update_permission,
        mock_parse_token,
        mock_oauth_account_info
    ):
        """Test successful OAuth callback with Okta group processing."""
        # Arrange
        mock_parse_token.return_value = ("admin", ["group1", "group2"])
        mock_update_permission.return_value = True
        
        with patch.object(self.oauth_manager, '_create_or_update_user') as mock_create_user:
            mock_create_user.return_value = self.mock_user
            
            # Act
            result = self.oauth_manager.oauth_callback(
                oauth_account_info=mock_oauth_account_info,
                provider="oidc",
                db=self.mock_session
            )
            
            # Assert
            assert result == self.mock_user
            mock_parse_token.assert_called_once_with(mock_oauth_account_info["id_token"])
            mock_update_permission.assert_called_once_with(
                self.mock_session,
                "test-user-id",
                "admin",
                ["group1", "group2"]
            )
            mock_monitor.log_permission_grant.assert_called_once_with(
                "test-user-id",
                "admin",
                ["group1", "group2"]
            )

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True)
    @patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True)
    @patch('onyx.auth.users.parse_okta_token_for_permissions')
    @patch('onyx.auth.users.OAuthPermissionMonitor')
    def test_oauth_callback_with_token_parsing_error(
        self,
        mock_monitor,
        mock_parse_token,
        mock_oauth_account_info
    ):
        """Test OAuth callback with token parsing error - should not fail login."""
        # Arrange
        mock_parse_token.side_effect = Exception("Token parsing failed")
        
        with patch.object(self.oauth_manager, '_create_or_update_user') as mock_create_user:
            mock_create_user.return_value = self.mock_user
            
            # Act
            result = self.oauth_manager.oauth_callback(
                oauth_account_info=mock_oauth_account_info,
                provider="oidc",
                db=self.mock_session
            )
            
            # Assert
            assert result == self.mock_user  # Login should still succeed
            mock_monitor.log_token_parsing_failure.assert_called_once_with(
                "test-user-id",
                "Token parsing failed"
            )

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True)
    @patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True)
    @patch('onyx.auth.users.parse_okta_token_for_permissions')
    @patch('onyx.auth.users.update_user_oauth_permission')
    @patch('onyx.auth.users.OAuthPermissionMonitor')
    def test_oauth_callback_with_database_error(
        self,
        mock_monitor,
        mock_update_permission,
        mock_parse_token,
        mock_oauth_account_info
    ):
        """Test OAuth callback with database error - should not fail login."""
        # Arrange
        mock_parse_token.return_value = ("admin", ["group1"])
        mock_update_permission.side_effect = Exception("Database error")
        
        with patch.object(self.oauth_manager, '_create_or_update_user') as mock_create_user:
            mock_create_user.return_value = self.mock_user
            
            # Act
            result = self.oauth_manager.oauth_callback(
                oauth_account_info=mock_oauth_account_info,
                provider="oidc",
                db=self.mock_session
            )
            
            # Assert
            assert result == self.mock_user  # Login should still succeed
            mock_monitor.log_permission_error.assert_called_once_with(
                "test-user-id",
                "Database error"
            )

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', False)
    def test_oauth_callback_with_permissions_disabled(
        self,
        mock_oauth_account_info
    ):
        """Test OAuth callback when OAuth permissions are disabled."""
        with patch.object(self.oauth_manager, '_create_or_update_user') as mock_create_user:
            mock_create_user.return_value = self.mock_user
            
            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                # Act
                result = self.oauth_manager.oauth_callback(
                    oauth_account_info=mock_oauth_account_info,
                    provider="oidc",
                    db=self.mock_session
                )
                
                # Assert
                assert result == self.mock_user
                mock_parse_token.assert_not_called()

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True)
    @patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', False)
    def test_oauth_callback_with_okta_processing_disabled(
        self,
        mock_oauth_account_info
    ):
        """Test OAuth callback when Okta group processing is disabled."""
        with patch.object(self.oauth_manager, '_create_or_update_user') as mock_create_user:
            mock_create_user.return_value = self.mock_user
            
            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                # Act
                result = self.oauth_manager.oauth_callback(
                    oauth_account_info=mock_oauth_account_info,
                    provider="oidc",
                    db=self.mock_session
                )
                
                # Assert
                assert result == self.mock_user
                mock_parse_token.assert_not_called()

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True)
    @patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True)
    def test_oauth_callback_non_oidc_provider_skips_processing(
        self,
        mock_google_oauth_account_info
    ):
        """Test OAuth callback with non-OIDC provider skips group processing."""
        with patch.object(self.oauth_manager, '_create_or_update_user') as mock_create_user:
            mock_create_user.return_value = self.mock_user
            
            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                # Act
                result = self.oauth_manager.oauth_callback(
                    oauth_account_info=mock_google_oauth_account_info,
                    provider="google",
                    db=self.mock_session
                )
                
                # Assert
                assert result == self.mock_user
                mock_parse_token.assert_not_called()

    def test_oauth_callback_missing_id_token(self):
        """Test OAuth callback with missing id_token in account info."""
        oauth_info_no_token = {
            "sub": "test-sub-id",
            "email": "test@example.com",
            "name": "Test User"
        }
        
        with patch.object(self.oauth_manager, '_create_or_update_user') as mock_create_user:
            mock_create_user.return_value = self.mock_user
            
            with patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True):
                with patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True):
                    with patch('onyx.auth.users.OAuthPermissionMonitor') as mock_monitor:
                        # Act
                        result = self.oauth_manager.oauth_callback(
                            oauth_account_info=oauth_info_no_token,
                            provider="oidc",
                            db=self.mock_session
                        )
                        
                        # Assert
                        assert result == self.mock_user
                        mock_monitor.log_token_parsing_failure.assert_called_once()

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True)
    @patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True)
    @patch('onyx.auth.users.parse_okta_token_for_permissions')
    @patch('onyx.auth.users.update_user_oauth_permission')
    @patch('onyx.auth.users.OAuthPermissionMonitor')
    def test_process_okta_groups_method_directly(
        self,
        mock_monitor,
        mock_update_permission,
        mock_parse_token
    ):
        """Test the _process_okta_groups method directly."""
        # Arrange
        mock_parse_token.return_value = ("basic", ["developers"])
        mock_update_permission.return_value = True
        id_token = "test.jwt.token"
        
        # Act
        self.oauth_manager._process_okta_groups(
            user=self.mock_user,
            id_token=id_token,
            db=self.mock_session
        )
        
        # Assert
        mock_parse_token.assert_called_once_with(id_token)
        mock_update_permission.assert_called_once_with(
            self.mock_session,
            "test-user-id",
            "basic",
            ["developers"]
        )
        mock_monitor.log_permission_grant.assert_called_once_with(
            "test-user-id",
            "basic",
            ["developers"]
        )

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True)
    @patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True)
    @patch('onyx.auth.users.parse_okta_token_for_permissions')
    @patch('onyx.auth.users.OAuthPermissionMonitor')
    def test_process_okta_groups_with_none_permission(
        self,
        mock_monitor,
        mock_parse_token
    ):
        """Test _process_okta_groups when parse_okta_token_for_permissions returns None."""
        # Arrange
        mock_parse_token.return_value = (None, [])
        id_token = "test.jwt.token"
        
        # Act
        self.oauth_manager._process_okta_groups(
            user=self.mock_user,
            id_token=id_token,
            db=self.mock_session
        )
        
        # Assert
        mock_parse_token.assert_called_once_with(id_token)
        # Should log that no permissions were found
        mock_monitor.log_permission_grant.assert_not_called()

    def test_backwards_compatibility_with_existing_oauth_flow(self):
        """Test that existing OAuth flows are not affected."""
        oauth_providers = ["google", "github", "microsoft", "slack"]
        
        for provider in oauth_providers:
            with patch.object(self.oauth_manager, '_create_or_update_user') as mock_create_user:
                mock_create_user.return_value = self.mock_user
                
                oauth_info = {
                    "sub": f"{provider}-sub-id",
                    "email": f"test@{provider}.com",
                    "name": f"{provider.title()} User"
                }
                
                with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                    # Act
                    result = self.oauth_manager.oauth_callback(
                        oauth_account_info=oauth_info,
                        provider=provider,
                        db=self.mock_session
                    )
                    
                    # Assert
                    assert result == self.mock_user
                    mock_parse_token.assert_not_called()


class TestOAuthPermissionMonitor:
    """Test suite for OAuth Permission Monitor."""

    @patch('onyx.auth.oauth_monitoring.logger')
    def test_log_permission_grant(self, mock_logger):
        """Test logging permission grant."""
        OAuthPermissionMonitor.log_permission_grant(
            "user-123", "admin", ["admins", "developers"]
        )
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "OAuth permission granted" in call_args
        assert "user-123" in call_args
        assert "admin" in call_args

    @patch('onyx.auth.oauth_monitoring.logger')
    def test_log_permission_error(self, mock_logger):
        """Test logging permission error."""
        OAuthPermissionMonitor.log_permission_error(
            "user-123", "Database connection failed"
        )
        
        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args[0][0]
        assert "OAuth permission error" in call_args
        assert "user-123" in call_args
        assert "Database connection failed" in call_args

    @patch('onyx.auth.oauth_monitoring.logger')
    def test_log_security_event(self, mock_logger):
        """Test logging security event."""
        OAuthPermissionMonitor.log_security_event(
            "user-123", "Suspicious token detected"
        )
        
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[0][0]
        assert "OAuth security event" in call_args
        assert "user-123" in call_args
        assert "Suspicious token detected" in call_args

    @patch('onyx.auth.oauth_monitoring.logger')
    def test_log_token_parsing_failure(self, mock_logger):
        """Test logging token parsing failure."""
        OAuthPermissionMonitor.log_token_parsing_failure(
            "user-123", "Invalid JWT format"
        )
        
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[0][0]
        assert "OAuth token parsing failed" in call_args
        assert "user-123" in call_args
        assert "Invalid JWT format" in call_args


if __name__ == "__main__":
    pytest.main([__file__])
