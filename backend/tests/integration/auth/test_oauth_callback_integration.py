"""
Integration tests for Enhanced OAuth Callback Handler (Story 2.1)

Tests the complete integration flow from OAuth callback through
Okta group processing and database permission updates.
"""

import pytest
from unittest.mock import Mock, patch
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from onyx.auth.users import OAuthUserManager
from onyx.db.models import User, OAuthPermission
from onyx.db.oauth_permissions import update_user_oauth_permission
from onyx.auth.okta_parser import parse_okta_token_for_permissions
from onyx.configs.app_configs import (
    OAUTH_PERMISSIONS_ENABLED,
    OKTA_GROUP_PROCESSING_ENABLED
)


class TestOAuthCallbackIntegration:
    """Integration tests for OAuth callback with permission processing."""

    @pytest.fixture
    def db_session(self):
        """Create a test database session."""
        # In a real integration test, you would use a test database
        # For this example, we'll mock the session
        return Mock(spec=Session)

    @pytest.fixture
    def oauth_manager(self):
        """Create OAuth manager instance."""
        return OAuthUserManager()

    @pytest.fixture
    def sample_jwt_token(self):
        """Sample JWT token for testing."""
        # This would be a real JWT token in actual tests
        return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZ3JvdXBzIjpbImFkbWlucyIsImRldmVsb3BlcnMiXX0.test"

    @pytest.fixture
    def okta_oauth_account_info(self, sample_jwt_token):
        """OAuth account info from Okta with JWT token."""
        return {
            "sub": "okta-user-123",
            "email": "test@company.com",
            "name": "Test User",
            "preferred_username": "testuser",
            "id_token": sample_jwt_token
        }

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True)
    @patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True)
    def test_complete_oauth_flow_with_okta_groups(
        self,
        oauth_manager,
        db_session,
        okta_oauth_account_info
    ):
        """Test complete OAuth flow with Okta group processing."""
        
        # Mock the user creation/retrieval
        mock_user = Mock(spec=User)
        mock_user.id = "user-123"
        mock_user.email = "test@company.com"
        
        with patch.object(oauth_manager, '_create_or_update_user') as mock_create_user:
            mock_create_user.return_value = mock_user
            
            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                mock_parse_token.return_value = ("admin", ["admins", "developers"])
                
                with patch('onyx.auth.users.update_user_oauth_permission') as mock_update_permission:
                    mock_update_permission.return_value = True
                    
                    # Act
                    result = oauth_manager.oauth_callback(
                        oauth_account_info=okta_oauth_account_info,
                        provider="oidc",
                        db=db_session
                    )
                    
                    # Assert
                    assert result == mock_user
                    
                    # Verify the complete flow
                    mock_create_user.assert_called_once()
                    mock_parse_token.assert_called_once_with(okta_oauth_account_info["id_token"])
                    mock_update_permission.assert_called_once_with(
                        db_session,
                        "user-123",
                        "admin",
                        ["admins", "developers"]
                    )

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True)
    @patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True)
    def test_oauth_flow_with_multiple_permission_levels(
        self,
        oauth_manager,
        db_session,
        okta_oauth_account_info
    ):
        """Test OAuth flow with different permission levels."""
        
        permission_scenarios = [
            ("basic", ["employees"]),
            ("admin", ["admins", "employees"]),
            ("curator", ["curators", "employees"]),
            (None, [])  # No permissions
        ]
        
        for permission_level, groups in permission_scenarios:
            mock_user = Mock(spec=User)
            mock_user.id = f"user-{permission_level or 'none'}"
            mock_user.email = "test@company.com"
            
            with patch.object(oauth_manager, '_create_or_update_user') as mock_create_user:
                mock_create_user.return_value = mock_user
                
                with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                    mock_parse_token.return_value = (permission_level, groups)
                    
                    with patch('onyx.auth.users.update_user_oauth_permission') as mock_update_permission:
                        mock_update_permission.return_value = True
                        
                        # Act
                        result = oauth_manager.oauth_callback(
                            oauth_account_info=okta_oauth_account_info,
                            provider="oidc",
                            db=db_session
                        )
                        
                        # Assert
                        assert result == mock_user
                        
                        if permission_level:
                            mock_update_permission.assert_called_once_with(
                                db_session,
                                mock_user.id,
                                permission_level,
                                groups
                            )
                        else:
                            # Should not call update if no permission level
                            mock_update_permission.assert_not_called()

    def test_oauth_flow_performance_timing(
        self,
        oauth_manager,
        db_session,
        okta_oauth_account_info
    ):
        """Test that OAuth flow completes within performance requirements."""
        import time
        
        mock_user = Mock(spec=User)
        mock_user.id = "user-perf-test"
        mock_user.email = "test@company.com"
        
        with patch.object(oauth_manager, '_create_or_update_user') as mock_create_user:
            mock_create_user.return_value = mock_user
            
            with patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True):
                with patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True):
                    with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                        mock_parse_token.return_value = ("admin", ["admins"])
                        
                        with patch('onyx.auth.users.update_user_oauth_permission') as mock_update_permission:
                            mock_update_permission.return_value = True
                            
                            # Act
                            start_time = time.time()
                            result = oauth_manager.oauth_callback(
                                oauth_account_info=okta_oauth_account_info,
                                provider="oidc",
                                db=db_session
                            )
                            end_time = time.time()
                            
                            # Assert
                            assert result == mock_user
                            processing_time = end_time - start_time
                            
                            # Should complete within 2 seconds (requirement from story)
                            assert processing_time < 2.0, f"OAuth processing took {processing_time} seconds, exceeding 2 second limit"

    def test_error_recovery_scenarios(
        self,
        oauth_manager,
        db_session,
        okta_oauth_account_info
    ):
        """Test error recovery in various failure scenarios."""
        
        error_scenarios = [
            ("Token parsing failure", Exception("Invalid JWT")),
            ("Database failure", Exception("Connection timeout")),
            ("Permission update failure", Exception("Constraint violation"))
        ]
        
        for scenario_name, error in error_scenarios:
            mock_user = Mock(spec=User)
            mock_user.id = f"user-error-{scenario_name.replace(' ', '-').lower()}"
            mock_user.email = "test@company.com"
            
            with patch.object(oauth_manager, '_create_or_update_user') as mock_create_user:
                mock_create_user.return_value = mock_user
                
                with patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True):
                    with patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True):
                        if "Token parsing" in scenario_name:
                            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                                mock_parse_token.side_effect = error
                                
                                # Act & Assert - login should still succeed
                                result = oauth_manager.oauth_callback(
                                    oauth_account_info=okta_oauth_account_info,
                                    provider="oidc",
                                    db=db_session
                                )
                                assert result == mock_user
                        
                        elif "Database failure" in scenario_name or "Permission update" in scenario_name:
                            with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                                mock_parse_token.return_value = ("admin", ["admins"])
                                
                                with patch('onyx.auth.users.update_user_oauth_permission') as mock_update_permission:
                                    mock_update_permission.side_effect = error
                                    
                                    # Act & Assert - login should still succeed
                                    result = oauth_manager.oauth_callback(
                                        oauth_account_info=okta_oauth_account_info,
                                        provider="oidc",
                                        db=db_session
                                    )
                                    assert result == mock_user

    def test_backwards_compatibility_integration(
        self,
        oauth_manager,
        db_session
    ):
        """Test backwards compatibility with existing OAuth providers."""
        
        oauth_providers = [
            ("google", {
                "sub": "google-123",
                "email": "user@gmail.com",
                "name": "Google User",
                "picture": "https://example.com/photo.jpg"
            }),
            ("github", {
                "id": "github-456",
                "login": "githubuser",
                "email": "user@github.com",
                "name": "GitHub User"
            }),
            ("microsoft", {
                "id": "microsoft-789",
                "userPrincipalName": "user@microsoft.com",
                "displayName": "Microsoft User"
            })
        ]
        
        for provider, oauth_info in oauth_providers:
            mock_user = Mock(spec=User)
            mock_user.id = f"user-{provider}"
            mock_user.email = oauth_info.get("email", oauth_info.get("userPrincipalName"))
            
            with patch.object(oauth_manager, '_create_or_update_user') as mock_create_user:
                mock_create_user.return_value = mock_user
                
                with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                    # Act
                    result = oauth_manager.oauth_callback(
                        oauth_account_info=oauth_info,
                        provider=provider,
                        db=db_session
                    )
                    
                    # Assert
                    assert result == mock_user
                    # Should not call Okta token parsing for non-OIDC providers
                    mock_parse_token.assert_not_called()

    @patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True)
    @patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True)
    def test_concurrent_oauth_callbacks(
        self,
        oauth_manager,
        db_session
    ):
        """Test handling of concurrent OAuth callbacks."""
        import threading
        import time
        
        results = []
        errors = []
        
        def oauth_callback_worker(user_id):
            try:
                oauth_info = {
                    "sub": f"okta-user-{user_id}",
                    "email": f"user{user_id}@company.com",
                    "name": f"Test User {user_id}",
                    "id_token": "test.jwt.token"
                }
                
                mock_user = Mock(spec=User)
                mock_user.id = f"user-{user_id}"
                mock_user.email = oauth_info["email"]
                
                with patch.object(oauth_manager, '_create_or_update_user') as mock_create_user:
                    mock_create_user.return_value = mock_user
                    
                    with patch('onyx.auth.users.parse_okta_token_for_permissions') as mock_parse_token:
                        mock_parse_token.return_value = ("basic", ["employees"])
                        
                        with patch('onyx.auth.users.update_user_oauth_permission') as mock_update_permission:
                            mock_update_permission.return_value = True
                            
                            result = oauth_manager.oauth_callback(
                                oauth_account_info=oauth_info,
                                provider="oidc",
                                db=db_session
                            )
                            results.append(result)
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads to simulate concurrent requests
        threads = []
        for i in range(5):
            thread = threading.Thread(target=oauth_callback_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Assert
        assert len(errors) == 0, f"Concurrent OAuth callbacks failed with errors: {errors}"
        assert len(results) == 5, f"Expected 5 successful callbacks, got {len(results)}"

    def test_security_validation_integration(
        self,
        oauth_manager,
        db_session
    ):
        """Test security validation in the OAuth flow."""
        
        security_test_cases = [
            {
                "name": "malformed_token",
                "oauth_info": {
                    "sub": "security-test-1",
                    "email": "test@company.com",
                    "name": "Security Test",
                    "id_token": "malformed.jwt.token"
                },
                "should_succeed": True  # Login should succeed even with bad token
            },
            {
                "name": "missing_required_fields",
                "oauth_info": {
                    "sub": "security-test-2",
                    "id_token": "test.jwt.token"
                    # Missing email and name
                },
                "should_succeed": True  # Depends on implementation
            },
            {
                "name": "extremely_long_token",
                "oauth_info": {
                    "sub": "security-test-3",
                    "email": "test@company.com",
                    "name": "Security Test",
                    "id_token": "x" * 10000  # Extremely long token
                },
                "should_succeed": True  # Should handle gracefully
            }
        ]
        
        for test_case in security_test_cases:
            mock_user = Mock(spec=User)
            mock_user.id = f"user-{test_case['name']}"
            mock_user.email = test_case["oauth_info"].get("email", "default@test.com")
            
            with patch.object(oauth_manager, '_create_or_update_user') as mock_create_user:
                if test_case["should_succeed"]:
                    mock_create_user.return_value = mock_user
                else:
                    mock_create_user.side_effect = Exception("Security validation failed")
                
                with patch('onyx.auth.users.OAUTH_PERMISSIONS_ENABLED', True):
                    with patch('onyx.auth.users.OKTA_GROUP_PROCESSING_ENABLED', True):
                        try:
                            result = oauth_manager.oauth_callback(
                                oauth_account_info=test_case["oauth_info"],
                                provider="oidc",
                                db=db_session
                            )
                            
                            if test_case["should_succeed"]:
                                assert result == mock_user, f"Security test case '{test_case['name']}' should have succeeded"
                            else:
                                pytest.fail(f"Security test case '{test_case['name']}' should have failed")
                                
                        except Exception as e:
                            if test_case["should_succeed"]:
                                pytest.fail(f"Security test case '{test_case['name']}' should have succeeded but failed with: {e}")
                            # Expected failure for security validation


if __name__ == "__main__":
    pytest.main([__file__])
