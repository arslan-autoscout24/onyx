import pytest
import requests
from unittest.mock import patch, Mock
from onyx.configs.oauth_settings import oauth_settings, OAuthSettings


@pytest.mark.asyncio
async def test_okta_well_known_endpoint_accessible():
    """Test that Okta well-known endpoint is accessible."""
    test_settings = OAuthSettings(
        okta_domain="test-org.okta.com",
        okta_client_id="test_client_id",
        okta_client_secret="test_client_secret",
        okta_issuer="https://test-org.okta.com/oauth2/default",
        oidc_well_known_url="https://test-org.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    
    # Mock the actual request in test environment
    with patch('requests.get') as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'issuer': 'https://test-org.okta.com/oauth2/default',
            'authorization_endpoint': 'https://test-org.okta.com/oauth2/default/v1/authorize',
            'token_endpoint': 'https://test-org.okta.com/oauth2/default/v1/token',
            'jwks_uri': 'https://test-org.okta.com/oauth2/default/v1/keys'
        }
        mock_get.return_value = mock_response
        
        # Test actual validation logic
        with patch('backend.scripts.validate_oauth_config.get_oauth_settings', return_value=test_settings):
            from backend.scripts.validate_oauth_config import validate_oidc_configuration
            result = validate_oidc_configuration()
            assert result is True


def test_environment_variable_loading():
    """Test that environment variables are loaded correctly."""
    # This test would verify that settings load from environment
    if oauth_settings is not None:
        assert oauth_settings.okta_groups_claim == "groups"
        assert oauth_settings.jwt_algorithm == "RS256"


@pytest.mark.asyncio
async def test_configuration_validation_script():
    """Test the configuration validation script."""
    test_settings = OAuthSettings(
        okta_domain="test-org.okta.com",
        okta_client_id="test_client_id",
        okta_client_secret="test_client_secret",
        okta_issuer="https://test-org.okta.com/oauth2/default",
        oidc_well_known_url="https://test-org.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    
    with patch('requests.get') as mock_get:
        # Mock successful Okta responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'issuer': test_settings.okta_issuer,
            'authorization_endpoint': f"{test_settings.okta_issuer}/v1/authorize",
            'token_endpoint': f"{test_settings.okta_issuer}/v1/token",
            'jwks_uri': f"{test_settings.okta_issuer}/v1/keys"
        }
        mock_get.return_value = mock_response
        
        with patch('backend.scripts.validate_oauth_config.get_oauth_settings', return_value=test_settings):
            from backend.scripts.validate_oauth_config import validate_okta_domain
            result = validate_okta_domain()
            assert result is True


def test_oauth_settings_loading_from_env():
    """Test OAuth settings can be loaded from environment variables."""
    with patch.dict('os.environ', {
        'OKTA_DOMAIN': 'test-org.okta.com',
        'OKTA_CLIENT_ID': 'test_client_id_123',
        'OKTA_CLIENT_SECRET': 'test_client_secret_456',
        'OKTA_ISSUER': 'https://test-org.okta.com/oauth2/default',
        'OIDC_WELL_KNOWN_URL': 'https://test-org.okta.com/oauth2/default/.well-known/openid-configuration'
    }):
        # Reload settings to pick up environment variables
        from onyx.configs.oauth_settings import OAuthSettings
        test_settings = OAuthSettings()
        
        assert test_settings.okta_domain == 'test-org.okta.com'
        assert test_settings.okta_client_id == 'test_client_id_123'
        assert test_settings.okta_client_secret == 'test_client_secret_456'


@pytest.mark.asyncio
async def test_validate_group_configuration():
    """Test group configuration validation."""
    test_settings = OAuthSettings(
        okta_domain="test-org.okta.com",
        okta_client_id="test_client_id",
        okta_client_secret="test_client_secret",
        okta_issuer="https://test-org.okta.com/oauth2/default",
        oidc_well_known_url="https://test-org.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    
    with patch('backend.scripts.validate_oauth_config.get_oauth_settings', return_value=test_settings):
        from backend.scripts.validate_oauth_config import validate_group_configuration
        result = validate_group_configuration()
        assert result is True


def test_oauth_config_error_handling():
    """Test error handling in OAuth configuration validation."""
    test_settings = OAuthSettings(
        okta_domain="test-org.okta.com",
        okta_client_id="test_client_id",
        okta_client_secret="test_client_secret",
        okta_issuer="https://test-org.okta.com/oauth2/default",
        oidc_well_known_url="https://test-org.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    
    with patch('requests.get') as mock_get:
        # Mock failed request
        mock_get.side_effect = requests.RequestException("Connection failed")
        
        with patch('backend.scripts.validate_oauth_config.get_oauth_settings', return_value=test_settings):
            from backend.scripts.validate_oauth_config import validate_okta_domain
            result = validate_okta_domain()
            assert result is False


def test_oidc_config_missing_fields():
    """Test OIDC configuration with missing required fields."""
    test_settings = OAuthSettings(
        okta_domain="test-org.okta.com",
        okta_client_id="test_client_id",
        okta_client_secret="test_client_secret",
        okta_issuer="https://test-org.okta.com/oauth2/default",
        oidc_well_known_url="https://test-org.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    
    with patch('requests.get') as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'issuer': 'https://test-org.okta.com/oauth2/default',
            # Missing required fields: authorization_endpoint, token_endpoint, jwks_uri
        }
        mock_get.return_value = mock_response
        
        with patch('backend.scripts.validate_oauth_config.get_oauth_settings', return_value=test_settings):
            from backend.scripts.validate_oauth_config import validate_oidc_configuration
            result = validate_oidc_configuration()
            assert result is False
