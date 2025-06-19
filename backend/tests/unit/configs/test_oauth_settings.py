import pytest
from pydantic import ValidationError
from onyx.configs.oauth_settings import OAuthSettings


def test_oauth_settings_valid_config():
    """Test OAuth settings with valid configuration."""
    config = OAuthSettings(
        okta_domain="test-org.okta.com",
        okta_client_id="test_client_id",
        okta_client_secret="test_client_secret",
        okta_issuer="https://test-org.okta.com/oauth2/default",
        oidc_well_known_url="https://test-org.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    
    assert config.okta_domain == "test-org.okta.com"
    assert config.okta_groups_claim == "groups"
    assert config.jwt_algorithm == "RS256"


def test_oauth_settings_invalid_domain():
    """Test OAuth settings validation with invalid domain."""
    with pytest.raises(ValidationError) as exc_info:
        OAuthSettings(
            okta_domain="invalid-domain.com",
            okta_client_id="test_client_id",
            okta_client_secret="test_client_secret",
            okta_issuer="https://invalid-domain.com/oauth2/default",
            oidc_well_known_url="https://invalid-domain.com/oauth2/default/.well-known/openid-configuration"
        )
    
    assert "must end with .okta.com" in str(exc_info.value)


def test_group_permission_mapping():
    """Test group to permission mapping."""
    config = OAuthSettings(
        okta_domain="test-org.okta.com",
        okta_client_id="test_client_id",
        okta_client_secret="test_client_secret",
        okta_issuer="https://test-org.okta.com/oauth2/default",
        oidc_well_known_url="https://test-org.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    
    mapping = config.get_group_permission_mapping()
    
    assert mapping["Onyx-Admins"] == "admin"
    assert mapping["Onyx-Writers"] == "write"
    assert mapping["Onyx-Readers"] == "read"


def test_oauth_settings_custom_groups():
    """Test OAuth settings with custom group names."""
    config = OAuthSettings(
        okta_domain="test-org.okta.com",
        okta_client_id="test_client_id",
        okta_client_secret="test_client_secret",
        okta_issuer="https://test-org.okta.com/oauth2/default",
        oidc_well_known_url="https://test-org.okta.com/oauth2/default/.well-known/openid-configuration",
        okta_admin_group="Custom-Admins",
        okta_write_group="Custom-Writers",
        okta_read_group="Custom-Readers"
    )
    
    mapping = config.get_group_permission_mapping()
    
    assert mapping["Custom-Admins"] == "admin"
    assert mapping["Custom-Writers"] == "write"
    assert mapping["Custom-Readers"] == "read"


def test_oauth_settings_feature_flags():
    """Test OAuth settings feature flag defaults."""
    config = OAuthSettings(
        okta_domain="test-org.okta.com",
        okta_client_id="test_client_id",
        okta_client_secret="test_client_secret",
        okta_issuer="https://test-org.okta.com/oauth2/default",
        oidc_well_known_url="https://test-org.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    
    assert config.oauth_permissions_enabled is False
    assert config.oauth_permission_enforcement is False
    assert config.okta_group_processing is False
    assert config.okta_token_validation_strict is True
    assert config.okta_group_claim_required is True


def test_oauth_settings_invalid_credentials():
    """Test OAuth settings validation with invalid credentials."""
    with pytest.raises(ValidationError) as exc_info:
        OAuthSettings(
            okta_domain="test-org.okta.com",
            okta_client_id="short",  # Too short
            okta_client_secret="test_client_secret",
            okta_issuer="https://test-org.okta.com/oauth2/default",
            oidc_well_known_url="https://test-org.okta.com/oauth2/default/.well-known/openid-configuration"
        )
    
    assert "must be properly configured" in str(exc_info.value)


def test_oauth_settings_mismatched_domain():
    """Test OAuth settings validation with mismatched domain in OIDC URL."""
    with pytest.raises(ValidationError) as exc_info:
        OAuthSettings(
            okta_domain="test-org.okta.com",
            okta_client_id="test_client_id",
            okta_client_secret="test_client_secret",
            okta_issuer="https://test-org.okta.com/oauth2/default",
            oidc_well_known_url="https://different-org.okta.com/oauth2/default/.well-known/openid-configuration"
        )
    
    assert "must match Okta domain" in str(exc_info.value)
