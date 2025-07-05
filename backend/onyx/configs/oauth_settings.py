from pydantic import BaseSettings, field_validator, HttpUrl
from pydantic_core import ValidationError
from typing import Optional
import os


class OAuthSettings(BaseSettings):
    """OAuth and Okta configuration settings."""
    
    # Okta Configuration
    okta_domain: str
    okta_client_id: str
    okta_client_secret: str
    okta_groups_claim: str = "groups"
    okta_audience: Optional[str] = None
    okta_issuer: HttpUrl
    oidc_well_known_url: HttpUrl
    
    # Feature Flags - simplified
    oauth_permissions_enabled: bool = False  # Not used in simplified version
    oauth_permission_enforcement: bool = False  # Not used in simplified version
    okta_group_processing: bool = True  # Simplified group processing
    
    # Group Mappings - simplified to just admin vs user
    okta_admin_groups: str = "Onyx-Admins"  # Comma-separated admin groups
    
    # Security Settings
    okta_token_validation_strict: bool = True
    okta_group_claim_required: bool = True
    jwt_algorithm: str = "RS256"
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    @field_validator('okta_domain')
    @classmethod
    def validate_okta_domain(cls, v):
        if not v or not v.endswith('.okta.com'):
            raise ValueError('Okta domain must end with .okta.com')
        return v
    
    @field_validator('okta_client_id', 'okta_client_secret')
    @classmethod
    def validate_okta_credentials(cls, v):
        if not v or len(v) < 10:
            raise ValueError('Okta credentials must be properly configured')
        return v
    
    @field_validator('oidc_well_known_url')
    @classmethod
    def validate_oidc_url(cls, v, info):
        if 'okta_domain' in info.data:
            expected_domain = info.data['okta_domain']
            if expected_domain not in str(v):
                raise ValueError('OIDC well-known URL must match Okta domain')
        return v

    def get_admin_groups(self) -> list[str]:
        """Get list of admin groups for simplified role mapping."""
        return [group.strip() for group in self.okta_admin_groups.split(",")]


# Global settings instance - will be None if environment is not configured
try:
    oauth_settings = OAuthSettings()
except Exception:
    # Environment not configured, oauth_settings will be None
    oauth_settings = None
