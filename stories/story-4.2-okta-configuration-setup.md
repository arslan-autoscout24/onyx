# Story 4.2: Okta Configuration and Environment Setup

**Priority**: P1 - High  
**Estimate**: 1 day  
**Dependencies**: None  
**Sprint**: 4 - Admin Protection & Testing

## Description

Set up Okta configuration and environment variables for OAuth integration, including proper group configuration and JWT token setup for the authorization system.

## Acceptance Criteria

- [ ] Environment variables for Okta configuration properly set
- [ ] Okta application configured with correct redirect URIs
- [ ] Test Okta groups created: Onyx-Admins, Onyx-Writers, Onyx-Readers
- [ ] Okta JWT token includes groups claim
- [ ] Documentation for Okta setup process
- [ ] Environment validation scripts
- [ ] Configuration templates for different environments
- [ ] Secure credential management setup

## Technical Implementation

### Environment Configuration

#### 1. Environment Variables Setup
```bash
# File: backend/.env.example (enhancement)
# OAuth/Okta Configuration
OKTA_DOMAIN=your-org.okta.com
OKTA_CLIENT_ID=your_okta_app_client_id
OKTA_CLIENT_SECRET=your_okta_app_client_secret
OKTA_GROUPS_CLAIM=groups
OKTA_AUDIENCE=your_audience
OKTA_ISSUER=https://your-org.okta.com/oauth2/default
OIDC_WELL_KNOWN_URL=https://your-org.okta.com/oauth2/default/.well-known/openid-configuration

# OAuth Permission Settings
OAUTH_PERMISSIONS_ENABLED=true
OAUTH_PERMISSION_ENFORCEMENT=true
OKTA_GROUP_PROCESSING=true

# Permission Group Mappings
OKTA_ADMIN_GROUP=Onyx-Admins
OKTA_WRITE_GROUP=Onyx-Writers
OKTA_READ_GROUP=Onyx-Readers

# Security Settings
OKTA_TOKEN_VALIDATION_STRICT=true
OKTA_GROUP_CLAIM_REQUIRED=true
JWT_ALGORITHM=RS256
```

#### 2. Configuration Validation
```python
# File: backend/onyx/configs/oauth_settings.py (new file)
from pydantic import BaseSettings, validator, HttpUrl
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
    
    # Feature Flags
    oauth_permissions_enabled: bool = False
    oauth_permission_enforcement: bool = False
    okta_group_processing: bool = False
    
    # Group Mappings
    okta_admin_group: str = "Onyx-Admins"
    okta_write_group: str = "Onyx-Writers"
    okta_read_group: str = "Onyx-Readers"
    
    # Security Settings
    okta_token_validation_strict: bool = True
    okta_group_claim_required: bool = True
    jwt_algorithm: str = "RS256"
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    @validator('okta_domain')
    def validate_okta_domain(cls, v):
        if not v or not v.endswith('.okta.com'):
            raise ValueError('Okta domain must end with .okta.com')
        return v
    
    @validator('okta_client_id', 'okta_client_secret')
    def validate_okta_credentials(cls, v):
        if not v or len(v) < 10:
            raise ValueError('Okta credentials must be properly configured')
        return v
    
    @validator('oidc_well_known_url')
    def validate_oidc_url(cls, v, values):
        if 'okta_domain' in values:
            expected_domain = values['okta_domain']
            if expected_domain not in str(v):
                raise ValueError('OIDC well-known URL must match Okta domain')
        return v

    def get_group_permission_mapping(self) -> dict:
        """Get mapping of Okta groups to permission levels."""
        return {
            self.okta_admin_group: "admin",
            self.okta_write_group: "write", 
            self.okta_read_group: "read"
        }


# Global settings instance
oauth_settings = OAuthSettings()
```

#### 3. Environment Validation Script
```python
# File: backend/scripts/validate_oauth_config.py (new file)
#!/usr/bin/env python3
"""
Validate OAuth and Okta configuration.
Run this script to verify environment setup.
"""

import sys
import requests
from typing import Dict, List
from onyx.configs.oauth_settings import oauth_settings
from onyx.utils.logger import setup_logger

logger = setup_logger()


def validate_okta_domain() -> bool:
    """Validate Okta domain accessibility."""
    try:
        url = f"https://{oauth_settings.okta_domain}/.well-known/openid-configuration"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            config = response.json()
            logger.info(f"✅ Okta domain {oauth_settings.okta_domain} is accessible")
            logger.info(f"   Issuer: {config.get('issuer')}")
            logger.info(f"   Authorization endpoint: {config.get('authorization_endpoint')}")
            return True
        else:
            logger.error(f"❌ Okta domain returned status {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Failed to connect to Okta domain: {e}")
        return False


def validate_oidc_configuration() -> bool:
    """Validate OIDC well-known configuration."""
    try:
        response = requests.get(str(oauth_settings.oidc_well_known_url), timeout=10)
        
        if response.status_code == 200:
            config = response.json()
            required_fields = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri']
            
            missing_fields = [field for field in required_fields if field not in config]
            if missing_fields:
                logger.error(f"❌ OIDC configuration missing fields: {missing_fields}")
                return False
            
            logger.info("✅ OIDC configuration is valid")
            logger.info(f"   JWKS URI: {config.get('jwks_uri')}")
            return True
        else:
            logger.error(f"❌ OIDC configuration returned status {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Failed to fetch OIDC configuration: {e}")
        return False


def validate_environment_variables() -> bool:
    """Validate all required environment variables are set."""
    required_vars = [
        'OKTA_DOMAIN',
        'OKTA_CLIENT_ID', 
        'OKTA_CLIENT_SECRET',
        'OIDC_WELL_KNOWN_URL'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not getattr(oauth_settings, var.lower(), None):
            missing_vars.append(var)
    
    if missing_vars:
        logger.error(f"❌ Missing environment variables: {missing_vars}")
        return False
    
    logger.info("✅ All required environment variables are set")
    return True


def validate_group_configuration() -> bool:
    """Validate Okta group configuration."""
    groups = oauth_settings.get_group_permission_mapping()
    
    logger.info("✅ Group to permission mapping:")
    for group, permission in groups.items():
        logger.info(f"   {group} → {permission}")
    
    # Check for duplicate groups
    if len(groups) != len(set(groups.keys())):
        logger.error("❌ Duplicate groups found in configuration")
        return False
    
    return True


def main():
    """Run all validation checks."""
    logger.info("🔍 Validating OAuth/Okta Configuration...")
    
    checks = [
        ("Environment Variables", validate_environment_variables),
        ("Okta Domain", validate_okta_domain),
        ("OIDC Configuration", validate_oidc_configuration),
        ("Group Configuration", validate_group_configuration),
    ]
    
    passed = 0
    total = len(checks)
    
    for check_name, check_func in checks:
        logger.info(f"\n🧪 {check_name}...")
        if check_func():
            passed += 1
        else:
            logger.error(f"❌ {check_name} failed")
    
    logger.info(f"\n📊 Results: {passed}/{total} checks passed")
    
    if passed == total:
        logger.info("🎉 All OAuth/Okta configuration checks passed!")
        sys.exit(0)
    else:
        logger.error("💥 Some configuration checks failed. Please fix before proceeding.")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### Okta Application Configuration

#### 1. Okta App Setup Instructions
```markdown
# File: docs/OKTA_SETUP.md (new file)

# Okta Application Setup Guide

## Prerequisites

- Okta Administrator access
- Onyx application domain/URL
- Understanding of OAuth 2.0 flow

## Step 1: Create Okta Application

1. **Login to Okta Admin Console**
   - Navigate to your Okta org: `https://your-org.okta.com`
   - Login with admin credentials

2. **Create New Application**
   - Go to Applications > Applications
   - Click "Create App Integration"
   - Select "OIDC - OpenID Connect"
   - Select "Web Application"

3. **Configure Application Settings**
   ```
   App integration name: Onyx Knowledge Platform
   Grant type: Authorization Code
   Sign-in redirect URIs: 
     - http://localhost:3000/auth/callback (development)
     - https://your-domain.com/auth/callback (production)
   Sign-out redirect URIs:
     - http://localhost:3000/auth/logout (development) 
     - https://your-domain.com/auth/logout (production)
   ```

4. **Assignments**
   - Assign to appropriate users/groups
   - Configure group assignments for permissions

## Step 2: Configure Groups

Create the following groups in Okta:

### Onyx-Admins
- **Description**: Full administrative access to Onyx platform
- **Members**: System administrators only
- **Permissions**: Can manage connectors, users, system settings

### Onyx-Writers  
- **Description**: Read and write access to Onyx platform
- **Members**: Content creators, document managers
- **Permissions**: Can create/edit documents, manage chat sessions

### Onyx-Readers
- **Description**: Read-only access to Onyx platform  
- **Members**: General users, viewers
- **Permissions**: Can view documents, participate in chat

## Step 3: Configure Claims

1. **Go to Security > API > Authorization Servers**
2. **Select "default" authorization server**
3. **Add Claims**:
   
   **Groups Claim**:
   ```
   Name: groups
   Include in token type: ID Token, Access Token
   Value type: Groups
   Filter: Regex: .*
   Include in: Any scope
   ```

## Step 4: Test Configuration

1. **Test Login Flow**
   - Use Okta preview to test login
   - Verify redirect URIs work correctly
   - Check that groups claim is included in tokens

2. **Validate JWT Tokens**
   - Use jwt.io to decode tokens
   - Verify groups claim contains expected groups
   - Check token expiration and audience

## Environment Variables

After setup, configure these environment variables:

```bash
OKTA_DOMAIN=your-org.okta.com
OKTA_CLIENT_ID=<from_okta_app>
OKTA_CLIENT_SECRET=<from_okta_app>
OKTA_GROUPS_CLAIM=groups
OIDC_WELL_KNOWN_URL=https://your-org.okta.com/oauth2/default/.well-known/openid-configuration
```

## Troubleshooting

### Common Issues

1. **Groups not appearing in token**
   - Check groups claim configuration
   - Verify user is assigned to groups
   - Ensure claim is included in token type

2. **Redirect URI mismatch**
   - Verify exact URL match in Okta config
   - Check protocol (http vs https)
   - Ensure no trailing slashes

3. **Token validation failures**
   - Check audience configuration
   - Verify issuer URL
   - Ensure algorithm matches (RS256)

### Validation Commands

```bash
# Validate configuration
python backend/scripts/validate_oauth_config.py

# Test token decoding
python backend/scripts/test_jwt_parsing.py
```
```

#### 2. Configuration Templates
```yaml
# File: deployment/configs/oauth-config-template.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: onyx-oauth-config
data:
  OKTA_DOMAIN: "your-org.okta.com"
  OKTA_GROUPS_CLAIM: "groups"
  OKTA_ADMIN_GROUP: "Onyx-Admins"
  OKTA_WRITE_GROUP: "Onyx-Writers"
  OKTA_READ_GROUP: "Onyx-Readers"
  OAUTH_PERMISSIONS_ENABLED: "true"
  OAUTH_PERMISSION_ENFORCEMENT: "true"
  OKTA_GROUP_PROCESSING: "true"
---
apiVersion: v1
kind: Secret
metadata:
  name: onyx-oauth-secrets
type: Opaque
stringData:
  OKTA_CLIENT_ID: "your_okta_client_id"
  OKTA_CLIENT_SECRET: "your_okta_client_secret"
```

#### 3. Docker Compose Configuration
```yaml
# File: deployment/docker_compose/docker-compose.oauth.yml
version: '3.8'

services:
  backend:
    environment:
      # OAuth Configuration
      - OKTA_DOMAIN=${OKTA_DOMAIN}
      - OKTA_CLIENT_ID=${OKTA_CLIENT_ID}
      - OKTA_CLIENT_SECRET=${OKTA_CLIENT_SECRET}
      - OKTA_GROUPS_CLAIM=${OKTA_GROUPS_CLAIM:-groups}
      - OIDC_WELL_KNOWN_URL=https://${OKTA_DOMAIN}/oauth2/default/.well-known/openid-configuration
      
      # Permission Settings
      - OAUTH_PERMISSIONS_ENABLED=${OAUTH_PERMISSIONS_ENABLED:-true}
      - OAUTH_PERMISSION_ENFORCEMENT=${OAUTH_PERMISSION_ENFORCEMENT:-true}
      - OKTA_GROUP_PROCESSING=${OKTA_GROUP_PROCESSING:-true}
      
      # Group Mappings
      - OKTA_ADMIN_GROUP=${OKTA_ADMIN_GROUP:-Onyx-Admins}
      - OKTA_WRITE_GROUP=${OKTA_WRITE_GROUP:-Onyx-Writers}
      - OKTA_READ_GROUP=${OKTA_READ_GROUP:-Onyx-Readers}
```

## Testing Requirements

### Unit Tests
```python
# File: backend/tests/unit/configs/test_oauth_settings.py
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
```

### Integration Tests
```python
# File: backend/tests/integration/test_oauth_configuration.py
import pytest
import requests
from unittest.mock import patch, Mock
from onyx.configs.oauth_settings import oauth_settings


@pytest.mark.asyncio
async def test_okta_well_known_endpoint_accessible():
    """Test that Okta well-known endpoint is accessible."""
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
        from backend.scripts.validate_oauth_config import validate_oidc_configuration
        result = validate_oidc_configuration()
        assert result is True


def test_environment_variable_loading():
    """Test that environment variables are loaded correctly."""
    # This test would verify that settings load from environment
    assert oauth_settings.okta_groups_claim == "groups"
    assert oauth_settings.jwt_algorithm == "RS256"


@pytest.mark.asyncio
async def test_configuration_validation_script():
    """Test the configuration validation script."""
    with patch('requests.get') as mock_get:
        # Mock successful Okta responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'issuer': oauth_settings.okta_issuer,
            'authorization_endpoint': f"{oauth_settings.okta_issuer}/v1/authorize",
            'token_endpoint': f"{oauth_settings.okta_issuer}/v1/token",
            'jwks_uri': f"{oauth_settings.okta_issuer}/v1/keys"
        }
        mock_get.return_value = mock_response
        
        from backend.scripts.validate_oauth_config import validate_okta_domain
        result = validate_okta_domain()
        assert result is True
```

## Security Considerations

### Credential Management
- **Environment Variables**: Never commit credentials to version control
- **Secret Management**: Use proper secret management systems in production
- **Rotation**: Implement credential rotation procedures
- **Access Control**: Limit access to OAuth configuration

### Token Security
- **Algorithm Validation**: Enforce RS256 for JWT signatures
- **Audience Validation**: Verify token audience matches application
- **Expiration**: Implement proper token expiration handling
- **Revocation**: Support token revocation scenarios

### Network Security
- **HTTPS Only**: All OAuth endpoints must use HTTPS
- **Certificate Validation**: Validate Okta SSL certificates
- **Firewall Rules**: Restrict outbound access to Okta domains only

## Performance Requirements

### Configuration Loading
- **Startup Time**: Configuration validation < 5 seconds
- **Memory Usage**: OAuth settings < 1MB memory footprint
- **Caching**: Cache OIDC configuration for 1 hour

### Network Performance
- **Okta Connectivity**: < 200ms response time to Okta endpoints
- **Well-Known Config**: Cache configuration for 1 hour
- **Failover**: Handle Okta service unavailability gracefully

## Deployment Procedures

### Pre-Deployment Checklist
- [ ] Okta application configured correctly
- [ ] Groups created and assigned
- [ ] Environment variables set
- [ ] Configuration validation passes
- [ ] Test users created in each group
- [ ] Documentation updated

### Deployment Steps
1. **Create Okta Groups**: Set up permission groups in Okta
2. **Configure Application**: Set redirect URIs and claims
3. **Set Environment Variables**: Configure all required settings
4. **Validate Configuration**: Run validation script
5. **Test Login Flow**: Verify OAuth login works
6. **Enable Features**: Turn on OAuth permission processing

### Rollback Plan
1. **Disable Features**: Turn off OAuth processing via feature flags
2. **Revert Environment**: Restore previous environment configuration
3. **Validate Fallback**: Ensure existing auth still works
4. **Monitor**: Watch for any authentication issues

### Monitoring & Alerts
- **Configuration Errors**: Alert on OAuth setup failures
- **Okta Connectivity**: Monitor connection to Okta services
- **Token Validation**: Track JWT validation success rates
- **Group Assignment**: Monitor group membership changes

## Definition of Done

### Configuration Requirements ✅
- [ ] All environment variables properly documented and set
- [ ] Okta application configured with correct settings
- [ ] Groups created and mapped to permissions
- [ ] JWT tokens include groups claim
- [ ] Configuration validation script passes

### Documentation Requirements ✅
- [ ] Complete Okta setup guide created
- [ ] Environment variable documentation updated
- [ ] Configuration templates provided
- [ ] Troubleshooting guide available
- [ ] Security considerations documented

### Testing Requirements ✅
- [ ] Unit tests for configuration validation
- [ ] Integration tests for Okta connectivity
- [ ] Validation script thoroughly tested
- [ ] Configuration loading tested
- [ ] Error handling scenarios covered

### Security Requirements ✅
- [ ] Credential management procedures established
- [ ] Security review completed
- [ ] Network security validated
- [ ] Token security verified
- [ ] Access controls implemented

---

**Story Notes**: This story establishes the foundation for OAuth integration with Okta. It's independent of other stories but enables all subsequent OAuth functionality. Proper configuration here is critical for the entire authorization system.
