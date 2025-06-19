#!/usr/bin/env python3
"""
Validate OAuth and Okta configuration.
Run this script to verify environment setup.
"""

import sys
import requests
from typing import Dict, List
from onyx.configs.oauth_settings import oauth_settings, OAuthSettings
from onyx.utils.logger import setup_logger

logger = setup_logger()


def get_oauth_settings() -> OAuthSettings:
    """Get OAuth settings, creating them if needed."""
    if oauth_settings is None:
        try:
            return OAuthSettings()
        except Exception as e:
            logger.error(f"❌ Failed to load OAuth settings: {e}")
            sys.exit(1)
    return oauth_settings


def validate_okta_domain() -> bool:
    """Validate Okta domain accessibility."""
    settings = get_oauth_settings()
    try:
        url = f"https://{settings.okta_domain}/.well-known/openid-configuration"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            config = response.json()
            logger.info(f"✅ Okta domain {settings.okta_domain} is accessible")
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
    settings = get_oauth_settings()
    try:
        response = requests.get(str(settings.oidc_well_known_url), timeout=10)
        
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
    settings = get_oauth_settings()
    required_vars = [
        'OKTA_DOMAIN',
        'OKTA_CLIENT_ID', 
        'OKTA_CLIENT_SECRET',
        'OIDC_WELL_KNOWN_URL'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not getattr(settings, var.lower(), None):
            missing_vars.append(var)
    
    if missing_vars:
        logger.error(f"❌ Missing environment variables: {missing_vars}")
        return False
    
    logger.info("✅ All required environment variables are set")
    return True


def validate_group_configuration() -> bool:
    """Validate Okta group configuration."""
    settings = get_oauth_settings()
    groups = settings.get_group_permission_mapping()
    
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
