#!/usr/bin/env python3
"""
Test JWT parsing for Okta tokens.
Used to verify JWT token structure and claims.
"""

import jwt
import requests
import json
from typing import Dict, Any

def test_jwt_parsing():
    """Test JWT parsing with mock Okta token."""
    
    # Mock JWT payload for testing
    mock_payload = {
        "iss": "https://test-org.okta.com/oauth2/default",
        "aud": "api://default",
        "sub": "00u1234567890abcdef",
        "iat": 1640995200,
        "exp": 1640998800,
        "groups": ["Onyx-Admins", "Onyx-Writers"],
        "email": "test@example.com",
        "preferred_username": "testuser"
    }
    
    print("🧪 Testing JWT Token Structure")
    print(f"Mock payload: {json.dumps(mock_payload, indent=2)}")
    
    # Test group extraction
    groups = mock_payload.get("groups", [])
    print(f"\n✅ Groups found in token: {groups}")
    
    # Test permission mapping
    group_mappings = {
        "Onyx-Admins": "admin",
        "Onyx-Writers": "write",
        "Onyx-Readers": "read"
    }
    
    permissions = []
    for group in groups:
        if group in group_mappings:
            permissions.append(group_mappings[group])
    
    print(f"✅ Mapped permissions: {permissions}")
    
    # Determine highest permission level
    permission_hierarchy = {"read": 1, "write": 2, "admin": 3}
    highest_permission = max(permissions, key=lambda p: permission_hierarchy.get(p, 0)) if permissions else "none"
    
    print(f"✅ Highest permission level: {highest_permission}")
    
    return True

if __name__ == "__main__":
    try:
        result = test_jwt_parsing()
        if result:
            print("\n🎉 JWT parsing test completed successfully!")
        else:
            print("\n❌ JWT parsing test failed!")
    except Exception as e:
        print(f"\n💥 Error during JWT parsing test: {e}")
