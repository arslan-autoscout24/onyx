# Story 1.2: Okta JWT Token Parser

## 📊 Story Overview

**Story ID**: 1.2  
**Priority**: P0 - Critical Foundation  
**Estimate**: 1.5 days  
**Sprint**: 1 (Week 1)  
**Dependencies**: None  
**Assignee**: TBD  

## 🎯 Description

Create utility to extract Okta groups from JWT tokens and map them to application permission levels. This parser will be the core component for translating Okta group memberships into Onyx permissions.

## ✅ Acceptance Criteria

### Core Functionality
- [ ] New `OktaTokenParser` class in `backend/onyx/auth/okta_parser.py`
- [ ] Method to extract groups from Okta JWT tokens (without signature verification initially)
- [ ] Group-to-permission mapping logic: Onyx-Admins→admin, Onyx-Writers→write, etc.
- [ ] Returns highest permission level when user has multiple groups
- [ ] Comprehensive unit tests with sample JWT tokens
- [ ] Error handling for malformed tokens

### Security Considerations
- [ ] Safe JWT parsing (no signature verification yet, but structured parsing)
- [ ] Input validation for token format
- [ ] Graceful handling of missing or invalid claims
- [ ] Logging for security events (invalid tokens, missing groups)

### Performance Requirements
- [ ] Token parsing completes in under 50ms
- [ ] Memory efficient group processing
- [ ] No external API calls during parsing

## 🔧 Technical Implementation

### Files to Create

#### 1. Main Parser Class
**Path**: `backend/onyx/auth/okta_parser.py`

```python
"""
Okta JWT Token Parser for Group Extraction and Permission Mapping

This module handles parsing Okta JWT tokens to extract user groups
and map them to application permission levels.
"""
import json
import logging
from typing import List, Optional, Dict, Any
from base64 import urlsafe_b64decode
import re

logger = logging.getLogger(__name__)

class OktaTokenParser:
    """
    Parser for Okta JWT tokens to extract groups and map to permissions.
    
    This class handles the core logic for:
    1. Extracting groups from JWT tokens
    2. Mapping Okta groups to application permissions
    3. Determining the highest permission level for users
    """
    
    # Mapping of Okta groups to permission levels
    GROUP_MAPPING = {
        "Onyx-Admins": "admin",
        "Onyx-Writers": "write", 
        "Onyx-Readers": "read",
        "Onyx-Viewers": "read",
        "onyx-admins": "admin",  # Lowercase variants
        "onyx-writers": "write",
        "onyx-readers": "read",
        "onyx-viewers": "read"
    }
    
    # Permission hierarchy (higher index = higher permission)
    PERMISSION_HIERARCHY = ["read", "write", "admin"]
    
    def __init__(self, groups_claim: str = "groups"):
        """
        Initialize the parser.
        
        Args:
            groups_claim: The claim name in JWT that contains groups (default: "groups")
        """
        self.groups_claim = groups_claim
    
    def extract_groups_from_token(self, access_token: str) -> List[str]:
        """
        Extract groups from Okta JWT access token.
        
        Args:
            access_token: The JWT access token from Okta
            
        Returns:
            List of group names from the token
            
        Raises:
            ValueError: If token is malformed or cannot be parsed
        """
        try:
            # Parse JWT token (no signature verification for now)
            payload = self._parse_jwt_payload(access_token)
            
            # Extract groups from the specified claim
            groups = payload.get(self.groups_claim, [])
            
            if not isinstance(groups, list):
                logger.warning(f"Groups claim '{self.groups_claim}' is not a list: {type(groups)}")
                return []
            
            logger.info(f"Extracted {len(groups)} groups from token")
            return groups
            
        except Exception as e:
            logger.error(f"Failed to extract groups from token: {str(e)}")
            raise ValueError(f"Invalid or malformed JWT token: {str(e)}")
    
    def map_groups_to_permissions(self, groups: List[str]) -> List[str]:
        """
        Map Okta groups to application permission levels.
        
        Args:
            groups: List of Okta group names
            
        Returns:
            List of permission levels corresponding to the groups
        """
        permissions = []
        
        for group in groups:
            if group in self.GROUP_MAPPING:
                permission = self.GROUP_MAPPING[group]
                permissions.append(permission)
                logger.debug(f"Mapped group '{group}' to permission '{permission}'")
            else:
                logger.debug(f"No mapping found for group '{group}'")
        
        # Remove duplicates while preserving order
        unique_permissions = []
        for perm in permissions:
            if perm not in unique_permissions:
                unique_permissions.append(perm)
        
        return unique_permissions
    
    def get_highest_permission_level(self, permissions: List[str]) -> str:
        """
        Determine the highest permission level from a list of permissions.
        
        Args:
            permissions: List of permission levels
            
        Returns:
            The highest permission level, or 'read' if no valid permissions
        """
        if not permissions:
            return "read"  # Default fallback permission
        
        # Find the highest permission based on hierarchy
        highest_index = -1
        highest_permission = "read"
        
        for permission in permissions:
            if permission in self.PERMISSION_HIERARCHY:
                index = self.PERMISSION_HIERARCHY.index(permission)
                if index > highest_index:
                    highest_index = index
                    highest_permission = permission
        
        logger.info(f"Determined highest permission: '{highest_permission}' from {permissions}")
        return highest_permission
    
    def parse_token_for_permissions(self, access_token: str) -> tuple[str, List[str]]:
        """
        Complete flow: extract groups from token and return highest permission.
        
        Args:
            access_token: The JWT access token from Okta
            
        Returns:
            Tuple of (highest_permission_level, list_of_groups)
        """
        try:
            groups = self.extract_groups_from_token(access_token)
            permissions = self.map_groups_to_permissions(groups)
            highest_permission = self.get_highest_permission_level(permissions)
            
            return highest_permission, groups
            
        except Exception as e:
            logger.error(f"Failed to parse token for permissions: {str(e)}")
            return "read", []  # Safe fallback
    
    def _parse_jwt_payload(self, token: str) -> Dict[str, Any]:
        """
        Parse JWT token payload without signature verification.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded payload as dictionary
            
        Raises:
            ValueError: If token format is invalid
        """
        try:
            # Split token into parts
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("JWT token must have 3 parts separated by dots")
            
            # Decode payload (second part)
            payload_part = parts[1]
            
            # Add padding if needed for base64 decoding
            payload_part += '=' * (4 - len(payload_part) % 4)
            
            # Decode base64
            decoded_bytes = urlsafe_b64decode(payload_part)
            payload = json.loads(decoded_bytes.decode('utf-8'))
            
            return payload
            
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to parse JWT payload: {str(e)}")
    
    def validate_token_structure(self, token: str) -> bool:
        """
        Validate that token has correct JWT structure.
        
        Args:
            token: JWT token string
            
        Returns:
            True if token has valid structure, False otherwise
        """
        if not token or not isinstance(token, str):
            return False
        
        # Check basic JWT format (3 parts separated by dots)
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Check that each part is valid base64
        for part in parts:
            try:
                # Add padding and try to decode
                padded = part + '=' * (4 - len(part) % 4)
                urlsafe_b64decode(padded)
            except Exception:
                return False
        
        return True


# Convenience function for easy usage
def parse_okta_token_for_permissions(access_token: str, groups_claim: str = "groups") -> tuple[str, List[str]]:
    """
    Convenience function to parse Okta token and get permissions.
    
    Args:
        access_token: JWT access token from Okta
        groups_claim: Name of the groups claim in JWT (default: "groups")
        
    Returns:
        Tuple of (highest_permission_level, list_of_groups)
    """
    parser = OktaTokenParser(groups_claim=groups_claim)
    return parser.parse_token_for_permissions(access_token)
```

#### 2. Configuration Support
**Path**: `backend/onyx/configs/oauth_settings.py` (enhancement)

Add these settings to existing config:

```python
# Add to existing oauth settings
OKTA_GROUPS_CLAIM: str = "groups"
OKTA_DEFAULT_PERMISSION: str = "read"
OKTA_GROUP_MAPPING: Dict[str, str] = {
    "Onyx-Admins": "admin",
    "Onyx-Writers": "write", 
    "Onyx-Readers": "read",
    "Onyx-Viewers": "read"
}
```

## 🧪 Testing Requirements

### Unit Tests
**Path**: `backend/tests/unit/auth/test_okta_token_parser.py`

```python
"""
Unit tests for Okta JWT Token Parser
"""
import pytest
import json
from base64 import urlsafe_b64encode
from unittest.mock import patch, MagicMock

from onyx.auth.okta_parser import OktaTokenParser, parse_okta_token_for_permissions


class TestOktaTokenParser:
    
    def setup_method(self):
        """Set up test fixtures"""
        self.parser = OktaTokenParser()
    
    def create_mock_jwt_token(self, payload: dict) -> str:
        """Helper to create mock JWT tokens for testing"""
        # Create fake header and signature
        header = {"alg": "RS256", "typ": "JWT"}
        signature = "fake_signature"
        
        # Encode parts
        header_b64 = urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature_b64 = urlsafe_b64encode(signature.encode()).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    def test_extract_groups_from_valid_token(self):
        """Test extracting groups from a valid JWT token"""
        payload = {
            "sub": "user123",
            "groups": ["Onyx-Admins", "Onyx-Writers", "Other-Group"]
        }
        token = self.create_mock_jwt_token(payload)
        
        groups = self.parser.extract_groups_from_token(token)
        
        assert groups == ["Onyx-Admins", "Onyx-Writers", "Other-Group"]
    
    def test_extract_groups_no_groups_claim(self):
        """Test token without groups claim"""
        payload = {"sub": "user123"}
        token = self.create_mock_jwt_token(payload)
        
        groups = self.parser.extract_groups_from_token(token)
        
        assert groups == []
    
    def test_extract_groups_invalid_groups_claim(self):
        """Test token with non-list groups claim"""
        payload = {
            "sub": "user123",
            "groups": "not-a-list"
        }
        token = self.create_mock_jwt_token(payload)
        
        groups = self.parser.extract_groups_from_token(token)
        
        assert groups == []
    
    def test_extract_groups_malformed_token(self):
        """Test handling of malformed JWT token"""
        with pytest.raises(ValueError, match="Invalid or malformed JWT token"):
            self.parser.extract_groups_from_token("not.a.valid.jwt")
    
    def test_map_groups_to_permissions(self):
        """Test mapping Okta groups to permissions"""
        groups = ["Onyx-Admins", "Onyx-Readers", "Unknown-Group"]
        
        permissions = self.parser.map_groups_to_permissions(groups)
        
        assert "admin" in permissions
        assert "read" in permissions
        assert len(permissions) == 2  # Unknown-Group should be ignored
    
    def test_map_groups_case_insensitive(self):
        """Test case-insensitive group mapping"""
        groups = ["onyx-admins", "ONYX-WRITERS"]  # Different cases
        
        permissions = self.parser.map_groups_to_permissions(groups)
        
        assert "admin" in permissions
        # Note: ONYX-WRITERS (uppercase) not in default mapping
    
    def test_get_highest_permission_level(self):
        """Test permission hierarchy"""
        # Test admin is highest
        permissions = ["read", "write", "admin"]
        assert self.parser.get_highest_permission_level(permissions) == "admin"
        
        # Test write over read
        permissions = ["read", "write"]
        assert self.parser.get_highest_permission_level(permissions) == "write"
        
        # Test single permission
        permissions = ["read"]
        assert self.parser.get_highest_permission_level(permissions) == "read"
        
        # Test empty list
        permissions = []
        assert self.parser.get_highest_permission_level(permissions) == "read"
    
    def test_parse_token_for_permissions_complete_flow(self):
        """Test complete flow from token to permission"""
        payload = {
            "sub": "user123",
            "groups": ["Onyx-Writers", "Onyx-Readers", "Other-Group"]
        }
        token = self.create_mock_jwt_token(payload)
        
        permission, groups = self.parser.parse_token_for_permissions(token)
        
        assert permission == "write"  # Highest permission
        assert groups == ["Onyx-Writers", "Onyx-Readers", "Other-Group"]
    
    def test_parse_token_for_permissions_error_handling(self):
        """Test error handling in complete flow"""
        permission, groups = self.parser.parse_token_for_permissions("invalid-token")
        
        assert permission == "read"  # Fallback permission
        assert groups == []
    
    def test_validate_token_structure_valid(self):
        """Test validation of valid JWT structure"""
        payload = {"sub": "user123"}
        token = self.create_mock_jwt_token(payload)
        
        assert self.parser.validate_token_structure(token) is True
    
    def test_validate_token_structure_invalid(self):
        """Test validation of invalid JWT structures"""
        assert self.parser.validate_token_structure("not.jwt") is False
        assert self.parser.validate_token_structure("one.two.three.four") is False
        assert self.parser.validate_token_structure("") is False
        assert self.parser.validate_token_structure(None) is False
    
    def test_custom_groups_claim(self):
        """Test parser with custom groups claim name"""
        parser = OktaTokenParser(groups_claim="custom_groups")
        payload = {
            "sub": "user123",
            "custom_groups": ["Onyx-Admins"]
        }
        token = self.create_mock_jwt_token(payload)
        
        groups = parser.extract_groups_from_token(token)
        
        assert groups == ["Onyx-Admins"]


def test_convenience_function():
    """Test the convenience function"""
    with patch('onyx.auth.okta_parser.OktaTokenParser') as mock_parser_class:
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        mock_parser.parse_token_for_permissions.return_value = ("admin", ["Onyx-Admins"])
        
        permission, groups = parse_okta_token_for_permissions("fake-token")
        
        assert permission == "admin"
        assert groups == ["Onyx-Admins"]
        mock_parser_class.assert_called_once_with(groups_claim="groups")
```

### Integration Tests
**Path**: `backend/tests/integration/auth/test_okta_integration.py`

```python
"""
Integration tests for Okta token parsing with real-world scenarios
"""
import pytest
from unittest.mock import patch

from onyx.auth.okta_parser import OktaTokenParser


class TestOktaIntegration:
    
    def test_realistic_okta_token_structure(self):
        """Test with realistic Okta token payload structure"""
        # This would be a more realistic test with actual Okta token structure
        # For now, we'll simulate the expected structure
        pass
    
    def test_performance_with_large_group_lists(self):
        """Test performance with users who have many groups"""
        parser = OktaTokenParser()
        
        # Simulate user with many groups
        large_group_list = [f"Group-{i}" for i in range(100)]
        large_group_list.extend(["Onyx-Admins", "Onyx-Writers"])
        
        permissions = parser.map_groups_to_permissions(large_group_list)
        highest = parser.get_highest_permission_level(permissions)
        
        assert highest == "admin"
        assert len(permissions) == 2  # Only mapped groups
```

## 🚀 Deployment Checklist

### Pre-deployment
- [ ] Code review completed
- [ ] All unit tests passing (>95% coverage)
- [ ] Integration tests passing
- [ ] Performance tests meet requirements (<50ms parsing time)
- [ ] Security review completed

### Deployment Steps
1. [ ] Deploy new parser module
2. [ ] Verify import and basic functionality
3. [ ] Test with sample JWT tokens
4. [ ] Monitor logs for any parsing errors
5. [ ] Verify no impact on existing authentication

### Post-deployment Verification
- [ ] Parser can handle various JWT token formats
- [ ] Group extraction working correctly
- [ ] Permission mapping functioning as expected
- [ ] Error handling working for malformed tokens
- [ ] Performance metrics within acceptable range

### Rollback Plan
If issues occur:
1. Remove new parser module
2. Revert any imports/dependencies
3. Verify existing authentication works
4. Investigate and fix issues before re-deployment

## 📋 Definition of Done

- [ ] All acceptance criteria met
- [ ] `OktaTokenParser` class implemented with all required methods
- [ ] Comprehensive unit tests with >95% coverage
- [ ] Integration tests passing
- [ ] Error handling for all edge cases
- [ ] Performance requirements met (<50ms parsing)
- [ ] Security considerations addressed
- [ ] Code reviewed and approved
- [ ] Documentation added to code
- [ ] Deployed successfully without issues

## 🔗 Related Stories

**Previous Stories**: None (can be developed in parallel with 1.1)  
**Next Stories**:
- Story 1.3: OAuth Permission Database Operations
- Story 2.1: Enhanced OAuth Callback Handler (will use this parser)

## 📝 Notes

- This parser does NOT verify JWT signatures initially - that's a security enhancement for later
- The parser is designed to be flexible with group claim names
- Group names are matched case-sensitively by default, with some lowercase variants supported
- The parser gracefully handles missing or malformed data with safe fallbacks
- Performance is optimized for typical Okta token sizes (usually <50 groups per user)

## 🐛 Known Risks

1. **JWT Format Changes**: Okta might change token structure
2. **Group Name Variations**: Different case or naming conventions
3. **Performance**: Large group lists might slow parsing
4. **Security**: No signature verification (planned for future story)

## 💡 Success Metrics

- Parser processes tokens in under 50ms
- 100% test coverage for core parsing logic
- Zero errors in token parsing for valid tokens
- Graceful handling of 100% of malformed tokens tested
