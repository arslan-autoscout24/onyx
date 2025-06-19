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
    
    def test_extract_groups_incomplete_token(self):
        """Test handling of incomplete JWT token"""
        with pytest.raises(ValueError, match="Invalid or malformed JWT token"):
            self.parser.extract_groups_from_token("missing.parts")
    
    def test_map_groups_to_permissions(self):
        """Test mapping Okta groups to permissions"""
        groups = ["Onyx-Admins", "Onyx-Readers", "Unknown-Group"]
        
        permissions = self.parser.map_groups_to_permissions(groups)
        
        assert "admin" in permissions
        assert "read" in permissions
        assert len(permissions) == 2  # Unknown-Group should be ignored
    
    def test_map_groups_case_sensitivity(self):
        """Test case-sensitive group mapping"""
        groups = ["onyx-admins", "Onyx-Writers"]
        
        permissions = self.parser.map_groups_to_permissions(groups)
        
        assert "admin" in permissions
        assert "write" in permissions
        assert len(permissions) == 2
    
    def test_map_groups_empty_list(self):
        """Test mapping empty group list"""
        groups = []
        
        permissions = self.parser.map_groups_to_permissions(groups)
        
        assert permissions == []
    
    def test_map_groups_duplicate_permissions(self):
        """Test that duplicate permissions are removed"""
        groups = ["Onyx-Readers", "Onyx-Viewers"]  # Both map to 'read'
        
        permissions = self.parser.map_groups_to_permissions(groups)
        
        assert permissions == ["read"]  # Should only appear once
    
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
    
    def test_get_highest_permission_level_invalid_permissions(self):
        """Test handling of invalid permission levels"""
        permissions = ["invalid", "unknown", "read"]
        
        result = self.parser.get_highest_permission_level(permissions)
        
        assert result == "read"
    
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
    
    def test_parse_token_for_permissions_admin_user(self):
        """Test complete flow for admin user"""
        payload = {
            "sub": "admin123",
            "groups": ["Onyx-Admins", "Onyx-Writers", "Onyx-Readers"]
        }
        token = self.create_mock_jwt_token(payload)
        
        permission, groups = self.parser.parse_token_for_permissions(token)
        
        assert permission == "admin"  # Highest permission
        assert len(groups) == 3
    
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
        assert self.parser.validate_token_structure(123) is False
    
    def test_validate_token_structure_invalid_base64(self):
        """Test validation with invalid base64 parts"""
        invalid_token = "invalid_header.invalid_payload.invalid_signature"
        
        assert self.parser.validate_token_structure(invalid_token) is False
    
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
    
    def test_custom_groups_claim_missing(self):
        """Test custom groups claim when claim is missing"""
        parser = OktaTokenParser(groups_claim="missing_claim")
        payload = {
            "sub": "user123",
            "groups": ["Onyx-Admins"]  # Different claim name
        }
        token = self.create_mock_jwt_token(payload)
        
        groups = parser.extract_groups_from_token(token)
        
        assert groups == []
    
    def test_parse_jwt_payload_invalid_json(self):
        """Test parsing JWT with invalid JSON payload"""
        # Create token with invalid JSON in payload
        header = {"alg": "RS256", "typ": "JWT"}
        invalid_payload = "invalid-json"
        signature = "fake_signature"
        
        header_b64 = urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = urlsafe_b64encode(invalid_payload.encode()).decode().rstrip('=')
        signature_b64 = urlsafe_b64encode(signature.encode()).decode().rstrip('=')
        
        token = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        with pytest.raises(ValueError, match="Invalid or malformed JWT token"):
            self.parser.extract_groups_from_token(token)
    
    def test_jwt_payload_with_padding_needed(self):
        """Test JWT payload that needs base64 padding"""
        # Create a payload that when base64 encoded will need padding
        payload = {"sub": "test"}  # Short payload
        payload_json = json.dumps(payload)
        
        # Encode without padding
        payload_b64 = urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
        
        # Create complete token
        header = {"alg": "RS256", "typ": "JWT"}
        signature = "fake_signature"
        
        header_b64 = urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        signature_b64 = urlsafe_b64encode(signature.encode()).decode().rstrip('=')
        
        token = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        # Should work despite missing padding
        decoded_payload = self.parser._parse_jwt_payload(token)
        assert decoded_payload["sub"] == "test"
    
    def test_performance_with_large_group_list(self):
        """Test performance with users who have many groups"""
        # Create a large group list
        large_group_list = [f"Group-{i}" for i in range(100)]
        large_group_list.extend(["Onyx-Admins", "Onyx-Writers"])
        
        payload = {
            "sub": "user123",
            "groups": large_group_list
        }
        token = self.create_mock_jwt_token(payload)
        
        import time
        start_time = time.time()
        
        permission, groups = self.parser.parse_token_for_permissions(token)
        
        end_time = time.time()
        processing_time = (end_time - start_time) * 1000  # Convert to milliseconds
        
        # Should complete in under 50ms (performance requirement)
        assert processing_time < 50
        assert permission == "admin"
        assert len(groups) == 102  # 100 + 2 mapped groups


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


def test_convenience_function_with_custom_claim():
    """Test the convenience function with custom groups claim"""
    with patch('onyx.auth.okta_parser.OktaTokenParser') as mock_parser_class:
        mock_parser = MagicMock()
        mock_parser_class.return_value = mock_parser
        mock_parser.parse_token_for_permissions.return_value = ("write", ["Onyx-Writers"])
        
        permission, groups = parse_okta_token_for_permissions("fake-token", "custom_groups")
        
        assert permission == "write"
        assert groups == ["Onyx-Writers"]
        mock_parser_class.assert_called_once_with(groups_claim="custom_groups")


class TestOktaTokenParserErrorCases:
    """Additional test cases for error handling and edge cases"""
    
    def setup_method(self):
        self.parser = OktaTokenParser()
    
    def test_extract_groups_with_none_token(self):
        """Test handling of None token"""
        with pytest.raises(ValueError, match="Invalid or malformed JWT token"):
            self.parser.extract_groups_from_token(None)
    
    def test_extract_groups_with_empty_string(self):
        """Test handling of empty string token"""
        with pytest.raises(ValueError, match="Invalid or malformed JWT token"):
            self.parser.extract_groups_from_token("")
    
    def test_groups_claim_with_null_value(self):
        """Test handling of null groups claim"""
        payload = {
            "sub": "user123",
            "groups": None
        }
        token_parts = ["header", urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('='), "signature"]
        token = ".".join(token_parts)
        
        groups = self.parser.extract_groups_from_token(token)
        
        assert groups == []
    
    def test_permission_hierarchy_consistency(self):
        """Test that permission hierarchy is consistent"""
        hierarchy = self.parser.PERMISSION_HIERARCHY
        
        # Check that hierarchy is properly ordered
        assert hierarchy.index("read") < hierarchy.index("write")
        assert hierarchy.index("write") < hierarchy.index("admin")
        
        # Check that all mapped permissions are in hierarchy
        for permission in self.parser.GROUP_MAPPING.values():
            assert permission in hierarchy
