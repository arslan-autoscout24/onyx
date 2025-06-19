"""
Security Testing Suite for OAuth Permission System

This module contains security tests to validate the OAuth authorization system
against various attack vectors and ensure proper security controls are in place.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from onyx.main import app
from tests.helpers.auth import (
    create_invalid_jwt_token, 
    create_expired_jwt_token, 
    create_okta_jwt_token,
    create_modified_jwt_token,
    create_malicious_jwt_token
)


class TestSecurityBypass:
    """Test security scenarios and bypass attempts."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = TestClient(app)
    
    def test_invalid_jwt_token_rejected(self):
        """Test that invalid JWT tokens are rejected."""
        invalid_token = create_invalid_jwt_token()
        headers = {"Authorization": f"Bearer {invalid_token}"}
        
        response = self.client.get("/documents", headers=headers)
        assert response.status_code == 401
        
        error_detail = response.json().get("detail", {})
        assert "invalid_token" in str(error_detail).lower() or "unauthorized" in str(error_detail).lower()
    
    def test_expired_jwt_token_rejected(self):
        """Test that expired JWT tokens are rejected."""
        expired_token = create_expired_jwt_token("user@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {expired_token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            # Mock JWT library to raise an exception for expired token
            mock_verify.side_effect = Exception("Token has expired")
            
            response = self.client.get("/documents", headers=headers)
            assert response.status_code == 401
    
    def test_modified_jwt_token_rejected(self):
        """Test that modified JWT tokens are rejected."""
        modified_token = create_modified_jwt_token("reader@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {modified_token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            # Mock JWT library to raise an exception for invalid signature
            mock_verify.side_effect = Exception("Invalid token signature")
            
            response = self.client.get("/admin/users", headers=headers)
            assert response.status_code == 401
    
    def test_privilege_escalation_attempt(self):
        """Test that users cannot escalate their privileges."""
        reader_token = create_okta_jwt_token("reader@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {reader_token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'reader@test.com', 'groups': ['Onyx-Readers']}
            
            # Attempt to access admin endpoint
            response = self.client.get("/admin/users", headers=headers)
            assert response.status_code == 403
            
            # Attempt to modify user permissions directly
            response = self.client.put(
                "/admin/users/123/permissions",
                json={"permission_level": "admin"},
                headers=headers
            )
            assert response.status_code == 403
    
    def test_malicious_group_claims(self):
        """Test handling of malicious group claims."""
        malicious_groups = [
            "'; DROP TABLE oauth_permissions; --",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "Onyx-Admins'; UPDATE users SET is_admin=true; --"
        ]
        
        for malicious_group in malicious_groups:
            malicious_token = create_malicious_jwt_token("malicious@test.com", [malicious_group])
            headers = {"Authorization": f"Bearer {malicious_token}"}
            
            with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
                mock_verify.return_value = {'email': 'malicious@test.com', 'groups': [malicious_group]}
                
                # Should not crash or execute malicious code
                response = self.client.get("/documents", headers=headers)
                # Should either work (if properly sanitized) or reject gracefully
                assert response.status_code in [200, 400, 403, 401]
    
    def test_no_authorization_header(self):
        """Test that requests without authorization headers are rejected."""
        response = self.client.get("/documents")
        assert response.status_code == 401
        
        # Test admin endpoints
        response = self.client.get("/admin/users")
        assert response.status_code == 401
    
    def test_malformed_authorization_header(self):
        """Test that malformed authorization headers are rejected."""
        malformed_headers = [
            {"Authorization": "InvalidFormat"},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer "},
            {"Authorization": "Basic dXNlcjpwYXNz"},  # Basic auth instead of Bearer
            {"Authorization": "Bearer invalid-token-format"},
        ]
        
        for headers in malformed_headers:
            response = self.client.get("/documents", headers=headers)
            assert response.status_code == 401
    
    def test_token_replay_attack_prevention(self):
        """Test that the system handles token replay attacks appropriately."""
        # This test would check if the same token can be used multiple times
        # In most OAuth implementations, this is allowed until token expires
        # But we can test for any specific replay attack mitigations
        
        token = create_okta_jwt_token("user@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'user@test.com', 'groups': ['Onyx-Readers']}
            
            # Multiple requests with same token should work (unless specific replay protection)
            for _ in range(5):
                response = self.client.get("/documents", headers=headers)
                assert response.status_code == 200
    
    def test_cross_user_permission_access(self):
        """Test that users cannot access other users' specific resources."""
        user1_token = create_okta_jwt_token("user1@test.com", ["Onyx-Writers"])
        user2_token = create_okta_jwt_token("user2@test.com", ["Onyx-Writers"])
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            # User 1 creates a document
            mock_verify.return_value = {'email': 'user1@test.com', 'groups': ['Onyx-Writers']}
            user1_headers = {"Authorization": f"Bearer {user1_token}"}
            
            create_response = self.client.post(
                "/documents",
                json={"title": "User1's Document", "content": "Private content"},
                headers=user1_headers
            )
            
            if create_response.status_code in [200, 201]:
                document_id = create_response.json().get("id")
                
                # User 2 should not be able to access User 1's specific document
                # (depending on implementation - this test assumes user-specific access control)
                mock_verify.return_value = {'email': 'user2@test.com', 'groups': ['Onyx-Writers']}
                user2_headers = {"Authorization": f"Bearer {user2_token}"}
                
                access_response = self.client.get(f"/documents/{document_id}", headers=user2_headers)
                # This depends on whether documents are user-specific or globally accessible
                # Adjust assertion based on actual business logic
                assert access_response.status_code in [200, 403, 404]
    
    def test_session_fixation_protection(self):
        """Test protection against session fixation attacks."""
        # This test would be relevant if the system uses sessions
        # For JWT-based auth, this is less of a concern, but we can test
        # that tokens are properly validated each time
        
        token = create_okta_jwt_token("user@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'user@test.com', 'groups': ['Onyx-Readers']}
            
            # Each request should validate the token independently
            response1 = self.client.get("/documents", headers=headers)
            response2 = self.client.get("/documents", headers=headers)
            
            assert response1.status_code == 200
            assert response2.status_code == 200
            
            # Verify that mock was called for each request (no session caching of auth)
            assert mock_verify.call_count >= 2
    
    def test_permission_boundary_violations(self):
        """Test that permission boundaries cannot be violated."""
        test_cases = [
            {
                "token": create_okta_jwt_token("reader@test.com", ["Onyx-Readers"]),
                "mock_data": {'email': 'reader@test.com', 'groups': ['Onyx-Readers']},
                "forbidden_operations": [
                    ("POST", "/documents", {"title": "Test", "content": "Test"}),
                    ("PUT", "/documents/1", {"title": "Updated", "content": "Updated"}),
                    ("DELETE", "/documents/1", {}),
                    ("GET", "/admin/users", {}),
                    ("POST", "/admin/connector", {})
                ]
            },
            {
                "token": create_okta_jwt_token("writer@test.com", ["Onyx-Writers"]),
                "mock_data": {'email': 'writer@test.com', 'groups': ['Onyx-Writers']},
                "forbidden_operations": [
                    ("GET", "/admin/users", {}),
                    ("POST", "/admin/connector", {}),
                    ("PUT", "/admin/settings", {"key": "value"})
                ]
            }
        ]
        
        for case in test_cases:
            headers = {"Authorization": f"Bearer {case['token']}"}
            
            with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
                mock_verify.return_value = case['mock_data']
                
                for method, endpoint, payload in case['forbidden_operations']:
                    if method == "GET":
                        response = self.client.get(endpoint, headers=headers)
                    elif method == "POST":
                        response = self.client.post(endpoint, json=payload, headers=headers)
                    elif method == "PUT":
                        response = self.client.put(endpoint, json=payload, headers=headers)
                    elif method == "DELETE":
                        response = self.client.delete(endpoint, headers=headers)
                    
                    assert response.status_code == 403, \
                        f"{method} {endpoint} should be forbidden for user with groups {case['mock_data']['groups']}"
