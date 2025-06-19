"""
End-to-End OAuth Authorization Integration Tests

This module contains comprehensive integration tests for the OAuth authorization system,
testing the complete flow from Okta login through permission assignment to API access enforcement.
"""

import pytest
import asyncio
import time
import concurrent.futures
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from onyx.main import app
from onyx.db.models import User, OAuthPermission, PermissionLevel
from tests.helpers.auth import (
    create_okta_jwt_token, 
    create_test_user_with_groups,
    cleanup_test_data,
    get_test_users_data,
    create_test_user_in_db
)


class TestOAuthAuthorization:
    """Comprehensive OAuth authorization test suite."""
    
    @pytest.fixture(autouse=True)
    async def setup_and_teardown(self):
        """Setup test data and cleanup after each test."""
        # Setup
        self.client = TestClient(app)
        self.test_users = {}
        yield
        # Teardown
        await cleanup_test_data()
    
    @pytest.mark.asyncio
    async def test_okta_login_grants_permissions(self):
        """Test complete flow: Okta login → permission assignment → API access."""
        test_cases = get_test_users_data()
        
        for case in test_cases:
            # Create JWT token with groups
            jwt_token = create_okta_jwt_token(
                email=case["email"],
                groups=case["groups"]
            )
            
            # Step 1: Login and trigger OAuth callback
            with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
                mock_verify.return_value = {
                    'email': case["email"],
                    'groups': case["groups"]
                }
                
                response = self.client.post(
                    "/auth/callback",
                    json={"code": "test_code", "state": "test_state"},
                    headers={"Authorization": f"Bearer {jwt_token}"}
                )
                assert response.status_code == 200
                
                # Step 2: Verify permission assignment
                user_data = response.json()
                assert user_data["email"] == case["email"]
                
                # Step 3: Test API access with assigned permissions
                auth_header = {"Authorization": f"Bearer {jwt_token}"}
                
                # Test read access (should work for all)
                read_response = self.client.get("/documents", headers=auth_header)
                assert read_response.status_code == 200
                
                # Test write access
                write_response = self.client.post(
                    "/documents",
                    json={"title": "Test Doc", "content": "Test content"},
                    headers=auth_header
                )
                if case["expected_permission"] in ["write", "admin"]:
                    assert write_response.status_code in [200, 201]
                else:
                    assert write_response.status_code == 403
                
                # Test admin access
                admin_response = self.client.get("/admin/users", headers=auth_header)
                if case["expected_permission"] == "admin":
                    assert admin_response.status_code == 200
                else:
                    assert admin_response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_permission_enforcement_on_documents(self):
        """Test permission enforcement on document endpoints."""
        # Create users with different permission levels
        admin_token = create_okta_jwt_token("admin@test.com", ["Onyx-Admins"])
        writer_token = create_okta_jwt_token("writer@test.com", ["Onyx-Writers"])
        reader_token = create_okta_jwt_token("reader@test.com", ["Onyx-Readers"])
        
        test_document = {
            "title": "Permission Test Document",
            "content": "This is a test document for permission testing"
        }
        
        # Test document operations with different permission levels
        endpoints = [
            ("GET", "/documents", [admin_token, writer_token, reader_token]),
            ("POST", "/documents", [admin_token, writer_token]),
            ("PUT", "/documents/1", [admin_token, writer_token]),
            ("DELETE", "/documents/1", [admin_token, writer_token])
        ]
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            for method, endpoint, allowed_tokens in endpoints:
                # Test allowed tokens
                for token in allowed_tokens:
                    # Mock JWT verification based on token
                    if token == admin_token:
                        mock_verify.return_value = {'email': 'admin@test.com', 'groups': ['Onyx-Admins']}
                    elif token == writer_token:
                        mock_verify.return_value = {'email': 'writer@test.com', 'groups': ['Onyx-Writers']}
                    elif token == reader_token:
                        mock_verify.return_value = {'email': 'reader@test.com', 'groups': ['Onyx-Readers']}
                    
                    headers = {"Authorization": f"Bearer {token}"}
                    if method == "GET":
                        response = self.client.get(endpoint, headers=headers)
                    elif method == "POST":
                        response = self.client.post(endpoint, json=test_document, headers=headers)
                    elif method == "PUT":
                        response = self.client.put(endpoint, json=test_document, headers=headers)
                    elif method == "DELETE":
                        response = self.client.delete(endpoint, headers=headers)
                    
                    assert response.status_code in [200, 201, 204], \
                        f"{method} {endpoint} failed for allowed token"
                
                # Test forbidden tokens
                all_tokens = [admin_token, writer_token, reader_token]
                forbidden_tokens = [t for t in all_tokens if t not in allowed_tokens]
                
                for token in forbidden_tokens:
                    # Mock JWT verification
                    if token == admin_token:
                        mock_verify.return_value = {'email': 'admin@test.com', 'groups': ['Onyx-Admins']}
                    elif token == writer_token:
                        mock_verify.return_value = {'email': 'writer@test.com', 'groups': ['Onyx-Writers']}
                    elif token == reader_token:
                        mock_verify.return_value = {'email': 'reader@test.com', 'groups': ['Onyx-Readers']}
                    
                    headers = {"Authorization": f"Bearer {token}"}
                    if method == "GET":
                        response = self.client.get(endpoint, headers=headers)
                    elif method == "POST":
                        response = self.client.post(endpoint, json=test_document, headers=headers)
                    elif method == "PUT":
                        response = self.client.put(endpoint, json=test_document, headers=headers)
                    elif method == "DELETE":
                        response = self.client.delete(endpoint, headers=headers)
                    
                    assert response.status_code == 403, \
                        f"{method} {endpoint} should be forbidden for token"
    
    @pytest.mark.asyncio
    async def test_permission_enforcement_on_chat(self):
        """Test permission enforcement on chat endpoints."""
        admin_token = create_okta_jwt_token("admin@test.com", ["Onyx-Admins"])
        writer_token = create_okta_jwt_token("writer@test.com", ["Onyx-Writers"])
        reader_token = create_okta_jwt_token("reader@test.com", ["Onyx-Readers"])
        
        test_chat_session = {
            "name": "Test Chat Session",
            "description": "Test session for permission testing"
        }
        
        # Test chat session operations
        endpoints = [
            ("GET", "/chat-sessions", [admin_token, writer_token, reader_token]),
            ("POST", "/chat-sessions", [admin_token, writer_token]),
            ("PUT", "/chat-sessions/1", [admin_token, writer_token]),
            ("DELETE", "/chat-sessions/1", [admin_token, writer_token])
        ]
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            for method, endpoint, allowed_tokens in endpoints:
                # Test allowed access
                for token in allowed_tokens:
                    # Mock JWT verification
                    if token == admin_token:
                        mock_verify.return_value = {'email': 'admin@test.com', 'groups': ['Onyx-Admins']}
                    elif token == writer_token:
                        mock_verify.return_value = {'email': 'writer@test.com', 'groups': ['Onyx-Writers']}
                    elif token == reader_token:
                        mock_verify.return_value = {'email': 'reader@test.com', 'groups': ['Onyx-Readers']}
                    
                    headers = {"Authorization": f"Bearer {token}"}
                    if method == "GET":
                        response = self.client.get(endpoint, headers=headers)
                    elif method == "POST":
                        response = self.client.post(endpoint, json=test_chat_session, headers=headers)
                    elif method == "PUT":
                        response = self.client.put(endpoint, json=test_chat_session, headers=headers)
                    elif method == "DELETE":
                        response = self.client.delete(endpoint, headers=headers)
                    
                    assert response.status_code in [200, 201, 204]
                
                # Test forbidden access
                all_tokens = [admin_token, writer_token, reader_token]
                forbidden_tokens = [t for t in all_tokens if t not in allowed_tokens]
                
                for token in forbidden_tokens:
                    # Mock JWT verification
                    if token == admin_token:
                        mock_verify.return_value = {'email': 'admin@test.com', 'groups': ['Onyx-Admins']}
                    elif token == writer_token:
                        mock_verify.return_value = {'email': 'writer@test.com', 'groups': ['Onyx-Writers']}
                    elif token == reader_token:
                        mock_verify.return_value = {'email': 'reader@test.com', 'groups': ['Onyx-Readers']}
                    
                    headers = {"Authorization": f"Bearer {token}"}
                    if method == "POST":
                        response = self.client.post(endpoint, json=test_chat_session, headers=headers)
                        assert response.status_code == 403
    
    @pytest.mark.asyncio 
    async def test_admin_permission_enforcement(self):
        """Test admin-only endpoint protection."""
        admin_token = create_okta_jwt_token("admin@test.com", ["Onyx-Admins"])
        writer_token = create_okta_jwt_token("writer@test.com", ["Onyx-Writers"])
        reader_token = create_okta_jwt_token("reader@test.com", ["Onyx-Readers"])
        
        admin_endpoints = [
            ("GET", "/admin/users"),
            ("GET", "/admin/settings"),
            ("POST", "/admin/connector"),
            ("GET", "/admin/analytics")
        ]
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            for method, endpoint in admin_endpoints:
                # Admin should have access
                mock_verify.return_value = {'email': 'admin@test.com', 'groups': ['Onyx-Admins']}
                admin_headers = {"Authorization": f"Bearer {admin_token}"}
                if method == "GET":
                    admin_response = self.client.get(endpoint, headers=admin_headers)
                elif method == "POST":
                    admin_response = self.client.post(endpoint, json={}, headers=admin_headers)
                
                assert admin_response.status_code in [200, 201]
                
                # Non-admin users should be forbidden
                for non_admin_token, email, groups in [
                    (writer_token, "writer@test.com", ["Onyx-Writers"]),
                    (reader_token, "reader@test.com", ["Onyx-Readers"])
                ]:
                    mock_verify.return_value = {'email': email, 'groups': groups}
                    headers = {"Authorization": f"Bearer {non_admin_token}"}
                    if method == "GET":
                        response = self.client.get(endpoint, headers=headers)
                    elif method == "POST":
                        response = self.client.post(endpoint, json={}, headers=headers)
                    
                    assert response.status_code == 403
                    error_detail = response.json().get("detail", {})
                    if isinstance(error_detail, dict):
                        assert "admin_permission_required" in error_detail.get("error", "")
    
    @pytest.mark.asyncio
    async def test_permission_caching_performance(self):
        """Test permission caching and performance under load."""
        user_token = create_okta_jwt_token("test@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {user_token}"}
        
        def make_request():
            start_time = time.time()
            with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
                mock_verify.return_value = {'email': 'test@test.com', 'groups': ['Onyx-Readers']}
                response = self.client.get("/documents", headers=headers)
            end_time = time.time()
            return response.status_code, (end_time - start_time) * 1000
        
        # Test concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Verify all requests succeeded
        status_codes, response_times = zip(*results)
        assert all(code == 200 for code in status_codes)
        
        # Verify performance requirements
        avg_response_time = sum(response_times) / len(response_times)
        assert avg_response_time < 100, f"Average response time {avg_response_time}ms exceeds 100ms"
        
        # Verify cache hit rate (first request should be slower)
        first_time = response_times[0]
        subsequent_times = response_times[1:]
        avg_subsequent = sum(subsequent_times) / len(subsequent_times)
        
        # Subsequent requests should be faster due to caching
        assert avg_subsequent < first_time * 0.8, "Permission caching not effective"
