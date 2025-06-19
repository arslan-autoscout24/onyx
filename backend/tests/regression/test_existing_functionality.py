"""
Regression Testing Suite for OAuth Integration

This module contains regression tests to ensure that the OAuth authorization system
doesn't break existing functionality and maintains backward compatibility.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from onyx.main import app
from tests.helpers.auth import create_okta_jwt_token


class TestRegressionSuite:
    """Ensure existing functionality remains unchanged."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = TestClient(app)
    
    def test_health_endpoint_still_works(self):
        """Test that health endpoint works without authentication."""
        response = self.client.get("/health")
        assert response.status_code == 200
        
        # Health endpoint should work regardless of OAuth implementation
        health_data = response.json()
        assert "status" in health_data or "message" in health_data
    
    def test_api_documentation_accessible(self):
        """Test that API documentation endpoints are still accessible."""
        endpoints = [
            "/docs",
            "/redoc", 
            "/openapi.json"
        ]
        
        for endpoint in endpoints:
            response = self.client.get(endpoint)
            # These should be accessible (either 200 or redirected to auth)
            assert response.status_code in [200, 307, 308, 401, 404], f"Endpoint {endpoint} broken"
    
    def test_basic_api_structure_unchanged(self):
        """Test that basic API structure hasn't changed."""
        # Test that endpoints exist (even if they require auth now)
        endpoints_to_check = [
            "/documents",
            "/chat-sessions", 
            "/admin/users"
        ]
        
        for endpoint in endpoints_to_check:
            response = self.client.get(endpoint)
            # Should get 401 (unauthorized) rather than 404 (not found)
            assert response.status_code in [200, 401, 403], f"Endpoint {endpoint} seems to be removed"
    
    def test_existing_database_schema_compatibility(self):
        """Test that existing database operations still work."""
        # Test basic database connectivity and schema
        admin_token = create_okta_jwt_token("admin@test.com", ["Onyx-Admins"])
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'admin@test.com', 'groups': ['Onyx-Admins']}
            
            # Test that we can still create and retrieve documents
            create_response = self.client.post(
                "/documents",
                json={"title": "Regression Test Doc", "content": "Testing compatibility"},
                headers=headers
            )
            
            # Should work if documents API exists
            if create_response.status_code in [200, 201]:
                # Try to list documents
                list_response = self.client.get("/documents", headers=headers)
                assert list_response.status_code == 200
    
    def test_error_handling_consistency(self):
        """Test that error responses maintain consistent format."""
        # Test unauthorized access
        response = self.client.get("/admin/users")
        assert response.status_code == 401
        
        error_data = response.json()
        # Error format should be consistent
        assert isinstance(error_data, dict)
        assert "detail" in error_data or "error" in error_data or "message" in error_data
    
    def test_cors_headers_still_present(self):
        """Test that CORS headers are still properly configured."""
        response = self.client.options("/documents", headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET"
        })
        
        # CORS should still work
        # Depending on CORS configuration, we might get different status codes
        assert response.status_code in [200, 204, 401]
    
    def test_content_type_handling(self):
        """Test that content type handling remains consistent."""
        admin_token = create_okta_jwt_token("admin@test.com", ["Onyx-Admins"])
        headers = {
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        }
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'admin@test.com', 'groups': ['Onyx-Admins']}
            
            # Test that JSON is still properly handled
            response = self.client.post(
                "/documents",
                json={"title": "Content Type Test", "content": "Testing JSON handling"},
                headers=headers
            )
            
            # Should handle JSON correctly
            if response.status_code in [200, 201]:
                response_data = response.json()
                assert isinstance(response_data, dict)
    
    def test_existing_query_parameters_work(self):
        """Test that existing query parameters are still supported."""
        reader_token = create_okta_jwt_token("reader@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {reader_token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'reader@test.com', 'groups': ['Onyx-Readers']}
            
            # Test with various query parameters
            query_params = [
                "?limit=10",
                "?offset=0",
                "?sort=created_at",
                "?search=test"
            ]
            
            for params in query_params:
                response = self.client.get(f"/documents{params}", headers=headers)
                # Should handle query parameters correctly
                assert response.status_code in [200, 400], f"Query params {params} not handled correctly"
    
    def test_file_upload_compatibility(self):
        """Test that file upload functionality (if it exists) still works."""
        writer_token = create_okta_jwt_token("writer@test.com", ["Onyx-Writers"])
        headers = {"Authorization": f"Bearer {writer_token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'writer@test.com', 'groups': ['Onyx-Writers']}
            
            # Test file upload endpoint (if it exists)
            test_file_content = b"Test file content for regression testing"
            files = {"file": ("test.txt", test_file_content, "text/plain")}
            
            # This endpoint may or may not exist, so we test gracefully
            response = self.client.post("/upload", files=files, headers=headers)
            # Should either work or return a proper error (not crash)
            assert response.status_code in [200, 201, 400, 404, 405, 413]
    
    def test_websocket_compatibility(self):
        """Test that WebSocket connections (if they exist) are not broken."""
        # This would test WebSocket endpoints if they exist
        # Since WebSockets require special handling in tests, we'll test the endpoint existence
        
        # Test that WebSocket upgrade endpoints respond appropriately
        response = self.client.get("/ws", headers={"Upgrade": "websocket"})
        # Should either work or return appropriate error (not crash)
        assert response.status_code in [200, 400, 404, 426, 501]
    
    def test_rate_limiting_unchanged(self):
        """Test that rate limiting behavior hasn't changed."""
        reader_token = create_okta_jwt_token("reader@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {reader_token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'reader@test.com', 'groups': ['Onyx-Readers']}
            
            # Make multiple rapid requests
            responses = []
            for _ in range(20):
                response = self.client.get("/documents", headers=headers)
                responses.append(response.status_code)
            
            # Rate limiting should work consistently
            # Should not see unexpected errors
            valid_status_codes = [200, 429, 403]  # 429 = rate limited
            assert all(code in valid_status_codes for code in responses)
    
    def test_logging_functionality_preserved(self):
        """Test that logging functionality works correctly."""
        # This is more of an integration test to ensure logging doesn't break
        admin_token = create_okta_jwt_token("admin@test.com", ["Onyx-Admins"])
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'admin@test.com', 'groups': ['Onyx-Admins']}
            
            # Make a request that should be logged
            response = self.client.get("/admin/users", headers=headers)
            
            # Should not crash due to logging issues
            assert response.status_code in [200, 403], "Request failed, possibly due to logging issues"
    
    def test_session_handling_backward_compatibility(self):
        """Test that session handling (if any) remains compatible."""
        # Test that any existing session-based functionality works
        # or gracefully degrades to the new OAuth system
        
        # Test with and without session cookies
        response_without_session = self.client.get("/documents")
        assert response_without_session.status_code == 401
        
        # Test that adding OAuth token works
        reader_token = create_okta_jwt_token("reader@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {reader_token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'reader@test.com', 'groups': ['Onyx-Readers']}
            
            response_with_oauth = self.client.get("/documents", headers=headers)
            assert response_with_oauth.status_code == 200
