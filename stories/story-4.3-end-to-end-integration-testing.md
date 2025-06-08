# Story 4.3: End-to-End Integration Testing

**Priority**: P0 - Critical  
**Estimate**: 2 days  
**Dependencies**: All previous stories (1.1-4.2)  
**Sprint**: 4 - Admin Protection & Testing

## Description

Comprehensive testing of the complete OAuth authorization flow, validating the entire system from Okta login through permission assignment to API access enforcement.

## Acceptance Criteria

- [ ] End-to-end test: Okta login → permission assignment → API access
- [ ] Test all permission levels: read, write, admin
- [ ] Test permission enforcement across all protected endpoints
- [ ] Performance testing: permission checks under load
- [ ] Security testing: attempt to bypass permissions
- [ ] Test data cleanup and reset procedures
- [ ] Regression testing: ensure existing functionality unchanged
- [ ] Cross-browser compatibility testing
- [ ] Mobile responsiveness testing

## Technical Implementation

### End-to-End Test Suite

#### 1. Complete OAuth Flow Testing
```python
# File: backend/tests/integration/test_oauth_authorization.py
import pytest
import asyncio
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from onyx.main import app
from onyx.db.models import User, OAuthPermission, PermissionLevel
from tests.helpers.auth import (
    create_okta_jwt_token, 
    create_test_user_with_groups,
    cleanup_test_data
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
        # Step 1: Simulate Okta login with different group memberships
        test_cases = [
            {
                "email": "admin@example.com",
                "groups": ["Onyx-Admins", "Onyx-Writers", "Onyx-Readers"],
                "expected_permission": "admin"
            },
            {
                "email": "writer@example.com", 
                "groups": ["Onyx-Writers", "Onyx-Readers"],
                "expected_permission": "write"
            },
            {
                "email": "reader@example.com",
                "groups": ["Onyx-Readers"],
                "expected_permission": "read"
            }
        ]
        
        for case in test_cases:
            # Create JWT token with groups
            jwt_token = create_okta_jwt_token(
                email=case["email"],
                groups=case["groups"]
            )
            
            # Step 2: Login and trigger OAuth callback
            response = self.client.post(
                "/auth/callback",
                json={"code": "test_code", "state": "test_state"},
                headers={"Authorization": f"Bearer {jwt_token}"}
            )
            assert response.status_code == 200
            
            # Step 3: Verify permission assignment
            user_data = response.json()
            assert user_data["email"] == case["email"]
            
            # Step 4: Test API access with assigned permissions
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
        
        # Test document creation permissions
        endpoints = [
            ("GET", "/documents", [admin_token, writer_token, reader_token]),
            ("POST", "/documents", [admin_token, writer_token]),
            ("PUT", "/documents/1", [admin_token, writer_token]),
            ("DELETE", "/documents/1", [admin_token, writer_token])
        ]
        
        for method, endpoint, allowed_tokens in endpoints:
            # Test allowed tokens
            for token in allowed_tokens:
                headers = {"Authorization": f"Bearer {token}"}
                if method == "GET":
                    response = self.client.get(endpoint, headers=headers)
                elif method == "POST":
                    response = self.client.post(endpoint, json=test_document, headers=headers)
                elif method == "PUT":
                    response = self.client.put(endpoint, json=test_document, headers=headers)
                elif method == "DELETE":
                    response = self.client.delete(endpoint, headers=headers)
                
                assert response.status_code in [200, 201, 204], f"{method} {endpoint} failed for allowed token"
            
            # Test forbidden tokens
            all_tokens = [admin_token, writer_token, reader_token]
            forbidden_tokens = [t for t in all_tokens if t not in allowed_tokens]
            
            for token in forbidden_tokens:
                headers = {"Authorization": f"Bearer {token}"}
                if method == "GET":
                    response = self.client.get(endpoint, headers=headers)
                elif method == "POST":
                    response = self.client.post(endpoint, json=test_document, headers=headers)
                elif method == "PUT":
                    response = self.client.put(endpoint, json=test_document, headers=headers)
                elif method == "DELETE":
                    response = self.client.delete(endpoint, headers=headers)
                
                assert response.status_code == 403, f"{method} {endpoint} should be forbidden for token"
    
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
        
        for method, endpoint, allowed_tokens in endpoints:
            # Test allowed access
            for token in allowed_tokens:
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
        
        for method, endpoint in admin_endpoints:
            # Admin should have access
            admin_headers = {"Authorization": f"Bearer {admin_token}"}
            if method == "GET":
                admin_response = self.client.get(endpoint, headers=admin_headers)
            elif method == "POST":
                admin_response = self.client.post(endpoint, json={}, headers=admin_headers)
            
            assert admin_response.status_code in [200, 201]
            
            # Non-admin users should be forbidden
            for non_admin_token in [writer_token, reader_token]:
                headers = {"Authorization": f"Bearer {non_admin_token}"}
                if method == "GET":
                    response = self.client.get(endpoint, headers=headers)
                elif method == "POST":
                    response = self.client.post(endpoint, json={}, headers=headers)
                
                assert response.status_code == 403
                error_detail = response.json()["detail"]
                assert "admin_permission_required" in error_detail["error"]
    
    @pytest.mark.asyncio
    async def test_permission_caching_performance(self):
        """Test permission caching and performance under load."""
        import time
        import concurrent.futures
        
        user_token = create_okta_jwt_token("test@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {user_token}"}
        
        def make_request():
            start_time = time.time()
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
```

#### 2. Security Testing Suite
```python
# File: backend/tests/security/test_permission_bypass.py
import pytest
from fastapi.testclient import TestClient
from onyx.main import app
from tests.helpers.auth import create_invalid_jwt_token, create_expired_jwt_token

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
    
    def test_expired_jwt_token_rejected(self):
        """Test that expired JWT tokens are rejected."""
        expired_token = create_expired_jwt_token("user@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {expired_token}"}
        
        response = self.client.get("/documents", headers=headers)
        assert response.status_code == 401
    
    def test_modified_jwt_token_rejected(self):
        """Test that modified JWT tokens are rejected."""
        valid_token = create_okta_jwt_token("reader@test.com", ["Onyx-Readers"])
        # Modify the token payload
        modified_token = valid_token[:-10] + "modified123"
        headers = {"Authorization": f"Bearer {modified_token}"}
        
        response = self.client.get("/admin/users", headers=headers)
        assert response.status_code == 401
    
    def test_privilege_escalation_attempt(self):
        """Test that users cannot escalate their privileges."""
        reader_token = create_okta_jwt_token("reader@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {reader_token}"}
        
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
    
    def test_group_claim_manipulation(self):
        """Test that manipulated group claims are handled securely."""
        # This would test JWT tokens with invalid or manipulated groups
        # Implementation depends on JWT validation logic
        pass
    
    def test_sql_injection_in_permission_queries(self):
        """Test that permission queries are safe from SQL injection."""
        malicious_payload = "'; DROP TABLE oauth_permissions; --"
        
        # Test with malicious user ID or group name
        # This requires careful implementation of test scenarios
        pass
```

#### 3. Performance Testing Suite
```python
# File: backend/tests/performance/test_oauth_performance.py
import pytest
import time
import asyncio
import concurrent.futures
from fastapi.testclient import TestClient
from onyx.main import app
from tests.helpers.auth import create_okta_jwt_token

class TestOAuthPerformance:
    """Performance tests for OAuth authorization system."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = TestClient(app)
    
    def test_permission_check_latency(self):
        """Test that permission checks are fast."""
        token = create_okta_jwt_token("test@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {token}"}
        
        # Measure single request latency
        start_time = time.time()
        response = self.client.get("/documents", headers=headers)
        end_time = time.time()
        
        assert response.status_code == 200
        latency_ms = (end_time - start_time) * 1000
        assert latency_ms < 100, f"Permission check took {latency_ms}ms, exceeds 100ms limit"
    
    def test_concurrent_permission_checks(self):
        """Test permission system under concurrent load."""
        token = create_okta_jwt_token("test@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {token}"}
        
        def make_request():
            start_time = time.time()
            response = self.client.get("/documents", headers=headers)
            end_time = time.time()
            return response.status_code, (end_time - start_time) * 1000
        
        # Test with 50 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Verify all requests succeeded
        status_codes, response_times = zip(*results)
        assert all(code == 200 for code in status_codes), "Some requests failed under load"
        
        # Verify performance under load
        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)
        
        assert avg_response_time < 200, f"Average response time {avg_response_time}ms under load exceeds 200ms"
        assert max_response_time < 500, f"Max response time {max_response_time}ms under load exceeds 500ms"
    
    def test_permission_cache_effectiveness(self):
        """Test that permission caching reduces database load."""
        token = create_okta_jwt_token("test@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {token}"}
        
        # First request (cache miss)
        start_time = time.time()
        response1 = self.client.get("/documents", headers=headers)
        first_request_time = (time.time() - start_time) * 1000
        
        # Subsequent requests (cache hits)
        times = []
        for _ in range(10):
            start_time = time.time()
            response = self.client.get("/documents", headers=headers)
            times.append((time.time() - start_time) * 1000)
            assert response.status_code == 200
        
        avg_cached_time = sum(times) / len(times)
        
        # Cached requests should be significantly faster
        improvement_ratio = first_request_time / avg_cached_time
        assert improvement_ratio > 2.0, f"Cache improvement ratio {improvement_ratio} is too low"
    
    def test_memory_usage_under_load(self):
        """Test memory usage of permission system under load."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create many users with different permissions
        tokens = []
        for i in range(100):
            token = create_okta_jwt_token(f"user{i}@test.com", ["Onyx-Readers"])
            tokens.append(token)
        
        # Make requests with all users
        for token in tokens:
            headers = {"Authorization": f"Bearer {token}"}
            response = self.client.get("/documents", headers=headers)
            assert response.status_code == 200
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable
        assert memory_increase < 50, f"Memory increased by {memory_increase}MB, exceeds 50MB limit"
```

#### 4. Regression Testing Suite
```python
# File: backend/tests/regression/test_existing_functionality.py
import pytest
from fastapi.testclient import TestClient
from onyx.main import app

class TestRegressionSuite:
    """Ensure existing functionality remains unchanged."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        self.client = TestClient(app)
    
    def test_basic_auth_still_works(self):
        """Test that basic authentication still functions."""
        # Test existing auth mechanisms if any
        response = self.client.get("/health")
        assert response.status_code == 200
    
    def test_api_endpoints_unchanged(self):
        """Test that API endpoint responses haven't changed."""
        # Test critical endpoints for backward compatibility
        endpoints = [
            "/health",
            "/api/docs",
            "/openapi.json"
        ]
        
        for endpoint in endpoints:
            response = self.client.get(endpoint)
            assert response.status_code in [200, 401], f"Endpoint {endpoint} broken"
    
    def test_database_schema_compatibility(self):
        """Test that database operations still work."""
        # Test basic database operations
        # This would be specific to existing database usage
        pass
    
    def test_existing_user_flows(self):
        """Test that existing user workflows remain functional."""
        # Test critical user journeys that existed before OAuth
        pass
```

#### 5. Test Utilities and Helpers
```python
# File: backend/tests/helpers/auth.py
import jwt
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any

def create_okta_jwt_token(email: str, groups: List[str], expires_in: int = 3600) -> str:
    """Create a valid JWT token for testing."""
    now = datetime.utcnow()
    payload = {
        "iss": "https://test-org.okta.com/oauth2/default",
        "aud": "test_audience",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        "sub": f"test_user_{email}",
        "email": email,
        "groups": groups,
        "preferred_username": email
    }
    
    # Use test secret for JWT signing
    return jwt.encode(payload, "test_secret", algorithm="HS256")

def create_invalid_jwt_token() -> str:
    """Create an invalid JWT token for testing."""
    return "invalid.jwt.token"

def create_expired_jwt_token(email: str, groups: List[str]) -> str:
    """Create an expired JWT token for testing."""
    return create_okta_jwt_token(email, groups, expires_in=-3600)

def create_test_user_with_groups(email: str, groups: List[str]) -> Dict[str, Any]:
    """Create a test user with specific group memberships."""
    return {
        "email": email,
        "groups": groups,
        "token": create_okta_jwt_token(email, groups)
    }

async def cleanup_test_data():
    """Clean up test data after each test."""
    # Implementation to clean up test users, permissions, etc.
    pass
```

### Frontend Integration Testing

#### Cross-Browser Testing
```typescript
// File: web/tests/e2e/oauth-flow.spec.ts
import { test, expect } from '@playwright/test';

test.describe('OAuth Authorization Flow', () => {
  test('complete login flow with admin user', async ({ page }) => {
    // Test admin login and access
    await page.goto('/login');
    
    // Mock Okta login
    await page.route('**/auth/callback', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          user: {
            email: 'admin@test.com',
            permission_level: 'admin'
          }
        })
      });
    });
    
    await page.click('[data-testid="login-button"]');
    
    // Verify admin dashboard access
    await expect(page.locator('[data-testid="admin-panel"]')).toBeVisible();
  });
  
  test('permission-gated UI elements', async ({ page }) => {
    // Test that UI elements show/hide based on permissions
    await page.goto('/dashboard');
    
    // Mock user with read-only permissions
    await page.addInitScript(() => {
      window.mockUser = {
        email: 'reader@test.com',
        permission_level: 'read'
      };
    });
    
    await page.reload();
    
    // Admin elements should be hidden
    await expect(page.locator('[data-testid="admin-menu"]')).toBeHidden();
    
    // Write elements should be hidden
    await expect(page.locator('[data-testid="create-document"]')).toBeHidden();
    
    // Read elements should be visible
    await expect(page.locator('[data-testid="document-list"]')).toBeVisible();
  });
});
```

## Performance Requirements

### Response Time Targets
- **End-to-End Flow**: Complete OAuth flow < 3 seconds
- **Permission Check**: Individual permission validation < 100ms
- **API Response**: Protected endpoint response < 500ms
- **Cache Performance**: 95%+ cache hit rate after initial load

### Load Testing Targets
- **Concurrent Users**: Support 100+ simultaneous OAuth users
- **Request Volume**: Handle 1000+ requests/minute with OAuth
- **Memory Usage**: < 100MB additional memory for OAuth system
- **Database Load**: < 20% increase in database queries

### Scalability Requirements
- **User Growth**: System scales to 10,000+ OAuth users
- **Group Management**: Support 100+ Okta groups
- **Permission Cache**: Handle cache for all active users
- **Token Processing**: Process 100+ JWT tokens/second

## Security Testing Requirements

### Vulnerability Testing
- **Token Validation**: Verify all JWT validation scenarios
- **Permission Bypass**: Test all potential bypass methods
- **Input Validation**: Test all OAuth-related inputs
- **Session Security**: Verify session handling is secure

### Penetration Testing
- **Authentication Bypass**: Attempt to bypass OAuth
- **Privilege Escalation**: Test permission escalation attempts
- **Token Manipulation**: Test JWT token manipulation scenarios
- **API Security**: Test all protected endpoint security

## Deployment Procedures

### Pre-Deployment Testing
- [ ] All unit tests pass (100% success rate)
- [ ] Integration tests pass (100% success rate)
- [ ] Performance tests meet requirements
- [ ] Security tests pass vulnerability scans
- [ ] Regression tests show no breaking changes
- [ ] Load testing validates scalability
- [ ] Cross-browser testing completed

### Deployment Steps
1. **Staging Validation**: Complete test suite in staging environment
2. **Performance Baseline**: Establish performance metrics
3. **Security Scan**: Final security validation
4. **Feature Flag**: Enable OAuth system gradually
5. **Monitor**: Watch for issues during rollout
6. **Validate**: Confirm all functionality works in production

### Rollback Plan
1. **Immediate**: Disable OAuth via feature flags
2. **Monitoring**: Watch for authentication issues
3. **Fallback**: Ensure existing auth mechanisms work
4. **Recovery**: Plan for data consistency issues

### Monitoring & Alerts
- **Test Results**: Daily automated test execution
- **Performance Metrics**: Real-time performance monitoring
- **Error Rates**: OAuth-related error tracking
- **User Experience**: Monitor user authentication success rates

## Definition of Done

### Testing Coverage ✅
- [ ] Unit test coverage > 95% for OAuth code
- [ ] Integration tests cover all OAuth workflows
- [ ] End-to-end tests validate complete flows
- [ ] Performance tests meet all requirements
- [ ] Security tests pass vulnerability scans
- [ ] Regression tests show no breaking changes

### Quality Assurance ✅
- [ ] All test suites execute successfully
- [ ] Performance requirements validated
- [ ] Security requirements verified
- [ ] Cross-browser compatibility confirmed
- [ ] Mobile responsiveness tested

### Documentation ✅
- [ ] Test documentation complete
- [ ] Performance benchmarks documented
- [ ] Security test results documented
- [ ] Troubleshooting guide updated
- [ ] Deployment procedures validated

### Production Readiness ✅
- [ ] Staging environment fully validates system
- [ ] Monitoring and alerting configured
- [ ] Rollback procedures tested
- [ ] Performance baselines established
- [ ] Security review completed and approved

---

**Story Dependencies**: This story requires completion of ALL previous stories (1.1-4.2) as it validates the entire OAuth authorization system end-to-end. Success here indicates the system is ready for production deployment.
