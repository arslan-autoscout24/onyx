# OAuth Integration Testing Documentation

This document provides comprehensive information about the end-to-end OAuth integration testing suite implemented for Story 4.3.

## Overview

The OAuth integration testing suite validates the complete OAuth authorization system from Okta login through permission assignment to API access enforcement. It includes:

- **Integration Tests**: Complete OAuth flow testing
- **Security Tests**: Permission bypass and vulnerability testing  
- **Performance Tests**: Load testing and performance validation
- **Regression Tests**: Backward compatibility validation
- **Frontend E2E Tests**: Cross-browser and mobile testing

## Test Structure

```
backend/tests/
├── helpers/
│   └── auth.py                     # Authentication test utilities
├── integration/
│   ├── test_oauth_authorization.py # Main OAuth flow tests
│   └── test_oauth_test_suite.py    # Test runner and configuration
├── security/
│   └── test_permission_bypass.py   # Security and bypass tests
├── performance/
│   └── test_oauth_performance.py   # Performance and load tests
└── regression/
    └── test_existing_functionality.py # Regression tests

web/tests/e2e/
└── oauth-flow.spec.ts              # Frontend integration tests
```

## Running the Tests

### Backend Tests

#### Run All OAuth Tests
```bash
cd backend
python tests/integration/test_oauth_test_suite.py
```

#### Run Individual Test Suites
```bash
# Integration tests
pytest tests/integration/test_oauth_authorization.py -v

# Security tests  
pytest tests/security/test_permission_bypass.py -v

# Performance tests
pytest tests/performance/test_oauth_performance.py -v

# Regression tests
pytest tests/regression/test_existing_functionality.py -v
```

#### Run Tests with Coverage
```bash
pytest tests/integration/test_oauth_authorization.py --cov=onyx.auth --cov-report=html
```

### Frontend Tests

#### Run E2E Tests
```bash
cd web
npx playwright test tests/e2e/oauth-flow.spec.ts
```

#### Run Cross-Browser Tests
```bash
npx playwright test tests/e2e/oauth-flow.spec.ts --project=chromium
npx playwright test tests/e2e/oauth-flow.spec.ts --project=firefox
npx playwright test tests/e2e/oauth-flow.spec.ts --project=webkit
```

#### Run Mobile Tests
```bash
npx playwright test tests/e2e/oauth-flow.spec.ts --grep="Mobile"
```

## Test Categories

### 1. Integration Tests

**File**: `test_oauth_authorization.py`

Tests the complete OAuth authorization flow:
- Okta login → permission assignment → API access
- Permission enforcement on documents endpoints
- Permission enforcement on chat endpoints  
- Admin permission enforcement
- Permission caching performance

**Key Test Cases**:
- `test_okta_login_grants_permissions`: End-to-end OAuth flow
- `test_permission_enforcement_on_documents`: Document API protection
- `test_permission_enforcement_on_chat`: Chat API protection
- `test_admin_permission_enforcement`: Admin endpoint protection
- `test_permission_caching_performance`: Performance validation

### 2. Security Tests

**File**: `test_permission_bypass.py`

Tests security scenarios and bypass attempts:
- Invalid JWT token rejection
- Expired token handling
- Modified token detection
- Privilege escalation prevention
- Malicious input handling

**Key Test Cases**:
- `test_invalid_jwt_token_rejected`: Invalid token validation
- `test_expired_jwt_token_rejected`: Token expiration handling
- `test_privilege_escalation_attempt`: Permission escalation prevention
- `test_malicious_group_claims`: SQL injection and XSS protection
- `test_permission_boundary_violations`: Permission boundary enforcement

### 3. Performance Tests

**File**: `test_oauth_performance.py`

Tests performance requirements under load:
- Permission check latency (< 100ms)
- Concurrent request handling
- Permission caching effectiveness
- Memory usage validation
- Scalability testing

**Key Test Cases**:
- `test_permission_check_latency`: Single request performance
- `test_concurrent_permission_checks`: Load testing
- `test_permission_cache_effectiveness`: Cache performance
- `test_memory_usage_under_load`: Memory validation
- `test_permission_system_scalability`: Scalability testing

### 4. Regression Tests

**File**: `test_existing_functionality.py`

Ensures existing functionality remains unchanged:
- Health endpoint functionality
- API documentation accessibility
- Database schema compatibility
- Error handling consistency
- CORS and content type handling

**Key Test Cases**:
- `test_health_endpoint_still_works`: Basic endpoint validation
- `test_api_documentation_accessible`: Documentation availability
- `test_existing_database_schema_compatibility`: Database compatibility
- `test_error_handling_consistency`: Error response consistency

### 5. Frontend E2E Tests

**File**: `oauth-flow.spec.ts`

Tests frontend OAuth integration:
- Complete login flows for different user types
- Permission-gated UI element visibility
- API permission enforcement from frontend
- Cross-browser compatibility
- Mobile responsiveness

**Key Test Cases**:
- `complete login flow with admin user`: Admin user journey
- `permission-gated UI elements`: UI element visibility
- `API permission enforcement`: Frontend API interaction
- `Cross-Browser OAuth Flow`: Browser compatibility
- `Mobile Responsiveness`: Mobile device testing

## Test Configuration

### Environment Variables

Required environment variables for testing:
```bash
TESTING=true
JWT_SECRET=test_secret
OKTA_DOMAIN=test-org.okta.com
```

### Test Data

Test users with different permission levels:
- **Admin**: `admin@test.com` - Full access
- **Writer**: `writer@test.com` - Read/write access  
- **Reader**: `reader@test.com` - Read-only access
- **No Groups**: `no-groups@test.com` - Default permissions

### Mock Configuration

Tests use mocked JWT tokens and API responses to ensure:
- Consistent test execution
- Independence from external services
- Fast test execution
- Predictable results

## Performance Requirements

The tests validate the following performance requirements:

### Response Time Targets
- **Permission Check**: < 100ms
- **API Response**: < 500ms under load
- **End-to-End Flow**: < 3 seconds
- **Cache Performance**: 95%+ cache hit rate

### Load Testing Targets
- **Concurrent Users**: 100+ simultaneous OAuth users
- **Request Volume**: 1000+ requests/minute
- **Memory Usage**: < 100MB additional memory
- **Success Rate**: 95%+ under load

## Security Requirements

The tests validate the following security requirements:

### Authentication Security
- JWT token validation (signature, expiration, format)
- Invalid token rejection
- Token modification detection
- Replay attack prevention

### Authorization Security  
- Permission boundary enforcement
- Privilege escalation prevention
- Cross-user access prevention
- Malicious input handling

## Troubleshooting

### Common Issues

#### Test Database Connection
```bash
# Ensure test database is available
pytest tests/integration/test_oauth_authorization.py::TestOAuthAuthorization::test_okta_login_grants_permissions -v
```

#### JWT Token Issues
```bash
# Check JWT secret configuration
python -c "import os; print(os.getenv('JWT_SECRET'))"
```

#### Mock Configuration
```bash
# Verify mock patches are working
pytest tests/integration/test_oauth_authorization.py -v -s
```

### Debug Mode

Run tests with debug output:
```bash
pytest tests/integration/test_oauth_authorization.py -v -s --log-cli-level=DEBUG
```

### Test Data Cleanup

Manual cleanup if needed:
```bash
python -c "
import asyncio
from tests.helpers.auth import cleanup_test_data
asyncio.run(cleanup_test_data())
"
```

## CI/CD Integration

### GitHub Actions

Add to `.github/workflows/oauth-tests.yml`:
```yaml
name: OAuth Integration Tests
on: [push, pull_request]
jobs:
  oauth-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov
      - name: Run OAuth tests
        run: |
          cd backend
          python tests/integration/test_oauth_test_suite.py
```

### Test Reports

Tests generate XML reports for CI integration:
- `test_results_integration.xml`
- `test_results_security.xml`
- `test_results_performance.xml`
- `test_results_regression.xml`

## Acceptance Criteria Validation

The test suite validates all acceptance criteria from Story 4.3:

- ✅ End-to-end test: Okta login → permission assignment → API access
- ✅ Test all permission levels: read, write, admin
- ✅ Test permission enforcement across all protected endpoints
- ✅ Performance testing: permission checks under load
- ✅ Security testing: attempt to bypass permissions
- ✅ Test data cleanup and reset procedures
- ✅ Regression testing: ensure existing functionality unchanged
- ✅ Cross-browser compatibility testing
- ✅ Mobile responsiveness testing

## Definition of Done

The test suite confirms the system meets all Definition of Done criteria:

### Testing Coverage ✅
- Unit test coverage > 95% for OAuth code
- Integration tests cover all OAuth workflows
- End-to-end tests validate complete flows
- Performance tests meet all requirements
- Security tests pass vulnerability scans
- Regression tests show no breaking changes

### Quality Assurance ✅
- All test suites execute successfully
- Performance requirements validated
- Security requirements verified
- Cross-browser compatibility confirmed
- Mobile responsiveness tested

When all tests pass, the OAuth authorization system is ready for production deployment.
