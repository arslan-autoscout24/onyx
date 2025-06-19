"""
Test Configuration and Test Runner for End-to-End OAuth Integration

This module provides comprehensive test configuration and utilities for running
all OAuth integration tests in the correct order and with proper setup.
"""

import pytest
import asyncio
import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from tests.helpers.auth import cleanup_test_data


class TestSuiteConfiguration:
    """Configuration for the complete OAuth test suite."""
    
    # Test execution order
    TEST_EXECUTION_ORDER = [
        "test_oauth_authorization.py",
        "test_permission_bypass.py", 
        "test_oauth_performance.py",
        "test_existing_functionality.py"
    ]
    
    # Performance thresholds
    PERFORMANCE_THRESHOLDS = {
        "max_response_time_ms": 100,
        "max_concurrent_response_time_ms": 200,
        "max_memory_increase_mb": 50,
        "min_cache_improvement_ratio": 1.5,
        "min_success_rate": 0.95
    }
    
    # Security test requirements
    SECURITY_REQUIREMENTS = [
        "invalid_token_rejection",
        "expired_token_rejection", 
        "modified_token_rejection",
        "privilege_escalation_prevention",
        "malicious_input_handling"
    ]
    
    # Test user configurations
    TEST_USERS = {
        "admin": {
            "email": "admin@test.com",
            "groups": ["Onyx-Admins", "Onyx-Writers", "Onyx-Readers"],
            "expected_permission": "admin"
        },
        "writer": {
            "email": "writer@test.com",
            "groups": ["Onyx-Writers", "Onyx-Readers"], 
            "expected_permission": "write"
        },
        "reader": {
            "email": "reader@test.com",
            "groups": ["Onyx-Readers"],
            "expected_permission": "read"
        },
        "no_groups": {
            "email": "no-groups@test.com",
            "groups": [],
            "expected_permission": "read"
        }
    }


@pytest.fixture(scope="session", autouse=True)
async def setup_test_environment():
    """Setup the test environment before running any tests."""
    print("Setting up OAuth integration test environment...")
    
    # Cleanup any existing test data
    await cleanup_test_data()
    
    # Set test environment variables
    os.environ["TESTING"] = "true"
    os.environ["JWT_SECRET"] = "test_secret"
    os.environ["OKTA_DOMAIN"] = "test-org.okta.com"
    
    yield
    
    # Cleanup after all tests
    print("Cleaning up OAuth integration test environment...")
    await cleanup_test_data()


@pytest.fixture(autouse=True)
async def cleanup_between_tests():
    """Cleanup between individual tests."""
    yield
    # Cleanup after each test
    await cleanup_test_data()


class TestResults:
    """Track test results across all test suites."""
    
    def __init__(self):
        self.results = {
            "integration": {"passed": 0, "failed": 0, "errors": []},
            "security": {"passed": 0, "failed": 0, "errors": []},
            "performance": {"passed": 0, "failed": 0, "errors": []},
            "regression": {"passed": 0, "failed": 0, "errors": []}
        }
        self.performance_metrics = {}
        self.security_violations = []
    
    def add_result(self, suite: str, test_name: str, status: str, error: str = None):
        """Add a test result."""
        if status == "passed":
            self.results[suite]["passed"] += 1
        else:
            self.results[suite]["failed"] += 1
            if error:
                self.results[suite]["errors"].append(f"{test_name}: {error}")
    
    def add_performance_metric(self, metric_name: str, value: float, threshold: float):
        """Add a performance metric."""
        self.performance_metrics[metric_name] = {
            "value": value,
            "threshold": threshold,
            "passed": value <= threshold
        }
    
    def add_security_violation(self, violation: str):
        """Add a security violation."""
        self.security_violations.append(violation)
    
    def get_summary(self):
        """Get a summary of all test results."""
        total_passed = sum(suite["passed"] for suite in self.results.values())
        total_failed = sum(suite["failed"] for suite in self.results.values())
        total_tests = total_passed + total_failed
        
        return {
            "total_tests": total_tests,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "success_rate": total_passed / total_tests if total_tests > 0 else 0,
            "suite_results": self.results,
            "performance_metrics": self.performance_metrics,
            "security_violations": self.security_violations,
            "ready_for_production": (
                total_failed == 0 and 
                len(self.security_violations) == 0 and
                all(m["passed"] for m in self.performance_metrics.values())
            )
        }


def run_oauth_integration_tests():
    """Run the complete OAuth integration test suite."""
    print("=" * 80)
    print("OAUTH INTEGRATION TEST SUITE")
    print("=" * 80)
    
    test_results = TestResults()
    
    # Test suites to run
    test_suites = [
        {
            "name": "Integration Tests",
            "path": "tests/integration/test_oauth_authorization.py",
            "suite_key": "integration"
        },
        {
            "name": "Security Tests", 
            "path": "tests/security/test_permission_bypass.py",
            "suite_key": "security"
        },
        {
            "name": "Performance Tests",
            "path": "tests/performance/test_oauth_performance.py", 
            "suite_key": "performance"
        },
        {
            "name": "Regression Tests",
            "path": "tests/regression/test_existing_functionality.py",
            "suite_key": "regression"
        }
    ]
    
    for suite in test_suites:
        print(f"\nRunning {suite['name']}...")
        print("-" * 50)
        
        # Run the test suite
        exit_code = pytest.main([
            suite["path"],
            "-v",
            "--tb=short",
            f"--junitxml=test_results_{suite['suite_key']}.xml"
        ])
        
        if exit_code == 0:
            print(f"✅ {suite['name']} PASSED")
        else:
            print(f"❌ {suite['name']} FAILED")
    
    # Generate final report
    print("\n" + "=" * 80)
    print("OAUTH INTEGRATION TEST SUMMARY")
    print("=" * 80)
    
    summary = test_results.get_summary()
    
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Passed: {summary['total_passed']}")
    print(f"Failed: {summary['total_failed']}")
    print(f"Success Rate: {summary['success_rate']:.2%}")
    
    if summary['ready_for_production']:
        print("\n🎉 OAUTH SYSTEM READY FOR PRODUCTION!")
    else:
        print("\n⚠️  OAUTH SYSTEM NOT READY - ISSUES NEED TO BE RESOLVED")
    
    return summary


def validate_test_environment():
    """Validate that the test environment is properly configured."""
    required_env_vars = [
        "JWT_SECRET",
        "OKTA_DOMAIN"
    ]
    
    missing_vars = []
    for var in required_env_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        raise EnvironmentError(f"Missing required environment variables: {missing_vars}")
    
    # Check that test database is available
    try:
        from onyx.db.engine import get_async_session
        print("✅ Database connection available")
    except Exception as e:
        raise EnvironmentError(f"Database connection failed: {e}")
    
    # Check that required modules are available
    required_modules = ["jwt", "fastapi", "pytest", "asyncio"]
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            raise EnvironmentError(f"Required module not available: {module}")
    
    print("✅ Test environment validation passed")


if __name__ == "__main__":
    """Run the OAuth integration test suite."""
    try:
        validate_test_environment()
        results = run_oauth_integration_tests()
        
        # Exit with appropriate code
        if results['ready_for_production']:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Test suite failed to run: {e}")
        sys.exit(1)
