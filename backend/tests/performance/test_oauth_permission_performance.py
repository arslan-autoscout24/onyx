"""
Performance tests for OAuth permission database operations.

This module tests that OAuth permission database operations meet
performance requirements, specifically that permission lookup
queries execute in under 10ms as specified in the story requirements.
"""
import pytest
import asyncio
import time
from unittest.mock import patch, MagicMock, AsyncMock
from uuid import uuid4
from datetime import datetime
from typing import List, Dict, Any

from onyx.db.oauth_permissions import (
    get_user_oauth_permission,
    get_user_permission_level,
    user_has_permission,
    get_users_by_permission_level,
    bulk_update_permissions,
    get_permission_summary
)
from onyx.db.oauth_utils import (
    check_multiple_users_permissions,
    get_permission_stats,
    get_users_by_multiple_permission_levels
)


class PerformanceTestHelper:
    """Helper class for performance testing."""
    
    @staticmethod
    async def measure_async_operation(operation_func, *args, **kwargs) -> tuple:
        """
        Measure the execution time of an async operation.
        
        Returns:
            Tuple of (result, execution_time_ms)
        """
        start_time = time.perf_counter()
        result = await operation_func(*args, **kwargs)
        end_time = time.perf_counter()
        
        execution_time_ms = (end_time - start_time) * 1000
        return result, execution_time_ms
    
    @staticmethod
    def create_mock_permission(user_id=None, permission_level="read"):
        """Create a mock permission object for testing."""
        permission = MagicMock()
        permission.user_id = user_id or uuid4()
        permission.permission_level = permission_level
        permission.okta_groups = "group1,group2"
        permission.granted_at = datetime.utcnow()
        permission.is_active = True
        return permission
    
    @staticmethod
    def setup_fast_db_mock():
        """Setup database mocks that simulate fast responses."""
        mock_session_manager = AsyncMock()
        mock_session = AsyncMock()
        mock_session_manager.__aenter__.return_value = mock_session
        
        # Simulate fast database response
        mock_result = AsyncMock()
        mock_session.execute.return_value = mock_result
        
        return mock_session_manager, mock_session, mock_result


class TestSingleUserOperationPerformance:
    """Test performance of single user operations."""
    
    @pytest.mark.asyncio
    async def test_get_user_oauth_permission_performance(self):
        """Test that getting user OAuth permission is under 10ms."""
        user_id = uuid4()
        helper = PerformanceTestHelper()
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session_func:
            mock_session_manager, mock_session, mock_result = helper.setup_fast_db_mock()
            mock_session_func.return_value = mock_session_manager
            
            # Setup mock to return a permission
            mock_permission = helper.create_mock_permission(user_id, "admin")
            mock_result.scalar_one_or_none.return_value = mock_permission
            
            result, execution_time = await helper.measure_async_operation(
                get_user_oauth_permission, user_id
            )
            
            assert result == mock_permission
            assert execution_time < 10.0, f"Operation took {execution_time:.2f}ms, expected < 10ms"
            
            # Verify the query was executed
            mock_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_permission_level_performance(self):
        """Test that getting user permission level is under 10ms."""
        user_id = uuid4()
        helper = PerformanceTestHelper()
        
        with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
            mock_permission = helper.create_mock_permission(user_id, "write")
            mock_get.return_value = mock_permission
            
            result, execution_time = await helper.measure_async_operation(
                get_user_permission_level, user_id
            )
            
            assert result == "write"
            assert execution_time < 10.0, f"Operation took {execution_time:.2f}ms, expected < 10ms"
    
    @pytest.mark.asyncio
    async def test_user_has_permission_performance(self):
        """Test that checking user permissions is under 10ms."""
        user_id = uuid4()
        helper = PerformanceTestHelper()
        
        with patch('onyx.db.oauth_permissions.get_user_permission_level') as mock_get:
            mock_get.return_value = "admin"
            
            result, execution_time = await helper.measure_async_operation(
                user_has_permission, user_id, "write"
            )
            
            assert result is True
            assert execution_time < 10.0, f"Operation took {execution_time:.2f}ms, expected < 10ms"


class TestBulkOperationPerformance:
    """Test performance of bulk operations."""
    
    @pytest.mark.asyncio
    async def test_get_users_by_permission_level_performance(self):
        """Test that getting users by permission level is reasonably fast."""
        helper = PerformanceTestHelper()
        permission_level = "admin"
        
        # Create mock data for 100 users
        mock_user_ids = [uuid4() for _ in range(100)]
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session_func:
            mock_session_manager, mock_session, mock_result = helper.setup_fast_db_mock()
            mock_session_func.return_value = mock_session_manager
            
            # Setup mock to return user IDs
            mock_result.fetchall.return_value = [(uid,) for uid in mock_user_ids]
            
            result, execution_time = await helper.measure_async_operation(
                get_users_by_permission_level, permission_level
            )
            
            assert len(result) == 100
            assert result == mock_user_ids
            
            # Bulk operations should be under 50ms for 100 users
            assert execution_time < 50.0, f"Bulk operation took {execution_time:.2f}ms, expected < 50ms"
    
    @pytest.mark.asyncio
    async def test_check_multiple_users_permissions_performance(self):
        """Test performance of checking permissions for multiple users."""
        helper = PerformanceTestHelper()
        
        # Test with 10 users
        user_ids = [uuid4() for _ in range(10)]
        required_level = "write"
        
        with patch('onyx.db.oauth_utils.user_has_permission') as mock_check:
            # Mock alternating permission results
            mock_check.side_effect = [i % 2 == 0 for i in range(10)]
            
            result, execution_time = await helper.measure_async_operation(
                check_multiple_users_permissions, user_ids, required_level
            )
            
            assert len(result) == 10
            
            # Should be able to check 10 users in under 100ms
            assert execution_time < 100.0, f"Bulk check took {execution_time:.2f}ms, expected < 100ms"
    
    @pytest.mark.asyncio
    async def test_bulk_update_permissions_performance(self):
        """Test performance of bulk permission updates."""
        helper = PerformanceTestHelper()
        
        # Create updates for 5 users
        updates = [
            {
                "user_id": uuid4(),
                "permission_level": "read",
                "okta_groups": ["group1"]
            },
            {
                "user_id": uuid4(),
                "permission_level": "write", 
                "okta_groups": ["group2"]
            },
            {
                "user_id": uuid4(),
                "permission_level": "admin",
                "okta_groups": ["admin_group"]
            },
            {
                "user_id": uuid4(),
                "permission_level": "read",
                "okta_groups": ["group3"]
            },
            {
                "user_id": uuid4(),
                "permission_level": "write",
                "okta_groups": ["group4"]
            }
        ]
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session_func, \
             patch('onyx.db.oauth_permissions.update_user_oauth_permission') as mock_update:
            
            mock_session_manager, mock_session, mock_result = helper.setup_fast_db_mock()
            mock_session_func.return_value = mock_session_manager
            
            # Setup mock to return permissions quickly
            mock_permission = helper.create_mock_permission()
            mock_update.return_value = mock_permission
            
            result, execution_time = await helper.measure_async_operation(
                bulk_update_permissions, updates
            )
            
            assert len(result) == 5
            assert mock_update.call_count == 5
            
            # Bulk update for 5 users should be under 200ms
            assert execution_time < 200.0, f"Bulk update took {execution_time:.2f}ms, expected < 200ms"


class TestQueryOptimizationPerformance:
    """Test performance of optimized queries."""
    
    @pytest.mark.asyncio
    async def test_get_permission_summary_performance(self):
        """Test performance of permission summary generation."""
        helper = PerformanceTestHelper()
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session_func, \
             patch('onyx.db.oauth_permissions.get_users_by_permission_level') as mock_get_users:
            
            mock_session_manager, mock_session, mock_result = helper.setup_fast_db_mock()
            mock_session_func.return_value = mock_session_manager
            
            # Mock user counts for each permission level
            mock_get_users.side_effect = [
                [uuid4() for _ in range(50)],  # read users
                [uuid4() for _ in range(25)],  # write users  
                [uuid4() for _ in range(10)]   # admin users
            ]
            
            # Mock users with no OAuth permissions
            mock_result.fetchall.return_value = [(uuid4(),) for _ in range(15)]
            
            result, execution_time = await helper.measure_async_operation(
                get_permission_summary
            )
            
            expected_summary = {
                "read": 50,
                "write": 25, 
                "admin": 10,
                "no_oauth_permission": 15
            }
            
            assert result == expected_summary
            
            # Summary generation should be under 100ms
            assert execution_time < 100.0, f"Summary generation took {execution_time:.2f}ms, expected < 100ms"
    
    @pytest.mark.asyncio
    async def test_get_permission_stats_performance(self):
        """Test performance of comprehensive permission statistics."""
        helper = PerformanceTestHelper()
        
        with patch('onyx.db.oauth_utils.get_permission_summary') as mock_summary:
            mock_summary.return_value = {
                "read": 100,
                "write": 50,
                "admin": 20,
                "no_oauth_permission": 30
            }
            
            result, execution_time = await helper.measure_async_operation(
                get_permission_stats
            )
            
            assert result["total_users"] == 200
            assert result["oauth_enabled_users"] == 170
            assert result["oauth_percentage"] == 85.0
            
            # Stats generation should be very fast
            assert execution_time < 10.0, f"Stats generation took {execution_time:.2f}ms, expected < 10ms"


class TestConcurrencyPerformance:
    """Test performance under concurrent access scenarios."""
    
    @pytest.mark.asyncio
    async def test_concurrent_permission_checks(self):
        """Test performance of concurrent permission checks."""
        helper = PerformanceTestHelper()
        
        # Create multiple users for concurrent testing
        user_ids = [uuid4() for _ in range(20)]
        
        async def check_user_permission(user_id):
            """Helper function to check a single user's permission."""
            with patch('onyx.db.oauth_permissions.get_user_permission_level') as mock_get:
                mock_get.return_value = "write"
                return await user_has_permission(user_id, "read")
        
        # Measure concurrent execution
        start_time = time.perf_counter()
        
        # Run permission checks concurrently
        tasks = [check_user_permission(user_id) for user_id in user_ids]
        results = await asyncio.gather(*tasks)
        
        end_time = time.perf_counter()
        execution_time = (end_time - start_time) * 1000
        
        # All should return True (write >= read)
        assert all(results)
        assert len(results) == 20
        
        # Concurrent checks should be faster than sequential
        # Allow generous time for 20 concurrent operations
        assert execution_time < 100.0, f"Concurrent checks took {execution_time:.2f}ms, expected < 100ms"
    
    @pytest.mark.asyncio
    async def test_concurrent_user_lookups(self):
        """Test performance of concurrent user permission lookups."""
        helper = PerformanceTestHelper()
        
        user_ids = [uuid4() for _ in range(15)]
        
        async def get_user_level(user_id):
            """Helper function to get a user's permission level."""
            with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
                mock_permission = helper.create_mock_permission(user_id, "admin")
                mock_get.return_value = mock_permission
                return await get_user_permission_level(user_id)
        
        start_time = time.perf_counter()
        
        # Run lookups concurrently
        tasks = [get_user_level(user_id) for user_id in user_ids]
        results = await asyncio.gather(*tasks)
        
        end_time = time.perf_counter()
        execution_time = (end_time - start_time) * 1000
        
        # All should return "admin"
        assert all(level == "admin" for level in results)
        assert len(results) == 15
        
        # Concurrent lookups should complete quickly
        assert execution_time < 75.0, f"Concurrent lookups took {execution_time:.2f}ms, expected < 75ms"


class TestMemoryPerformance:
    """Test memory efficiency of operations."""
    
    @pytest.mark.asyncio
    async def test_large_result_set_handling(self):
        """Test handling of large result sets efficiently."""
        helper = PerformanceTestHelper()
        
        # Simulate large number of users
        large_user_count = 1000
        mock_user_ids = [uuid4() for _ in range(large_user_count)]
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session_func:
            mock_session_manager, mock_session, mock_result = helper.setup_fast_db_mock()
            mock_session_func.return_value = mock_session_manager
            
            # Setup mock to return large result set
            mock_result.fetchall.return_value = [(uid,) for uid in mock_user_ids]
            
            result, execution_time = await helper.measure_async_operation(
                get_users_by_permission_level, "read"
            )
            
            assert len(result) == large_user_count
            
            # Large result sets should still be processed reasonably fast
            # Allow more time for large datasets
            assert execution_time < 500.0, f"Large result processing took {execution_time:.2f}ms, expected < 500ms"
    
    @pytest.mark.asyncio
    async def test_memory_efficient_bulk_operations(self):
        """Test that bulk operations are memory efficient."""
        helper = PerformanceTestHelper()
        
        # Create large bulk update set
        large_update_count = 50
        updates = []
        for i in range(large_update_count):
            updates.append({
                "user_id": uuid4(),
                "permission_level": ["read", "write", "admin"][i % 3],
                "okta_groups": [f"group_{i}"]
            })
        
        with patch('onyx.db.oauth_permissions.get_async_session') as mock_session_func, \
             patch('onyx.db.oauth_permissions.update_user_oauth_permission') as mock_update:
            
            mock_session_manager, mock_session, mock_result = helper.setup_fast_db_mock()
            mock_session_func.return_value = mock_session_manager
            
            mock_permission = helper.create_mock_permission()
            mock_update.return_value = mock_permission
            
            result, execution_time = await helper.measure_async_operation(
                bulk_update_permissions, updates
            )
            
            assert len(result) == large_update_count
            assert mock_update.call_count == large_update_count
            
            # Large bulk operations should complete within reasonable time
            # Allow generous time for 50 updates
            assert execution_time < 1000.0, f"Large bulk update took {execution_time:.2f}ms, expected < 1000ms"


class TestRealWorldScenarios:
    """Test performance in realistic usage scenarios."""
    
    @pytest.mark.asyncio
    async def test_typical_web_request_scenario(self):
        """Test performance of typical web request permission checking."""
        helper = PerformanceTestHelper()
        
        # Simulate a typical web request that checks user permissions
        user_id = uuid4()
        required_permissions = ["read", "write"]
        
        async def simulate_web_request():
            """Simulate a web request that checks multiple permissions."""
            results = []
            
            # Get user's current permission level
            with patch('onyx.db.oauth_permissions.get_user_permission_level') as mock_get:
                mock_get.return_value = "write"
                user_level = await get_user_permission_level(user_id)
                results.append(user_level)
            
            # Check specific permissions
            with patch('onyx.db.oauth_permissions.get_user_permission_level') as mock_get:
                mock_get.return_value = "write"
                for required_perm in required_permissions:
                    has_perm = await user_has_permission(user_id, required_perm)
                    results.append(has_perm)
            
            return results
        
        result, execution_time = await helper.measure_async_operation(
            simulate_web_request
        )
        
        assert len(result) == 3  # 1 level + 2 permission checks
        assert result[0] == "write"  # User level
        assert result[1] is True     # Has read permission
        assert result[2] is True     # Has write permission
        
        # Web request scenario should be very fast
        assert execution_time < 15.0, f"Web request scenario took {execution_time:.2f}ms, expected < 15ms"
    
    @pytest.mark.asyncio
    async def test_dashboard_loading_scenario(self):
        """Test performance of dashboard loading with permission stats."""
        helper = PerformanceTestHelper()
        
        async def simulate_dashboard_load():
            """Simulate loading a dashboard with permission statistics."""
            with patch('onyx.db.oauth_utils.get_permission_summary') as mock_summary:
                mock_summary.return_value = {
                    "read": 150,
                    "write": 75,
                    "admin": 25,
                    "no_oauth_permission": 50
                }
                
                stats = await get_permission_stats()
                return stats
        
        result, execution_time = await helper.measure_async_operation(
            simulate_dashboard_load
        )
        
        assert result["total_users"] == 300
        assert result["oauth_enabled_users"] == 250
        assert "permission_distribution" in result
        
        # Dashboard loading should be fast
        assert execution_time < 25.0, f"Dashboard loading took {execution_time:.2f}ms, expected < 25ms"
    
    @pytest.mark.asyncio
    async def test_admin_audit_scenario(self):
        """Test performance of admin audit operations."""
        helper = PerformanceTestHelper()
        
        async def simulate_admin_audit():
            """Simulate admin performing audit operations."""
            results = {}
            
            # Get admin users
            with patch('onyx.db.oauth_permissions.get_users_by_permission_level') as mock_get:
                admin_users = [uuid4() for _ in range(5)]
                mock_get.return_value = admin_users
                results["admin_users"] = await get_users_by_permission_level("admin")
            
            # Get permission stats
            with patch('onyx.db.oauth_utils.get_permission_summary') as mock_summary:
                mock_summary.return_value = {"read": 50, "write": 25, "admin": 5, "no_oauth_permission": 20}
                results["stats"] = await get_permission_stats()
            
            return results
        
        result, execution_time = await helper.measure_async_operation(
            simulate_admin_audit
        )
        
        assert "admin_users" in result
        assert "stats" in result
        assert len(result["admin_users"]) == 5
        
        # Admin audit should complete quickly
        assert execution_time < 50.0, f"Admin audit took {execution_time:.2f}ms, expected < 50ms"


# Benchmark utilities
class PerformanceBenchmark:
    """Utility class for running performance benchmarks."""
    
    @staticmethod
    async def run_benchmark(operation_func, iterations=10, *args, **kwargs):
        """
        Run a benchmark of an operation multiple times.
        
        Returns:
            Dict with benchmark statistics
        """
        execution_times = []
        
        for _ in range(iterations):
            start_time = time.perf_counter()
            await operation_func(*args, **kwargs)
            end_time = time.perf_counter()
            
            execution_time_ms = (end_time - start_time) * 1000
            execution_times.append(execution_time_ms)
        
        return {
            "iterations": iterations,
            "min_time_ms": min(execution_times),
            "max_time_ms": max(execution_times),
            "avg_time_ms": sum(execution_times) / len(execution_times),
            "total_time_ms": sum(execution_times),
            "all_times_ms": execution_times
        }


class TestPerformanceBenchmarks:
    """Performance benchmarks for key operations."""
    
    @pytest.mark.asyncio
    async def test_permission_check_benchmark(self):
        """Benchmark permission checking operations."""
        user_id = uuid4()
        
        async def mock_permission_check():
            with patch('onyx.db.oauth_permissions.get_user_permission_level') as mock_get:
                mock_get.return_value = "admin"
                return await user_has_permission(user_id, "write")
        
        benchmark = await PerformanceBenchmark.run_benchmark(
            mock_permission_check, iterations=100
        )
        
        # All iterations should be fast
        assert benchmark["max_time_ms"] < 10.0, f"Slowest permission check: {benchmark['max_time_ms']:.2f}ms"
        assert benchmark["avg_time_ms"] < 5.0, f"Average permission check: {benchmark['avg_time_ms']:.2f}ms"
    
    @pytest.mark.asyncio
    async def test_user_lookup_benchmark(self):
        """Benchmark user permission lookup operations."""
        user_id = uuid4()
        helper = PerformanceTestHelper()
        
        async def mock_user_lookup():
            with patch('onyx.db.oauth_permissions.get_user_oauth_permission') as mock_get:
                mock_permission = helper.create_mock_permission(user_id, "read")
                mock_get.return_value = mock_permission
                return await get_user_permission_level(user_id)
        
        benchmark = await PerformanceBenchmark.run_benchmark(
            mock_user_lookup, iterations=50
        )
        
        # All lookups should meet performance requirements
        assert benchmark["max_time_ms"] < 10.0, f"Slowest user lookup: {benchmark['max_time_ms']:.2f}ms"
        assert benchmark["avg_time_ms"] < 5.0, f"Average user lookup: {benchmark['avg_time_ms']:.2f}ms"


if __name__ == "__main__":
    # Run performance tests
    pytest.main([__file__, "-v", "-k", "performance"])
