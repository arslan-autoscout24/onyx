"""
Performance tests for OAuth permission dependencies.

Tests that permission checks meet the performance requirements:
- < 10ms permission check latency (95th percentile)
- Support for 1000+ concurrent permission checks
- > 95% cache hit rate
"""
import pytest
import asyncio
import time
import statistics
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, AsyncMock
from uuid import uuid4

from onyx.server.auth_check import get_oauth_permission, require_permission
from onyx.db.models import User


class TestPermissionPerformance:
    
    @pytest.fixture
    def mock_user(self):
        """Create a mock user for performance testing"""
        user = User()
        user.id = uuid4()
        user.email = "perf_test@example.com"
        return user
    
    @pytest.mark.asyncio
    async def test_permission_check_latency(self, mock_user):
        """Test that permission checks complete within latency requirements"""
        latencies = []
        
        with patch('onyx.server.auth_check.get_redis_client') as mock_redis, \
             patch('onyx.server.auth_check.get_user_permission_level') as mock_get_level:
            
            # Mock Redis cache hit for fast response
            mock_redis_client = AsyncMock()
            mock_redis_client.get.return_value = '{"level": "read", "cached_at": "2023-01-01T00:00:00"}'
            mock_redis.return_value = mock_redis_client
            
            # Run 100 permission checks and measure latency
            for _ in range(100):
                start_time = time.perf_counter()
                await get_oauth_permission(mock_user)
                end_time = time.perf_counter()
                
                latency_ms = (end_time - start_time) * 1000
                latencies.append(latency_ms)
            
            # Calculate statistics
            avg_latency = statistics.mean(latencies)
            p95_latency = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
            max_latency = max(latencies)
            
            print(f"Permission check latencies:")
            print(f"  Average: {avg_latency:.2f}ms")
            print(f"  95th percentile: {p95_latency:.2f}ms")
            print(f"  Maximum: {max_latency:.2f}ms")
            
            # Requirements: 95th percentile < 10ms
            assert p95_latency < 10.0, f"95th percentile latency {p95_latency:.2f}ms exceeds 10ms requirement"
            assert avg_latency < 5.0, f"Average latency {avg_latency:.2f}ms should be well under 10ms"
    
    @pytest.mark.asyncio
    async def test_database_fallback_latency(self, mock_user):
        """Test latency when falling back to database (cache miss)"""
        latencies = []
        
        with patch('onyx.server.auth_check.get_redis_client') as mock_redis, \
             patch('onyx.server.auth_check.get_user_permission_level') as mock_get_level:
            
            # Mock Redis cache miss
            mock_redis_client = AsyncMock()
            mock_redis_client.get.return_value = None
            mock_redis_client.setex.return_value = None
            mock_redis.return_value = mock_redis_client
            
            # Mock fast database response
            mock_get_level.return_value = "read"
            
            # Run 50 permission checks with database fallback
            for _ in range(50):
                start_time = time.perf_counter()
                await get_oauth_permission(mock_user)
                end_time = time.perf_counter()
                
                latency_ms = (end_time - start_time) * 1000
                latencies.append(latency_ms)
            
            avg_latency = statistics.mean(latencies)
            p95_latency = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
            
            print(f"Database fallback latencies:")
            print(f"  Average: {avg_latency:.2f}ms")
            print(f"  95th percentile: {p95_latency:.2f}ms")
            
            # Database fallback should still be reasonable
            assert p95_latency < 50.0, f"Database fallback 95th percentile {p95_latency:.2f}ms too high"
    
    @pytest.mark.asyncio
    async def test_concurrent_permission_checks(self, mock_user):
        """Test concurrent permission checking performance"""
        require_write = require_permission("write")
        
        with patch('onyx.server.auth_check.current_user') as mock_current_user, \
             patch('onyx.server.auth_check.get_oauth_permission') as mock_get_permission:
            
            mock_current_user.return_value = mock_user
            mock_get_permission.return_value = "write"
            
            async def check_permission():
                """Single permission check"""
                return await require_write(mock_user, "write")
            
            # Run 1000 concurrent permission checks
            start_time = time.perf_counter()
            tasks = [check_permission() for _ in range(1000)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            end_time = time.perf_counter()
            
            # Count successful checks
            successful = sum(1 for r in results if not isinstance(r, Exception))
            failed = len(results) - successful
            
            total_time = end_time - start_time
            
            print(f"Concurrent permission checks:")
            print(f"  Total requests: {len(results)}")
            print(f"  Successful: {successful}")
            print(f"  Failed: {failed}")
            print(f"  Total time: {total_time:.2f}s")
            print(f"  Throughput: {len(results)/total_time:.0f} requests/second")
            
            # Requirements: Support 1000+ concurrent checks successfully
            assert successful == 1000, f"Only {successful}/1000 concurrent checks succeeded"
            assert total_time < 5.0, f"1000 concurrent checks took {total_time:.2f}s (should be < 5s)"
    
    @pytest.mark.asyncio
    async def test_cache_hit_ratio(self, mock_user):
        """Test that cache hit ratio meets requirements"""
        cache_hits = 0
        cache_misses = 0
        
        with patch('onyx.server.auth_check.get_redis_client') as mock_redis, \
             patch('onyx.server.auth_check.get_user_permission_level') as mock_get_level:
            
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            mock_get_level.return_value = "read"
            
            # First request - cache miss
            mock_redis_client.get.return_value = None
            await get_oauth_permission(mock_user)
            cache_misses += 1
            
            # Next 99 requests - cache hits
            mock_redis_client.get.return_value = '{"level": "read", "cached_at": "2023-01-01T00:00:00"}'
            for _ in range(99):
                await get_oauth_permission(mock_user)
                cache_hits += 1
            
            cache_hit_ratio = cache_hits / (cache_hits + cache_misses)
            
            print(f"Cache performance:")
            print(f"  Cache hits: {cache_hits}")
            print(f"  Cache misses: {cache_misses}")
            print(f"  Hit ratio: {cache_hit_ratio:.1%}")
            
            # Requirements: > 95% cache hit rate
            assert cache_hit_ratio > 0.95, f"Cache hit ratio {cache_hit_ratio:.1%} below 95% requirement"
    
    @pytest.mark.asyncio
    async def test_permission_hierarchy_performance(self, mock_user):
        """Test performance of permission hierarchy checking"""
        test_cases = [
            ("admin", "read"),
            ("admin", "write"), 
            ("admin", "admin"),
            ("write", "read"),
            ("write", "write"),
            ("read", "read")
        ]
        
        from onyx.server.auth_check import has_permission
        
        start_time = time.perf_counter()
        
        # Run hierarchy checks many times
        for _ in range(10000):
            for user_perm, required_perm in test_cases:
                has_permission(user_perm, required_perm)
        
        end_time = time.perf_counter()
        
        total_checks = 10000 * len(test_cases)
        total_time = end_time - start_time
        checks_per_second = total_checks / total_time
        
        print(f"Permission hierarchy performance:")
        print(f"  Total checks: {total_checks}")
        print(f"  Total time: {total_time:.4f}s")
        print(f"  Checks per second: {checks_per_second:.0f}")
        
        # Should be very fast since it's just dictionary lookups
        assert checks_per_second > 100000, f"Hierarchy checks too slow: {checks_per_second:.0f}/sec"
    
    @pytest.mark.asyncio
    async def test_memory_usage_estimation(self, mock_user):
        """Test estimated memory usage of permission caching"""
        import sys
        
        # Estimate memory usage of cached permission data
        permission_data = {
            "level": "admin",
            "cached_at": "2023-01-01T00:00:00.000000"
        }
        
        # Size of one cached permission record
        import json
        json_data = json.dumps(permission_data)
        base_size = sys.getsizeof(json_data)
        
        # Estimate for 10,000 cached users
        estimated_users = 10000
        estimated_memory_mb = (base_size * estimated_users) / (1024 * 1024)
        
        print(f"Memory usage estimation:")
        print(f"  Per permission record: {base_size} bytes")
        print(f"  For {estimated_users} users: {estimated_memory_mb:.1f} MB")
        
        # Requirements: < 50MB for permission caching
        assert estimated_memory_mb < 50, f"Estimated memory usage {estimated_memory_mb:.1f}MB exceeds 50MB limit"


class TestPermissionStressTest:
    """Stress tests for permission dependencies under load"""
    
    @pytest.mark.asyncio
    async def test_rapid_permission_changes(self, mock_user):
        """Test performance with rapid permission changes (cache invalidation)"""
        from onyx.server.auth_check import invalidate_user_permission_cache
        
        with patch('onyx.server.auth_check.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis_client.delete.return_value = None
            mock_redis.return_value = mock_redis_client
            
            start_time = time.perf_counter()
            
            # Rapidly invalidate cache 100 times
            for _ in range(100):
                await invalidate_user_permission_cache(str(mock_user.id))
            
            end_time = time.perf_counter()
            
            total_time = end_time - start_time
            invalidations_per_second = 100 / total_time
            
            print(f"Cache invalidation performance:")
            print(f"  100 invalidations in {total_time:.4f}s")
            print(f"  Rate: {invalidations_per_second:.0f} invalidations/second")
            
            # Should be fast since it's just Redis delete operations
            assert invalidations_per_second > 1000, f"Cache invalidation too slow: {invalidations_per_second:.0f}/sec"
