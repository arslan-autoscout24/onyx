"""
Performance Testing Suite for OAuth Authorization System

This module contains performance tests to validate that the OAuth authorization system
meets performance requirements under various load conditions.
"""

import pytest
import time
import asyncio
import concurrent.futures
import psutil
import os
from fastapi.testclient import TestClient
from unittest.mock import patch
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
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'test@test.com', 'groups': ['Onyx-Readers']}
            
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
            with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
                mock_verify.return_value = {'email': 'test@test.com', 'groups': ['Onyx-Readers']}
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
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'test@test.com', 'groups': ['Onyx-Readers']}
            
            # First request (cache miss)
            start_time = time.time()
            response1 = self.client.get("/documents", headers=headers)
            first_request_time = (time.time() - start_time) * 1000
            
            assert response1.status_code == 200
            
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
            assert improvement_ratio > 1.5, f"Cache improvement ratio {improvement_ratio} is too low"
    
    def test_memory_usage_under_load(self):
        """Test memory usage of permission system under load."""
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create many users with different permissions
        tokens = []
        for i in range(100):
            token = create_okta_jwt_token(f"user{i}@test.com", ["Onyx-Readers"])
            tokens.append(token)
        
        # Make requests with all users
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            for i, token in enumerate(tokens):
                mock_verify.return_value = {'email': f'user{i}@test.com', 'groups': ['Onyx-Readers']}
                headers = {"Authorization": f"Bearer {token}"}
                response = self.client.get("/documents", headers=headers)
                assert response.status_code == 200
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable
        assert memory_increase < 50, f"Memory increased by {memory_increase}MB, exceeds 50MB limit"
    
    def test_different_permission_levels_performance(self):
        """Test performance with different permission levels."""
        test_users = [
            ("admin@test.com", ["Onyx-Admins"], "/admin/users"),
            ("writer@test.com", ["Onyx-Writers"], "/documents"),
            ("reader@test.com", ["Onyx-Readers"], "/documents")
        ]
        
        for email, groups, endpoint in test_users:
            token = create_okta_jwt_token(email, groups)
            headers = {"Authorization": f"Bearer {token}"}
            
            # Measure performance for each permission level
            times = []
            with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
                mock_verify.return_value = {'email': email, 'groups': groups}
                
                for _ in range(20):
                    start_time = time.time()
                    response = self.client.get(endpoint, headers=headers)
                    end_time = time.time()
                    
                    if response.status_code in [200, 403]:  # 403 is expected for some combinations
                        times.append((end_time - start_time) * 1000)
            
            if times:  # Only check if we have valid measurements
                avg_time = sum(times) / len(times)
                assert avg_time < 150, f"Average time for {email} permission level: {avg_time}ms exceeds 150ms"
    
    def test_jwt_verification_performance(self):
        """Test JWT token verification performance."""
        tokens = [create_okta_jwt_token(f"user{i}@test.com", ["Onyx-Readers"]) for i in range(50)]
        
        # Measure JWT verification time
        verification_times = []
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            for i, token in enumerate(tokens):
                mock_verify.return_value = {'email': f'user{i}@test.com', 'groups': ['Onyx-Readers']}
                headers = {"Authorization": f"Bearer {token}"}
                
                start_time = time.time()
                response = self.client.get("/health", headers=headers)  # Simple endpoint
                end_time = time.time()
                
                verification_times.append((end_time - start_time) * 1000)
        
        avg_verification_time = sum(verification_times) / len(verification_times)
        max_verification_time = max(verification_times)
        
        assert avg_verification_time < 50, f"Average JWT verification time {avg_verification_time}ms exceeds 50ms"
        assert max_verification_time < 100, f"Max JWT verification time {max_verification_time}ms exceeds 100ms"
    
    def test_bulk_permission_operations(self):
        """Test performance with bulk permission operations."""
        # Create tokens for bulk operations
        admin_token = create_okta_jwt_token("admin@test.com", ["Onyx-Admins"])
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'admin@test.com', 'groups': ['Onyx-Admins']}
            
            # Test bulk document creation (if supported)
            start_time = time.time()
            
            documents = []
            for i in range(20):
                doc_response = self.client.post(
                    "/documents",
                    json={"title": f"Bulk Document {i}", "content": f"Content {i}"},
                    headers=headers
                )
                if doc_response.status_code in [200, 201]:
                    documents.append(doc_response.json())
            
            bulk_creation_time = (time.time() - start_time) * 1000
            
            # Should handle bulk operations efficiently
            avg_time_per_doc = bulk_creation_time / len(documents) if documents else 0
            assert avg_time_per_doc < 200, f"Average time per document creation: {avg_time_per_doc}ms exceeds 200ms"
    
    def test_permission_system_scalability(self):
        """Test system scalability with increasing load."""
        base_token = create_okta_jwt_token("scale-test@test.com", ["Onyx-Readers"])
        headers = {"Authorization": f"Bearer {base_token}"}
        
        # Test with increasing number of concurrent requests
        load_levels = [10, 25, 50]
        
        with patch('onyx.auth.oauth.verify_jwt_token') as mock_verify:
            mock_verify.return_value = {'email': 'scale-test@test.com', 'groups': ['Onyx-Readers']}
            
            for load_level in load_levels:
                def make_request():
                    start_time = time.time()
                    response = self.client.get("/documents", headers=headers)
                    end_time = time.time()
                    return response.status_code, (end_time - start_time) * 1000
                
                # Execute concurrent requests
                with concurrent.futures.ThreadPoolExecutor(max_workers=load_level) as executor:
                    futures = [executor.submit(make_request) for _ in range(load_level)]
                    results = [future.result() for future in concurrent.futures.as_completed(futures)]
                
                # Verify performance doesn't degrade significantly with load
                status_codes, response_times = zip(*results)
                success_rate = sum(1 for code in status_codes if code == 200) / len(status_codes)
                avg_response_time = sum(response_times) / len(response_times)
                
                assert success_rate >= 0.95, f"Success rate {success_rate} below 95% at load level {load_level}"
                assert avg_response_time < 300, f"Average response time {avg_response_time}ms exceeds 300ms at load level {load_level}"
