"""
Integration tests for Okta token parsing with real-world scenarios
"""
import pytest
import json
import time
from base64 import urlsafe_b64encode
from unittest.mock import patch

from onyx.auth.okta_parser import OktaTokenParser


class TestOktaIntegration:
    
    def setup_method(self):
        self.parser = OktaTokenParser()
    
    def create_realistic_okta_token(self, groups: list, extra_claims: dict = None) -> str:
        """Create a more realistic Okta token structure"""
        payload = {
            "ver": 1,
            "jti": "AT.example-jti-value",
            "iss": "https://dev-12345.okta.com/oauth2/default",
            "aud": "api://default",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "cid": "client-id-example",
            "uid": "00u1234567890abcdef",
            "scp": ["openid", "profile", "email"],
            "auth_time": int(time.time()),
            "sub": "user@example.com",
            "groups": groups
        }
        
        if extra_claims:
            payload.update(extra_claims)
        
        # Create realistic header
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "kid": "key-id-example"
        }
        
        # Encode parts
        header_b64 = urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature_b64 = urlsafe_b64encode("realistic-signature-would-be-here".encode()).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    def test_realistic_okta_token_structure(self):
        """Test with realistic Okta token payload structure"""
        groups = ["Onyx-Admins", "Everyone", "Company-All-Users"]
        token = self.create_realistic_okta_token(groups)
        
        permission, extracted_groups = self.parser.parse_token_for_permissions(token)
        
        assert permission == "admin"
        assert "Onyx-Admins" in extracted_groups
        assert "Everyone" in extracted_groups
        assert len(extracted_groups) == 3
    
    def test_realistic_token_with_no_onyx_groups(self):
        """Test realistic token with no Onyx-specific groups"""
        groups = ["Everyone", "Company-All-Users", "Department-Engineering"]
        token = self.create_realistic_okta_token(groups)
        
        permission, extracted_groups = self.parser.parse_token_for_permissions(token)
        
        assert permission == "read"  # Default permission
        assert len(extracted_groups) == 3
    
    def test_realistic_token_mixed_permissions(self):
        """Test realistic token with mixed permission levels"""
        groups = ["Onyx-Writers", "Onyx-Readers", "Department-Marketing", "Team-Product"]
        token = self.create_realistic_okta_token(groups)
        
        permission, extracted_groups = self.parser.parse_token_for_permissions(token)
        
        assert permission == "write"  # Highest available
        assert len(extracted_groups) == 4
    
    def test_performance_with_large_group_lists(self):
        """Test performance with users who have many groups"""
        # Simulate user with many groups (common in large organizations)
        large_group_list = [f"Department-{i}" for i in range(50)]
        large_group_list.extend([f"Team-{i}" for i in range(30)])
        large_group_list.extend([f"Project-{i}" for i in range(20)])
        large_group_list.extend(["Onyx-Admins", "Onyx-Writers"])
        
        token = self.create_realistic_okta_token(large_group_list)
        
        start_time = time.time()
        permission, groups = self.parser.parse_token_for_permissions(token)
        end_time = time.time()
        
        processing_time = (end_time - start_time) * 1000  # Convert to milliseconds
        
        # Should meet performance requirement of <50ms
        assert processing_time < 50
        assert permission == "admin"
        assert len(groups) == 102  # 50 + 30 + 20 + 2
    
    def test_token_with_custom_groups_claim(self):
        """Test integration with custom groups claim"""
        parser = OktaTokenParser(groups_claim="custom_groups")
        
        extra_claims = {
            "custom_groups": ["Onyx-Writers", "Special-Group"]
        }
        groups = ["Onyx-Readers"]  # This should be ignored
        token = self.create_realistic_okta_token(groups, extra_claims)
        
        permission, extracted_groups = parser.parse_token_for_permissions(token)
        
        assert permission == "write"
        assert "Onyx-Writers" in extracted_groups
        assert "Special-Group" in extracted_groups
        assert "Onyx-Readers" not in extracted_groups  # Should not be extracted
    
    def test_token_with_nested_group_structure(self):
        """Test token where groups might be nested or have complex structure"""
        # Some OIDC providers might return groups in different formats
        groups = [
            "CN=Onyx-Admins,OU=Groups,DC=company,DC=com",
            "CN=Onyx-Writers,OU=Groups,DC=company,DC=com",
            "Simple-Group-Name"
        ]
        
        # Update group mapping to handle DN format
        test_parser = OktaTokenParser()
        test_parser.GROUP_MAPPING.update({
            "CN=Onyx-Admins,OU=Groups,DC=company,DC=com": "admin",
            "CN=Onyx-Writers,OU=Groups,DC=company,DC=com": "write"
        })
        
        token = self.create_realistic_okta_token(groups)
        
        permission, extracted_groups = test_parser.parse_token_for_permissions(token)
        
        assert permission == "admin"
        assert len(extracted_groups) == 3
    
    def test_token_parsing_memory_efficiency(self):
        """Test that token parsing is memory efficient"""
        import gc
        import psutil
        import os
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Parse many tokens to test memory efficiency
        for i in range(100):
            groups = [f"Group-{i}", "Onyx-Writers"]
            token = self.create_realistic_okta_token(groups)
            self.parser.parse_token_for_permissions(token)
        
        # Force garbage collection
        gc.collect()
        
        # Check memory usage hasn't grown significantly
        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory
        
        # Should not grow by more than 10MB for 100 token parses
        assert memory_growth < 10 * 1024 * 1024  # 10MB
    
    def test_concurrent_token_parsing(self):
        """Test that parser works correctly with concurrent access"""
        import threading
        import queue
        
        results = queue.Queue()
        
        def parse_token(thread_id):
            groups = [f"Thread-{thread_id}-Group", "Onyx-Admins"]
            token = self.create_realistic_okta_token(groups)
            permission, extracted_groups = self.parser.parse_token_for_permissions(token)
            results.put((thread_id, permission, len(extracted_groups)))
        
        # Create multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=parse_token, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all results
        assert results.qsize() == 10
        while not results.empty():
            thread_id, permission, group_count = results.get()
            assert permission == "admin"
            assert group_count == 2
    
    def test_token_with_special_characters_in_groups(self):
        """Test handling of groups with special characters"""
        groups = [
            "Onyx-Admins",
            "Group with spaces",
            "Group-with-dashes",
            "Group_with_underscores",
            "Group.with.dots",
            "Group@with@symbols"
        ]
        
        token = self.create_realistic_okta_token(groups)
        
        permission, extracted_groups = self.parser.parse_token_for_permissions(token)
        
        assert permission == "admin"
        assert len(extracted_groups) == 6
        for group in groups:
            assert group in extracted_groups
    
    def test_token_validation_edge_cases(self):
        """Test token validation with various edge cases"""
        # Test with minimal valid token
        minimal_payload = {"groups": ["Onyx-Readers"]}
        token = self.create_realistic_okta_token(["Onyx-Readers"])
        
        assert self.parser.validate_token_structure(token) is True
        
        # Test with extra long token (large payload)
        large_payload_groups = [f"Very-Long-Group-Name-{i}-With-Lots-Of-Characters" for i in range(100)]
        large_token = self.create_realistic_okta_token(large_payload_groups)
        
        assert self.parser.validate_token_structure(large_token) is True
        
        # Test with Unicode characters in groups
        unicode_groups = ["Onyx-Admins", "Группа-Пользователей", "グループ-ユーザー"]
        unicode_token = self.create_realistic_okta_token(unicode_groups)
        
        permission, extracted_groups = self.parser.parse_token_for_permissions(unicode_token)
        assert permission == "admin"
        assert len(extracted_groups) == 3


class TestOktaIntegrationErrorRecovery:
    """Test error recovery and resilience in integration scenarios"""
    
    def setup_method(self):
        self.parser = OktaTokenParser()
    
    def test_partial_token_corruption(self):
        """Test handling of partially corrupted tokens"""
        # Create a valid token first
        valid_token = TestOktaIntegration().create_realistic_okta_token(["Onyx-Admins"])
        
        # Corrupt the signature part (common in transmission errors)
        parts = valid_token.split('.')
        corrupted_token = f"{parts[0]}.{parts[1]}.corrupted_signature"
        
        # Parser should still work (since we don't verify signatures)
        permission, groups = self.parser.parse_token_for_permissions(corrupted_token)
        assert permission == "admin"
        assert "Onyx-Admins" in groups
    
    def test_malformed_token_recovery(self):
        """Test that parser recovers gracefully from malformed tokens"""
        malformed_tokens = [
            "not-a-token",
            "one.part",
            "too.many.parts.here",
            "",
            None,
            123
        ]
        
        for bad_token in malformed_tokens:
            try:
                permission, groups = self.parser.parse_token_for_permissions(bad_token)
                # Should always return safe defaults
                assert permission == "read"
                assert groups == []
            except TypeError:
                # None and 123 might raise TypeError, which is acceptable
                pass
    
    def test_network_timeout_simulation(self):
        """Test behavior under simulated network conditions"""
        # This simulates what might happen if token parsing occurs
        # during network instability (though parsing is local)
        
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Simulated network timeout")
        
        # Set a very short timeout
        signal.signal(signal.SIGALRM, timeout_handler)
        
        try:
            signal.alarm(1)  # 1 second timeout
            
            # Parse a token within the timeout
            token = TestOktaIntegration().create_realistic_okta_token(["Onyx-Writers"])
            permission, groups = self.parser.parse_token_for_permissions(token)
            
            assert permission == "write"
            
        finally:
            signal.alarm(0)  # Cancel timeout
