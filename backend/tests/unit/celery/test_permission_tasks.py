"""
Unit tests for permission service Celery tasks.
"""
import pytest
from unittest.mock import patch, MagicMock

from onyx.background.celery.tasks.permission.tasks import permission_cache_cleanup_task


class TestPermissionCeleryTasks:
    """Test permission service Celery tasks"""
    
    def test_permission_cache_cleanup_task_success(self):
        """Test successful permission cache cleanup task"""
        # Mock the permission service
        mock_service = MagicMock()
        mock_service.cleanup_expired_cache.return_value = 5
        mock_service.get_cache_stats.return_value = {
            "cache_size": 100,
            "hit_rate_percent": 95.0
        }
        
        with patch('onyx.background.celery.tasks.permission.tasks.get_permission_service') as mock_get_service:
            mock_get_service.return_value = mock_service
            
            result = permission_cache_cleanup_task()
            
            assert result == 5
            mock_service.cleanup_expired_cache.assert_called_once()
            mock_service.get_cache_stats.assert_called_once()
    
    def test_permission_cache_cleanup_task_failure(self):
        """Test permission cache cleanup task failure handling"""
        with patch('onyx.background.celery.tasks.permission.tasks.get_permission_service') as mock_get_service:
            mock_get_service.side_effect = Exception("Service unavailable")
            
            with pytest.raises(Exception, match="Service unavailable"):
                permission_cache_cleanup_task()
    
    def test_permission_cache_cleanup_task_partial_failure(self):
        """Test permission cache cleanup task with partial failure"""
        mock_service = MagicMock()
        mock_service.cleanup_expired_cache.side_effect = Exception("Cleanup failed")
        
        with patch('onyx.background.celery.tasks.permission.tasks.get_permission_service') as mock_get_service:
            mock_get_service.return_value = mock_service
            
            with pytest.raises(Exception, match="Cleanup failed"):
                permission_cache_cleanup_task()
