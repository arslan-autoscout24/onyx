"""
Celery tasks for permission service maintenance.
"""
from celery import shared_task

from onyx.background.celery.apps.app_base import task_logger
from onyx.background.permission_cache_cleanup import cleanup_permission_cache
from onyx.configs.constants import OnyxCeleryTask


@shared_task(
    name=OnyxCeleryTask.PERMISSION_CACHE_CLEANUP,
    soft_time_limit=300,  # 5 minutes
    time_limit=360,  # 6 minutes
)
def permission_cache_cleanup_task() -> int:
    """
    Celery task to clean up expired permission cache entries.
    
    Returns:
        Number of expired entries removed
    """
    task_logger.info("Starting permission cache cleanup task")
    
    try:
        # Run the cleanup function directly since it doesn't use async operations
        from onyx.auth.permission_service import get_permission_service
        
        service = get_permission_service()
        expired_count = service.cleanup_expired_cache()
        stats = service.get_cache_stats()
        
        task_logger.info(
            f"Permission cache cleanup completed: "
            f"removed {expired_count} expired entries, "
            f"cache size: {stats['cache_size']}, "
            f"hit rate: {stats['hit_rate_percent']}%"
        )
        
        return expired_count
        
    except Exception as e:
        task_logger.error(f"Permission cache cleanup failed: {str(e)}")
        raise
