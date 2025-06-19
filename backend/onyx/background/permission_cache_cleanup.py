"""
Background task for permission cache cleanup.
"""
import asyncio
import logging
from datetime import datetime

from onyx.auth.permission_service import get_permission_service
from onyx.configs.app_configs import PERMISSION_CACHE_CLEANUP_INTERVAL_MINUTES

logger = logging.getLogger(__name__)

async def cleanup_permission_cache():
    """Background task to clean up expired cache entries."""
    service = get_permission_service()
    
    try:
        expired_count = service.cleanup_expired_cache()
        stats = service.get_cache_stats()
        
        logger.info(
            f"Permission cache cleanup completed: "
            f"removed {expired_count} expired entries, "
            f"cache size: {stats['cache_size']}, "
            f"hit rate: {stats['hit_rate_percent']}%"
        )
        
        return expired_count
        
    except Exception as e:
        logger.error(f"Error during permission cache cleanup: {str(e)}")
        raise

# Function to be called by background job scheduler
async def schedule_permission_cache_cleanup():
    """Schedule periodic cache cleanup using configured interval."""
    cleanup_interval_seconds = PERMISSION_CACHE_CLEANUP_INTERVAL_MINUTES * 60
    logger.info(f"Starting permission cache cleanup scheduler with {PERMISSION_CACHE_CLEANUP_INTERVAL_MINUTES}m interval")
    
    while True:
        await cleanup_permission_cache()
        await asyncio.sleep(cleanup_interval_seconds)
