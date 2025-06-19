"""
Permission service related Celery tasks.
"""

from onyx.background.celery.tasks.permission.tasks import permission_cache_cleanup_task

__all__ = ["permission_cache_cleanup_task"]
