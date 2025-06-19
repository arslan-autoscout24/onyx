"""
Permission Retrieval Service with caching and fallback handling.

This service provides the primary interface for checking user permissions
throughout the application, with intelligent caching and reliability features.
"""
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Set
from uuid import UUID
from dataclasses import dataclass
from threading import Lock
import time

from onyx.db.oauth_permissions import get_user_permission_level
from onyx.configs.app_configs import OAUTH_PERMISSIONS_ENABLED

logger = logging.getLogger(__name__)

@dataclass
class CachedPermission:
    """Cached permission data with timestamp"""
    permission_level: str
    cached_at: datetime
    user_id: UUID

@dataclass
class CircuitBreakerState:
    """Circuit breaker state for database failures"""
    failure_count: int = 0
    last_failure_time: Optional[datetime] = None
    is_open: bool = False

class PermissionService:
    """
    Service for retrieving and caching user OAuth permissions.
    
    This service provides:
    - Fast permission lookups with caching
    - Fallback behavior when permissions aren't found
    - Cache invalidation when permissions change
    - Metrics collection for monitoring
    - Circuit breaker pattern for database issues
    """
    
    def __init__(self, cache_ttl_minutes: int = 5):
        """
        Initialize the permission service.
        
        Args:
            cache_ttl_minutes: How long to cache permissions (default: 5 minutes)
        """
        self.cache_ttl = timedelta(minutes=cache_ttl_minutes)
        self._cache: Dict[UUID, CachedPermission] = {}
        self._cache_lock = Lock()
        
        # Circuit breaker for database failures
        self._circuit_breaker = CircuitBreakerState()
        self._circuit_breaker_lock = Lock()
        self._failure_threshold = 5  # Open circuit after 5 failures
        self._recovery_timeout = timedelta(minutes=2)  # Try again after 2 minutes
        
        # Metrics
        self._cache_hits = 0
        self._cache_misses = 0
        self._db_errors = 0
        self._total_requests = 0
        self._circuit_breaker_trips = 0
        
        logger.info(f"PermissionService initialized with {cache_ttl_minutes}m cache TTL")
    
    async def get_user_permission_level(self, user_id: UUID) -> str:
        """
        Get user's permission level with caching.
        
        This is the primary method for retrieving user permissions.
        Checks cache first, falls back to database, and handles errors gracefully.
        
        Args:
            user_id: UUID of the user
            
        Returns:
            Permission level string ('read', 'write', 'admin')
        """
        self._total_requests += 1
        start_time = time.time()
        
        try:
            # Check cache first
            cached_permission = self._get_from_cache(user_id)
            if cached_permission:
                self._cache_hits += 1
                logger.debug(f"Cache hit for user {user_id}: {cached_permission.permission_level}")
                return cached_permission.permission_level
            
            # Cache miss - fetch from database
            self._cache_misses += 1
            permission_level = await self._fetch_from_database(user_id)
            
            # Store in cache
            self._store_in_cache(user_id, permission_level)
            
            elapsed_ms = (time.time() - start_time) * 1000
            logger.debug(f"Permission lookup for user {user_id}: {permission_level} ({elapsed_ms:.2f}ms)")
            
            return permission_level
            
        except Exception as e:
            self._db_errors += 1
            logger.error(f"Error getting permission for user {user_id}: {str(e)}")
            # Fallback to 'read' permission
            return "read"
    
    async def get_multiple_user_permissions(self, user_ids: Set[UUID]) -> Dict[UUID, str]:
        """
        Get permissions for multiple users efficiently.
        
        Args:
            user_ids: Set of user UUIDs
            
        Returns:
            Dictionary mapping user_id to permission level
        """
        results = {}
        uncached_users = set()
        
        # Check cache for all users
        for user_id in user_ids:
            cached_permission = self._get_from_cache(user_id)
            if cached_permission:
                results[user_id] = cached_permission.permission_level
                self._cache_hits += 1
            else:
                uncached_users.add(user_id)
                self._cache_misses += 1
        
        # Fetch uncached users from database
        for user_id in uncached_users:
            try:
                permission = await self._fetch_from_database(user_id)
                self._store_in_cache(user_id, permission)
                results[user_id] = permission
            except Exception as e:
                logger.error(f"Error fetching permission for user {user_id}: {str(e)}")
                results[user_id] = "read"  # Fallback
        
        return results
    
    def invalidate_user_cache(self, user_id: UUID) -> None:
        """
        Invalidate cache for a specific user.
        
        Args:
            user_id: UUID of the user to invalidate
        """
        with self._cache_lock:
            if user_id in self._cache:
                del self._cache[user_id]
                logger.debug(f"Invalidated cache for user {user_id}")
    
    def invalidate_all_cache(self) -> None:
        """Invalidate all cached permissions."""
        with self._cache_lock:
            cache_size = len(self._cache)
            self._cache.clear()
            logger.info(f"Invalidated all cache ({cache_size} entries)")
    
    def cleanup_expired_cache(self) -> int:
        """
        Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        now = datetime.utcnow()
        expired_users = []
        
        with self._cache_lock:
            for user_id, cached_perm in self._cache.items():
                if not self._is_cache_valid(cached_perm.cached_at, now):
                    expired_users.append(user_id)
            
            for user_id in expired_users:
                del self._cache[user_id]
        
        if expired_users:
            logger.debug(f"Cleaned up {len(expired_users)} expired cache entries")
        
        return len(expired_users)
    
    def get_cache_stats(self) -> Dict[str, any]:
        """
        Get cache statistics for monitoring.
        
        Returns:
            Dictionary with cache statistics
        """
        with self._cache_lock:
            cache_size = len(self._cache)
        
        hit_rate = (self._cache_hits / self._total_requests * 100) if self._total_requests > 0 else 0
        
        return {
            "cache_size": cache_size,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "hit_rate_percent": round(hit_rate, 2),
            "db_errors": self._db_errors,
            "total_requests": self._total_requests,
            "circuit_breaker_trips": self._circuit_breaker_trips,
            "circuit_breaker_open": self._circuit_breaker.is_open,
            "circuit_breaker_failures": self._circuit_breaker.failure_count
        }
    
    def _get_from_cache(self, user_id: UUID) -> Optional[CachedPermission]:
        """Get permission from cache if valid."""
        with self._cache_lock:
            cached_perm = self._cache.get(user_id)
            
            if cached_perm and self._is_cache_valid(cached_perm.cached_at):
                return cached_perm
            elif cached_perm:
                # Remove expired entry
                del self._cache[user_id]
        
        return None
    
    def _store_in_cache(self, user_id: UUID, permission_level: str) -> None:
        """Store permission in cache."""
        cached_permission = CachedPermission(
            permission_level=permission_level,
            cached_at=datetime.utcnow(),
            user_id=user_id
        )
        
        with self._cache_lock:
            self._cache[user_id] = cached_permission
    
    def _is_cache_valid(self, cached_time: datetime, now: datetime = None) -> bool:
        """Check if cached entry is still valid."""
        if now is None:
            now = datetime.utcnow()
        return (now - cached_time) < self.cache_ttl

    async def _fetch_from_database(self, user_id: UUID) -> str:
        """Fetch permission from database with error handling and circuit breaker."""
        if not OAUTH_PERMISSIONS_ENABLED:
            logger.debug("OAuth permissions disabled, returning default 'read' permission")
            return "read"

        # Check circuit breaker
        if self._is_circuit_breaker_open():
            logger.warning("Circuit breaker is open, returning fallback permission")
            return "read"

        try:
            permission_level = await get_user_permission_level(user_id)
            logger.debug(f"Fetched permission from database for user {user_id}: {permission_level}")
            
            # Reset circuit breaker on success
            self._reset_circuit_breaker()
            
            return permission_level
        except Exception as e:
            logger.error(f"Database error fetching permission for user {user_id}: {str(e)}")
            self._record_failure()
            raise

    def _is_circuit_breaker_open(self) -> bool:
        """Check if circuit breaker is open"""
        with self._circuit_breaker_lock:
            if not self._circuit_breaker.is_open:
                return False
            
            # Check if recovery timeout has passed
            if (self._circuit_breaker.last_failure_time and 
                datetime.utcnow() - self._circuit_breaker.last_failure_time > self._recovery_timeout):
                logger.info("Circuit breaker recovery timeout reached, attempting to close")
                self._circuit_breaker.is_open = False
                return False
            
            return True

    def _record_failure(self) -> None:
        """Record a database failure for circuit breaker"""
        with self._circuit_breaker_lock:
            self._circuit_breaker.failure_count += 1
            self._circuit_breaker.last_failure_time = datetime.utcnow()
            
            if self._circuit_breaker.failure_count >= self._failure_threshold:
                self._circuit_breaker.is_open = True
                self._circuit_breaker_trips += 1
                logger.warning(
                    f"Circuit breaker opened after {self._failure_threshold} failures. "
                    f"Will retry after {self._recovery_timeout.total_seconds()} seconds"
                )

    def _reset_circuit_breaker(self) -> None:
        """Reset circuit breaker after successful operation"""
        with self._circuit_breaker_lock:
            if self._circuit_breaker.failure_count > 0 or self._circuit_breaker.is_open:
                logger.info("Circuit breaker reset after successful database operation")
                self._circuit_breaker.failure_count = 0
                self._circuit_breaker.is_open = False
                self._circuit_breaker.last_failure_time = None


# Global service instance
_permission_service: Optional[PermissionService] = None
_service_lock = Lock()


def get_permission_service() -> PermissionService:
    """
    Get the global permission service instance.
    
    Returns:
        PermissionService instance
    """
    global _permission_service
    
    if _permission_service is None:
        with _service_lock:
            if _permission_service is None:
                from onyx.configs.app_configs import PERMISSION_CACHE_TTL_MINUTES
                _permission_service = PermissionService(cache_ttl_minutes=PERMISSION_CACHE_TTL_MINUTES)
    
    return _permission_service


# Convenience functions for easy access
async def get_user_permission(user_id: UUID) -> str:
    """
    Convenience function to get user's permission level.
    
    Args:
        user_id: UUID of the user
        
    Returns:
        Permission level string
    """
    service = get_permission_service()
    return await service.get_user_permission_level(user_id)


async def user_has_permission(user_id: UUID, required_permission: str) -> bool:
    """
    Check if user has the required permission level or higher.
    
    Args:
        user_id: UUID of the user
        required_permission: Required permission level ('read', 'write', 'admin')
        
    Returns:
        True if user has sufficient permission
    """
    user_permission = await get_user_permission(user_id)
    
    permission_hierarchy = {"read": 1, "write": 2, "admin": 3}
    user_level = permission_hierarchy.get(user_permission, 1)
    required_level = permission_hierarchy.get(required_permission, 1)
    
    return user_level >= required_level


def invalidate_user_permission_cache(user_id: UUID) -> None:
    """
    Convenience function to invalidate user's cached permission.
    
    Args:
        user_id: UUID of the user
    """
    service = get_permission_service()
    service.invalidate_user_cache(user_id)
