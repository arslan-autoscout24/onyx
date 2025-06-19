"""
Utility functions for OAuth permission database operations.

This module provides additional utility functions for batch operations,
statistics, and convenience methods for OAuth permission management.
"""
import logging
from typing import List, Dict, Any, Optional
from uuid import UUID

from onyx.db.oauth_permissions import (
    get_user_permission_level,
    user_has_permission,
    get_permission_summary,
    get_users_by_permission_level,
    VALID_PERMISSION_LEVELS
)

logger = logging.getLogger(__name__)


async def check_multiple_users_permissions(
    user_ids: List[UUID], 
    required_level: str
) -> Dict[UUID, bool]:
    """
    Check permissions for multiple users efficiently.
    
    Args:
        user_ids: List of user UUIDs to check
        required_level: Required permission level
        
    Returns:
        Dictionary mapping user_id to permission check result
    """
    if required_level not in VALID_PERMISSION_LEVELS:
        logger.warning(f"Invalid required level '{required_level}', returning False for all users")
        return {user_id: False for user_id in user_ids}
    
    results = {}
    
    for user_id in user_ids:
        try:
            results[user_id] = await user_has_permission(user_id, required_level)
        except Exception as e:
            logger.error(f"Error checking permission for user {user_id}: {str(e)}")
            results[user_id] = False
    
    logger.debug(f"Checked permissions for {len(user_ids)} users, required level: {required_level}")
    return results


async def get_permission_stats() -> Dict[str, Any]:
    """
    Get comprehensive permission statistics.
    
    Returns:
        Dictionary with permission statistics including:
        - total_users: Total number of users in the system
        - oauth_enabled_users: Number of users with OAuth permissions
        - oauth_percentage: Percentage of users with OAuth permissions
        - permission_distribution: Breakdown by permission level
    """
    try:
        summary = await get_permission_summary()
        
        total_users = sum(summary.values())
        oauth_users = total_users - summary.get("no_oauth_permission", 0)
        
        stats = {
            "total_users": total_users,
            "oauth_enabled_users": oauth_users,
            "oauth_percentage": round((oauth_users / total_users * 100), 2) if total_users > 0 else 0,
            "permission_distribution": summary
        }
        
        logger.info(f"Generated permission stats: {oauth_users}/{total_users} users have OAuth permissions")
        return stats
    except Exception as e:
        logger.error(f"Error generating permission stats: {str(e)}")
        return {
            "total_users": 0,
            "oauth_enabled_users": 0,
            "oauth_percentage": 0,
            "permission_distribution": {},
            "error": str(e)
        }


async def get_users_by_multiple_permission_levels(
    permission_levels: List[str]
) -> Dict[str, List[UUID]]:
    """
    Get users for multiple permission levels in a single operation.
    
    Args:
        permission_levels: List of permission levels to query
        
    Returns:
        Dictionary mapping permission level to list of user UUIDs
    """
    results = {}
    
    for level in permission_levels:
        if level in VALID_PERMISSION_LEVELS:
            try:
                users = await get_users_by_permission_level(level)
                results[level] = users
                logger.debug(f"Found {len(users)} users with permission level '{level}'")
            except Exception as e:
                logger.error(f"Error getting users for permission level '{level}': {str(e)}")
                results[level] = []
        else:
            logger.warning(f"Invalid permission level '{level}', skipping")
            results[level] = []
    
    return results


async def validate_permission_hierarchy(
    user_permissions: Dict[UUID, str]
) -> Dict[str, Any]:
    """
    Validate permission hierarchy for a set of users.
    
    Args:
        user_permissions: Dictionary mapping user_id to permission_level
        
    Returns:
        Validation results including:
        - valid_permissions: Count of valid permission assignments
        - invalid_permissions: List of invalid permission levels found
        - hierarchy_analysis: Analysis of permission distribution
    """
    hierarchy = {"read": 0, "write": 1, "admin": 2}
    
    valid_count = 0
    invalid_permissions = []
    level_counts = {level: 0 for level in VALID_PERMISSION_LEVELS}
    
    for user_id, permission_level in user_permissions.items():
        if permission_level in VALID_PERMISSION_LEVELS:
            valid_count += 1
            level_counts[permission_level] += 1
        else:
            invalid_permissions.append({
                "user_id": str(user_id),
                "invalid_level": permission_level
            })
    
    # Calculate hierarchy distribution
    total_valid = sum(level_counts.values())
    hierarchy_percentages = {}
    if total_valid > 0:
        for level, count in level_counts.items():
            hierarchy_percentages[level] = round((count / total_valid * 100), 2)
    
    results = {
        "total_users_checked": len(user_permissions),
        "valid_permissions": valid_count,
        "invalid_permissions": invalid_permissions,
        "invalid_count": len(invalid_permissions),
        "hierarchy_analysis": {
            "level_counts": level_counts,
            "level_percentages": hierarchy_percentages,
            "hierarchy_order": ["read", "write", "admin"]
        }
    }
    
    logger.info(f"Validated {len(user_permissions)} user permissions: {valid_count} valid, {len(invalid_permissions)} invalid")
    return results


async def find_permission_conflicts(
    user_permissions: Dict[UUID, str],
    expected_permissions: Optional[Dict[UUID, str]] = None
) -> List[Dict[str, Any]]:
    """
    Find conflicts between actual and expected permissions.
    
    Args:
        user_permissions: Current user permission mappings
        expected_permissions: Expected permission mappings (optional)
        
    Returns:
        List of conflicts found
    """
    conflicts = []
    
    if expected_permissions:
        for user_id, expected_level in expected_permissions.items():
            actual_level = user_permissions.get(user_id)
            
            if actual_level != expected_level:
                conflicts.append({
                    "user_id": str(user_id),
                    "expected_level": expected_level,
                    "actual_level": actual_level,
                    "conflict_type": "permission_mismatch"
                })
    
    # Check for duplicate admin permissions (if business rule applies)
    admin_users = [uid for uid, level in user_permissions.items() if level == "admin"]
    if len(admin_users) > 10:  # Example business rule: max 10 admins
        conflicts.append({
            "conflict_type": "too_many_admins",
            "admin_count": len(admin_users),
            "admin_limit": 10,
            "admin_users": [str(uid) for uid in admin_users]
        })
    
    logger.info(f"Found {len(conflicts)} permission conflicts")
    return conflicts


async def generate_permission_audit_report() -> Dict[str, Any]:
    """
    Generate a comprehensive audit report for OAuth permissions.
    
    Returns:
        Comprehensive audit report
    """
    try:
        # Get basic statistics
        stats = await get_permission_stats()
        
        # Get users by permission level
        all_levels_users = await get_users_by_multiple_permission_levels(
            list(VALID_PERMISSION_LEVELS)
        )
        
        # Build user permission mapping for analysis
        user_permissions = {}
        for level, users in all_levels_users.items():
            for user_id in users:
                user_permissions[user_id] = level
        
        # Validate hierarchy
        validation_results = await validate_permission_hierarchy(user_permissions)
        
        # Find potential conflicts
        conflicts = await find_permission_conflicts(user_permissions)
        
        # Generate timestamp
        report_timestamp = datetime.utcnow().isoformat()
        
        audit_report = {
            "report_metadata": {
                "generated_at": report_timestamp,
                "report_type": "oauth_permission_audit",
                "total_users_analyzed": len(user_permissions)
            },
            "permission_statistics": stats,
            "users_by_level": {
                level: len(users) for level, users in all_levels_users.items()
            },
            "validation_results": validation_results,
            "conflicts": conflicts,
            "recommendations": []
        }
        
        # Add recommendations based on findings
        if validation_results["invalid_count"] > 0:
            audit_report["recommendations"].append({
                "type": "cleanup",
                "description": f"Clean up {validation_results['invalid_count']} invalid permission assignments"
            })
        
        if len(conflicts) > 0:
            audit_report["recommendations"].append({
                "type": "conflict_resolution",
                "description": f"Resolve {len(conflicts)} permission conflicts"
            })
        
        oauth_percentage = stats.get("oauth_percentage", 0)
        if oauth_percentage < 50:
            audit_report["recommendations"].append({
                "type": "adoption",
                "description": f"Consider increasing OAuth adoption (currently {oauth_percentage}%)"
            })
        
        logger.info(f"Generated audit report for {len(user_permissions)} users")
        return audit_report
        
    except Exception as e:
        logger.error(f"Error generating audit report: {str(e)}")
        return {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "report_type": "oauth_permission_audit",
                "error": str(e)
            },
            "error": "Failed to generate audit report"
        }
