"""
Okta JWT Token Parser for Group Extraction and Permission Mapping

This module handles parsing Okta JWT tokens to extract user groups
and map them to application permission levels.
"""
import json
import logging
from typing import List, Optional, Dict, Any
from base64 import urlsafe_b64decode

logger = logging.getLogger(__name__)


class OktaTokenParser:
    """
    Parser for Okta JWT tokens to extract groups and map to permissions.
    
    This class handles the core logic for:
    1. Extracting groups from JWT tokens
    2. Mapping Okta groups to application permissions
    3. Determining the highest permission level for users
    """
    
    # Mapping of Okta groups to permission levels
    GROUP_MAPPING = {
        "Onyx-Admins": "admin",
        "Onyx-Writers": "write", 
        "Onyx-Readers": "read",
        "Onyx-Viewers": "read",
        "onyx-admins": "admin",  # Lowercase variants
        "onyx-writers": "write",
        "onyx-readers": "read",
        "onyx-viewers": "read"
    }
    
    # Permission hierarchy (higher index = higher permission)
    PERMISSION_HIERARCHY = ["read", "write", "admin"]
    
    def __init__(self, groups_claim: str = "groups"):
        """
        Initialize the parser.
        
        Args:
            groups_claim: The claim name in JWT that contains groups (default: "groups")
        """
        self.groups_claim = groups_claim
    
    def extract_groups_from_token(self, access_token: str) -> List[str]:
        """
        Extract groups from Okta JWT access token.
        
        Args:
            access_token: The JWT access token from Okta
            
        Returns:
            List of group names from the token
            
        Raises:
            ValueError: If token is malformed or cannot be parsed
        """
        try:
            # Parse JWT token (no signature verification for now)
            payload = self._parse_jwt_payload(access_token)
            
            # Extract groups from the specified claim
            groups = payload.get(self.groups_claim, [])
            
            if not isinstance(groups, list):
                logger.warning(f"Groups claim '{self.groups_claim}' is not a list: {type(groups)}")
                return []
            
            logger.info(f"Extracted {len(groups)} groups from token")
            return groups
            
        except Exception as e:
            logger.error(f"Failed to extract groups from token: {str(e)}")
            raise ValueError(f"Invalid or malformed JWT token: {str(e)}")
    
    def map_groups_to_permissions(self, groups: List[str]) -> List[str]:
        """
        Map Okta groups to application permission levels.
        
        Args:
            groups: List of Okta group names
            
        Returns:
            List of permission levels corresponding to the groups
        """
        permissions = []
        
        for group in groups:
            if group in self.GROUP_MAPPING:
                permission = self.GROUP_MAPPING[group]
                permissions.append(permission)
                logger.debug(f"Mapped group '{group}' to permission '{permission}'")
            else:
                logger.debug(f"No mapping found for group '{group}'")
        
        # Remove duplicates while preserving order
        unique_permissions = []
        for perm in permissions:
            if perm not in unique_permissions:
                unique_permissions.append(perm)
        
        return unique_permissions
    
    def get_highest_permission_level(self, permissions: List[str]) -> str:
        """
        Determine the highest permission level from a list of permissions.
        
        Args:
            permissions: List of permission levels
            
        Returns:
            The highest permission level, or 'read' if no valid permissions
        """
        if not permissions:
            return "read"  # Default fallback permission
        
        # Find the highest permission based on hierarchy
        highest_index = -1
        highest_permission = "read"
        
        for permission in permissions:
            if permission in self.PERMISSION_HIERARCHY:
                index = self.PERMISSION_HIERARCHY.index(permission)
                if index > highest_index:
                    highest_index = index
                    highest_permission = permission
        
        logger.info(f"Determined highest permission: '{highest_permission}' from {permissions}")
        return highest_permission
    
    def parse_token_for_permissions(self, access_token: str) -> tuple[str, List[str]]:
        """
        Complete flow: extract groups from token and return highest permission.
        
        Args:
            access_token: The JWT access token from Okta
            
        Returns:
            Tuple of (highest_permission_level, list_of_groups)
        """
        try:
            groups = self.extract_groups_from_token(access_token)
            permissions = self.map_groups_to_permissions(groups)
            highest_permission = self.get_highest_permission_level(permissions)
            
            return highest_permission, groups
            
        except Exception as e:
            logger.error(f"Failed to parse token for permissions: {str(e)}")
            return "read", []  # Safe fallback
    
    def _parse_jwt_payload(self, token: str) -> Dict[str, Any]:
        """
        Parse JWT token payload without signature verification.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded payload as dictionary
            
        Raises:
            ValueError: If token format is invalid
        """
        try:
            # Split token into parts
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("JWT token must have 3 parts separated by dots")
            
            # Decode payload (second part)
            payload_part = parts[1]
            
            # Add padding if needed for base64 decoding
            payload_part += '=' * (4 - len(payload_part) % 4)
            
            # Decode base64
            decoded_bytes = urlsafe_b64decode(payload_part)
            payload = json.loads(decoded_bytes.decode('utf-8'))
            
            return payload
            
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to parse JWT payload: {str(e)}")
    
    def validate_token_structure(self, token: str) -> bool:
        """
        Validate that token has correct JWT structure.
        
        Args:
            token: JWT token string
            
        Returns:
            True if token has valid structure, False otherwise
        """
        if not token or not isinstance(token, str):
            return False
        
        # Check basic JWT format (3 parts separated by dots)
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Check that each part is valid base64
        for part in parts:
            try:
                # Add padding and try to decode
                padded = part + '=' * (4 - len(part) % 4)
                urlsafe_b64decode(padded)
            except Exception:
                return False
        
        return True


# Convenience function for easy usage
def parse_okta_token_for_permissions(access_token: str, groups_claim: str = "groups") -> tuple[str, List[str]]:
    """
    Convenience function to parse Okta token and get permissions.
    
    Args:
        access_token: JWT access token from Okta
        groups_claim: Name of the groups claim in JWT (default: "groups")
        
    Returns:
        Tuple of (highest_permission_level, list_of_groups)
    """
    parser = OktaTokenParser(groups_claim=groups_claim)
    return parser.parse_token_for_permissions(access_token)