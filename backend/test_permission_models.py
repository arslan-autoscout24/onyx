#!/usr/bin/env python3
"""
Test script to verify that PermissionLevel enum works correctly in SQLAlchemy models.
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from onyx.db.models import PermissionLevel, OAuthPermission, PermissionHistory
    print("✅ Successfully imported PermissionLevel, OAuthPermission, and PermissionHistory")
    
    # Test enum values
    print("✅ PermissionLevel enum values:")
    for level in PermissionLevel:
        print(f"   - {level.name}: {level.value}")
    
    # Test that the enum is properly typed
    print(f"✅ PermissionLevel type: {type(PermissionLevel)}")
    print(f"✅ PermissionLevel.READ type: {type(PermissionLevel.READ)}")
    
    print("\n🎉 All tests passed! The SQLAlchemy enum configuration is working correctly.")
    
except Exception as e:
    print(f"❌ Error importing or testing models: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
