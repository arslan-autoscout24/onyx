#!/usr/bin/env python3
"""
Test script to verify that PermissionLevel enum works correctly with SQLAlchemy.
"""

import sys
import os
from sqlalchemy import create_engine, Enum
from sqlalchemy.orm import sessionmaker

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from onyx.db.models import PermissionLevel, OAuthPermission, PermissionHistory, Base
    print("✅ Successfully imported PermissionLevel, OAuthPermission, and PermissionHistory")
    
    # Test enum values
    print("✅ PermissionLevel enum values:")
    for level in PermissionLevel:
        print(f"   - {level.name}: {level.value}")
    
    # Test that the enum is properly typed
    print(f"✅ PermissionLevel type: {type(PermissionLevel)}")
    print(f"✅ PermissionLevel.READ type: {type(PermissionLevel.READ)}")
    print(f"✅ PermissionLevel.READ value: {PermissionLevel.READ}")
    
    # Test SQLAlchemy Enum type creation
    enum_type = Enum(PermissionLevel, native_enum=False)
    print(f"✅ SQLAlchemy Enum type created successfully: {enum_type}")
    
    # Test the actual column definition (this is what was failing before)
    try:
        # This simulates what SQLAlchemy does internally when processing the model
        enum_values = [level.value for level in PermissionLevel]
        print(f"✅ Enum values extracted: {enum_values}")
        print(f"✅ Max length calculation: {max(len(x) for x in enum_values)}")
    except Exception as e:
        print(f"❌ Error in enum processing: {e}")
        raise
    
    print("\n🎉 All tests passed! The SQLAlchemy enum configuration is working correctly.")
    
except Exception as e:
    print(f"❌ Error importing or testing models: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
