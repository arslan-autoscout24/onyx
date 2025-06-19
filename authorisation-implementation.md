# OAuth Authorization Implementation Plan - ENHANCED & SIMPLIFIED

## Executive Summary - Senior Architect Review

**ORIGINAL PLAN ASSESSMENT**: The junior developer's plan is comprehensive but overly complex for initial implementation. This enhanced version prioritizes Okta integration first and breaks the implementation into smaller, more manageable phases.

**KEY IMPROVEMENTS**:
- ✅ **Okta-First Approach**: Start with Okta as primary OAuth provider
- ✅ **Simplified Scope Model**: Reduce complexity by focusing on essential scopes
- ✅ **Incremental Implementation**: Smaller phases with clear deliverables
- ✅ **Leverage Existing Infrastructure**: Build on current FastAPI Users implementation
- ✅ **Backwards Compatibility**: Maintain existing auth while adding OAuth authorization

This document provides a simplified, practical approach to OAuth authorization in the Onyx backend system, starting with Okta integration and expanding incrementally.

## Current State Analysis - Architectural Review

### ✅ Strengths of Current Implementation

The existing FastAPI Users OAuth implementation is well-structured:

1. **Solid Foundation**: 
   - OIDC already supports Okta
   - OAuth callback handling in `users.py` is robust
   - Token refresh mechanism exists
   - Role-based auth provides fallback authorization

2. **Existing Okta Support**:
   - `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` already configured
   - JWT token handling via `fastapi-users[oauth]`
   - Callback URL: `/auth/oidc/callback` (works for Okta)

3. **Database Foundation**:
   - `OAuthAccount` model stores tokens
   - `UserRole` enum provides basic authorization
   - `User` model supports multiple auth methods

### 🔍 Gaps Analysis

**Critical Missing Elements**:
1. **OAuth Scope Enforcement**: Tokens stored but scopes not validated
2. **Group-Based Authorization**: Okta groups not mapped to permissions
3. **Resource-Level Permissions**: No granular access control
4. **Token Scope Validation**: No middleware to check OAuth scopes
5. **Dynamic Permission Updates**: No sync with Okta group changes

### Current Database Models - Analysis

```python
# ✅ GOOD: Existing User model has solid foundation
class User:
    - id: UUID
    - email: str
    - role: UserRole (LIMITED, BASIC, ADMIN, CURATOR, GLOBAL_CURATOR, etc.)
    - oauth_accounts: List[OAuthAccount]  # ✅ Ready for OAuth enhancement

# ✅ GOOD: OAuthAccount model stores tokens properly
class OAuthAccount:
    - oauth_name: str (oidc = Okta)
    - access_token: str  # ✅ Can extract scopes from this
    - expires_at: Optional[int]
    - refresh_token: Optional[str]
    - account_email: str

# ❌ MISSING: OAuth scope and permission models (to be added)
```

### 🎯 Simplified Scope Strategy

Instead of complex scope management, focus on **3 core authorization levels**:

1. **`read`** - View documents, chats, basic resources
2. **`write`** - Create/edit documents, chats, configurations  
3. **`admin`** - Full system access, user management, connectors

**Okta Group Mapping** (Simplified):
```
Okta Group → Application Permission
├── "Onyx-Admins" → admin (full access)
├── "Onyx-Writers" → write (create/edit content)
├── "Onyx-Readers" → read (view-only)
└── "Onyx-Viewers" → read (alias for readers)
```

## 🚀 SIMPLIFIED IMPLEMENTATION PLAN

### Phase 1: Okta OAuth Scope Foundation (Week 1-2)
**Goal**: Enable basic Okta group-based authorization

#### 1.1 Minimal Database Enhancement

**Add ONLY essential tables**:

```python
# Simple OAuth permission tracking
class OAuthPermission(SQLAlchemyBaseUserTable):
    """Track OAuth-granted permissions"""
    id: UUID
    user_id: UUID
    permission_level: str  # 'read', 'write', 'admin'
    granted_by: str  # 'okta_groups', 'manual'
    okta_groups: str  # JSON string of Okta groups
    granted_at: datetime
    is_active: bool = True
```

**Migration Strategy**:
- Single Alembic migration
- No disruption to existing auth
- Index on `user_id` and `permission_level`

#### 1.2 Okta JWT Token Parser

**New File**: `onyx/auth/okta_parser.py`

```python
import jwt
from typing import List, Optional, Dict

class OktaTokenParser:
    """Extract permissions from Okta JWT tokens"""
    
    def extract_groups_from_token(self, access_token: str) -> List[str]:
        """Extract Okta groups from JWT token"""
        try:
            # Decode without verification for now (add verification later)
            payload = jwt.decode(access_token, options={"verify_signature": False})
            return payload.get("groups", [])
        except Exception:
            return []
    
    def map_groups_to_permissions(self, groups: List[str]) -> str:
        """Map Okta groups to permission level"""
        group_mapping = {
            "Onyx-Admins": "admin",
            "Onyx-Writers": "write", 
            "Onyx-Readers": "read",
            "Onyx-Viewers": "read"
        }
        
        # Return highest permission level
        if any(group in group_mapping and group_mapping[group] == "admin" for group in groups):
            return "admin"
        elif any(group in group_mapping and group_mapping[group] == "write" for group in groups):
            return "write"
        else:
            return "read"
```

#### 1.3 Enhanced OAuth Callback

**File**: `onyx/auth/users.py` (Minimal Enhancement)

```python
# Add to existing OAuthUserManager class
async def oauth_callback(self, *args, **kwargs):
    """Enhanced callback with Okta group processing"""
    
    # Call existing callback logic
    user = await super().oauth_callback(*args, **kwargs)
    
    # Only process Okta tokens
    if kwargs.get('oauth_name') == 'oidc':  # Okta uses oidc
        access_token = kwargs.get('access_token')
        if access_token:
            await self._process_okta_groups(user, access_token)
    
    return user

async def _process_okta_groups(self, user: User, access_token: str):
    """Process Okta groups and grant permissions"""
    parser = OktaTokenParser()
    groups = parser.extract_groups_from_token(access_token)
    permission_level = parser.map_groups_to_permissions(groups)
    
    # Store/update OAuth permission
    await self._update_oauth_permission(user.id, permission_level, groups)
```

### Phase 2: Simple Authorization Middleware (Week 3)
**Goal**: Protect API endpoints with OAuth permissions

#### 2.1 Permission Checker

**File**: `onyx/server/auth_check.py` (Enhancement)

```python
# Add new permission dependencies
async def get_oauth_permission(user: User = Depends(current_user)) -> str:
    """Get user's OAuth permission level"""
    # Query OAuthPermission table
    permission = await db.get_oauth_permission(user.id)
    return permission.permission_level if permission else "read"

def require_permission(required_level: str):
    """Factory for permission-based dependencies"""
    
    async def permission_dependency(
        user: User = Depends(current_user),
        oauth_permission: str = Depends(get_oauth_permission)
    ) -> User:
        
        permission_hierarchy = {"read": 1, "write": 2, "admin": 3}
        
        user_level = permission_hierarchy.get(oauth_permission, 1)
        required_level_num = permission_hierarchy.get(required_level, 1)
        
        if user_level < required_level_num:
            raise HTTPException(
                status_code=403,
                detail=f"Requires '{required_level}' permission"
            )
        
        return user
    
    return permission_dependency

# Simple permission dependencies
require_read = require_permission("read")
require_write = require_permission("write") 
require_admin = require_permission("admin")
```

### Phase 3: API Protection (Week 4)
**Goal**: Apply permissions to key endpoints

#### 3.1 Document API Protection

```python
# onyx/server/documents/document.py
@router.get("/documents")
async def get_documents(
    user: User = Depends(require_read),  # ✅ Simple permission check
    # ... existing parameters
):
    """Get documents - requires read permission"""

@router.post("/documents") 
async def create_document(
    user: User = Depends(require_write),  # ✅ Requires write
    # ... existing parameters
):
    """Create document - requires write permission"""
```

#### 3.2 Admin API Protection

```python
# onyx/server/manage/connector.py
@router.post("/admin/connector")
async def create_connector(
    user: User = Depends(require_admin),  # ✅ Admin only
    # ... existing parameters
):
    """Create connector - admin permission required"""
```

### Phase 4: Okta Integration Testing (Week 5)
**Goal**: End-to-end Okta integration with group mapping

#### 4.1 Okta Configuration
```bash
# Environment variables for Okta
OIDC_CLIENT_ID=your_okta_client_id
OIDC_CLIENT_SECRET=your_okta_client_secret  
OIDC_WELL_KNOWN_URL=https://your-org.okta.com/oauth2/default/.well-known/openid-configuration

# Custom claims configuration
OKTA_GROUPS_CLAIM=groups
OKTA_TOKEN_VALIDATION=true
```

#### 4.2 Testing Strategy
1. **Test Okta Groups**: Create test groups in Okta
2. **Test Permission Mapping**: Verify group → permission mapping
3. **Test API Access**: Confirm endpoint protection works
4. **Test Token Refresh**: Ensure permissions persist

### Phase 5: Frontend Integration (Week 6)
**Goal**: Update UI to handle OAuth permissions

#### 5.1 Simple Permission Context

```typescript
// web/src/lib/auth.ts
export interface UserPermissions {
  level: 'read' | 'write' | 'admin';
  okta_groups?: string[];
}

export function usePermissions(): UserPermissions {
  // Fetch user's OAuth permissions
  const { data } = useSWR('/api/auth/permissions');
  return data || { level: 'read' };
}
```

#### 5.2 Permission-Based UI Components

```tsx
// web/src/components/PermissionGate.tsx
interface PermissionGateProps {
  required: 'read' | 'write' | 'admin';
  children: React.ReactNode;
}

export function PermissionGate({ required, children }: PermissionGateProps) {
  const { level } = usePermissions();
  
  const hierarchy = { read: 1, write: 2, admin: 3 };
  
  if (hierarchy[level] >= hierarchy[required]) {
    return <>{children}</>;
  }
  
  return null; // Hide content if insufficient permission
}
```
```

**Migration Strategy**:
- Create new Alembic migration for scope-related tables
- Add indexes for performance on user_id, oauth_account_id, and resource queries
- Ensure backward compatibility with existing role-based permissions

#### 1.2 OAuth Configuration Updates

**File**: `onyx/configs/app_configs.py`

```python
# New OAuth scope configurations
OAUTH_SCOPES_CONFIG = {
    "google": {
        "default_scopes": ["read:documents", "read:chats"],
        "available_scopes": ["read:documents", "write:documents", "read:chats", "write:chats", "admin:connectors"],
        "scope_mapping": {
            "https://www.googleapis.com/auth/userinfo.email": "read:profile",
            "https://www.googleapis.com/auth/userinfo.profile": "read:profile"
        }
    },
    "oidc": {
        "scope_claim": "scope",  # JWT claim containing scopes
        "default_scopes": ["read:documents"],
        "scope_separator": " "
    },
    "okta": {
        "scope_claim": "scp",  # Okta uses 'scp' claim for scopes
        "default_scopes": ["read:documents", "read:chats"],
        "available_scopes": ["read:documents", "write:documents", "read:chats", "write:chats", "admin:connectors"],
        "scope_separator": " ",
        "custom_claims": {
            "groups_claim": "groups",  # Okta groups for role mapping
            "department_claim": "department"
        },
        "scope_mapping": {
            "openid": "read:profile",
            "profile": "read:profile",
            "email": "read:profile",
            "groups": "read:groups"
        }
    }
}
```

### Phase 2: Core Authorization Framework

#### 2.1 OAuth Scope Manager

**New File**: `onyx/auth/oauth_scopes.py`

```python
class OAuthScopeManager:
    """Manages OAuth scope validation and enforcement"""
    
    async def validate_token_scopes(self, oauth_account: OAuthAccount) -> List[str]:
        """Validate and return active scopes for an OAuth token"""
    
    async def check_scope_permission(self, user: User, required_scope: str, resource_id: Optional[UUID] = None) -> bool:
        """Check if user has required scope for resource access"""
    
    async def grant_scopes_to_user(self, user: User, oauth_account: OAuthAccount, scopes: List[str]) -> None:
        """Grant OAuth scopes to user based on OAuth provider response"""
    
    async def revoke_expired_scopes(self) -> None:
        """Background task to revoke expired OAuth scopes"""
    
    async def sync_oauth_scopes(self, oauth_account: OAuthAccount) -> None:
        """Sync scopes with OAuth provider (for token refresh scenarios)"""
    
    async def extract_okta_scopes(self, id_token: str, access_token: str) -> List[str]:
        """Extract and map Okta scopes from JWT tokens"""
        # Decode JWT tokens to extract scope claims
        # Map Okta groups to application scopes
        # Handle custom claims for enhanced authorization
    
    async def validate_okta_groups(self, user: User, required_groups: List[str]) -> bool:
        """Validate user's Okta group membership for authorization"""
```

#### 2.2 Enhanced Authorization Dependency

**File**: `onyx/server/auth_check.py` (Enhancement)

```python
# New OAuth scope-based dependencies
def require_oauth_scope(required_scope: str, resource_param: Optional[str] = None):
    """Dependency factory for OAuth scope-based authorization"""
    
    async def oauth_scope_dependency(
        user: User = Depends(current_user),
        request: Request = None,
        scope_manager: OAuthScopeManager = Depends(get_scope_manager)
    ) -> User:
        # Extract resource ID from request if specified
        resource_id = None
        if resource_param and request:
            resource_id = request.path_params.get(resource_param)
        
        # Check OAuth scope permission
        has_permission = await scope_manager.check_scope_permission(
            user, required_scope, resource_id
        )
        
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient OAuth scope: {required_scope} required"
            )
        
        return user
    
    return oauth_scope_dependency

# Convenience functions for common scopes
require_read_documents = require_oauth_scope("read:documents", "document_id")
require_write_documents = require_oauth_scope("write:documents", "document_id")
require_read_chats = require_oauth_scope("read:chats", "chat_session_id")
require_write_chats = require_oauth_scope("write:chats", "chat_session_id")
require_admin_connectors = require_oauth_scope("admin:connectors", "connector_id")
```

### Phase 3: OAuth Provider Integration

#### 3.1 Enhanced OAuth Callback Handling

**File**: `onyx/auth/users.py` (Enhancement)

```python
class OAuthUserManager(BaseUserManager[User, UUID]):
    """Enhanced OAuth user manager with scope handling"""
    
    async def oauth_callback(
        self,
        oauth_name: str,
        access_token: str,
        account_id: str,
        account_email: str,
        expires_at: Optional[int] = None,
        refresh_token: Optional[str] = None,
        request: Optional[Request] = None,
        associate_by_email: bool = False,
        is_verified_by_default: bool = False,
        oauth_scopes: Optional[List[str]] = None,  # New parameter
    ) -> User:
        """Enhanced OAuth callback with scope processing"""
        
        # Existing user creation/update logic...
        
        # Process OAuth scopes
        if oauth_scopes:
            scope_manager = get_scope_manager()
            await scope_manager.grant_scopes_to_user(user, oauth_account, oauth_scopes)
        
        return user
```

#### 3.2 Okta-Specific Integration

**New File**: `onyx/auth/okta_integration.py`

```python
import jwt
from typing import Dict, List, Optional
from onyx.configs.app_configs import OAUTH_SCOPES_CONFIG

class OktaIntegration:
    """Okta-specific OAuth integration handler"""
    
    async def process_okta_callback(
        self,
        id_token: str,
        access_token: str,
        user: User,
        oauth_account: OAuthAccount
    ) -> None:
        """Process Okta OAuth callback with custom claims"""
        
        # Decode ID token to extract claims
        id_claims = jwt.decode(id_token, options={"verify_signature": False})
        access_claims = jwt.decode(access_token, options={"verify_signature": False})
        
        # Extract Okta groups
        groups = id_claims.get("groups", [])
        department = id_claims.get("department")
        
        # Map Okta groups to application scopes
        mapped_scopes = await self._map_okta_groups_to_scopes(groups)
        
        # Grant scopes based on Okta groups and claims
        scope_manager = get_scope_manager()
        await scope_manager.grant_scopes_to_user(user, oauth_account, mapped_scopes)
        
        # Store additional Okta metadata
        await self._store_okta_metadata(user, groups, department)
    
    async def _map_okta_groups_to_scopes(self, groups: List[str]) -> List[str]:
        """Map Okta groups to application scopes"""
        scope_mapping = {
## ⚡ QUICK WINS & IMMEDIATE IMPROVEMENTS

### 🔧 Phase 0: Immediate Setup (Day 1-2)
**Goal**: Prepare for Okta OAuth authorization

#### 0.1 Okta Application Configuration
```bash
# Required Okta settings (add to environment)
OKTA_DOMAIN=your-org.okta.com
OKTA_CLIENT_ID=your_okta_app_client_id
OKTA_CLIENT_SECRET=your_okta_app_client_secret
OKTA_GROUPS_CLAIM=groups  # Custom claim for groups
```

#### 0.2 Test Okta Groups
Create these groups in Okta admin:
- `Onyx-Admins` (full access)
- `Onyx-Writers` (read/write)  
- `Onyx-Readers` (read-only)

#### 0.3 Verify Current OIDC Integration
Test existing OIDC callback: `/auth/oidc/callback`

### 📊 Success Metrics & Monitoring

#### Key Success Indicators
1. **Zero Auth Bypass**: No unauthorized access to protected endpoints
2. **Okta Group Sync**: Groups properly mapped to permissions 
3. **Performance**: <100ms overhead for permission checks
4. **User Experience**: Seamless login with appropriate access

#### Monitoring Dashboard
```python
# Add to existing monitoring
OAUTH_METRICS = {
    "okta_login_success_rate": 0.99,
    "permission_check_latency_ms": 50,
    "group_mapping_failures": 0,
    "unauthorized_access_attempts": 0
}
```

## 🔒 Security Considerations - Simplified

### 1. Token Security ✅
- **Current**: Tokens encrypted in DB
- **Enhanced**: Add JWT signature verification
- **Okta**: Use Okta's token introspection endpoint

### 2. Permission Validation ✅  
- **Strategy**: Check permissions on every API request
- **Caching**: Cache permissions for 5 minutes
- **Fallback**: Default to `read` permission if unclear

### 3. Group Sync Security ✅
- **Frequency**: Sync on login and token refresh
- **Validation**: Verify Okta JWT signatures
- **Audit**: Log all permission changes

## 📅 REVISED TIMELINE - Manageable Phases

| Phase | Duration | Deliverable | Dependencies |
|-------|----------|-------------|--------------|
| **Phase 0** | 2 days | Okta setup & testing | Okta admin access |
| **Phase 1** | 1 week | Basic permission model | Database migration |
| **Phase 2** | 3 days | Permission middleware | Phase 1 complete |
| **Phase 3** | 4 days | API endpoint protection | Phase 2 complete |
| **Phase 4** | 1 week | End-to-end testing | All phases |
| **Phase 5** | 1 week | Frontend integration | UI development |

**Total Time**: ~4 weeks vs. original 12 weeks

## 🎯 Critical Architectural Decisions

### 1. ✅ Keep It Simple
- **3 permission levels** instead of complex scopes
- **Group-based** instead of individual scope assignment
- **JWT token parsing** instead of external API calls

### 2. ✅ Backwards Compatibility
- **Existing UserRole** remains functional
- **OAuth permissions** enhance, don't replace
- **Gradual migration** of endpoints

### 3. ✅ Okta-First Approach
- **Start with Okta** as primary OAuth provider
- **Expand later** to Google, other OIDC providers
- **Group mapping** as primary authorization mechanism

### 4. ✅ Performance Focus
- **In-memory permission caching**
- **Minimal database queries**
- **Fast JWT token parsing**

## 🚨 Risk Mitigation

### High-Risk Areas & Solutions

1. **Risk**: Complex OAuth scope management
   **Solution**: Simplified 3-level permission model

2. **Risk**: Performance impact of permission checks  
   **Solution**: Caching + optimized database queries

3. **Risk**: Okta group changes not reflected
   **Solution**: Token refresh triggers permission sync

4. **Risk**: Authentication bypass
   **Solution**: Default deny + comprehensive testing

## 📝 Implementation Checklist

### Phase 1 Tasks
- [ ] Create `OAuthPermission` database model
- [ ] Write Alembic migration script  
- [ ] Implement `OktaTokenParser` class
- [ ] Enhance OAuth callback in `users.py`
- [ ] Add unit tests for group mapping

### Phase 2 Tasks
- [ ] Create permission dependency functions
- [ ] Add permission caching mechanism
- [ ] Implement fallback to existing roles
- [ ] Add error handling for invalid tokens

### Phase 3 Tasks  
- [ ] Protect document API endpoints
- [ ] Protect chat API endpoints
- [ ] Protect admin/connector endpoints
- [ ] Add API endpoint test coverage

### Phase 4 Tasks
- [ ] End-to-end Okta integration test
- [ ] Performance testing under load
- [ ] Security penetration testing  
- [ ] User acceptance testing

### Phase 5 Tasks
- [ ] Frontend permission context
- [ ] Permission-based UI components
- [ ] User permission management page
- [ ] Documentation updates

## 🎓 LESSONS LEARNED FROM ORIGINAL PLAN

### ❌ What Was Overly Complex
1. **Too many database models** - 3+ new tables vs. 1 simple table
2. **Complex scope hierarchy** - Dozens of scopes vs. 3 permission levels  
3. **Multiple OAuth providers** - Start simple with Okta only
4. **Resource-level permissions** - Add later if needed
5. **Extensive frontend changes** - Minimal UI changes initially

### ✅ What Was Good
1. **OAuth callback enhancement** - Build on existing FastAPI Users
2. **Security considerations** - Keep all security requirements
3. **Backwards compatibility** - Essential for production
4. **Testing strategy** - Comprehensive testing still needed
5. **Monitoring approach** - Track metrics from day one

## 🏆 CONCLUSION - Enhanced Implementation Strategy

This simplified approach delivers **80% of the value with 30% of the complexity**:

**✅ Immediate Benefits**:
- Okta group-based authorization working in 4 weeks
- Simple permission model that's easy to understand
- Minimal disruption to existing authentication
- Clear path for future enhancements

**🔮 Future Expansion Path**:
- Add Google OAuth group mapping
- Implement resource-level permissions  
- Add more granular scopes if needed
- Enhanced audit logging and compliance features

**🎯 Success Criteria**:
- Okta users get appropriate permissions based on groups
- API endpoints properly protected
- Zero security incidents
- Development team can maintain and extend easily

This enhanced plan provides a **practical, implementable solution** that delivers OAuth authorization capabilities quickly while maintaining the flexibility to expand in the future.

---

*Enhanced by Senior Architect - Focus on simplicity, Okta-first approach, and manageable implementation phases*
