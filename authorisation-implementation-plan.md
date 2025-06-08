# OAuth Authorization Implementation Plan - MOVED TO INDIVIDUAL STORIES

## 🚨 IMPORTANT NOTICE

**This plan has been split into individual developer stories for better implementation.**

**For Development Work**: Go to the `stories/` directory and follow the individual story files:

📁 **stories/**
- `story-1.1-oauth-permission-schema.md` - Database schema for OAuth permissions
- `story-1.2-okta-jwt-token-parser.md` - Okta JWT token validation and parsing  
- `story-1.3-oauth-permission-database-operations.md` - CRUD operations for permissions
- `story-2.1-enhanced-oauth-callback-handler.md` - Enhanced OAuth callback processing
- `story-2.2-permission-retrieval-service.md` - Permission lookup and caching service
- `story-3.1-permission-dependencies.md` - OAuth permission middleware integration
- `story-3.2-document-api-protection.md` - Document API endpoint security
- `story-3.3-chat-api-protection.md` - Chat API and WebSocket security
- `story-4.1-admin-api-protection.md` - Admin API security with audit logging
- `story-4.2-okta-configuration-setup.md` - Okta environment configuration
- `story-4.3-end-to-end-integration-testing.md` - Comprehensive E2E testing
- `story-4.4-permission-management-api.md` - Permission management API
- `story-4.5-basic-frontend-permission-context.md` - React permission context

## 📖 Quick Navigation

- **Master Overview**: `authorisation-implementation-plan-summary.md` - High-level project overview
- **Story Directory**: `stories/README.md` - Complete story listing with progress tracking
- **Individual Stories**: `stories/story-*.md` - Detailed implementation guides

## 🎯 Why Individual Stories?

Each story now contains:
- ✅ **Comprehensive Implementation** - 200-400 lines of complete code examples
- ✅ **Detailed Testing** - Unit and integration tests with 95%+ coverage targets
- ✅ **Security Considerations** - Access control and audit logging requirements
- ✅ **Performance Requirements** - Specific metrics and optimization targets
- ✅ **Deployment Procedures** - Step-by-step deployment and rollback plans
- ✅ **Definition of Done** - Clear completion criteria with deliverables

## 🚀 Getting Started

1. Read `stories/README.md` for an overview
2. Start with `stories/story-1.1-oauth-permission-schema.md`
3. Follow the acceptance criteria and implementation guidance
4. Use the testing requirements to validate your work
5. Update progress in the story README as you complete each story

---

*For the original detailed plan content, refer to the individual story files which contain enhanced versions of each story with complete implementation details.*

#### **Story 1.2: Okta JWT Token Parser**
**Priority**: P0 - Critical Foundation  
**Estimate**: 1.5 days  
**Dependencies**: None

**Description**: Create utility to extract Okta groups from JWT tokens and map them to application permission levels.

**Acceptance Criteria**:
- [ ] New `OktaTokenParser` class in `backend/onyx/auth/okta_parser.py`
- [ ] Method to extract groups from Okta JWT tokens (without signature verification initially)
- [ ] Group-to-permission mapping logic: Onyx-Admins→admin, Onyx-Writers→write, etc.
- [ ] Returns highest permission level when user has multiple groups
- [ ] Comprehensive unit tests with sample JWT tokens
- [ ] Error handling for malformed tokens

**Technical Implementation**:
```python
# File: backend/onyx/auth/okta_parser.py (new file)
class OktaTokenParser:
    GROUP_MAPPING = {
        "Onyx-Admins": "admin",
        "Onyx-Writers": "write", 
        "Onyx-Readers": "read",
        "Onyx-Viewers": "read"
    }
    
    def extract_groups_from_token(self, access_token: str) -> List[str]
    def map_groups_to_permissions(self, groups: List[str]) -> str
    def get_highest_permission_level(self, permissions: List[str]) -> str
```

**Deployment Test**:
- Test with sample Okta JWT tokens
- Verify group extraction and permission mapping
- Confirm graceful handling of invalid tokens

---

#### **Story 1.3: OAuth Permission Database Operations**
**Priority**: P0 - Critical Foundation  
**Estimate**: 1 day  
**Dependencies**: Story 1.1

**Description**: Create database operations to manage OAuth permissions.

**Acceptance Criteria**:
- [ ] CRUD operations for `OAuthPermission` model
- [ ] Method to get user's current permission level
- [ ] Method to update/create user's OAuth permissions
- [ ] Method to deactivate expired permissions
- [ ] Unit tests for all database operations
- [ ] Performance optimized queries with proper indexing

**Technical Implementation**:
```python
# File: backend/onyx/db/oauth_permissions.py (new file)
async def get_user_oauth_permission(user_id: UUID) -> Optional[OAuthPermission]
async def update_user_oauth_permission(user_id: UUID, permission_level: str, okta_groups: List[str]) -> OAuthPermission
async def deactivate_user_oauth_permissions(user_id: UUID) -> None
async def get_users_by_permission_level(permission_level: str) -> List[UUID]
```

**Deployment Test**:
- Test database operations with sample data
- Verify query performance
- Confirm data integrity

---

### **Sprint 2: OAuth Callback Enhancement (Week 2)**
*Goal: Process Okta groups during OAuth login and store permissions*

#### **Story 2.1: Enhanced OAuth Callback Handler**
**Priority**: P0 - Critical  
**Estimate**: 2 days  
**Dependencies**: Stories 1.1, 1.2, 1.3

**Description**: Enhance existing OAuth callback to process Okta groups and grant permissions.

**Acceptance Criteria**:
- [ ] Enhanced `oauth_callback` method in `OAuthUserManager`
- [ ] Okta group processing only triggered for OIDC provider
- [ ] Permission granted/updated based on Okta groups in JWT token
- [ ] Backwards compatible with existing OAuth flow
- [ ] Error handling for token parsing failures
- [ ] Integration tests with mock Okta responses

**Technical Implementation**:
```python
# File: backend/onyx/auth/users.py (enhancement)
async def oauth_callback(self, *args, **kwargs):
    # Existing callback logic
    user = await super().oauth_callback(*args, **kwargs)
    
    # Process Okta groups for OIDC provider
    if kwargs.get('oauth_name') == 'oidc':
        await self._process_okta_groups(user, kwargs.get('access_token'))
    
    return user

async def _process_okta_groups(self, user: User, access_token: str):
    # Extract groups and update permissions
```

**Deployment Test**:
- Test OAuth login with Okta
- Verify permissions are stored correctly
- Confirm existing OAuth providers still work

---

#### **Story 2.2: Permission Retrieval Service**
**Priority**: P1 - High  
**Estimate**: 1 day  
**Dependencies**: Story 2.1

**Description**: Create service to retrieve user's current OAuth permissions with caching.

**Acceptance Criteria**:
- [ ] Service to get user's current permission level
- [ ] In-memory caching for 5 minutes to improve performance
- [ ] Fallback to 'read' permission if no OAuth permission found
- [ ] Method to invalidate cache when permissions change
- [ ] Unit tests for caching behavior

**Technical Implementation**:
```python
# File: backend/onyx/auth/permission_service.py (new file)
class PermissionService:
    def __init__(self):
        self._cache = {}  # Simple in-memory cache
    
    async def get_user_permission_level(self, user_id: UUID) -> str
    def invalidate_user_cache(self, user_id: UUID) -> None
    def _is_cache_valid(self, cached_time: datetime) -> bool
```

**Deployment Test**:
- Test permission retrieval for various users
- Verify caching behavior
- Test cache invalidation

---

### **Sprint 3: Authorization Middleware (Week 3)**
*Goal: Implement permission checking middleware for API endpoints*

#### **Story 3.1: Permission Dependency Functions**
**Priority**: P0 - Critical  
**Estimate**: 2 days  
**Dependencies**: Story 2.2

**Description**: Create FastAPI dependencies for OAuth permission checking.

**Acceptance Criteria**:
- [ ] Permission dependency factory `require_permission(level)`
- [ ] Specific dependencies: `require_read`, `require_write`, `require_admin`
- [ ] Integration with existing `current_user` dependency
- [ ] Proper HTTP 403 responses for insufficient permissions
- [ ] Permission hierarchy enforcement (admin > write > read)
- [ ] Unit tests for all permission levels

**Technical Implementation**:
```python
# File: backend/onyx/server/auth_check.py (enhancement)
async def get_oauth_permission(user: User = Depends(current_user)) -> str:
    # Get user's OAuth permission level

def require_permission(required_level: str):
    async def permission_dependency(user: User = Depends(current_user)) -> User:
        # Check permission and raise 403 if insufficient
    return permission_dependency

require_read = require_permission("read")
require_write = require_permission("write") 
require_admin = require_permission("admin")
```

**Deployment Test**:
- Test permission dependencies with different user types
- Verify HTTP 403 responses for unauthorized access
- Confirm backwards compatibility

---

#### **Story 3.2: Document API Permission Protection**
**Priority**: P1 - High  
**Estimate**: 1.5 days  
**Dependencies**: Story 3.1

**Description**: Apply OAuth permissions to document-related API endpoints.

**Acceptance Criteria**:
- [ ] GET `/documents` requires `read` permission
- [ ] POST `/documents` requires `write` permission  
- [ ] PUT/PATCH `/documents/{id}` requires `write` permission
- [ ] DELETE `/documents/{id}` requires `write` permission
- [ ] All endpoints return proper 403 errors for insufficient permissions
- [ ] Integration tests for each protected endpoint

**Technical Implementation**:
```python
# File: backend/onyx/server/documents/document.py (enhancement)
@router.get("/documents")
async def get_documents(user: User = Depends(require_read)):
    # Existing implementation

@router.post("/documents") 
async def create_document(user: User = Depends(require_write)):
    # Existing implementation
```

**Deployment Test**:
- Test document operations with different permission levels
- Verify unauthorized users cannot access protected endpoints
- Confirm authorized users can perform allowed operations

---

#### **Story 3.3: Chat API Permission Protection**
**Priority**: P1 - High  
**Estimate**: 1 day  
**Dependencies**: Story 3.1

**Description**: Apply OAuth permissions to chat-related API endpoints.

**Acceptance Criteria**:
- [ ] GET `/chat-sessions` requires `read` permission
- [ ] POST `/chat-sessions` requires `write` permission
- [ ] Chat message endpoints require appropriate permissions
- [ ] Integration tests for chat permission enforcement

**Technical Implementation**:
```python
# File: backend/onyx/server/chat/chat_session.py (enhancement)
@router.get("/chat-sessions")
async def get_chat_sessions(user: User = Depends(require_read)):
    # Existing implementation

@router.post("/chat-sessions")
async def create_chat_session(user: User = Depends(require_write)):
    # Existing implementation
```

**Deployment Test**:
- Test chat operations with different permission levels
- Verify proper access control enforcement

---

### **Sprint 4: Admin Protection & Testing (Week 4)**
*Goal: Protect admin endpoints and comprehensive testing*

#### **Story 4.1: Admin API Permission Protection**
**Priority**: P0 - Critical  
**Estimate**: 1.5 days  
**Dependencies**: Story 3.1

**Description**: Apply admin-level OAuth permissions to administrative endpoints.

**Acceptance Criteria**:
- [ ] Connector management endpoints require `admin` permission
- [ ] User management endpoints require `admin` permission
- [ ] System configuration endpoints require `admin` permission
- [ ] All admin endpoints return 403 for non-admin users
- [ ] Integration tests for admin endpoint protection

**Technical Implementation**:
```python
# File: backend/onyx/server/manage/connector.py (enhancement)
@router.post("/admin/connector")
async def create_connector(user: User = Depends(require_admin)):
    # Existing implementation

# File: backend/onyx/server/manage/users.py (enhancement)
@router.get("/admin/users")
async def get_users(user: User = Depends(require_admin)):
    # Existing implementation
```

**Deployment Test**:
- Test admin operations with admin users
- Verify non-admin users cannot access admin endpoints
- Confirm proper error responses

---

#### **Story 4.2: Okta Configuration and Environment Setup**
**Priority**: P1 - High  
**Estimate**: 1 day  
**Dependencies**: None

**Description**: Set up Okta configuration and environment variables for OAuth integration.

**Acceptance Criteria**:
- [ ] Environment variables for Okta configuration
- [ ] Okta application configured with correct redirect URIs
- [ ] Test Okta groups created: Onyx-Admins, Onyx-Writers, Onyx-Readers
- [ ] Okta JWT token includes groups claim
- [ ] Documentation for Okta setup process

**Technical Implementation**:
```bash
# Environment variables
OKTA_DOMAIN=your-org.okta.com
OKTA_CLIENT_ID=your_okta_app_client_id
OKTA_CLIENT_SECRET=your_okta_app_client_secret
OKTA_GROUPS_CLAIM=groups
OIDC_WELL_KNOWN_URL=https://your-org.okta.com/oauth2/default/.well-known/openid-configuration
```

**Deployment Test**:
- Test OAuth login with Okta
- Verify groups are included in JWT tokens
- Confirm environment variables are properly configured

---

#### **Story 4.3: End-to-End Integration Testing**
**Priority**: P0 - Critical  
**Estimate**: 2 days  
**Dependencies**: All previous stories

**Description**: Comprehensive testing of the complete OAuth authorization flow.

**Acceptance Criteria**:
- [ ] End-to-end test: Okta login → permission assignment → API access
- [ ] Test all permission levels: read, write, admin
- [ ] Test permission enforcement across all protected endpoints
- [ ] Performance testing: permission checks under load
- [ ] Security testing: attempt to bypass permissions
- [ ] Test data cleanup and reset procedures

**Technical Implementation**:
```python
# File: backend/tests/integration/test_oauth_authorization.py (new file)
class TestOAuthAuthorization:
    async def test_okta_login_grants_permissions(self)
    async def test_permission_enforcement_on_documents(self)
    async def test_permission_enforcement_on_chat(self)
    async def test_admin_permission_enforcement(self)
    async def test_permission_caching_performance(self)
```

**Deployment Test**:
- Run full test suite
- Verify all tests pass
- Confirm no regression in existing functionality

---

#### **Story 4.4: Permission Management API**
**Priority**: P2 - Medium  
**Estimate**: 1.5 days  
**Dependencies**: Story 4.1

**Description**: Create API endpoints for viewing and managing user permissions.

**Acceptance Criteria**:
- [ ] GET `/auth/permissions` - view current user's permissions
- [ ] GET `/admin/users/{id}/permissions` - admin view of user permissions
- [ ] API responses include permission level and Okta groups
- [ ] Admin can view all users and their permission levels
- [ ] Integration tests for permission management endpoints

**Technical Implementation**:
```python
# File: backend/onyx/server/auth/permissions.py (new file)
@router.get("/auth/permissions")
async def get_current_user_permissions(user: User = Depends(current_user)):
    # Return current user's OAuth permissions

@router.get("/admin/users/{user_id}/permissions")
async def get_user_permissions(user_id: UUID, admin: User = Depends(require_admin)):
    # Return specific user's permissions (admin only)
```

**Deployment Test**:
- Test permission viewing endpoints
- Verify admin-only access for user management
- Confirm proper permission data is returned

---

#### **Story 4.5: Basic Frontend Permission Context**
**Priority**: P2 - Medium  
**Estimate**: 2 days  
**Dependencies**: Story 4.4

**Description**: Add basic frontend integration for OAuth permissions.

**Acceptance Criteria**:
- [ ] Permission context in React application
- [ ] Hook to fetch current user's permissions
- [ ] Basic permission-gated UI components
- [ ] Hide/show elements based on user permissions
- [ ] Integration with existing authentication state

**Technical Implementation**:
```typescript
// File: web/src/lib/permissions.ts (new file)
export interface UserPermissions {
  level: 'read' | 'write' | 'admin';
  okta_groups?: string[];
}

export function usePermissions(): UserPermissions {
  // Fetch and return user permissions
}

// File: web/src/components/PermissionGate.tsx (new file)
interface PermissionGateProps {
  required: 'read' | 'write' | 'admin';
  children: React.ReactNode;
}
```

**Deployment Test**:
- Test permission context in frontend
- Verify UI elements show/hide correctly
- Confirm integration with backend API

---

## 🚀 Deployment Strategy

### **Release Phases**

#### **Phase 1: Foundation (Stories 1.1-1.3)**
- **Goal**: Database and core utilities ready
- **Risk**: Low - No user-facing changes
- **Rollback**: Simple database migration rollback

#### **Phase 2: OAuth Enhancement (Stories 2.1-2.2)**  
- **Goal**: Okta login grants permissions
- **Risk**: Medium - Changes OAuth flow
- **Rollback**: Feature flag to disable OAuth permission processing

#### **Phase 3: API Protection (Stories 3.1-3.3)**
- **Goal**: API endpoints protected by permissions
- **Risk**: High - Could break existing access
- **Rollback**: Feature flag to bypass permission checks

#### **Phase 4: Complete Integration (Stories 4.1-4.5)**
- **Goal**: Full OAuth authorization system
- **Risk**: Medium - Complete feature rollout
- **Rollback**: Comprehensive feature flag system

### **Feature Flags**

```python
# Configuration for gradual rollout
OAUTH_PERMISSIONS_ENABLED = env.bool("OAUTH_PERMISSIONS_ENABLED", default=False)
OAUTH_PERMISSION_ENFORCEMENT = env.bool("OAUTH_PERMISSION_ENFORCEMENT", default=False)
OKTA_GROUP_PROCESSING = env.bool("OKTA_GROUP_PROCESSING", default=False)
```

### **Monitoring & Alerts**

```python
# Key metrics to monitor
OAUTH_METRICS = {
    "permission_check_latency_ms": "< 100ms",
    "okta_login_success_rate": "> 99%",
    "permission_cache_hit_rate": "> 90%",
    "unauthorized_access_attempts": "= 0"
}
```

## 📊 Success Criteria

### **Story-Level Success**
- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] No breaking changes to existing functionality
- [ ] Performance requirements met
- [ ] Security requirements satisfied

### **Sprint-Level Success**
- [ ] End-to-end flow works correctly
- [ ] All protected endpoints properly secured
- [ ] Okta integration functional
- [ ] User experience seamless

### **Project-Level Success**
- [ ] Okta users get appropriate permissions based on groups
- [ ] Zero security incidents or bypasses
- [ ] Performance impact < 100ms per request
- [ ] System can handle current user load
- [ ] Documentation complete and accurate

## 🔧 Development Guidelines

### **Code Standards**
- Follow existing FastAPI patterns
- Maintain backwards compatibility
- Include comprehensive error handling
- Add detailed logging for debugging
- Write unit tests for all new code

### **Testing Requirements**
- Unit tests for all business logic
- Integration tests for API endpoints
- End-to-end tests for complete flows
- Performance tests for permission checks
- Security tests for authorization bypass attempts

### **Documentation Requirements**
- API documentation updates
- Configuration documentation
- Deployment guide updates
- Troubleshooting guide
- Developer setup instructions

---

## 📝 Story Template

### **Story X.X: [Title]**
**Priority**: P0/P1/P2  
**Estimate**: X days  
**Dependencies**: [List of dependent stories]

**Description**: [What needs to be built]

**Acceptance Criteria**:
- [ ] [Specific, testable requirement]
- [ ] [Another requirement]

**Technical Implementation**:
```python
# Code examples and key files
```

**Deployment Test**:
- [How to verify the story works in deployment]

---

*This implementation plan ensures each story is independently deployable and testable, reducing risk and enabling faster feedback cycles.*
