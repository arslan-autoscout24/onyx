# Story 4.5: Basic Frontend Permission Context

**Priority**: P2 - Medium  
**Estimate**: 2 days  
**Dependencies**: Story 4.4 (Permission Management API)  
**Sprint**: 4 - Admin Protection & Testing

## Description

Add basic frontend integration for OAuth permissions, providing React components and hooks to manage permission-based UI rendering and user experience.

## Acceptance Criteria

- [ ] Permission context in React application
- [ ] Hook to fetch current user's permissions
- [ ] Basic permission-gated UI components
- [ ] Hide/show elements based on user permissions
- [ ] Integration with existing authentication state
- [ ] Loading states for permission checks
- [ ] Error handling for permission failures
- [ ] TypeScript support for permission types

## Technical Implementation

### Core Permission System

#### 1. Permission Types and Context
```typescript
// File: web/src/lib/permissions.ts
export enum PermissionLevel {
  READ = 'read',
  WRITE = 'write',
  ADMIN = 'admin'
}

export interface UserPermissions {
  userId: string;
  email: string;
  permissionLevel: PermissionLevel;
  oktaGroups: string[];
  grantedAt: string;
  lastUpdated: string;
  source: string;
  isActive: boolean;
}

export interface PermissionContextType {
  permissions: UserPermissions | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  hasPermission: (required: PermissionLevel) => boolean;
  hasAnyPermission: (required: PermissionLevel[]) => boolean;
}

// Permission hierarchy for checking
const PERMISSION_HIERARCHY: Record<PermissionLevel, number> = {
  [PermissionLevel.READ]: 1,
  [PermissionLevel.WRITE]: 2,
  [PermissionLevel.ADMIN]: 3
};

export function hasPermissionLevel(
  userLevel: PermissionLevel,
  requiredLevel: PermissionLevel
): boolean {
  return PERMISSION_HIERARCHY[userLevel] >= PERMISSION_HIERARCHY[requiredLevel];
}

export function getPermissionDisplayName(level: PermissionLevel): string {
  switch (level) {
    case PermissionLevel.READ:
      return 'Reader';
    case PermissionLevel.WRITE:
      return 'Writer';
    case PermissionLevel.ADMIN:
      return 'Administrator';
    default:
      return 'Unknown';
  }
}
```

#### 2. Permission Context Provider
```typescript
// File: web/src/contexts/PermissionContext.tsx
import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { UserPermissions, PermissionLevel, PermissionContextType, hasPermissionLevel } from '@/lib/permissions';
import { useUser } from '@/contexts/UserContext';
import { toast } from '@/components/ui/use-toast';

const PermissionContext = createContext<PermissionContextType | undefined>(undefined);

export interface PermissionProviderProps {
  children: ReactNode;
}

export function PermissionProvider({ children }: PermissionProviderProps) {
  const [permissions, setPermissions] = useState<UserPermissions | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const { user, isAuthenticated } = useUser();

  const fetchPermissions = async (): Promise<void> => {
    if (!isAuthenticated || !user) {
      setPermissions(null);
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/auth/permissions', {
        headers: {
          'Authorization': `Bearer ${user.accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        if (response.status === 404) {
          // User doesn't have OAuth permissions yet
          setPermissions(null);
          return;
        }
        throw new Error(`Failed to fetch permissions: ${response.statusText}`);
      }

      const permissionData: UserPermissions = await response.json();
      setPermissions(permissionData);
      
      console.log('User permissions loaded:', {
        level: permissionData.permissionLevel,
        groups: permissionData.oktaGroups
      });

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load permissions';
      setError(errorMessage);
      console.error('Error fetching user permissions:', err);
      
      toast({
        title: 'Permission Error',
        description: 'Failed to load user permissions. Some features may not be available.',
        variant: 'destructive'
      });
    } finally {
      setLoading(false);
    }
  };

  const hasPermission = (required: PermissionLevel): boolean => {
    if (!permissions || !permissions.isActive) {
      return false;
    }
    return hasPermissionLevel(permissions.permissionLevel, required);
  };

  const hasAnyPermission = (required: PermissionLevel[]): boolean => {
    return required.some(level => hasPermission(level));
  };

  useEffect(() => {
    fetchPermissions();
  }, [isAuthenticated, user]);

  const contextValue: PermissionContextType = {
    permissions,
    loading,
    error,
    refetch: fetchPermissions,
    hasPermission,
    hasAnyPermission
  };

  return (
    <PermissionContext.Provider value={contextValue}>
      {children}
    </PermissionContext.Provider>
  );
}

export function usePermissions(): PermissionContextType {
  const context = useContext(PermissionContext);
  if (context === undefined) {
    throw new Error('usePermissions must be used within a PermissionProvider');
  }
  return context;
}
```

#### 3. Permission Hook Utilities
```typescript
// File: web/src/hooks/usePermissions.ts
import { useMemo } from 'react';
import { usePermissions as usePermissionContext } from '@/contexts/PermissionContext';
import { PermissionLevel } from '@/lib/permissions';

export function usePermissions() {
  return usePermissionContext();
}

export function useHasPermission(required: PermissionLevel) {
  const { hasPermission, loading } = usePermissions();
  
  return useMemo(() => ({
    hasPermission: hasPermission(required),
    loading
  }), [hasPermission, required, loading]);
}

export function useIsAdmin() {
  return useHasPermission(PermissionLevel.ADMIN);
}

export function useCanWrite() {
  return useHasPermission(PermissionLevel.WRITE);
}

export function useCanRead() {
  return useHasPermission(PermissionLevel.READ);
}

export function usePermissionLevel() {
  const { permissions, loading } = usePermissions();
  
  return useMemo(() => ({
    level: permissions?.permissionLevel || null,
    displayName: permissions ? getPermissionDisplayName(permissions.permissionLevel) : null,
    loading
  }), [permissions, loading]);
}

// Custom hook for conditional rendering based on permissions
export function useConditionalRender(required: PermissionLevel) {
  const { hasPermission, loading, error } = usePermissions();
  
  return useMemo(() => {
    if (loading) return { show: false, loading: true, error: null };
    if (error) return { show: false, loading: false, error };
    return { show: hasPermission(required), loading: false, error: null };
  }, [hasPermission, required, loading, error]);
}
```

### Permission-Gated Components

#### 1. Permission Gate Component
```typescript
// File: web/src/components/PermissionGate.tsx
import React, { ReactNode } from 'react';
import { PermissionLevel } from '@/lib/permissions';
import { usePermissions } from '@/hooks/usePermissions';
import { Loader2, AlertCircle } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';

export interface PermissionGateProps {
  required: PermissionLevel;
  children: ReactNode;
  fallback?: ReactNode;
  showLoading?: boolean;
  showError?: boolean;
  errorMessage?: string;
}

export function PermissionGate({
  required,
  children,
  fallback,
  showLoading = false,
  showError = false,
  errorMessage = 'You do not have permission to view this content.'
}: PermissionGateProps) {
  const { hasPermission, loading, error, permissions } = usePermissions();

  // Show loading state if enabled
  if (loading && showLoading) {
    return (
      <div className="flex items-center justify-center p-4">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        <span className="text-sm text-muted-foreground">Checking permissions...</span>
      </div>
    );
  }

  // Show error state if enabled
  if (error && showError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          Failed to load permissions: {error}
        </AlertDescription>
      </Alert>
    );
  }

  // Check if user has required permission
  if (!hasPermission(required)) {
    if (fallback) {
      return <>{fallback}</>;
    }
    
    if (showError) {
      return (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            {errorMessage} Required: {required.toUpperCase()}, 
            Current: {permissions?.permissionLevel?.toUpperCase() || 'NONE'}
          </AlertDescription>
        </Alert>
      );
    }
    
    return null;
  }

  return <>{children}</>;
}

// Specific permission gates for common use cases
export function AdminGate({ children, ...props }: Omit<PermissionGateProps, 'required'>) {
  return (
    <PermissionGate required={PermissionLevel.ADMIN} {...props}>
      {children}
    </PermissionGate>
  );
}

export function WriteGate({ children, ...props }: Omit<PermissionGateProps, 'required'>) {
  return (
    <PermissionGate required={PermissionLevel.WRITE} {...props}>
      {children}
    </PermissionGate>
  );
}

export function ReadGate({ children, ...props }: Omit<PermissionGateProps, 'required'>) {
  return (
    <PermissionGate required={PermissionLevel.READ} {...props}>
      {children}
    </PermissionGate>
  );
}
```

#### 2. Conditional Components
```typescript
// File: web/src/components/ConditionalRender.tsx
import React, { ReactNode } from 'react';
import { PermissionLevel } from '@/lib/permissions';
import { useConditionalRender } from '@/hooks/usePermissions';

interface ConditionalRenderProps {
  required: PermissionLevel;
  children: ReactNode;
  fallback?: ReactNode;
}

export function ConditionalRender({ required, children, fallback }: ConditionalRenderProps) {
  const { show, loading, error } = useConditionalRender(required);
  
  if (loading) {
    return null; // Or a loading spinner if desired
  }
  
  if (error) {
    console.error('Permission error:', error);
    return fallback || null;
  }
  
  return show ? <>{children}</> : (fallback || null);
}

// Higher-order component for permission-based rendering
export function withPermissions<P extends object>(
  Component: React.ComponentType<P>,
  required: PermissionLevel,
  fallback?: ReactNode
) {
  return function PermissionWrappedComponent(props: P) {
    return (
      <ConditionalRender required={required} fallback={fallback}>
        <Component {...props} />
      </ConditionalRender>
    );
  };
}
```

#### 3. Navigation and Menu Components
```typescript
// File: web/src/components/Navigation/PermissionAwareNav.tsx
import React from 'react';
import { usePermissions, useIsAdmin, useCanWrite } from '@/hooks/usePermissions';
import { PermissionGate, AdminGate, WriteGate } from '@/components/PermissionGate';
import { Button } from '@/components/ui/button';
import { 
  NavigationMenu,
  NavigationMenuContent,
  NavigationMenuItem,
  NavigationMenuLink,
  NavigationMenuList,
  NavigationMenuTrigger,
} from '@/components/ui/navigation-menu';
import { Settings, FileText, MessageSquare, Users } from 'lucide-react';

export function PermissionAwareNavigation() {
  const { permissions, loading } = usePermissions();
  const { hasPermission: isAdmin } = useIsAdmin();
  const { hasPermission: canWrite } = useCanWrite();

  if (loading) {
    return (
      <div className="flex space-x-2">
        <div className="h-9 w-20 bg-muted animate-pulse rounded"></div>
        <div className="h-9 w-20 bg-muted animate-pulse rounded"></div>
      </div>
    );
  }

  return (
    <NavigationMenu>
      <NavigationMenuList>
        {/* Documents - Available to all authenticated users */}
        <NavigationMenuItem>
          <NavigationMenuLink href="/documents">
            <Button variant="ghost" size="sm">
              <FileText className="h-4 w-4 mr-2" />
              Documents
            </Button>
          </NavigationMenuLink>
        </NavigationMenuItem>

        {/* Chat - Available to all authenticated users */}
        <NavigationMenuItem>
          <NavigationMenuLink href="/chat">
            <Button variant="ghost" size="sm">
              <MessageSquare className="h-4 w-4 mr-2" />
              Chat
            </Button>
          </NavigationMenuLink>
        </NavigationMenuItem>

        {/* Create/Write Actions - Requires write permission */}
        <WriteGate>
          <NavigationMenuItem>
            <NavigationMenuTrigger>
              <Button variant="ghost" size="sm">
                Create
              </Button>
            </NavigationMenuTrigger>
            <NavigationMenuContent>
              <div className="grid gap-2 p-4 w-48">
                <NavigationMenuLink href="/documents/new">
                  <Button variant="ghost" size="sm" className="w-full justify-start">
                    New Document
                  </Button>
                </NavigationMenuLink>
                <NavigationMenuLink href="/chat/new">
                  <Button variant="ghost" size="sm" className="w-full justify-start">
                    New Chat
                  </Button>
                </NavigationMenuLink>
              </div>
            </NavigationMenuContent>
          </NavigationMenuItem>
        </WriteGate>

        {/* Admin Menu - Requires admin permission */}
        <AdminGate>
          <NavigationMenuItem>
            <NavigationMenuTrigger>
              <Button variant="ghost" size="sm">
                <Settings className="h-4 w-4 mr-2" />
                Admin
              </Button>
            </NavigationMenuTrigger>
            <NavigationMenuContent>
              <div className="grid gap-2 p-4 w-48">
                <NavigationMenuLink href="/admin/users">
                  <Button variant="ghost" size="sm" className="w-full justify-start">
                    <Users className="h-4 w-4 mr-2" />
                    User Management
                  </Button>
                </NavigationMenuLink>
                <NavigationMenuLink href="/admin/connectors">
                  <Button variant="ghost" size="sm" className="w-full justify-start">
                    <Settings className="h-4 w-4 mr-2" />
                    Connectors
                  </Button>
                </NavigationMenuLink>
                <NavigationMenuLink href="/admin/permissions">
                  <Button variant="ghost" size="sm" className="w-full justify-start">
                    Permissions
                  </Button>
                </NavigationMenuLink>
              </div>
            </NavigationMenuContent>
          </NavigationMenuItem>
        </AdminGate>
      </NavigationMenuList>
    </NavigationMenu>
  );
}
```

#### 4. Permission Status Component
```typescript
// File: web/src/components/PermissionStatus.tsx
import React from 'react';
import { usePermissions } from '@/hooks/usePermissions';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, Users, Clock, AlertCircle } from 'lucide-react';
import { getPermissionDisplayName } from '@/lib/permissions';

export function PermissionStatus() {
  const { permissions, loading, error } = usePermissions();

  if (loading) {
    return (
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center">
            <Shield className="h-5 w-5 mr-2" />
            Permissions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="h-4 bg-muted animate-pulse rounded"></div>
            <div className="h-4 bg-muted animate-pulse rounded w-3/4"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="w-full max-w-md border-destructive">
        <CardHeader>
          <CardTitle className="flex items-center text-destructive">
            <AlertCircle className="h-5 w-5 mr-2" />
            Permission Error
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!permissions) {
    return (
      <Card className="w-full max-w-md border-yellow-200">
        <CardHeader>
          <CardTitle className="flex items-center text-yellow-600">
            <AlertCircle className="h-5 w-5 mr-2" />
            No Permissions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            OAuth permissions not configured. Contact your administrator.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle className="flex items-center">
          <Shield className="h-5 w-5 mr-2" />
          Your Permissions
        </CardTitle>
        <CardDescription>Current access level and group memberships</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium">Access Level:</span>
          <Badge variant={
            permissions.permissionLevel === 'admin' ? 'default' :
            permissions.permissionLevel === 'write' ? 'secondary' : 'outline'
          }>
            {getPermissionDisplayName(permissions.permissionLevel)}
          </Badge>
        </div>

        {permissions.oktaGroups && permissions.oktaGroups.length > 0 && (
          <div>
            <div className="flex items-center mb-2">
              <Users className="h-4 w-4 mr-2" />
              <span className="text-sm font-medium">Groups:</span>
            </div>
            <div className="flex flex-wrap gap-1">
              {permissions.oktaGroups.map((group) => (
                <Badge key={group} variant="outline" className="text-xs">
                  {group}
                </Badge>
              ))}
            </div>
          </div>
        )}

        <div className="flex items-center text-xs text-muted-foreground">
          <Clock className="h-3 w-3 mr-1" />
          <span>Updated: {new Date(permissions.lastUpdated).toLocaleDateString()}</span>
        </div>
      </CardContent>
    </Card>
  );
}
```

### Integration with Existing App

#### 1. App Root Integration
```typescript
// File: web/src/App.tsx (enhancement)
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { UserProvider } from '@/contexts/UserContext';
import { PermissionProvider } from '@/contexts/PermissionContext';
import { PermissionAwareNavigation } from '@/components/Navigation/PermissionAwareNav';
import { ProtectedRoute } from '@/components/ProtectedRoute';
import { AdminGate, WriteGate } from '@/components/PermissionGate';

// Import existing pages
import HomePage from '@/pages/HomePage';
import DocumentsPage from '@/pages/DocumentsPage';
import ChatPage from '@/pages/ChatPage';
import AdminUsersPage from '@/pages/admin/UsersPage';
import AdminConnectorsPage from '@/pages/admin/ConnectorsPage';
import AdminPermissionsPage from '@/pages/admin/PermissionsPage';

function App() {
  return (
    <Router>
      <UserProvider>
        <PermissionProvider>
          <div className="min-h-screen bg-background">
            <header className="border-b">
              <div className="container mx-auto px-4 py-3">
                <PermissionAwareNavigation />
              </div>
            </header>
            
            <main className="container mx-auto px-4 py-6">
              <Routes>
                <Route path="/" element={<HomePage />} />
                
                {/* Protected routes that require authentication */}
                <Route path="/documents" element={
                  <ProtectedRoute>
                    <DocumentsPage />
                  </ProtectedRoute>
                } />
                
                <Route path="/chat" element={
                  <ProtectedRoute>
                    <ChatPage />
                  </ProtectedRoute>
                } />
                
                {/* Admin routes that require admin permission */}
                <Route path="/admin/users" element={
                  <ProtectedRoute>
                    <AdminGate 
                      showError={true}
                      errorMessage="You need administrator privileges to access user management."
                    >
                      <AdminUsersPage />
                    </AdminGate>
                  </ProtectedRoute>
                } />
                
                <Route path="/admin/connectors" element={
                  <ProtectedRoute>
                    <AdminGate showError={true}>
                      <AdminConnectorsPage />
                    </AdminGate>
                  </ProtectedRoute>
                } />
                
                <Route path="/admin/permissions" element={
                  <ProtectedRoute>
                    <AdminGate showError={true}>
                      <AdminPermissionsPage />
                    </AdminGate>
                  </ProtectedRoute>
                } />
              </Routes>
            </main>
          </div>
        </PermissionProvider>
      </UserProvider>
    </Router>
  );
}

export default App;
```

#### 2. Example Page Implementation
```typescript
// File: web/src/pages/DocumentsPage.tsx (enhancement)
import React from 'react';
import { usePermissions, useCanWrite } from '@/hooks/usePermissions';
import { WriteGate } from '@/components/PermissionGate';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Plus, FileText, Lock } from 'lucide-react';

export default function DocumentsPage() {
  const { permissions, loading } = usePermissions();
  const { hasPermission: canWrite } = useCanWrite();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Documents</h1>
          <p className="text-muted-foreground">
            Manage and access your documents
          </p>
        </div>
        
        <WriteGate fallback={
          <div className="flex items-center text-sm text-muted-foreground">
            <Lock className="h-4 w-4 mr-2" />
            Read-only access
          </div>
        }>
          <Button>
            <Plus className="h-4 w-4 mr-2" />
            New Document
          </Button>
        </WriteGate>
      </div>

      {/* Document List */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <FileText className="h-5 w-5 mr-2" />
              Sample Document
            </CardTitle>
            <CardDescription>A sample document for testing</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex justify-between items-center">
              <Button variant="outline" size="sm">
                View
              </Button>
              
              <WriteGate>
                <div className="space-x-2">
                  <Button variant="outline" size="sm">
                    Edit
                  </Button>
                  <Button variant="destructive" size="sm">
                    Delete
                  </Button>
                </div>
              </WriteGate>
            </div>
          </CardContent>
        </Card>
      </div>

      {!canWrite && (
        <Card className="border-yellow-200 bg-yellow-50">
          <CardContent className="pt-6">
            <div className="flex items-center">
              <Lock className="h-5 w-5 mr-2 text-yellow-600" />
              <div>
                <p className="font-medium text-yellow-800">Read-Only Access</p>
                <p className="text-sm text-yellow-700">
                  You have read-only access to documents. Contact your administrator for write permissions.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
```

## Testing Requirements

### Unit Tests
```typescript
// File: web/src/components/__tests__/PermissionGate.test.tsx
import React from 'react';
import { render, screen } from '@testing-library/react';
import { PermissionGate, AdminGate } from '../PermissionGate';
import { PermissionLevel } from '@/lib/permissions';
import { usePermissions } from '@/hooks/usePermissions';

// Mock the permissions hook
jest.mock('@/hooks/usePermissions');
const mockUsePermissions = usePermissions as jest.MockedFunction<typeof usePermissions>;

describe('PermissionGate', () => {
  it('renders children when user has required permission', () => {
    mockUsePermissions.mockReturnValue({
      permissions: {
        userId: 'test-user',
        email: 'test@example.com',
        permissionLevel: PermissionLevel.ADMIN,
        oktaGroups: ['Onyx-Admins'],
        grantedAt: '2025-01-01T00:00:00Z',
        lastUpdated: '2025-01-01T00:00:00Z',
        source: 'okta',
        isActive: true
      },
      loading: false,
      error: null,
      refetch: jest.fn(),
      hasPermission: jest.fn().mockReturnValue(true),
      hasAnyPermission: jest.fn().mockReturnValue(true)
    });

    render(
      <PermissionGate required={PermissionLevel.ADMIN}>
        <div>Admin Content</div>
      </PermissionGate>
    );

    expect(screen.getByText('Admin Content')).toBeInTheDocument();
  });

  it('does not render children when user lacks permission', () => {
    mockUsePermissions.mockReturnValue({
      permissions: {
        userId: 'test-user',
        email: 'test@example.com',
        permissionLevel: PermissionLevel.READ,
        oktaGroups: ['Onyx-Readers'],
        grantedAt: '2025-01-01T00:00:00Z',
        lastUpdated: '2025-01-01T00:00:00Z',
        source: 'okta',
        isActive: true
      },
      loading: false,
      error: null,
      refetch: jest.fn(),
      hasPermission: jest.fn().mockReturnValue(false),
      hasAnyPermission: jest.fn().mockReturnValue(false)
    });

    render(
      <PermissionGate required={PermissionLevel.ADMIN}>
        <div>Admin Content</div>
      </PermissionGate>
    );

    expect(screen.queryByText('Admin Content')).not.toBeInTheDocument();
  });

  it('shows loading state when enabled', () => {
    mockUsePermissions.mockReturnValue({
      permissions: null,
      loading: true,
      error: null,
      refetch: jest.fn(),
      hasPermission: jest.fn().mockReturnValue(false),
      hasAnyPermission: jest.fn().mockReturnValue(false)
    });

    render(
      <PermissionGate required={PermissionLevel.ADMIN} showLoading={true}>
        <div>Admin Content</div>
      </PermissionGate>
    );

    expect(screen.getByText('Checking permissions...')).toBeInTheDocument();
  });

  it('shows error state when enabled', () => {
    mockUsePermissions.mockReturnValue({
      permissions: null,
      loading: false,
      error: 'Failed to load permissions',
      refetch: jest.fn(),
      hasPermission: jest.fn().mockReturnValue(false),
      hasAnyPermission: jest.fn().mockReturnValue(false)
    });

    render(
      <PermissionGate required={PermissionLevel.ADMIN} showError={true}>
        <div>Admin Content</div>
      </PermissionGate>
    );

    expect(screen.getByText(/Failed to load permissions/)).toBeInTheDocument();
  });

  it('renders fallback when provided and no permission', () => {
    mockUsePermissions.mockReturnValue({
      permissions: {
        userId: 'test-user',
        email: 'test@example.com',
        permissionLevel: PermissionLevel.READ,
        oktaGroups: ['Onyx-Readers'],
        grantedAt: '2025-01-01T00:00:00Z',
        lastUpdated: '2025-01-01T00:00:00Z',
        source: 'okta',
        isActive: true
      },
      loading: false,
      error: null,
      refetch: jest.fn(),
      hasPermission: jest.fn().mockReturnValue(false),
      hasAnyPermission: jest.fn().mockReturnValue(false)
    });

    render(
      <PermissionGate 
        required={PermissionLevel.ADMIN}
        fallback={<div>Access Denied</div>}
      >
        <div>Admin Content</div>
      </PermissionGate>
    );

    expect(screen.getByText('Access Denied')).toBeInTheDocument();
    expect(screen.queryByText('Admin Content')).not.toBeInTheDocument();
  });
});
```

### Integration Tests
```typescript
// File: web/src/__tests__/integration/PermissionFlow.test.tsx
import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import App from '@/App';
import { server } from '@/mocks/server';
import { rest } from 'msw';

// Mock API responses
const mockPermissionResponse = (level: string) => 
  server.use(
    rest.get('/api/auth/permissions', (req, res, ctx) => {
      return res(
        ctx.json({
          userId: 'test-user',
          email: 'test@example.com',
          permissionLevel: level,
          oktaGroups: level === 'admin' ? ['Onyx-Admins'] : ['Onyx-Readers'],
          grantedAt: '2025-01-01T00:00:00Z',
          lastUpdated: '2025-01-01T00:00:00Z',
          source: 'okta',
          isActive: true
        })
      );
    })
  );

describe('Permission Flow Integration', () => {
  it('shows admin navigation for admin users', async () => {
    mockPermissionResponse('admin');

    render(
      <BrowserRouter>
        <App />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('Admin')).toBeInTheDocument();
    });
  });

  it('hides admin navigation for non-admin users', async () => {
    mockPermissionResponse('read');

    render(
      <BrowserRouter>
        <App />
      </BrowserRouter>
    );

    await waitFor(() => {
      expect(screen.queryByText('Admin')).not.toBeInTheDocument();
    });
  });
});
```

## Performance Requirements

### Loading Performance
- **Permission Context Load**: < 500ms initial load
- **Permission Check**: < 10ms per component render
- **Navigation Render**: < 100ms with permissions
- **Conditional Rendering**: < 5ms per condition

### Memory Usage
- **Context Memory**: < 1MB for permission state
- **Component Overhead**: < 10KB per permission-gated component
- **Cache Efficiency**: Minimize re-renders on permission checks

## Deployment Procedures

### Pre-Deployment Checklist
- [ ] All TypeScript types properly defined
- [ ] Unit tests pass for all permission components
- [ ] Integration tests validate permission flows
- [ ] Error handling tested for permission failures
- [ ] Loading states tested and functional

### Deployment Steps
1. **Build Validation**: Ensure TypeScript compilation succeeds
2. **Component Testing**: Validate all permission components work
3. **Integration Testing**: Test with backend permission API
4. **Browser Testing**: Verify cross-browser compatibility
5. **Performance Testing**: Validate performance requirements

### Monitoring & Alerts
- **Permission API Errors**: Monitor failed permission requests
- **Component Errors**: Track permission gate error rates
- **Performance**: Monitor permission check performance
- **User Experience**: Track permission-related user issues

## Definition of Done

### Functional Requirements ✅
- [ ] Permission context provides user permission state
- [ ] Permission gates properly show/hide content
- [ ] Navigation adapts based on user permissions
- [ ] Error and loading states handle gracefully
- [ ] TypeScript types ensure type safety

### Quality Requirements ✅
- [ ] Unit test coverage > 95% for permission components
- [ ] Integration tests validate complete permission flows
- [ ] Performance requirements met for all components
- [ ] Error handling provides good user experience
- [ ] Code follows React and TypeScript best practices

### Documentation Requirements ✅
- [ ] Component documentation with usage examples
- [ ] Permission system integration guide
- [ ] TypeScript type documentation
- [ ] Troubleshooting guide for permission issues

---

**Story Dependencies**: This story completes the OAuth authorization system by providing frontend integration with the permission APIs created in Story 4.4. It enables users to have a permission-aware interface that adapts to their access levels.
