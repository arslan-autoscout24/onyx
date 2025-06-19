# Frontend Permission System Documentation

## Overview

This permission system provides React components and hooks for managing OAuth-based permission checks in the frontend. It integrates with the backend OAuth permission API to provide role-based access control.

## Permission Levels

The system supports three permission levels with a hierarchical structure:

- **READ**: Basic read access (level 1)
- **WRITE**: Read and write access (level 2) 
- **ADMIN**: Full administrative access (level 3)

Higher permission levels inherit all capabilities of lower levels.

## Core Components

### Permission Context Provider

The `PermissionProvider` must be added to your app's provider hierarchy:

```tsx
import { PermissionProvider } from '@/components/context/PermissionContext';

// Already integrated in AppProvider
<PermissionProvider>
  {children}
</PermissionProvider>
```

### Permission Gates

Use permission gates to conditionally render content based on user permissions:

```tsx
import { AdminGate, WriteGate, ReadGate } from '@/components/PermissionGate';

// Admin-only content
<AdminGate showError={true}>
  <AdminPanel />
</AdminGate>

// Write permission required
<WriteGate fallback={<ReadOnlyView />}>
  <EditForm />
</WriteGate>

// Generic permission gate
<PermissionGate 
  required={PermissionLevel.WRITE}
  showLoading={true}
  errorMessage="Write access required"
>
  <WriteContent />
</PermissionGate>
```

### Permission Hooks

Use hooks to access permission state and check permissions:

```tsx
import { usePermissions, useIsAdmin, useCanWrite } from '@/hooks/usePermissions';

function MyComponent() {
  const { permissions, loading, error } = usePermissions();
  const { hasPermission: isAdmin } = useIsAdmin();
  const { hasPermission: canWrite } = useCanWrite();
  
  if (loading) return <Loading />;
  if (error) return <Error message={error} />;
  
  return (
    <div>
      {isAdmin && <AdminButton />}
      {canWrite && <EditButton />}
    </div>
  );
}
```

## Integration Examples

### Protecting Admin Pages

Wrap admin pages with permission gates:

```tsx
import { AdminPageWrapper } from '@/components/admin/AdminPageWrapper';

export default function UserManagementPage() {
  return (
    <AdminPageWrapper title="User Management">
      <UserManagementContent />
    </AdminPageWrapper>
  );
}
```

### Permission-Aware Navigation

Use the navigation component to show different menu items based on permissions:

```tsx
import { PermissionAwareNavigation } from '@/components/Navigation/PermissionAwareNav';

<header>
  <PermissionAwareNavigation />
</header>
```

### Conditional UI Elements

Use conditional rendering for buttons and features:

```tsx
import { ConditionalRender } from '@/components/ConditionalRender';

<ConditionalRender 
  required={PermissionLevel.WRITE}
  fallback={<ReadOnlyIndicator />}
>
  <EditButtons />
</ConditionalRender>
```

## Permission Status Component

Display current user permissions:

```tsx
import { PermissionStatus } from '@/components/PermissionStatus';

<PermissionStatus />
```

## API Integration

The system automatically fetches permissions from `/api/auth/permissions` endpoint. The expected response format:

```json
{
  "userId": "user-123",
  "email": "user@example.com", 
  "permissionLevel": "admin",
  "oktaGroups": ["Onyx-Admins"],
  "grantedAt": "2025-01-01T00:00:00Z",
  "lastUpdated": "2025-01-01T00:00:00Z", 
  "source": "okta",
  "isActive": true
}
```

## Error Handling

The system handles common error scenarios:

- **Loading State**: Shows loading indicators while fetching permissions
- **Network Errors**: Displays error messages for API failures  
- **Missing Permissions**: Returns 404 when user has no OAuth permissions
- **Permission Denied**: Shows appropriate fallback content

## Performance Considerations

- Permission checks are memoized to prevent unnecessary re-renders
- Context updates only trigger re-renders for components that use permissions
- Permission API is called once per user session with automatic retries

## Best Practices

1. **Always provide fallbacks**: Use `fallback` props for graceful degradation
2. **Show loading states**: Enable `showLoading` for better UX
3. **Handle errors gracefully**: Use `showError` to inform users of issues
4. **Test all permission levels**: Ensure UI works for read, write, and admin users
5. **Use specific gates**: Prefer `AdminGate`, `WriteGate` over generic gates

## Testing

Test components with different permission levels:

```tsx
// Mock permissions for testing
const mockPermissions = {
  permissions: { permissionLevel: 'admin', isActive: true },
  loading: false,
  error: null,
  hasPermission: jest.fn().mockReturnValue(true)
};

jest.mock('@/hooks/usePermissions', () => ({
  usePermissions: () => mockPermissions
}));
```

## Troubleshooting

### Common Issues

1. **Provider not found error**: Ensure PermissionProvider is in component tree
2. **Permissions not loading**: Check API endpoint and authentication
3. **Gates not working**: Verify permission levels and hierarchy
4. **TypeScript errors**: Ensure proper imports and types

### Debug Tips

- Check browser console for permission API responses
- Use PermissionStatus component to debug current state
- Verify user authentication before checking permissions
- Test with different user roles in development
