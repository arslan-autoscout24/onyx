import { useMemo } from 'react';
import { usePermissions as usePermissionContext } from '@/components/context/PermissionContext';
import { PermissionLevel, getPermissionDisplayName } from '@/lib/permissions';

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
