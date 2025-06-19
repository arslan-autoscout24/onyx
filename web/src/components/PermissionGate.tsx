import React, { ReactNode } from 'react';
import { PermissionLevel } from '@/lib/permissions';
import { usePermissions } from '@/hooks/usePermissions';
import { LoadingAnimation } from '@/components/Loading';
import { ErrorCallout } from '@/components/ErrorCallout';

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
        <LoadingAnimation text="Checking permissions..." />
      </div>
    );
  }

  // Show error state if enabled
  if (error && showError) {
    return (
      <ErrorCallout errorTitle="Permission Error" errorMsg={`Failed to load permissions: ${error}`} />
    );
  }

  // Check if user has required permission
  if (!hasPermission(required)) {
    if (fallback) {
      return <>{fallback}</>;
    }
    
    if (showError) {
      return (
        <ErrorCallout 
          errorTitle="Access Denied" 
          errorMsg={`${errorMessage} Required: ${required.toUpperCase()}, Current: ${permissions?.permissionLevel?.toUpperCase() || 'NONE'}`} 
        />
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
