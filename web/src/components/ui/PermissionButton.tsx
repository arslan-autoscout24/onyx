import React from 'react';
import { Button } from '@/components/ui/button';
import { PermissionLevel } from '@/lib/permissions';
import { useHasPermission } from '@/hooks/usePermissions';
import { FiLock } from 'react-icons/fi';

interface PermissionButtonProps extends React.ComponentProps<typeof Button> {
  requiredPermission: PermissionLevel;
  fallbackContent?: React.ReactNode;
  showLockIcon?: boolean;
  lockMessage?: string;
}

export function PermissionButton({
  requiredPermission,
  fallbackContent,
  showLockIcon = true,
  lockMessage = 'Insufficient permissions',
  children,
  disabled,
  ...buttonProps
}: PermissionButtonProps) {
  const { hasPermission, loading } = useHasPermission(requiredPermission);

  if (loading) {
    return (
      <Button disabled {...buttonProps}>
        {children}
      </Button>
    );
  }

  if (!hasPermission) {
    if (fallbackContent) {
      return <>{fallbackContent}</>;
    }

    return (
      <Button 
        disabled 
        variant="outline" 
        title={lockMessage}
        {...buttonProps}
      >
        {showLockIcon && <FiLock className="h-4 w-4 mr-2" />}
        {children}
      </Button>
    );
  }

  return (
    <Button disabled={disabled} {...buttonProps}>
      {children}
    </Button>
  );
}

// Convenience components for common permission levels
export function AdminButton(props: Omit<PermissionButtonProps, 'requiredPermission'>) {
  return <PermissionButton requiredPermission={PermissionLevel.ADMIN} {...props} />;
}

export function WriteButton(props: Omit<PermissionButtonProps, 'requiredPermission'>) {
  return <PermissionButton requiredPermission={PermissionLevel.WRITE} {...props} />;
}

export function ReadButton(props: Omit<PermissionButtonProps, 'requiredPermission'>) {
  return <PermissionButton requiredPermission={PermissionLevel.READ} {...props} />;
}
