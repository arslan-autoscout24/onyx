import React, { ReactNode } from 'react';
import { PermissionLevel } from '@/lib/permissions';
import { useConditionalRender } from '@/hooks/usePermissions';

interface ConditionalRenderProps {
  required: PermissionLevel;
  children: ReactNode;
  fallback?: ReactNode;
}

export function ConditionalRender({ required, children, fallback }: ConditionalRenderProps): React.ReactElement | null {
  const { show, loading, error } = useConditionalRender(required);
  
  if (loading) {
    return null; // Or a loading spinner if desired
  }
  
  if (error) {
    console.error('Permission error:', error);
    return (fallback as React.ReactElement) || null;
  }
  
  return show ? (children as React.ReactElement) : ((fallback as React.ReactElement) || null);
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
