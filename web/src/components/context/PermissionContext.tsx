"use client";

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { UserPermissions, PermissionLevel, PermissionContextType, hasPermissionLevel } from '@/lib/permissions';
import { useUser } from '@/components/user/UserProvider';

const PermissionContext = createContext<PermissionContextType | undefined>(undefined);

export interface PermissionProviderProps {
  children: ReactNode;
}

export function PermissionProvider({ children }: PermissionProviderProps) {
  const [permissions, setPermissions] = useState<UserPermissions | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const { user } = useUser();
  const isAuthenticated = !!user;

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
      
      // Note: toast functionality would need to be implemented
      // toast({
      //   title: 'Permission Error',
      //   description: 'Failed to load user permissions. Some features may not be available.',
      //   variant: 'destructive'
      // });
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
