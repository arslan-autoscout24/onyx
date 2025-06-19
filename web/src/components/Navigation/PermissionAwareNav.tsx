import React from 'react';
import { usePermissions, useIsAdmin, useCanWrite } from '@/hooks/usePermissions';
import { PermissionGate, AdminGate, WriteGate } from '@/components/PermissionGate';
import { FiSettings, FiFileText, FiMessageSquare, FiUsers, FiLock } from 'react-icons/fi';
import Link from 'next/link';

export function PermissionAwareNavigation() {
  const { permissions, loading } = usePermissions();
  const { hasPermission: isAdmin } = useIsAdmin();
  const { hasPermission: canWrite } = useCanWrite();

  if (loading) {
    return (
      <div className="flex space-x-2">
        <div className="h-9 w-20 bg-gray-200 animate-pulse rounded"></div>
        <div className="h-9 w-20 bg-gray-200 animate-pulse rounded"></div>
      </div>
    );
  }

  return (
    <nav className="flex items-center space-x-4">
      {/* Documents - Available to all authenticated users */}
      <Link 
        href="/search" 
        className="flex items-center px-3 py-2 text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-100 rounded-md"
      >
        <FiFileText className="h-4 w-4 mr-2" />
        Documents
      </Link>

      {/* Chat - Available to all authenticated users */}
      <Link 
        href="/chat" 
        className="flex items-center px-3 py-2 text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-100 rounded-md"
      >
        <FiMessageSquare className="h-4 w-4 mr-2" />
        Chat
      </Link>

      {/* Admin Menu - Requires admin permission */}
      <AdminGate>
        <div className="relative group">
          <button className="flex items-center px-3 py-2 text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-100 rounded-md">
            <FiSettings className="h-4 w-4 mr-2" />
            Admin
          </button>
          <div className="absolute top-full left-0 mt-1 w-48 bg-white shadow-lg rounded-md border hidden group-hover:block z-50">
            <Link 
              href="/admin/users" 
              className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
            >
              <FiUsers className="h-4 w-4 mr-2" />
              User Management
            </Link>
            <Link 
              href="/admin/connectors" 
              className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
            >
              <FiSettings className="h-4 w-4 mr-2" />
              Connectors
            </Link>
            <Link 
              href="/admin/settings" 
              className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
            >
              <FiSettings className="h-4 w-4 mr-2" />
              Settings
            </Link>
          </div>
        </div>
      </AdminGate>

      {/* Permission Status Indicator */}
      {permissions && (
        <div className="flex items-center text-xs text-gray-500">
          <FiLock className="h-3 w-3 mr-1" />
          <span className="capitalize">{permissions.permissionLevel}</span>
        </div>
      )}
    </nav>
  );
}
