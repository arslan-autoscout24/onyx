import React from 'react';
import { usePermissions, useIsAdmin, useCanWrite, useCanRead } from '@/hooks/usePermissions';
import { AdminGate, WriteGate, ReadGate } from '@/components/PermissionGate';
import { PermissionStatus } from '@/components/PermissionStatus';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { FiPlus, FiEdit, FiTrash, FiLock, FiEye, FiSettings } from 'react-icons/fi';

export function PermissionDemoPage() {
  const { permissions, loading } = usePermissions();
  const { hasPermission: isAdmin } = useIsAdmin();
  const { hasPermission: canWrite } = useCanWrite();
  const { hasPermission: canRead } = useCanRead();

  return (
    <div className="container mx-auto px-4 py-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Permission Demo</h1>
          <p className="text-gray-600 mt-2">
            This page demonstrates permission-based UI rendering
          </p>
        </div>
        
        {/* Permission Status */}
        <PermissionStatus />
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {/* Basic Read Access */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <FiEye className="h-5 w-5 mr-2" />
              Read-Only Content
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-gray-600 mb-4">
              This content is available to all authenticated users.
            </p>
            <ReadGate>
              <div className="bg-green-50 border border-green-200 rounded p-3">
                <p className="text-green-800 text-sm">
                  ✅ You have read access to this content.
                </p>
              </div>
            </ReadGate>
          </CardContent>
        </Card>

        {/* Write Access */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <FiEdit className="h-5 w-5 mr-2" />
              Write-Protected Actions
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-gray-600">
              These actions require write permissions.
            </p>
            
            <WriteGate fallback={
              <div className="flex items-center text-sm text-gray-500">
                <FiLock className="h-4 w-4 mr-2" />
                Write permissions required
              </div>
            }>
              <div className="space-y-2">
                <Button size="sm" className="w-full">
                  <FiPlus className="h-4 w-4 mr-2" />
                  Create New
                </Button>
                <Button size="sm" variant="outline" className="w-full">
                  <FiEdit className="h-4 w-4 mr-2" />
                  Edit Content
                </Button>
              </div>
            </WriteGate>
          </CardContent>
        </Card>

        {/* Admin Access */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center">
              <FiSettings className="h-5 w-5 mr-2" />
              Admin-Only Features
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-gray-600">
              These features require administrator privileges.
            </p>
            
            <AdminGate fallback={
              <div className="flex items-center text-sm text-gray-500">
                <FiLock className="h-4 w-4 mr-2" />
                Administrator access required
              </div>
            }>
              <div className="space-y-2">
                <Button size="sm" variant="destructive" className="w-full">
                  <FiTrash className="h-4 w-4 mr-2" />
                  Delete Resource
                </Button>
                <Button size="sm" className="w-full">
                  <FiSettings className="h-4 w-4 mr-2" />
                  System Settings
                </Button>
              </div>
            </AdminGate>
          </CardContent>
        </Card>
      </div>

      {/* Permission Summary */}
      <Card>
        <CardHeader>
          <CardTitle>Your Current Permissions</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-gray-500">Loading permissions...</p>
          ) : permissions ? (
            <div className="grid gap-4 md:grid-cols-3">
              <div className={`p-3 rounded border ${canRead ? 'bg-green-50 border-green-200' : 'bg-gray-50 border-gray-200'}`}>
                <h4 className="font-medium mb-1">Read Access</h4>
                <p className="text-sm text-gray-600">
                  {canRead ? '✅ Granted' : '❌ Denied'}
                </p>
              </div>
              
              <div className={`p-3 rounded border ${canWrite ? 'bg-green-50 border-green-200' : 'bg-gray-50 border-gray-200'}`}>
                <h4 className="font-medium mb-1">Write Access</h4>
                <p className="text-sm text-gray-600">
                  {canWrite ? '✅ Granted' : '❌ Denied'}
                </p>
              </div>
              
              <div className={`p-3 rounded border ${isAdmin ? 'bg-green-50 border-green-200' : 'bg-gray-50 border-gray-200'}`}>
                <h4 className="font-medium mb-1">Admin Access</h4>
                <p className="text-sm text-gray-600">
                  {isAdmin ? '✅ Granted' : '❌ Denied'}
                </p>
              </div>
            </div>
          ) : (
            <div className="bg-yellow-50 border border-yellow-200 rounded p-4">
              <p className="text-yellow-800">
                OAuth permissions not configured. Contact your administrator to set up permissions.
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
