import React from 'react';
import { usePermissions } from '@/hooks/usePermissions';
import { Card } from '@/components/ui/card';
import { FiShield, FiUsers, FiClock, FiAlertCircle } from 'react-icons/fi';
import { getPermissionDisplayName } from '@/lib/permissions';
import { LoadingAnimation } from '@/components/Loading';
import { ErrorCallout } from '@/components/ErrorCallout';

export function PermissionStatus() {
  const { permissions, loading, error } = usePermissions();

  if (loading) {
    return (
      <Card className="w-full max-w-md p-4">
        <div className="flex items-center mb-4">
          <FiShield className="h-5 w-5 mr-2" />
          <h3 className="font-semibold">Permissions</h3>
        </div>
        <LoadingAnimation text="Loading permissions..." />
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="w-full max-w-md p-4 border-red-200">
        <div className="flex items-center text-red-600 mb-2">
          <FiAlertCircle className="h-5 w-5 mr-2" />
          <h3 className="font-semibold">Permission Error</h3>
        </div>
        <p className="text-sm text-gray-600">{error}</p>
      </Card>
    );
  }

  if (!permissions) {
    return (
      <Card className="w-full max-w-md p-4 border-yellow-200">
        <div className="flex items-center text-yellow-600 mb-2">
          <FiAlertCircle className="h-5 w-5 mr-2" />
          <h3 className="font-semibold">No Permissions</h3>
        </div>
        <p className="text-sm text-gray-600">
          OAuth permissions not configured. Contact your administrator.
        </p>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md p-4">
      <div className="flex items-center mb-4">
        <FiShield className="h-5 w-5 mr-2" />
        <h3 className="font-semibold">Your Permissions</h3>
      </div>
      <p className="text-sm text-gray-600 mb-4">Current access level and group memberships</p>
      
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium">Access Level:</span>
          <span className={`px-2 py-1 rounded text-xs font-medium ${
            permissions.permissionLevel === 'admin' ? 'bg-blue-100 text-blue-800' :
            permissions.permissionLevel === 'write' ? 'bg-green-100 text-green-800' : 
            'bg-gray-100 text-gray-800'
          }`}>
            {getPermissionDisplayName(permissions.permissionLevel)}
          </span>
        </div>

        {permissions.oktaGroups && permissions.oktaGroups.length > 0 && (
          <div>
            <div className="flex items-center mb-2">
              <FiUsers className="h-4 w-4 mr-2" />
              <span className="text-sm font-medium">Groups:</span>
            </div>
            <div className="flex flex-wrap gap-1">
              {permissions.oktaGroups.map((group) => (
                <span 
                  key={group} 
                  className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs"
                >
                  {group}
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="flex items-center text-xs text-gray-500">
          <FiClock className="h-3 w-3 mr-1" />
          <span>Updated: {new Date(permissions.lastUpdated).toLocaleDateString()}</span>
        </div>
      </div>
    </Card>
  );
}
