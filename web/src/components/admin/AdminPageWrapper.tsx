import React, { ReactNode } from 'react';
import { AdminGate } from '@/components/PermissionGate';
import { useUser } from '@/components/user/UserProvider';
import { ErrorCallout } from '@/components/ErrorCallout';
import { LoadingAnimation } from '@/components/Loading';

interface AdminPageWrapperProps {
  children: ReactNode;
  title?: string;
  description?: string;
}

export function AdminPageWrapper({ children, title, description }: AdminPageWrapperProps) {
  const { user } = useUser();

  // Check if user is authenticated first
  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingAnimation text="Loading..." />
      </div>
    );
  }

  return (
    <AdminGate 
      showLoading={true}
      showError={true}
      errorMessage={`You need administrator privileges to access ${title || 'this page'}.`}
    >
      <div className="container mx-auto px-4 py-6">
        {title && (
          <div className="mb-6">
            <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
            {description && (
              <p className="text-gray-600 mt-2">{description}</p>
            )}
          </div>
        )}
        {children}
      </div>
    </AdminGate>
  );
}

// Example enhanced admin user page
export function ProtectedUserManagement() {
  return (
    <AdminPageWrapper 
      title="User Management" 
      description="Manage users, invitations, and access levels"
    >
      <div className="space-y-6">
        <p className="text-gray-600">
          This page is protected by OAuth permissions. Only users with admin-level 
          permissions can access this content.
        </p>
        
        {/* The actual user management content would go here */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h3 className="font-semibold text-blue-900 mb-2">Permission-Protected Content</h3>
          <p className="text-blue-700 text-sm">
            This content is only visible to users with admin permissions. 
            The original user management interface would be rendered here.
          </p>
        </div>
      </div>
    </AdminPageWrapper>
  );
}
