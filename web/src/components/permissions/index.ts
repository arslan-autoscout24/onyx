// Permission types and utilities
export {
  PermissionLevel,
  hasPermissionLevel,
  getPermissionDisplayName,
  type UserPermissions,
  type PermissionContextType
} from '@/lib/permissions';

// Context and provider
export {
  PermissionProvider,
  usePermissions
} from '@/components/context/PermissionContext';

// Hooks
export {
  useHasPermission,
  useIsAdmin,
  useCanWrite,
  useCanRead,
  usePermissionLevel,
  useConditionalRender
} from '@/hooks/usePermissions';

// Components
export {
  PermissionGate,
  AdminGate,
  WriteGate,
  ReadGate,
  type PermissionGateProps
} from '@/components/PermissionGate';

export {
  ConditionalRender,
  withPermissions
} from '@/components/ConditionalRender';

export { PermissionStatus } from '@/components/PermissionStatus';

// UI Components
export {
  PermissionButton,
  AdminButton,
  WriteButton,
  ReadButton
} from '@/components/ui/PermissionButton';

// Navigation
export { PermissionAwareNavigation } from '@/components/Navigation/PermissionAwareNav';

// Admin components
export { AdminPageWrapper, ProtectedUserManagement } from '@/components/admin/AdminPageWrapper';

// Examples
export { PermissionDemoPage } from '@/components/examples/PermissionDemoPage';
