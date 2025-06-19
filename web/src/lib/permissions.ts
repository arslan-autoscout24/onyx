export enum PermissionLevel {
  READ = 'read',
  WRITE = 'write',
  ADMIN = 'admin'
}

export interface UserPermissions {
  userId: string;
  email: string;
  permissionLevel: PermissionLevel;
  oktaGroups: string[];
  grantedAt: string;
  lastUpdated: string;
  source: string;
  isActive: boolean;
}

export interface PermissionContextType {
  permissions: UserPermissions | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  hasPermission: (required: PermissionLevel) => boolean;
  hasAnyPermission: (required: PermissionLevel[]) => boolean;
}

// Permission hierarchy for checking
const PERMISSION_HIERARCHY: Record<PermissionLevel, number> = {
  [PermissionLevel.READ]: 1,
  [PermissionLevel.WRITE]: 2,
  [PermissionLevel.ADMIN]: 3
};

export function hasPermissionLevel(
  userLevel: PermissionLevel,
  requiredLevel: PermissionLevel
): boolean {
  return PERMISSION_HIERARCHY[userLevel] >= PERMISSION_HIERARCHY[requiredLevel];
}

export function getPermissionDisplayName(level: PermissionLevel): string {
  switch (level) {
    case PermissionLevel.READ:
      return 'Reader';
    case PermissionLevel.WRITE:
      return 'Writer';
    case PermissionLevel.ADMIN:
      return 'Administrator';
    default:
      return 'Unknown';
  }
}
