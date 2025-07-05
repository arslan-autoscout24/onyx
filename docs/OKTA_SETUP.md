# Okta OIDC Setup Guide

This guide explains how to configure Okta for simple OIDC authentication with Onyx, using a simplified admin/user role system.

## Prerequisites

- Okta Administrator access
- Onyx application domain/URL
- Understanding of OIDC/OAuth 2.0 flow

## Step 1: Create Okta Application

1. **Login to Okta Admin Console**
   - Navigate to your Okta org: `https://your-org.okta.com`
   - Login with admin credentials

2. **Create New Application**
   - Go to Applications > Applications
   - Click "Create App Integration"
   - Select "OIDC - OpenID Connect"
   - Select "Web Application"

3. **Configure Application Settings**
   ```
   App integration name: Onyx Knowledge Platform
   Grant type: Authorization Code
   Sign-in redirect URIs: 
     - http://localhost:3000/auth/callback (development)
     - https://your-domain.com/auth/callback (production)
   Sign-out redirect URIs:
     - http://localhost:3000/ (development) 
     - https://your-domain.com/ (production)
   ```

4. **Assignments**
   - Assign to appropriate users/groups
   - Configure group assignments for role mapping

## Step 2: Configure Groups (Simplified)

Onyx uses a simplified role system with only two roles: **Admin** and **User**.

### Onyx-Admins
- **Description**: Administrative access to Onyx platform
- **Members**: System administrators only
- **Role**: Mapped to `ADMIN` role in Onyx
- **Permissions**: Full access to all features, user management, system configuration

### Default Users
- **Description**: All other users not in Onyx-Admins group
- **Role**: Mapped to `BASIC` role in Onyx  
- **Permissions**: Standard user access to chat, search, and documents

## Step 3: Configure Claims

1. **Go to Security > API > Authorization Servers**
2. **Select "default" authorization server**
3. **Add Claims**:
   
   **Groups Claim**:
   ```
   Name: groups
   Include in token type: ID Token, Access Token
   Value type: Groups
   Filter: Regex: .*
   Include in: Any scope
   ```

   **Note**: Only the `Onyx-Admins` group is used for role mapping. Users not in this group automatically get the basic user role.

## Step 4: Role Mapping Logic

Onyx uses simple group-to-role mapping:

- **If user is in `Onyx-Admins` group** → `ADMIN` role
- **If user is not in `Onyx-Admins` group** → `BASIC` role

This simplified approach eliminates complex permission hierarchies and makes user management straightforward.

## Step 5: Test Configuration

1. **Test Login Flow**
   - Use Okta preview to test login
   - Verify redirect URIs work correctly
   - Check that groups claim is included in tokens

2. **Validate JWT Tokens**
   - Use jwt.io to decode tokens
   - Verify groups claim contains expected groups
   - Check token expiration and audience

3. **Test Role Mapping**
   - Login with admin user (should be in `Onyx-Admins` group)
   - Login with regular user (should not be in admin group)
   - Verify correct roles are assigned in Onyx

## Environment Variables

After setup, configure these environment variables:

```bash
# Required Okta Configuration
OKTA_DOMAIN=your-org.okta.com
OKTA_CLIENT_ID=<from_okta_app>
OKTA_CLIENT_SECRET=<from_okta_app>
OIDC_WELL_KNOWN_URL=https://your-org.okta.com/oauth2/default/.well-known/openid-configuration

# Optional Configuration  
OKTA_GROUPS_CLAIM=groups  # Default: "groups"
OKTA_ADMIN_GROUP=Onyx-Admins  # Default: "Onyx-Admins"

# Simplified Permission Settings
OAUTH_PERMISSION_ENFORCEMENT=false  # Simple role-based auth only
OKTA_GROUP_PROCESSING_ENABLED=true   # Enable group-to-role mapping
```

## Troubleshooting

### Common Issues

1. **User not getting admin role**
   - Verify user is assigned to `Onyx-Admins` group in Okta
   - Check groups claim is included in token
   - Ensure group name matches exactly (`Onyx-Admins`)

2. **All users getting admin role**
   - Check that only intended users are in `Onyx-Admins` group
   - Verify group filtering in Okta application assignment

3. **Redirect URI mismatch**
   - Verify exact URL match in Okta config
   - Check protocol (http vs https)
   - Ensure no trailing slashes

4. **Token validation failures**
   - Check audience configuration
   - Verify issuer URL matches Okta domain
   - Ensure algorithm is RS256

### Validation Commands

```bash
# Test OIDC configuration
python backend/test_oidc_config.py

# Validate OAuth setup
python backend/scripts/validate_oauth_config.py
```

## Migration from Complex Permission System

If upgrading from a previous Onyx installation with complex permissions:

1. **Backup existing user roles** before migration
2. **Remove old permission groups** (Onyx-Writers, Onyx-Readers) from Okta
3. **Keep only Onyx-Admins group** for admin users
4. **Update environment variables** to disable complex permissions
5. **All non-admin users will default to BASIC role**

This simplified system provides better maintainability while preserving essential admin/user distinction.
