# Okta Application Setup Guide

## Prerequisites

- Okta Administrator access
- Onyx application domain/URL
- Understanding of OAuth 2.0 flow

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
     - http://localhost:3000/auth/logout (development) 
     - https://your-domain.com/auth/logout (production)
   ```

4. **Assignments**
   - Assign to appropriate users/groups
   - Configure group assignments for permissions

## Step 2: Configure Groups

Create the following groups in Okta:

### Onyx-Admins
- **Description**: Full administrative access to Onyx platform
- **Members**: System administrators only
- **Permissions**: Can manage connectors, users, system settings

### Onyx-Writers  
- **Description**: Read and write access to Onyx platform
- **Members**: Content creators, document managers
- **Permissions**: Can create/edit documents, manage chat sessions

### Onyx-Readers
- **Description**: Read-only access to Onyx platform  
- **Members**: General users, viewers
- **Permissions**: Can view documents, participate in chat

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

## Step 4: Test Configuration

1. **Test Login Flow**
   - Use Okta preview to test login
   - Verify redirect URIs work correctly
   - Check that groups claim is included in tokens

2. **Validate JWT Tokens**
   - Use jwt.io to decode tokens
   - Verify groups claim contains expected groups
   - Check token expiration and audience

## Environment Variables

After setup, configure these environment variables:

```bash
OKTA_DOMAIN=your-org.okta.com
OKTA_CLIENT_ID=<from_okta_app>
OKTA_CLIENT_SECRET=<from_okta_app>
OKTA_GROUPS_CLAIM=groups
OIDC_WELL_KNOWN_URL=https://your-org.okta.com/oauth2/default/.well-known/openid-configuration
```

## Troubleshooting

### Common Issues

1. **Groups not appearing in token**
   - Check groups claim configuration
   - Verify user is assigned to groups
   - Ensure claim is included in token type

2. **Redirect URI mismatch**
   - Verify exact URL match in Okta config
   - Check protocol (http vs https)
   - Ensure no trailing slashes

3. **Token validation failures**
   - Check audience configuration
   - Verify issuer URL
   - Ensure algorithm matches (RS256)

### Validation Commands

```bash
# Validate configuration
python backend/scripts/validate_oauth_config.py

# Test token decoding
python backend/scripts/test_jwt_parsing.py
```
