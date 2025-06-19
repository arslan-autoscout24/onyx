# OAuth Configuration Scripts

This directory contains scripts for configuring and validating OAuth/Okta integration.

## Scripts

### `validate_oauth_config.py`
Validates the OAuth/Okta configuration including:
- Environment variables
- Okta domain accessibility
- OIDC configuration
- Group mappings

**Usage:**
```bash
python scripts/validate_oauth_config.py
```

### `test_jwt_parsing.py`
Tests JWT token parsing and group extraction logic.

**Usage:**
```bash
python scripts/test_jwt_parsing.py
```

## Prerequisites

Before running these scripts, ensure you have:

1. **Environment Variables Set:**
   - Copy `backend/.env.example` to `backend/.env`
   - Fill in your Okta configuration values

2. **Okta Application Configured:**
   - Follow the setup guide in `docs/OKTA_SETUP.md`
   - Ensure groups claim is configured

3. **Network Access:**
   - Scripts need to reach your Okta domain
   - Ensure firewall allows HTTPS to `*.okta.com`

## Environment Variables

Required environment variables:
- `OKTA_DOMAIN` - Your Okta organization domain
- `OKTA_CLIENT_ID` - OAuth application client ID  
- `OKTA_CLIENT_SECRET` - OAuth application client secret
- `OIDC_WELL_KNOWN_URL` - Okta OIDC discovery URL

Optional configuration:
- `OKTA_GROUPS_CLAIM` - JWT claim name for groups (default: "groups")
- `OKTA_ADMIN_GROUP` - Admin group name (default: "Onyx-Admins")
- `OKTA_WRITE_GROUP` - Writer group name (default: "Onyx-Writers")  
- `OKTA_READ_GROUP` - Reader group name (default: "Onyx-Readers")

## Troubleshooting

### Common Issues

1. **Missing environment variables**
   - Check that all required variables are set in `.env`
   - Verify variable names match exactly

2. **Network connectivity**
   - Ensure you can reach your Okta domain
   - Check corporate firewall settings

3. **Okta configuration**
   - Verify application settings in Okta admin console
   - Check that groups claim is configured
   - Ensure redirect URIs match

### Getting Help

1. Check the main documentation: `docs/OKTA_SETUP.md`
2. Review the configuration templates in `deployment/configs/`
3. Examine the unit tests for expected behavior
