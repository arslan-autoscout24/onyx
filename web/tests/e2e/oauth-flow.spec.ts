/**
 * End-to-End OAuth Authorization Flow Tests
 * 
 * This file contains comprehensive end-to-end tests for the OAuth authorization system,
 * testing the complete user journey from login through role-based UI interactions.
 */

import { test, expect } from '@playwright/test';
import { Page } from 'playwright';

// Mock user data for different roles
const TEST_USERS = {
  admin: {
    email: 'admin@test.com',
    role: 'admin',
    groups: ['Onyx-Admins']
  },
  user: {
    email: 'user@test.com',
    role: 'user',
    groups: ['Onyx-Users']
  }
};

// Helper function to mock OAuth callback
async function mockOAuthCallback(page: Page, user: any) {
  await page.route('**/auth/callback', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        user: user,
        token: 'mock_jwt_token_' + user.email.replace('@', '_').replace('.', '_')
      })
    });
  });
}

// Helper function to mock API endpoints with role checks
async function mockAPIEndpoints(page: Page, userRole: string) {
  // Mock documents endpoint
  await page.route('**/api/documents**', async route => {
    const method = route.request().method();
    
    if (method === 'GET') {
      // All authenticated users can read
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          documents: [
            { id: 1, title: 'Test Document', content: 'Sample content' }
          ]
        })
      });
    } else if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
      // Only admins can modify documents in this simplified system
      if (userRole === 'admin') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ success: true })
        });
      } else {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            detail: { error: 'admin_permission_required' }
          })
        });
      }
    }
  });

  // Mock admin endpoints
  await page.route('**/api/admin/**', async route => {
    if (userRole === 'admin') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          users: [{ id: 1, email: 'user@test.com' }],
          settings: { key: 'value' }
        })
      });
    } else {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({
          detail: { error: 'admin_permission_required' }
        })
      });
    }
  });

  // Mock chat endpoints
  await page.route('**/api/chat-sessions**', async route => {
    const method = route.request().method();
    
    if (method === 'GET') {
      // All authenticated users can read
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          sessions: [
            { id: 1, name: 'Test Chat', description: 'Sample chat session' }
          ]
        })
      });
    } else if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
      // All authenticated users can modify their own chat sessions
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true })
      });
    }
  });
}

test.describe('OAuth Authorization Flow', () => {
  test('complete login flow with admin user', async ({ page }) => {
    // Setup mock for admin user
    await mockOAuthCallback(page, TEST_USERS.admin);
    await mockAPIEndpoints(page, TEST_USERS.admin.role);
    
    // Navigate to login page
    await page.goto('/login');
    
    // Click login button (this would normally redirect to Okta)
    await page.click('[data-testid="login-button"]');
    
    // Verify successful login and redirect to dashboard
    await expect(page).toHaveURL('/dashboard');
    
    // Verify user info is displayed
    await expect(page.locator('[data-testid="user-email"]')).toContainText('admin@test.com');
    
    // Verify admin can access admin endpoints
    await page.goto('/admin/users');
    await expect(page.locator('[data-testid="admin-panel"]')).toBeVisible();
    
    // Verify admin can create documents
    await page.goto('/documents/create');
    await expect(page.locator('[data-testid="create-document-form"]')).toBeVisible();
  });

  test('complete login flow with regular user', async ({ page }) => {
    // Setup mock for regular user
    await mockOAuthCallback(page, TEST_USERS.user);
    await mockAPIEndpoints(page, TEST_USERS.user.role);
    
    // Navigate to login page
    await page.goto('/login');
    
    // Click login button (this would normally redirect to Okta)
    await page.click('[data-testid="login-button"]');
    
    // Verify successful login and redirect to dashboard
    await expect(page).toHaveURL('/dashboard');
    
    // Verify user info is displayed
    await expect(page.locator('[data-testid="user-email"]')).toContainText('user@test.com');
    
    // Verify regular user cannot access admin endpoints
    await page.goto('/admin/users');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('admin_permission_required');
    
    // Verify regular user can still access documents for reading
    await page.goto('/documents');
    await expect(page.locator('[data-testid="documents-list"]')).toBeVisible();
  });

  test('admin role assignment through OAuth groups', async ({ page }) => {
    // Setup mock for admin user
    await mockOAuthCallback(page, TEST_USERS.admin);
    await mockAPIEndpoints(page, TEST_USERS.admin.role);
    
    // Mock the user context endpoint
    await page.addInitScript((user) => {
      // @ts-ignore
      window.mockUser = user;
    }, TEST_USERS.admin);
    
    // Navigate to protected page
    await page.goto('/admin/settings');
    
    // Verify admin access is granted
    await expect(page.locator('[data-testid="admin-settings"]')).toBeVisible();
  });

  test('user role assignment through OAuth groups', async ({ page }) => {
    // Setup mock for regular user
    await mockOAuthCallback(page, TEST_USERS.user);
    await mockAPIEndpoints(page, TEST_USERS.user.role);
    
    // Mock the user context endpoint
    await page.addInitScript((user) => {
      // @ts-ignore
      window.mockUser = user;
    }, TEST_USERS.user);
    
    // Navigate to protected page that requires admin
    await page.goto('/admin/settings');
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied"]')).toBeVisible();
  });

  test('API endpoint role enforcement', async ({ page }) => {
    // Setup mock for admin user
    await mockOAuthCallback(page, TEST_USERS.admin);
    await mockAPIEndpoints(page, TEST_USERS.admin.role);
    
    // Mock the user context endpoint
    await page.addInitScript((user) => {
      // @ts-ignore
      window.mockUser = user;
    }, TEST_USERS.admin);
    
    // Test admin can access admin endpoints
    const response = await page.request.get('/api/admin/users');
    expect(response.status()).toBe(200);
    
    // Test admin can modify documents
    const docResponse = await page.request.post('/api/documents', {
      data: { title: 'Test Document', content: 'Test content' }
    });
    expect(docResponse.status()).toBe(200);
  });

  test('OAuth callback with invalid user', async ({ page }) => {
    // Setup mock for invalid user (no groups)
    const invalidUser = {
      email: 'invalid@test.com',
      role: 'user', // Default role
      groups: []
    };
    
    await mockOAuthCallback(page, invalidUser);
    await mockAPIEndpoints(page, invalidUser.role);
    
    // Navigate to login page
    await page.goto('/login');
    
    // Click login button
    await page.click('[data-testid="login-button"]');
    
    // Verify user is assigned default role
    await expect(page).toHaveURL('/dashboard');
    await expect(page.locator('[data-testid="user-email"]')).toContainText('invalid@test.com');
    
    // Verify default role restrictions
    await page.goto('/admin/users');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('admin_permission_required');
  });

  test('logout functionality', async ({ page }) => {
    // Setup mock for admin user
    await mockOAuthCallback(page, TEST_USERS.admin);
    await mockAPIEndpoints(page, TEST_USERS.admin.role);
    
    // Login first
    await page.goto('/login');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL('/dashboard');
    
    // Click logout
    await page.click('[data-testid="logout-button"]');
    
    // Verify redirect to login page
    await expect(page).toHaveURL('/login');
    
    // Verify user session is cleared
    await expect(page.locator('[data-testid="user-email"]')).not.toBeVisible();
  });
});

test.describe('OAuth Error Handling', () => {
  test('handles OAuth callback errors gracefully', async ({ page }) => {
    // Mock failed OAuth callback
    await page.route('**/auth/callback', async route => {
      await route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'invalid_token',
          error_description: 'The provided token is invalid'
        })
      });
    });
    
    // Navigate to login page
    await page.goto('/login');
    
    // Click login button
    await page.click('[data-testid="login-button"]');
    
    // Verify error handling
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Authentication failed');
  });

  test('handles network errors during OAuth flow', async ({ page }) => {
    // Mock network error
    await page.route('**/auth/callback', async route => {
      await route.abort('failed');
    });
    
    // Navigate to login page
    await page.goto('/login');
    
    // Click login button
    await page.click('[data-testid="login-button"]');
    
    // Verify error handling
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Network error');
  });
});

test.describe('Role-Based UI Elements', () => {
  test('admin sees admin-only navigation items', async ({ page }) => {
    // Setup mock for admin user
    await mockOAuthCallback(page, TEST_USERS.admin);
    await mockAPIEndpoints(page, TEST_USERS.admin.role);
    
    // Login and navigate to dashboard
    await page.goto('/login');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL('/dashboard');
    
    // Verify admin navigation items are visible
    await expect(page.locator('[data-testid="admin-nav-item"]')).toBeVisible();
    await expect(page.locator('[data-testid="user-management-nav"]')).toBeVisible();
    await expect(page.locator('[data-testid="system-settings-nav"]')).toBeVisible();
  });

  test('regular user does not see admin navigation items', async ({ page }) => {
    // Setup mock for regular user
    await mockOAuthCallback(page, TEST_USERS.user);
    await mockAPIEndpoints(page, TEST_USERS.user.role);
    
    // Login and navigate to dashboard
    await page.goto('/login');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL('/dashboard');
    
    // Verify admin navigation items are hidden
    await expect(page.locator('[data-testid="admin-nav-item"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="user-management-nav"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="system-settings-nav"]')).not.toBeVisible();
  });
});
