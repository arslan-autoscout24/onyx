/**
 * End-to-End OAuth Authorization Flow Tests
 * 
 * This file contains comprehensive end-to-end tests for the OAuth authorization system,
 * testing the complete user journey from login through permission-gated UI interactions.
 */

import { test, expect } from '@playwright/test';
import { Page } from 'playwright';

// Mock user data for different permission levels
const TEST_USERS = {
  admin: {
    email: 'admin@test.com',
    permission_level: 'admin',
    groups: ['Onyx-Admins', 'Onyx-Writers', 'Onyx-Readers']
  },
  writer: {
    email: 'writer@test.com', 
    permission_level: 'write',
    groups: ['Onyx-Writers', 'Onyx-Readers']
  },
  reader: {
    email: 'reader@test.com',
    permission_level: 'read',
    groups: ['Onyx-Readers']
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

// Helper function to mock API endpoints with permission checks
async function mockAPIEndpoints(page: Page, userPermissionLevel: string) {
  // Mock documents endpoint
  await page.route('**/api/documents**', async route => {
    const method = route.request().method();
    
    if (method === 'GET') {
      // All users can read
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
      // Only writers and admins can modify
      if (userPermissionLevel === 'read') {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            detail: { error: 'write_permission_required' }
          })
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ success: true })
        });
      }
    }
  });

  // Mock admin endpoints
  await page.route('**/api/admin/**', async route => {
    if (userPermissionLevel === 'admin') {
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
      // All users can read
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
      // Only writers and admins can modify
      if (userPermissionLevel === 'read') {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            detail: { error: 'write_permission_required' }
          })
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ success: true })
        });
      }
    }
  });
}

test.describe('OAuth Authorization Flow', () => {
  test('complete login flow with admin user', async ({ page }) => {
    // Setup mock for admin user
    await mockOAuthCallback(page, TEST_USERS.admin);
    await mockAPIEndpoints(page, TEST_USERS.admin.permission_level);
    
    // Navigate to login page
    await page.goto('/login');
    
    // Click login button (this would normally redirect to Okta)
    await page.click('[data-testid="login-button"]');
    
    // Should redirect to dashboard after successful login
    await expect(page).toHaveURL(/dashboard/);
    
    // Verify admin dashboard access
    await expect(page.locator('[data-testid="admin-panel"]')).toBeVisible({
      timeout: 10000
    });
    
    // Verify admin menu is available
    await expect(page.locator('[data-testid="admin-menu"]')).toBeVisible();
    
    // Verify user info is displayed
    await expect(page.locator('text=' + TEST_USERS.admin.email)).toBeVisible();
  });

  test('complete login flow with writer user', async ({ page }) => {
    // Setup mock for writer user
    await mockOAuthCallback(page, TEST_USERS.writer);
    await mockAPIEndpoints(page, TEST_USERS.writer.permission_level);
    
    await page.goto('/login');
    await page.click('[data-testid="login-button"]');
    
    // Should redirect to dashboard
    await expect(page).toHaveURL(/dashboard/);
    
    // Writer should see write functionality but not admin
    await expect(page.locator('[data-testid="create-document"]')).toBeVisible({
      timeout: 10000
    });
    await expect(page.locator('[data-testid="admin-panel"]')).toBeHidden();
  });

  test('complete login flow with reader user', async ({ page }) => {
    // Setup mock for reader user
    await mockOAuthCallback(page, TEST_USERS.reader);
    await mockAPIEndpoints(page, TEST_USERS.reader.permission_level);
    
    await page.goto('/login');
    await page.click('[data-testid="login-button"]');
    
    // Should redirect to dashboard
    await expect(page).toHaveURL(/dashboard/);
    
    // Reader should only see read functionality
    await expect(page.locator('[data-testid="document-list"]')).toBeVisible({
      timeout: 10000
    });
    await expect(page.locator('[data-testid="create-document"]')).toBeHidden();
    await expect(page.locator('[data-testid="admin-panel"]')).toBeHidden();
  });
});

test.describe('Permission-Gated UI Elements', () => {
  test('admin user sees all UI elements', async ({ page }) => {
    await mockOAuthCallback(page, TEST_USERS.admin);
    await mockAPIEndpoints(page, TEST_USERS.admin.permission_level);
    
    // Set user context before page load
    await page.addInitScript((user) => {
      window.mockUser = user;
    }, TEST_USERS.admin);
    
    await page.goto('/dashboard');
    
    // Admin should see everything
    await expect(page.locator('[data-testid="admin-menu"]')).toBeVisible();
    await expect(page.locator('[data-testid="create-document"]')).toBeVisible();
    await expect(page.locator('[data-testid="document-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="user-management"]')).toBeVisible();
    await expect(page.locator('[data-testid="system-settings"]')).toBeVisible();
  });

  test('writer user sees write elements but not admin', async ({ page }) => {
    await mockOAuthCallback(page, TEST_USERS.writer);
    await mockAPIEndpoints(page, TEST_USERS.writer.permission_level);
    
    await page.addInitScript((user) => {
      window.mockUser = user;
    }, TEST_USERS.writer);
    
    await page.goto('/dashboard');
    
    // Writer should see write elements but not admin
    await expect(page.locator('[data-testid="create-document"]')).toBeVisible();
    await expect(page.locator('[data-testid="document-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="edit-document"]')).toBeVisible();
    
    // Admin elements should be hidden
    await expect(page.locator('[data-testid="admin-menu"]')).toBeHidden();
    await expect(page.locator('[data-testid="user-management"]')).toBeHidden();
    await expect(page.locator('[data-testid="system-settings"]')).toBeHidden();
  });

  test('reader user only sees read elements', async ({ page }) => {
    await mockOAuthCallback(page, TEST_USERS.reader);
    await mockAPIEndpoints(page, TEST_USERS.reader.permission_level);
    
    await page.addInitScript((user) => {
      window.mockUser = user;
    }, TEST_USERS.reader);
    
    await page.goto('/dashboard');
    
    // Reader should only see read elements
    await expect(page.locator('[data-testid="document-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="search-documents"]')).toBeVisible();
    
    // Write and admin elements should be hidden
    await expect(page.locator('[data-testid="create-document"]')).toBeHidden();
    await expect(page.locator('[data-testid="edit-document"]')).toBeHidden();
    await expect(page.locator('[data-testid="admin-menu"]')).toBeHidden();
    await expect(page.locator('[data-testid="user-management"]')).toBeHidden();
  });
});

test.describe('API Permission Enforcement', () => {
  test('admin can access all API endpoints', async ({ page }) => {
    await mockOAuthCallback(page, TEST_USERS.admin);
    await mockAPIEndpoints(page, TEST_USERS.admin.permission_level);
    
    await page.addInitScript((user) => {
      window.mockUser = user;
    }, TEST_USERS.admin);
    
    await page.goto('/dashboard');
    
    // Test admin API access
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="user-management"]');
    
    // Should successfully load admin data
    await expect(page.locator('[data-testid="user-list"]')).toBeVisible({
      timeout: 10000
    });
    
    // Test document creation
    await page.click('[data-testid="create-document"]');
    await page.fill('[data-testid="document-title"]', 'Admin Test Document');
    await page.fill('[data-testid="document-content"]', 'Test content');
    await page.click('[data-testid="save-document"]');
    
    // Should show success message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
  });

  test('writer can create but not access admin endpoints', async ({ page }) => {
    await mockOAuthCallback(page, TEST_USERS.writer);
    await mockAPIEndpoints(page, TEST_USERS.writer.permission_level);
    
    await page.addInitScript((user) => {
      window.mockUser = user;
    }, TEST_USERS.writer);
    
    await page.goto('/dashboard');
    
    // Test document creation (should work)
    await page.click('[data-testid="create-document"]');
    await page.fill('[data-testid="document-title"]', 'Writer Test Document');
    await page.fill('[data-testid="document-content"]', 'Writer content');
    await page.click('[data-testid="save-document"]');
    
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    
    // Test direct admin URL access (should be blocked)
    await page.goto('/admin/users');
    await expect(page.locator('[data-testid="permission-denied"]')).toBeVisible();
  });

  test('reader cannot create or modify content', async ({ page }) => {
    await mockOAuthCallback(page, TEST_USERS.reader);
    await mockAPIEndpoints(page, TEST_USERS.reader.permission_level);
    
    await page.addInitScript((user) => {
      window.mockUser = user;
    }, TEST_USERS.reader);
    
    await page.goto('/dashboard');
    
    // Reader should be able to view documents
    await expect(page.locator('[data-testid="document-list"]')).toBeVisible();
    
    // But should not be able to create
    await expect(page.locator('[data-testid="create-document"]')).toBeHidden();
    
    // Test direct creation URL access (should be blocked)
    await page.goto('/documents/create');
    await expect(page.locator('[data-testid="permission-denied"]')).toBeVisible();
  });
});

test.describe('Cross-Browser OAuth Flow', () => {
  test('OAuth works in Chrome', async ({ page, browserName }) => {
    test.skip(browserName !== 'chromium', 'This test is for Chrome only');
    
    await mockOAuthCallback(page, TEST_USERS.admin);
    await mockAPIEndpoints(page, TEST_USERS.admin.permission_level);
    
    await page.goto('/login');
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/dashboard/);
    await expect(page.locator('[data-testid="admin-panel"]')).toBeVisible();
  });

  test('OAuth works in Firefox', async ({ page, browserName }) => {
    test.skip(browserName !== 'firefox', 'This test is for Firefox only');
    
    await mockOAuthCallback(page, TEST_USERS.admin);
    await mockAPIEndpoints(page, TEST_USERS.admin.permission_level);
    
    await page.goto('/login');
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/dashboard/);
    await expect(page.locator('[data-testid="admin-panel"]')).toBeVisible();
  });
});

test.describe('Mobile Responsiveness', () => {
  test('OAuth flow works on mobile viewport', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    await mockOAuthCallback(page, TEST_USERS.reader);
    await mockAPIEndpoints(page, TEST_USERS.reader.permission_level);
    
    await page.goto('/login');
    
    // Login button should be visible and clickable on mobile
    await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(/dashboard/);
    
    // Mobile navigation should work
    await expect(page.locator('[data-testid="mobile-menu"]')).toBeVisible();
    await page.click('[data-testid="mobile-menu"]');
    await expect(page.locator('[data-testid="mobile-nav"]')).toBeVisible();
  });

  test('permission-gated elements responsive on tablet', async ({ page }) => {
    // Set tablet viewport
    await page.setViewportSize({ width: 768, height: 1024 });
    
    await mockOAuthCallback(page, TEST_USERS.writer);
    await mockAPIEndpoints(page, TEST_USERS.writer.permission_level);
    
    await page.addInitScript((user) => {
      window.mockUser = user;
    }, TEST_USERS.writer);
    
    await page.goto('/dashboard');
    
    // Elements should be properly sized for tablet
    await expect(page.locator('[data-testid="document-list"]')).toBeVisible();
    await expect(page.locator('[data-testid="create-document"]')).toBeVisible();
    
    // Check responsive grid layout
    const documentCards = page.locator('[data-testid="document-card"]');
    await expect(documentCards).toHaveCount(1); // Assuming mock returns 1 document
  });
});
