/**
 * Tyton Authentication Utilities
 * Standardized authentication handling across all pages
 */

class TytonAuth {
  constructor() {
    this.token = localStorage.getItem('tyton_auth_token');
    this.currentUser = null;
  }

  /**
   * Get authentication headers for API requests
   * Supports both Bearer token and session-based auth
   */
  getAuthHeaders() {
    const headers = {};
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  /**
   * Make authenticated API request with automatic token refresh and error handling
   */
  async authFetch(url, options = {}) {
    const headers = {
      ...this.getAuthHeaders(),
      ...(options.headers || {})
    };

    // Use safeFetch if available, otherwise use regular fetch
    const fetchFn = typeof safeFetch !== 'undefined' ? safeFetch : fetch;

    try {
      const response = await fetchFn(url, {
        ...options,
        headers,
        credentials: 'include' // Enable session-based auth fallback
      });

      // Handle token expiration
      if (response.status === 401 && this.token) {
        console.log('Token expired, attempting to refresh...');
        await this.refreshAuth();
        
        // Retry request with potentially new token
        const retryHeaders = {
          ...this.getAuthHeaders(),
          ...(options.headers || {})
        };
        
        return fetchFn(url, {
          ...options,
          headers: retryHeaders,
          credentials: 'include'
        });
      }

      return response;
    } catch (error) {
      // Handle network errors gracefully
      if (typeof errorBoundary !== 'undefined') {
        errorBoundary.handleError({
          type: 'authentication',
          message: `Auth request failed: ${error.message}`,
          url: url
        });
      }
      throw error;
    }
  }

  /**
   * Check and refresh authentication status
   */
  async refreshAuth() {
    try {
      const response = await fetch('/auth/me', {
        headers: this.getAuthHeaders(),
        credentials: 'include'
      });

      if (response.ok) {
        const data = await response.json();
        this.currentUser = data.user || data;
        
        // If response includes a new token, store it
        if (data.token && data.token !== this.token) {
          this.setToken(data.token);
        }
        
        return true;
      } else {
        // Auth failed, clear stored token
        this.clearAuth();
        return false;
      }
    } catch (error) {
      console.error('Auth refresh failed:', error);
      this.clearAuth();
      return false;
    }
  }

  /**
   * Set authentication token
   */
  setToken(token) {
    this.token = token;
    if (token) {
      localStorage.setItem('tyton_auth_token', token);
    } else {
      localStorage.removeItem('tyton_auth_token');
    }
  }

  /**
   * Clear authentication state
   */
  clearAuth() {
    this.token = null;
    this.currentUser = null;
    localStorage.removeItem('tyton_auth_token');
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated() {
    return !!(this.token || this.currentUser);
  }

  /**
   * Get current user or attempt to load from server
   */
  async getCurrentUser() {
    if (this.currentUser) {
      return this.currentUser;
    }

    const isAuth = await this.refreshAuth();
    return isAuth ? this.currentUser : null;
  }

  /**
   * Handle URL-based token (for setup/profile pages)
   */
  handleUrlToken() {
    const urlParams = new URLSearchParams(window.location.search);
    const urlToken = urlParams.get('token');
    
    if (urlToken && urlToken !== this.token) {
      this.setToken(urlToken);
      // Clean URL without reloading
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }

  /**
   * Show authentication error toast
   */
  showAuthError(message = 'Please log in to continue') {
    if (typeof showToast === 'function') {
      showToast(message, 'error');
    } else {
      alert(message);
    }
  }

  /**
   * Redirect to login if not authenticated
   */
  requireAuth(redirectMessage = 'Please log in to access this feature') {
    if (!this.isAuthenticated()) {
      this.showAuthError(redirectMessage);
      setTimeout(() => {
        window.location.href = '/';
      }, 2000);
      return false;
    }
    return true;
  }
}

// Global auth instance
const tytonAuth = new TytonAuth();

// Expose for compatibility with existing code
function getAuthHeaders() {
  return tytonAuth.getAuthHeaders();
}

function isAuthenticated() {
  return tytonAuth.isAuthenticated();
}

async function getCurrentUser() {
  return await tytonAuth.getCurrentUser();
}