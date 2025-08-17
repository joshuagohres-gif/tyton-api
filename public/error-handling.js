/**
 * Tyton Error Handling & Graceful Fallbacks
 * Comprehensive error boundary system for better user experience
 */

class ErrorBoundary {
  constructor() {
    this.errors = [];
    this.retryAttempts = {};
    this.maxRetries = 3;
    this.retryDelay = 1000; // ms
    
    // Set up global error handlers
    this.setupGlobalErrorHandlers();
  }

  /**
   * Set up global error handlers for unhandled errors
   */
  setupGlobalErrorHandlers() {
    // Handle JavaScript errors
    window.addEventListener('error', (event) => {
      this.handleError({
        type: 'javascript',
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        error: event.error
      });
    });

    // Handle unhandled promise rejections
    window.addEventListener('unhandledrejection', (event) => {
      this.handleError({
        type: 'unhandled_promise',
        message: event.reason?.message || 'Unhandled promise rejection',
        reason: event.reason
      });
      event.preventDefault(); // Prevent browser console error
    });

    // Handle network connectivity issues
    window.addEventListener('online', () => {
      this.showToast('Connection restored', 'success');
      this.retryFailedRequests();
    });

    window.addEventListener('offline', () => {
      this.showToast('Connection lost. Operating in offline mode.', 'warning');
    });
  }

  /**
   * Main error handling function
   */
  handleError(errorInfo, context = {}) {
    const error = {
      ...errorInfo,
      context,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href
    };

    this.errors.push(error);
    console.error('Error captured by boundary:', error);

    // Show user-friendly error message
    this.showUserFriendlyError(error);
    
    // Log to server if possible
    this.logErrorToServer(error);
  }

  /**
   * Wrap async functions with error handling
   */
  async withErrorHandling(fn, fallback = null, context = {}) {
    try {
      return await fn();
    } catch (error) {
      this.handleError({
        type: 'function_error',
        message: error.message,
        stack: error.stack,
        name: error.name
      }, context);

      // Return fallback value or rethrow if no fallback
      if (fallback !== null) {
        return fallback;
      }
      throw error;
    }
  }

  /**
   * Retry failed network requests with exponential backoff
   */
  async retryWithBackoff(requestFn, maxRetries = this.maxRetries) {
    const requestId = Date.now() + Math.random();
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const result = await requestFn();
        // Success - clear retry count
        delete this.retryAttempts[requestId];
        return result;
      } catch (error) {
        if (attempt === maxRetries) {
          this.handleError({
            type: 'network_failure',
            message: `Request failed after ${maxRetries} attempts`,
            originalError: error.message
          });
          throw error;
        }

        // Wait before retry with exponential backoff
        const delay = this.retryDelay * Math.pow(2, attempt - 1);
        await this.sleep(delay);
        
        this.retryAttempts[requestId] = attempt;
      }
    }
  }

  /**
   * Show user-friendly error messages
   */
  showUserFriendlyError(error) {
    // Don't show errors for certain non-critical issues
    const silentErrors = ['data_loading_failed', 'dom_update_failed'];
    if (silentErrors.includes(error.type)) {
      return;
    }

    let message = 'Something went wrong. Please try again.';
    let type = 'error';

    switch (error.type) {
      case 'network_failure':
        message = 'Network connection issue. Please check your connection.';
        break;
      case 'authentication':
        message = 'Authentication failed. Please log in again.';
        break;
      case 'validation':
        message = error.message || 'Please check your input and try again.';
        break;
      case 'server_error':
        message = 'Server is currently unavailable. Please try again later.';
        break;
      case 'not_found':
        message = 'The requested content was not found.';
        break;
      case 'permission_denied':
        message = 'You don\'t have permission to perform this action.';
        break;
      default:
        // Only show generic error for truly unexpected errors
        if (error.type === 'javascript' || error.type === 'unhandled_promise') {
          console.error('Unexpected error:', error);
          return; // Don't show toast for JS errors
        }
        message = 'An unexpected error occurred. Please refresh the page.';
    }

    this.showToast(message, type);
  }

  /**
   * Safe toast notification (fallback to console if showToast not available)
   */
  showToast(message, type = 'error') {
    if (typeof window.showToast === 'function') {
      window.showToast(message, type);
    } else {
      // Fallback to console instead of alert to avoid disrupting user
      console.warn(`[${type.toUpperCase()}]: ${message}`);
    }
  }

  /**
   * Log errors to server for monitoring
   */
  async logErrorToServer(error) {
    try {
      // Only log to console for now - server endpoint not implemented yet
      if (this.isCriticalError(error)) {
        console.error('Critical error logged:', error);
        // Future: implement server-side error logging
        // await fetch('/api/errors', {
        //   method: 'POST',
        //   headers: { 'Content-Type': 'application/json' },
        //   body: JSON.stringify(error),
        //   credentials: 'include'
        // });
      }
    } catch (logError) {
      // Silently fail - don't create error loops
      console.warn('Failed to log error:', logError);
    }
  }

  /**
   * Determine if error is critical enough to log
   */
  isCriticalError(error) {
    const criticalTypes = [
      'javascript',
      'unhandled_promise',
      'network_failure',
      'authentication',
      'server_error'
    ];
    return criticalTypes.includes(error.type);
  }

  /**
   * Graceful data loading with fallbacks
   */
  async loadDataWithFallback(primarySource, fallbackData = []) {
    try {
      return await this.retryWithBackoff(primarySource);
    } catch (error) {
      this.handleError({
        type: 'data_loading_failed',
        message: 'Failed to load data, using cached version'
      });
      
      // Return fallback data or try to load from cache
      const cachedData = this.getFromCache(primarySource.name);
      return cachedData || fallbackData;
    }
  }

  /**
   * Safe DOM manipulation with fallbacks
   */
  safelyUpdateDOM(elementId, updateFn, fallbackContent = '') {
    try {
      const element = document.getElementById(elementId);
      if (!element) {
        throw new Error(`Element with ID '${elementId}' not found`);
      }
      
      updateFn(element);
    } catch (error) {
      this.handleError({
        type: 'dom_update_failed',
        message: `Failed to update element: ${elementId}`,
        originalError: error.message
      });

      // Try to set fallback content
      const element = document.getElementById(elementId);
      if (element && fallbackContent) {
        element.textContent = fallbackContent;
      }
    }
  }

  /**
   * Retry failed requests when connection is restored
   */
  retryFailedRequests() {
    // Implementation would retry stored failed requests
    console.log('Retrying failed requests...');
  }

  /**
   * Cache management for offline functionality
   */
  getFromCache(key) {
    try {
      const cached = localStorage.getItem(`cache_${key}`);
      return cached ? JSON.parse(cached) : null;
    } catch (error) {
      return null;
    }
  }

  setCache(key, data) {
    try {
      localStorage.setItem(`cache_${key}`, JSON.stringify(data));
    } catch (error) {
      // Storage might be full, silently fail
    }
  }

  /**
   * Utility function for delays
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get error summary for debugging
   */
  getErrorSummary() {
    return {
      totalErrors: this.errors.length,
      recentErrors: this.errors.slice(-10),
      errorTypes: this.errors.reduce((acc, error) => {
        acc[error.type] = (acc[error.type] || 0) + 1;
        return acc;
      }, {})
    };
  }
}

// Global error boundary instance
const errorBoundary = new ErrorBoundary();

// Utility functions for easy use throughout the app
function safeAsyncCall(fn, fallback = null, context = {}) {
  return errorBoundary.withErrorHandling(fn, fallback, context);
}

function safeDOMUpdate(elementId, updateFn, fallbackContent = '') {
  return errorBoundary.safelyUpdateDOM(elementId, updateFn, fallbackContent);
}

function loadWithFallback(dataLoader, fallbackData = []) {
  return errorBoundary.loadDataWithFallback(dataLoader, fallbackData);
}

// Enhanced fetch with automatic error handling and retries
async function safeFetch(url, options = {}) {
  try {
    return await errorBoundary.retryWithBackoff(async () => {
      const response = await fetch(url, options);
      
      if (!response.ok) {
        const errorType = response.status >= 500 ? 'server_error' : 
                         response.status === 404 ? 'not_found' :
                         response.status === 403 ? 'permission_denied' :
                         response.status === 401 ? 'authentication' : 'request_failed';
        
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return response;
    });
  } catch (error) {
    // Don't re-throw network errors, just log them
    console.error('safeFetch error:', error);
    throw error;
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ErrorBoundary, errorBoundary };
}