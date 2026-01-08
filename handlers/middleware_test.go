package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	// Create a dummy handler that the middleware will wrap
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap the dummy handler with the middleware
	middleware := SecurityHeadersMiddleware(dummyHandler)

	// Create a test request
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	// Serve the request
	middleware.ServeHTTP(rr, req)

	// Check for expected headers
	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "SAMEORIGIN",
		"X-XSS-Protection":       "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	for key, expectedValue := range expectedHeaders {
		if value := rr.Header().Get(key); value != expectedValue {
			t.Errorf("Header %s: expected %s, got %s", key, expectedValue, value)
		}
	}

	// Verify CSP
	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Expected Content-Security-Policy header, got empty")
	}

	expectedDirectives := []string{
		"default-src 'self'",
		"script-src 'self' 'unsafe-inline' https://unpkg.com",
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
		"font-src 'self' https://fonts.gstatic.com",
	}

	for _, directive := range expectedDirectives {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing directive: %s. Got: %s", directive, csp)
		}
	}

	// Ensure the handler was actually called
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", rr.Code)
	}
}

func TestCORSMiddleware(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := CORSMiddleware(dummyHandler)

	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "http://example.com")
	rr := httptest.NewRecorder()

	middleware.ServeHTTP(rr, req)

	if val := rr.Header().Get("Access-Control-Allow-Origin"); val != "http://example.com" {
		t.Errorf("Expected Access-Control-Allow-Origin to be http://example.com, got %s", val)
	}

	if val := rr.Header().Get("Access-Control-Allow-Methods"); val != "POST, GET, OPTIONS, PUT, DELETE" {
		t.Errorf("Unexpected Access-Control-Allow-Methods: %s", val)
	}
}
