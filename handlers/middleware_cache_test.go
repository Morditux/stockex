package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCacheControlHeaders(t *testing.T) {
	// Create a dummy handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Wrap with SecurityHeadersMiddleware
	middleware := SecurityHeadersMiddleware(handler)

	// Test case 1: Dynamic page
	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, req)

	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("Expected Cache-Control: no-store for /dashboard, got %q", cc)
	}

	// Test case 2: Static file
	req = httptest.NewRequest("GET", "/static/style.css", nil)
	w = httptest.NewRecorder()
	middleware.ServeHTTP(w, req)

	cc = w.Header().Get("Cache-Control")
	if strings.Contains(cc, "no-store") {
		t.Errorf("Expected NO Cache-Control: no-store for /static/style.css, got %q", cc)
	}
}
