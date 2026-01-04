package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"stockex/auth"
	"stockex/db"
)

func TestWeakPasswordVulnerability(t *testing.T) {
	// Initialize in-memory DB
	db.InitDB(":memory:")
	defer db.DB.Close()
	auth.InitStore()

	// Initialize handlers
	mux := http.NewServeMux()
	RegisterHandlers(mux)

	// Test Case: Create user with 1-char password
	t.Run("Create user with weak password", func(t *testing.T) {
		payload := `{"username": "weakuser", "password": "1"}`
		req := httptest.NewRequest("POST", "/api/v1/signup", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		if w.Code == http.StatusBadRequest {
			t.Logf("Security Fix Verified: Weak password rejected (status 400)")
		} else {
			t.Errorf("Expected status 400 Bad Request, got %d", w.Code)
		}

		// Verify NOT in DB
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'weakuser'").Scan(&count)
		if count != 0 {
			t.Errorf("Expected user NOT to be created in DB, found %d", count)
		}
	})

	// Test Case: Create user with strong password
	t.Run("Create user with strong password", func(t *testing.T) {
		payload := `{"username": "stronguser", "password": "correcthorsebatterystaple"}`
		req := httptest.NewRequest("POST", "/api/v1/signup", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected status 201 Created, got %d", w.Code)
		}

		// Verify in DB
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'stronguser'").Scan(&count)
		if count != 1 {
			t.Errorf("Expected user to be created in DB, found %d", count)
		}
	})
}
