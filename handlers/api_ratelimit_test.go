package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"stockex/auth"
	"stockex/config"
	"stockex/db"
	"stockex/i18n"
	"testing"
)

func TestAPISignupRateLimiting(t *testing.T) {
	// Setup
	config.AppConfig = config.Config{
		SessionKey: "test-session-key-must-be-32-bytes-long",
	}
	db.InitDB(":memory:")
	auth.InitStore()
	i18n.LoadTranslations("../i18n")

	// Helper to send signup request
	sendSignup := func(username string, ip string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{
			"username": username,
			"password": "strongpassword123",
		})
		req := httptest.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":12345"
		w := httptest.NewRecorder()
		APISignupHandler(w, req)
		return w
	}

	ip := "192.168.1.100"

	// 1. Send 5 successful signups
	for i := 0; i < 5; i++ {
		w := sendSignup("user"+string(rune('a'+i)), ip)
		if w.Code != http.StatusCreated {
			t.Fatalf("Expected created, got %d. Body: %s", w.Code, w.Body.String())
		}
	}

	// 2. Send 6th signup -> Should be rate limited
	w := sendSignup("user_blocked", ip)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 Too Many Requests, got %d", w.Code)
	}

	// 3. Different IP should still work
	w2 := sendSignup("user_other_ip", "10.0.0.5")
	if w2.Code != http.StatusCreated {
		t.Errorf("Expected created for different IP, got %d", w2.Code)
	}
}
