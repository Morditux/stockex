package auth

import (
	"bytes"
	"net/http/httptest"
	"os"
	"stockex/config"
	"stockex/db"
	"testing"
)

func TestMain(m *testing.M) {
	// Setup
	dbPath := "./test_auth.db"
	db.InitDB(dbPath)
	config.AppConfig.SessionKey = "test-secret-key-12345678901234567890123456789012"
	InitStore()

	// Run tests
	code := m.Run()

	// Teardown
	db.DB.Close()
	os.Remove(dbPath)

	os.Exit(code)
}

func TestSessionManagement(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	userID := 42
	role := "user"
	masterKey := []byte("test-master-key")

	// Set session
	SetSession(w, r, userID, role, masterKey)

	// Since SetSession modifies the response (cookies), we need to pass them back in a new request
	cookies := w.Result().Cookies()
	r2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		r2.AddCookie(c)
	}

	// Verify session values
	if GetUserID(r2) != userID {
		t.Errorf("Expected userID %d, got %d", userID, GetUserID(r2))
	}
	if !IsAdmin(r2) && role == "admin" {
		t.Error("IsAdmin returned false for admin role")
	}
	if IsAdmin(r2) && role == "user" {
		t.Error("IsAdmin returned true for user role")
	}

	retrievedKey := GetMasterKey(r2)
	if !bytes.Equal(retrievedKey, masterKey) {
		t.Errorf("Expected masterKey %v, got %v", masterKey, retrievedKey)
	}
}

func TestAPITokenPersistence(t *testing.T) {
	userID := 100
	role := "mobile-user"
	masterKey := []byte("mobile-master-key")

	token := CreateAPIToken(userID, role, masterKey)
	if token == "" {
		t.Fatal("Failed to create API token")
	}

	sess, ok := GetAPISession(token)
	if !ok {
		t.Error("Failed to retrieve API session by token")
	}

	if sess.UserID != userID {
		t.Errorf("Expected userID %d, got %d", userID, sess.UserID)
	}
	if sess.Role != role {
		t.Errorf("Expected role %s, got %s", role, sess.Role)
	}
	if !bytes.Equal(sess.MasterKey, masterKey) {
		t.Errorf("Expected masterKey %v, got %v", masterKey, sess.MasterKey)
	}

	// Test non-existent token
	_, ok = GetAPISession("invalid-token")
	if ok {
		t.Error("GetAPISession succeeded for invalid token")
	}
}

func TestGenerateRandomToken(t *testing.T) {
	t1 := generateRandomToken(32)
	t2 := generateRandomToken(32)

	if t1 == t2 {
		t.Error("generateRandomToken produced identical tokens")
	}
}
