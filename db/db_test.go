package db

import (
	"os"
	"testing"
)

func TestInitDB(t *testing.T) {
	dbPath := "./test_stockex.db"
	defer os.Remove(dbPath)

	// Test initialization
	InitDB(dbPath)
	if DB == nil {
		t.Fatal("DB was not initialized")
	}
	defer DB.Close()

	// Verify tables exist by attempting a simple select
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		t.Errorf("Could not query users table: %v", err)
	}

	err = DB.QueryRow("SELECT COUNT(*) FROM passwords").Scan(&count)
	if err != nil {
		t.Errorf("Could not query passwords table: %v", err)
	}

	err = DB.QueryRow("SELECT COUNT(*) FROM api_sessions").Scan(&count)
	if err != nil {
		t.Errorf("Could not query api_sessions table: %v", err)
	}

	// Verify default admin was created
	err = DB.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin' AND username = 'admin'").Scan(&count)
	if err != nil || count != 1 {
		t.Errorf("Default admin was not created correctly: count=%d, err=%v", count, err)
	}
}

func TestPasswordHashing(t *testing.T) {
	password := "mypassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !CheckPasswordHash(password, hash) {
		t.Error("CheckPasswordHash failed for correct password")
	}

	if CheckPasswordHash("wrongpassword", hash) {
		t.Error("CheckPasswordHash succeeded for wrong password")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, _ := GenerateSalt()
	salt2, _ := GenerateSalt()

	if salt1 == salt2 {
		t.Error("GenerateSalt produced sequential identical salts")
	}

	if len(salt1) < 16 {
		t.Errorf("Salt seems too short: %d", len(salt1))
	}
}
