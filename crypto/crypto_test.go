package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	password := "correct horse battery staple"
	salt := []byte("somesweetandsaltysalt")

	key1 := DeriveKey(password, salt)
	key2 := DeriveKey(password, salt)

	if !bytes.Equal(key1, key2) {
		t.Error("DeriveKey with same inputs produced different results")
	}

	key3 := DeriveKey("different password", salt)
	if bytes.Equal(key1, key3) {
		t.Error("DeriveKey with different passwords produced same results")
	}

	if len(key1) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key1))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	password := "my-secret-password"
	salt := []byte("static-salt-for-test")
	key := DeriveKey(password, salt)

	originalText := "Hello, World! This is a secret message."

	encrypted, err := Encrypt(originalText, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted == originalText {
		t.Error("Encrypted text is same as original text")
	}

	// Verify it can be decoded from base64
	_, err = base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Errorf("Encrypted output is not valid base64: %v", err)
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decrypted != originalText {
		t.Errorf("Decrypted text '%s' does not match original '%s'", decrypted, originalText)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	password := "my-secret-password"
	salt := []byte("static-salt-for-test")
	key := DeriveKey(password, salt)

	originalText := "Secret data"
	encrypted, _ := Encrypt(originalText, key)

	wrongKey := DeriveKey("wrong-password", salt)
	_, err := Decrypt(encrypted, wrongKey)

	if err == nil {
		t.Error("Decrypt succeeded with wrong key, expected error")
	}
}
