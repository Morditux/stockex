package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"stockex/config"
	"stockex/crypto"
	"stockex/db"

	"github.com/gorilla/sessions"
)

var Store *sessions.CookieStore

func InitStore() {
	// Derive two 32-byte keys from the session key to ensure secure encryption
	// Auth key for signing (HMAC)
	authKey := sha256.Sum256([]byte(config.AppConfig.SessionKey + "auth"))
	// Encryption key for content encryption (AES)
	encKey := sha256.Sum256([]byte(config.AppConfig.SessionKey + "encryption"))

	Store = sessions.NewCookieStore(authKey[:], encKey[:])

	// Ensure cookie security settings
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   config.AppConfig.ListenPort != 8080, // Default to true unless dev port
		SameSite: http.SameSiteLaxMode,
	}
}

const SessionName = "stockex-session"

func GetUserID(r *http.Request) int {
	session, _ := Store.Get(r, SessionName)
	if id, ok := session.Values["userID"].(int); ok {
		return id
	}
	return 0
}

func IsAdmin(r *http.Request) bool {
	session, _ := Store.Get(r, SessionName)
	if role, ok := session.Values["role"].(string); ok {
		return role == "admin"
	}
	return false
}

func GetMasterKey(r *http.Request) []byte {
	session, _ := Store.Get(r, SessionName)
	val, ok := session.Values["masterKey"].(string)
	if !ok {
		return nil
	}
	key, _ := base64.StdEncoding.DecodeString(val)
	return key
}

func SetSession(w http.ResponseWriter, r *http.Request, userID int, role string, masterKey []byte) {
	session, _ := Store.Get(r, SessionName)
	session.Values["userID"] = userID
	session.Values["role"] = role
	session.Values["masterKey"] = base64.StdEncoding.EncodeToString(masterKey)
	session.Save(r, w)
}

func ClearSession(w http.ResponseWriter, r *http.Request) {
	session, _ := Store.Get(r, SessionName)
	session.Options.MaxAge = -1
	session.Save(r, w)
}

// Token-based Auth for API (Persistent)
type APISession struct {
	UserID    int
	Role      string
	MasterKey []byte
}

func CreateAPIToken(userID int, role string, masterKey []byte) string {
	token := generateRandomToken(32)

	// Encrypt the master key with the server session key
	serverKey := sha256.Sum256([]byte(config.AppConfig.SessionKey))
	encryptedKey, _ := crypto.Encrypt(base64.StdEncoding.EncodeToString(masterKey), serverKey[:])

	_, err := db.DB.Exec("INSERT INTO api_sessions (token, user_id, role, encrypted_master_key) VALUES (?, ?, ?, ?)",
		token, userID, role, encryptedKey)
	if err != nil {
		fmt.Printf("Error creating API token in DB: %v\n", err)
		return ""
	}

	return token
}

func GetAPISession(token string) (APISession, bool) {
	var sess APISession
	var encryptedKey string

	err := db.DB.QueryRow("SELECT user_id, role, encrypted_master_key FROM api_sessions WHERE token = ?", token).
		Scan(&sess.UserID, &sess.Role, &encryptedKey)
	if err != nil {
		return APISession{}, false
	}

	// Decrypt the master key
	serverKey := sha256.Sum256([]byte(config.AppConfig.SessionKey))
	decryptedKeyB64, err := crypto.Decrypt(encryptedKey, serverKey[:])
	if err != nil {
		return APISession{}, false
	}

	sess.MasterKey, _ = base64.StdEncoding.DecodeString(decryptedKeyB64)
	return sess, true
}

func generateRandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// If we can't generate random numbers, the system is in a critical state.
		// Panic is appropriate here as we cannot securely continue.
		panic(fmt.Sprintf("critical security error: failed to generate random token: %v", err))
	}
	return base64.URLEncoding.EncodeToString(b)
}
