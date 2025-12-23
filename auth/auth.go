package auth

import (
	"encoding/base64"
	"net/http"
	"stockex/config"

	"github.com/gorilla/sessions"
)

var Store *sessions.CookieStore

func InitStore() {
	Store = sessions.NewCookieStore([]byte(config.AppConfig.SessionKey))
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
