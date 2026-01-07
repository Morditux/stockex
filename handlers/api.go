package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"stockex/auth"
	"stockex/crypto"
	"stockex/db"
	"stockex/i18n"
	"stockex/models"
)

type APIResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

func sendJSONResponse(w http.ResponseWriter, status int, response APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

func getAPISession(r *http.Request) (auth.APISession, bool) {
	token := r.Header.Get("X-API-Token")
	if token == "" {
		return auth.APISession{}, false
	}
	return auth.GetAPISession(token)
}

func APILoginHandler(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	if r.Method != http.MethodPost {
		sendJSONResponse(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Message: i18n.T(lang, "MethodNotAllowed")})
		return
	}

	ip := getClientIP(r)
	if !loginLimiter.Allow(ip) {
		sendJSONResponse(w, http.StatusTooManyRequests, APIResponse{Status: "error", Message: i18n.T(lang, "TooManyAttempts")})
		return
	}

	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{Status: "error", Message: i18n.T(lang, "InvalidRequestBody")})
		return
	}

	var user struct {
		ID           int
		Username     string
		PasswordHash string
		Role         string
		Salt         string
	}
	err := db.DB.QueryRow("SELECT id, username, password_hash, role, salt FROM users WHERE LOWER(username) = LOWER(?)", input.Username).
		Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.Salt)

	// Timing attack mitigation: always check password
	targetHash := user.PasswordHash
	if err != nil {
		targetHash = db.DummyHash
	}
	match := db.CheckPasswordHash(input.Password, targetHash)

	if err != nil || !match {
		loginLimiter.RecordFailure(ip)
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{Status: "error", Message: i18n.T(lang, "InvalidCredentials")})
		return
	}

	loginLimiter.Reset(ip)

	saltBytes, _ := base64.StdEncoding.DecodeString(user.Salt)
	masterKey := crypto.DeriveKey(input.Password, saltBytes)

	token := auth.CreateAPIToken(user.ID, user.Role, masterKey)

	sendJSONResponse(w, http.StatusOK, APIResponse{
		Status: "success",
		Data: map[string]any{
			"token":    token,
			"user_id":  user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func APISignupHandler(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	if r.Method != http.MethodPost {
		sendJSONResponse(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Message: i18n.T(lang, "MethodNotAllowed")})
		return
	}

	ip := getClientIP(r)
	if !signupLimiter.Allow(ip) {
		sendJSONResponse(w, http.StatusTooManyRequests, APIResponse{Status: "error", Message: i18n.T(lang, "TooManyAttempts")})
		return
	}

	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{Status: "error", Message: i18n.T(lang, "InvalidRequestBody")})
		return
	}

	if err := auth.ValidatePassword(input.Password); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{Status: "error", Message: i18n.T(lang, "PasswordTooShort")})
		return
	}

	hashedPassword, _ := db.HashPassword(input.Password)
	salt, _ := db.GenerateSalt()
	result, err := db.DB.Exec("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", input.Username, hashedPassword, salt)
	if err != nil {
		sendJSONResponse(w, http.StatusConflict, APIResponse{Status: "error", Message: i18n.T(lang, "UsernameAlreadyExists")})
		return
	}

	// Record signup attempt to limit rate of creation per IP
	signupLimiter.RecordFailure(ip)

	id, _ := result.LastInsertId()
	saltBytes, _ := base64.StdEncoding.DecodeString(salt)
	masterKey := crypto.DeriveKey(input.Password, saltBytes)

	token := auth.CreateAPIToken(int(id), "user", masterKey)

	sendJSONResponse(w, http.StatusCreated, APIResponse{
		Status: "success",
		Data: map[string]any{
			"token":    token,
			"user_id":  id,
			"username": input.Username,
		},
	})
}

func APIListPasswordsHandler(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	session, ok := getAPISession(r)
	if !ok {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{Status: "error", Message: i18n.T(lang, "Unauthorized")})
		return
	}

	domain := r.URL.Query().Get("domain")
	var rows *sql.Rows
	var err error

	if domain != "" {
		// Filter by domain: site contains domain OR domain contains site
		// SQLite LIKE is case-insensitive for ASCII
		// We use a simple LIKE for "site contains domain"
		// For "domain contains site", it is harder in SQL.
		// Given "google.com" (site) and "www.google.com" (domain), site is in domain.
		// Given "google.com" (site) and "google" (domain), domain is in site.

		// Let's implement what is commonly expected: site contains the search term.
		// If I search "google", I find "google.com".
		// If I search "www.google.com", I might NOT find "google.com" if I only check site LIKE %domain%.
		// "google.com" LIKE "%www.google.com%" -> False.

		// The JS implementation did:
		// p.site.includes(domain) || domain.includes(p.site)

		// To replicate "domain includes p.site", we can use:
		// WHERE ? LIKE '%' || site || '%'
		// But verify if site is not empty string, otherwise it matches everything.

		rows, err = db.DB.Query("SELECT id, site, username, encrypted_password, notes FROM passwords WHERE user_id = ? AND (site LIKE ? OR ? LIKE '%' || site || '%')",
			session.UserID, "%"+domain+"%", domain)
	} else {
		rows, err = db.DB.Query("SELECT id, site, username, encrypted_password, notes FROM passwords WHERE user_id = ?", session.UserID)
	}

	if err != nil {
		log.Printf("Error querying passwords (API): %v", err)
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: i18n.T(lang, "InternalServerError")})
		return
	}
	defer rows.Close()

	var passwords []models.PasswordEntry
	for rows.Next() {
		var p models.PasswordEntry
		if err := rows.Scan(&p.ID, &p.Site, &p.Username, &p.EncryptedPassword, &p.Notes); err != nil {
			continue
		}
		passwords = append(passwords, p)
	}

	sendJSONResponse(w, http.StatusOK, APIResponse{Status: "success", Data: passwords})
}

func APIAddPasswordHandler(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	session, ok := getAPISession(r)
	if !ok {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{Status: "error", Message: i18n.T(lang, "Unauthorized")})
		return
	}

	var input struct {
		Site     string `json:"site"`
		Username string `json:"username"`
		Password string `json:"password"`
		Notes    string `json:"notes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{Status: "error", Message: i18n.T(lang, "InvalidRequestBody")})
		return
	}

	encrypted, err := crypto.Encrypt(input.Password, session.MasterKey)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: i18n.T(lang, "EncryptionError")})
		return
	}

	result, err := db.DB.Exec("INSERT INTO passwords (user_id, site, username, encrypted_password, notes) VALUES (?, ?, ?, ?, ?)",
		session.UserID, input.Site, input.Username, encrypted, input.Notes)
	if err != nil {
		log.Printf("Error adding password (API): %v", err)
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: i18n.T(lang, "InternalServerError")})
		return
	}

	id, _ := result.LastInsertId()
	sendJSONResponse(w, http.StatusCreated, APIResponse{Status: "success", Data: map[string]int64{"id": id}})
}

func APIUpdatePasswordHandler(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	session, ok := getAPISession(r)
	if !ok {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{Status: "error", Message: i18n.T(lang, "Unauthorized")})
		return
	}

	var input struct {
		ID       int    `json:"id"`
		Site     string `json:"site"`
		Username string `json:"username"`
		Password string `json:"password"`
		Notes    string `json:"notes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{Status: "error", Message: i18n.T(lang, "InvalidRequestBody")})
		return
	}

	encrypted, err := crypto.Encrypt(input.Password, session.MasterKey)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: i18n.T(lang, "EncryptionError")})
		return
	}

	_, err = db.DB.Exec("UPDATE passwords SET site = ?, username = ?, encrypted_password = ?, notes = ? WHERE id = ? AND user_id = ?",
		input.Site, input.Username, encrypted, input.Notes, input.ID, session.UserID)
	if err != nil {
		log.Printf("Error updating password (API): %v", err)
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: i18n.T(lang, "InternalServerError")})
		return
	}

	sendJSONResponse(w, http.StatusOK, APIResponse{Status: "success", Message: i18n.T(lang, "PasswordUpdated")})
}

func APIDeletePasswordHandler(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	session, ok := getAPISession(r)
	if !ok {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{Status: "error", Message: i18n.T(lang, "Unauthorized")})
		return
	}

	var input struct {
		ID int `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{Status: "error", Message: i18n.T(lang, "InvalidRequestBody")})
		return
	}

	_, err := db.DB.Exec("DELETE FROM passwords WHERE id = ? AND user_id = ?", input.ID, session.UserID)
	if err != nil {
		log.Printf("Error deleting password (API): %v", err)
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: i18n.T(lang, "InternalServerError")})
		return
	}

	sendJSONResponse(w, http.StatusOK, APIResponse{Status: "success", Message: i18n.T(lang, "PasswordDeleted")})
}

func APIDecryptPasswordHandler(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	session, ok := getAPISession(r)
	if !ok {
		sendJSONResponse(w, http.StatusUnauthorized, APIResponse{Status: "error", Message: i18n.T(lang, "Unauthorized")})
		return
	}

	var input struct {
		EncryptedPassword string `json:"encrypted_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, APIResponse{Status: "error", Message: i18n.T(lang, "InvalidRequestBody")})
		return
	}

	decrypted, err := crypto.Decrypt(input.EncryptedPassword, session.MasterKey)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, APIResponse{Status: "error", Message: i18n.T(lang, "DecryptionErrorAPI")})
		return
	}

	sendJSONResponse(w, http.StatusOK, APIResponse{Status: "success", Data: map[string]string{"decrypted_password": decrypted}})
}
