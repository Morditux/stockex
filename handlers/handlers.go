package handlers

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"stockex/auth"
	"stockex/config"
	"stockex/crypto"
	"stockex/db"
	"stockex/i18n"
	"stockex/models"

	"github.com/dchest/captcha"
	"github.com/gorilla/csrf"
)

func RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", IndexHandler)
	mux.HandleFunc("/login", LoginHandler)
	mux.HandleFunc("/signup", SignupHandler)
	mux.HandleFunc("/logout", LogoutHandler)
	mux.HandleFunc("/dashboard", DashboardHandler)
	mux.HandleFunc("/passwords", PasswordsHandler)
	mux.HandleFunc("/passwords/add", AddPasswordHandler)
	mux.HandleFunc("/passwords/delete", DeletePasswordHandler)
	mux.HandleFunc("/passwords/update", UpdatePasswordHandler)
	mux.HandleFunc("/passwords/decrypt", DecryptPasswordHandler)
	mux.HandleFunc("/passwords/import", ImportPasswordsHandler)
	mux.HandleFunc("/passwords/export", ExportPasswordsHandler)
	mux.HandleFunc("/change-password", ChangePasswordHandler)
	mux.HandleFunc("/pending", PendingHandler)
	mux.HandleFunc("/admin", AdminHandler)
	mux.HandleFunc("/admin/users/validate", ValidateUserHandler)
	mux.HandleFunc("/admin/users/delete", DeleteUserHandler)

	// Mobile API endpoints (JSON)
	mux.HandleFunc("/api/v1/login", APILoginHandler)
	mux.HandleFunc("/api/v1/signup", APISignupHandler)
	mux.HandleFunc("/api/v1/passwords", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			APIListPasswordsHandler(w, r)
		case http.MethodPost:
			APIAddPasswordHandler(w, r)
		case http.MethodPut:
			APIUpdatePasswordHandler(w, r)
		case http.MethodDelete:
			APIDeletePasswordHandler(w, r)
		default:
			sendJSONResponse(w, http.StatusMethodNotAllowed, APIResponse{Status: "error", Message: "Method not allowed"})
		}
	})
	mux.HandleFunc("/api/v1/passwords/decrypt", APIDecryptPasswordHandler)

	// Captcha handler
	mux.Handle("/captcha/", captcha.Server(captcha.StdWidth, captcha.StdHeight))
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	if auth.GetUserID(r) != 0 {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	renderTemplate(w, r, "index.html", map[string]any{"AppName": config.AppConfig.AppName})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var user struct {
			ID           int
			Username     string
			PasswordHash string
			Role         string
			Salt         string
			Validated    bool
		}
		err := db.DB.QueryRow("SELECT id, username, password_hash, role, salt, validated FROM users WHERE LOWER(username) = LOWER(?)", username).
			Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.Salt, &user.Validated)

		// Timing attack mitigation: always check password
		targetHash := user.PasswordHash
		if err != nil {
			targetHash = db.DummyHash
		}
		match := db.CheckPasswordHash(password, targetHash)

		if err != nil || !match {
			w.Header().Set("HX-Trigger", "loginError")
			// HTMX doesn't process HX-Trigger on 401/403 by default.
			// We return 200 OK for HTMX requests to ensure the trigger works.
			if r.Header.Get("HX-Request") == "true" {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
			return
		}

		saltBytes, _ := base64.StdEncoding.DecodeString(user.Salt)
		masterKey := crypto.DeriveKey(password, saltBytes)

		auth.SetSession(w, r, user.ID, user.Role, masterKey)

		if !user.Validated && user.Role != "admin" {
			w.Header().Set("HX-Redirect", "/pending")
		} else {
			w.Header().Set("HX-Redirect", "/dashboard")
		}
		return
	}
	renderTemplate(w, r, "login.html", nil)
}

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		captchaID := r.FormValue("captcha_id")
		captchaSolution := r.FormValue("captcha_solution")

		if !captcha.VerifyString(captchaID, captchaSolution) {
			lang := i18n.DetectLanguage(r)
			w.Header().Set("HX-Retarget", "#error-message")
			w.Write([]byte(i18n.T(lang, "InvalidCaptcha")))
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		if err := auth.ValidatePassword(password); err != nil {
			lang := i18n.DetectLanguage(r)
			w.Header().Set("HX-Retarget", "#error-message")
			w.Write([]byte(i18n.T(lang, "PasswordTooShort")))
			return
		}

		hashedPassword, _ := db.HashPassword(password)
		salt, _ := db.GenerateSalt()
		result, err := db.DB.Exec("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", username, hashedPassword, salt)
		if err != nil {
			lang := i18n.DetectLanguage(r)
			w.Header().Set("HX-Retarget", "#error-message")
			w.Write([]byte(i18n.T(lang, "UsernameAlreadyExists")))
			return
		}

		id, _ := result.LastInsertId()
		saltBytes, _ := base64.StdEncoding.DecodeString(salt)
		masterKey := crypto.DeriveKey(password, saltBytes)

		auth.SetSession(w, r, int(id), "user", masterKey)
		w.Header().Set("HX-Redirect", "/pending")
		return
	}

	data := map[string]any{
		"CaptchaID": captcha.New(),
	}
	renderTemplate(w, r, "signup.html", data)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	auth.ClearSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func PendingHandler(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	if userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	renderTemplate(w, r, "pending.html", nil)
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	if userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Check validation
	var validated bool
	var role string
	err := db.DB.QueryRow("SELECT validated, role FROM users WHERE id = ?", userID).Scan(&validated, &role)
	if err != nil || (!validated && role != "admin") {
		http.Redirect(w, r, "/pending", http.StatusSeeOther)
		return
	}

	renderTemplate(w, r, "dashboard.html", map[string]any{
		"IsAdmin": auth.IsAdmin(r),
		"AppName": config.AppConfig.AppName,
	})
}

func PasswordsHandler(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	if userID == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Check validation
	var validated bool
	var role string
	err := db.DB.QueryRow("SELECT validated, role FROM users WHERE id = ?", userID).Scan(&validated, &role)
	if err != nil || (!validated && role != "admin") {
		http.Redirect(w, r, "/pending", http.StatusSeeOther)
		return
	}

	rows, err := db.DB.Query("SELECT id, site, username, encrypted_password, notes FROM passwords WHERE user_id = ?", userID)
	if err != nil {
		log.Printf("Error querying passwords: %v", err)
		lang := i18n.DetectLanguage(r)
		http.Error(w, i18n.T(lang, "InternalServerError"), http.StatusInternalServerError)
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

	renderTemplate(w, r, "passwords.html", map[string]any{"Passwords": passwords, "IsAdmin": auth.IsAdmin(r)})
}

func AddPasswordHandler(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	masterKey := auth.GetMasterKey(r)
	if userID == 0 || masterKey == nil || r.Method != http.MethodPost {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	site := r.FormValue("site")
	username := r.FormValue("username")
	password := r.FormValue("password")
	notes := r.FormValue("notes")

	encrypted, err := crypto.Encrypt(password, masterKey)
	if err != nil {
		http.Error(w, "Encryption error", http.StatusInternalServerError)
		return
	}

	_, err = db.DB.Exec("INSERT INTO passwords (user_id, site, username, encrypted_password, notes) VALUES (?, ?, ?, ?, ?)",
		userID, site, username, encrypted, notes)
	if err != nil {
		log.Printf("Error adding password: %v", err)
		lang := i18n.DetectLanguage(r)
		http.Error(w, i18n.T(lang, "InternalServerError"), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Redirect", "/dashboard")
}

func DeletePasswordHandler(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	if userID == 0 || r.Method != http.MethodPost {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id := r.FormValue("id")
	_, err := db.DB.Exec("DELETE FROM passwords WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		log.Printf("Error deleting password: %v", err)
		lang := i18n.DetectLanguage(r)
		http.Error(w, i18n.T(lang, "InternalServerError"), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Trigger", "passwordChanged")
	w.WriteHeader(http.StatusOK)
}

func UpdatePasswordHandler(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	masterKey := auth.GetMasterKey(r)
	if userID == 0 || masterKey == nil || r.Method != http.MethodPost {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id := r.FormValue("id")
	site := r.FormValue("site")
	username := r.FormValue("username")
	password := r.FormValue("password")
	notes := r.FormValue("notes")

	encrypted, err := crypto.Encrypt(password, masterKey)
	if err != nil {
		http.Error(w, "Encryption error", http.StatusInternalServerError)
		return
	}

	_, err = db.DB.Exec("UPDATE passwords SET site = ?, username = ?, encrypted_password = ?, notes = ? WHERE id = ? AND user_id = ?",
		site, username, encrypted, notes, id, userID)
	if err != nil {
		log.Printf("Error updating password: %v", err)
		lang := i18n.DetectLanguage(r)
		http.Error(w, i18n.T(lang, "InternalServerError"), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Redirect", "/dashboard")
}

func DecryptPasswordHandler(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	masterKey := auth.GetMasterKey(r)
	if userID == 0 || masterKey == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	encrypted := r.URL.Query().Get("p")
	if encrypted == "" {
		http.Error(w, "Missing password", http.StatusBadRequest)
		return
	}

	decrypted, err := crypto.Decrypt(encrypted, masterKey)
	if err != nil {
		http.Error(w, "Decryption error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(decrypted))
}

func ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	if userID == 0 || r.Method != http.MethodPost {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	newPassword := r.FormValue("new_password")
	if newPassword == "" {
		w.Header().Set("HX-Retarget", "#password-error")
		w.Write([]byte("Password cannot be empty"))
		return
	}

	if err := auth.ValidatePassword(newPassword); err != nil {
		w.Header().Set("HX-Retarget", "#password-error")
		lang := i18n.DetectLanguage(r)
		w.Write([]byte(i18n.T(lang, "PasswordTooShort")))
		return
	}

	hashedPassword, _ := db.HashPassword(newPassword)
	salt, _ := db.GenerateSalt()
	_, err := db.DB.Exec("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", hashedPassword, salt, userID)
	if err != nil {
		w.Header().Set("HX-Retarget", "#password-error")
		w.Write([]byte("Error updating password"))
		return
	}

	saltBytes, _ := base64.StdEncoding.DecodeString(salt)
	masterKey := crypto.DeriveKey(newPassword, saltBytes)
	role := "user"
	if auth.IsAdmin(r) {
		role = "admin"
	}
	auth.SetSession(w, r, userID, role, masterKey)

	w.Header().Set("HX-Trigger", "passwordUpdated")
	w.WriteHeader(http.StatusOK)
}

func AdminHandler(w http.ResponseWriter, r *http.Request) {
	if !auth.IsAdmin(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	rows, err := db.DB.Query("SELECT id, username, role, created_at, validated FROM users")
	if err != nil {
		log.Printf("Error querying users: %v", err)
		lang := i18n.DetectLanguage(r)
		http.Error(w, i18n.T(lang, "InternalServerError"), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &u.Validated); err != nil {
			continue
		}
		users = append(users, u)
	}

	renderTemplate(w, r, "admin.html", map[string]any{"Users": users, "IsAdmin": true})
}

func ValidateUserHandler(w http.ResponseWriter, r *http.Request) {
	if !auth.IsAdmin(r) || r.Method != http.MethodPost {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	id := r.FormValue("id")
	_, err := db.DB.Exec("UPDATE users SET validated = 1 WHERE id = ?", id)
	if err != nil {
		log.Printf("Error validating user: %v", err)
		lang := i18n.DetectLanguage(r)
		http.Error(w, i18n.T(lang, "InternalServerError"), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if !auth.IsAdmin(r) || r.Method != http.MethodPost {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	id := r.FormValue("id")
	// Prevent deleting the last admin if possible, but for now just prevent deleting self
	if id == fmt.Sprint(auth.GetUserID(r)) {
		http.Error(w, "Cannot delete yourself", http.StatusBadRequest)
		return
	}

	_, err := db.DB.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		lang := i18n.DetectLanguage(r)
		http.Error(w, i18n.T(lang, "InternalServerError"), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

func renderTemplate(w http.ResponseWriter, r *http.Request, name string, data any) {
	lang := i18n.DetectLanguage(r)

	funcMap := template.FuncMap{
		"T": func(key string) string {
			return i18n.T(lang, key)
		},
	}

	tmpl, err := template.New(name).Funcs(funcMap).ParseFiles("templates/layout.html", "templates/"+name)
	if err != nil {
		log.Printf("Error parsing templates: %v", err)
		http.Error(w, i18n.T(lang, "InternalServerError"), http.StatusInternalServerError)
		return
	}

	// Prepare CSRF field
	csrfField := csrf.TemplateField(r)

	// If data is a map, ensure AppName and Lang are there
	if m, ok := data.(map[string]any); ok {
		if _, exists := m["AppName"]; !exists {
			m["AppName"] = config.AppConfig.AppName
		}
		m["Lang"] = lang
		m["csrfField"] = csrfField
		m["csrfToken"] = csrf.Token(r)
	} else if data == nil {
		data = map[string]any{
			"AppName":   config.AppConfig.AppName,
			"Lang":      lang,
			"csrfField": csrfField,
			"csrfToken": csrf.Token(r),
		}
	}

	tmpl.ExecuteTemplate(w, "layout", data)
}

func ImportPasswordsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := auth.GetUserID(r)
	masterKey := auth.GetMasterKey(r)
	if userID == 0 || masterKey == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	file, _, err := r.FormFile("csv_file")
	if err != nil {
		lang := i18n.DetectLanguage(r)
		w.Header().Set("HX-Retarget", "#import-error")
		w.Write([]byte(i18n.T(lang, "ErrorUploadingFile")))
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// Skip header
	_, err = reader.Read()
	if err != nil {
		lang := i18n.DetectLanguage(r)
		w.Header().Set("HX-Retarget", "#import-error")
		w.Write([]byte(i18n.T(lang, "EmptyOrInvalidCSV")))
		return
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip malformed rows
		}

		// Chrome format: name,url,username,password,note
		if len(record) < 4 {
			continue
		}

		site := record[0]
		username := record[2]
		rawPassword := record[3]
		notes := ""
		if len(record) > 4 {
			notes = record[4]
		}

		// Deduplication: Check if already exists for this user
		var count int
		err = db.DB.QueryRow("SELECT COUNT(*) FROM passwords WHERE user_id = ? AND site = ? AND username = ?",
			userID, site, username).Scan(&count)
		if err == nil && count > 0 {
			continue // Skip duplicate
		}

		encrypted, err := crypto.Encrypt(rawPassword, masterKey)
		if err != nil {
			continue
		}

		_, err = db.DB.Exec("INSERT INTO passwords (user_id, site, username, encrypted_password, notes) VALUES (?, ?, ?, ?, ?)",
			userID, site, username, encrypted, notes)
	}
}

func ExportPasswordsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := auth.GetUserID(r)
	masterKey := auth.GetMasterKey(r)
	if userID == 0 || masterKey == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.DB.Query("SELECT site, username, encrypted_password, notes FROM passwords WHERE user_id = ?", userID)
	if err != nil {
		log.Printf("Error querying passwords for export: %v", err)
		lang := i18n.DetectLanguage(r)
		http.Error(w, i18n.T(lang, "InternalServerError"), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"passwords.csv\"")

	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	writer.Write([]string{"name", "url", "username", "password", "note"})

	for rows.Next() {
		var site, username, encrypted, notes string
		if err := rows.Scan(&site, &username, &encrypted, &notes); err != nil {
			continue
		}

		decrypted, err := crypto.Decrypt(encrypted, masterKey)
		if err != nil {
			// In case of decryption error, we might want to skip or write empty/error
			// For now, let's write an empty password or log it
			log.Printf("Error decrypting password for site: %s, user: %s, error: %v", site, username, err)
			continue
		}

		// Map to Chrome format: name (site), url (site), username, password, note
		writer.Write([]string{site, site, username, decrypted, notes})
	}
}
