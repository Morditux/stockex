package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"stockex/auth"
	"stockex/config"
	"stockex/db"
	"testing"
)

func TestMain(m *testing.M) {
	// Setup
	dbPath := "./test_api.db"
	db.InitDB(dbPath)
	config.AppConfig.SessionKey = "test-secret-key-for-api-handlers-test"
	config.AppConfig.AppName = "StockExTest"
	auth.InitStore()

	// Run tests
	code := m.Run()

	// Teardown
	db.DB.Close()
	os.Remove(dbPath)

	os.Exit(code)
}

func TestAPILoginSignupFlow(t *testing.T) {
	// 1. Signup
	signupData := map[string]string{
		"username": "api_user",
		"password": "api_password123",
	}
	body, _ := json.Marshal(signupData)
	req := httptest.NewRequest("POST", "/api/v1/signup", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	APISignupHandler(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Signup failed, expected 201, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != "success" {
		t.Errorf("Expected success status, got %s", resp.Status)
	}

	dataMap := resp.Data.(map[string]interface{})
	token := dataMap["token"].(string)
	if token == "" {
		t.Error("Signup did not return a token")
	}

	// 2. Login
	loginData := map[string]string{
		"username": "api_user",
		"password": "api_password123",
	}
	body, _ = json.Marshal(loginData)
	req = httptest.NewRequest("POST", "/api/v1/login", bytes.NewBuffer(body))
	w = httptest.NewRecorder()

	APILoginHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Login failed, expected 200, got %d", w.Code)
	}

	json.NewDecoder(w.Body).Decode(&resp)
	dataMap = resp.Data.(map[string]interface{})
	newToken := dataMap["token"].(string)
	if newToken == "" {
		t.Error("Login did not return a token")
	}

	// 3. Test list with token
	req = httptest.NewRequest("GET", "/api/v1/passwords", nil)
	req.Header.Set("X-API-Token", newToken)
	w = httptest.NewRecorder()

	APIListPasswordsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("List passwords failed with token, expected 200, got %d", w.Code)
	}
}

func TestAPIAddPassword(t *testing.T) {
	// Need a token first
	masterKey := []byte("a-very-secret-master-key-32-byte")
	token := auth.CreateAPIToken(1, "user", masterKey)

	pwdData := map[string]string{
		"site":     "Github",
		"username": "mordicus",
		"password": "git-password",
		"notes":    "some notes",
	}
	body, _ := json.Marshal(pwdData)
	req := httptest.NewRequest("POST", "/api/v1/passwords", bytes.NewBuffer(body))
	req.Header.Set("X-API-Token", token)
	w := httptest.NewRecorder()

	APIAddPasswordHandler(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Add password failed, expected 201, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp APIResponse
	json.NewDecoder(w.Body).Decode(&resp)
	dataMap := resp.Data.(map[string]interface{})
	passwordID := int(dataMap["id"].(float64))

	// 2. List to get encrypted password
	req = httptest.NewRequest("GET", "/api/v1/passwords", nil)
	req.Header.Set("X-API-Token", token)
	w = httptest.NewRecorder()
	APIListPasswordsHandler(w, req)

	var listResp APIResponse
	json.NewDecoder(w.Body).Decode(&listResp)
	passwords := listResp.Data.([]interface{})
	// 2. Verify password exists in list
	var found bool
	for _, p := range passwords {
		pMap := p.(map[string]interface{})
		if int(pMap["id"].(float64)) == passwordID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Password %d not found in list", passwordID)
	}

	// 3. Decrypt
	decryptData := map[string]int{
		"id": passwordID,
	}
	body, _ = json.Marshal(decryptData)
	req = httptest.NewRequest("POST", "/api/v1/passwords/decrypt", bytes.NewBuffer(body))
	req.Header.Set("X-API-Token", token)
	w = httptest.NewRecorder()

	APIDecryptPasswordHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Decrypt failed, expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var decryptResp APIResponse
	json.NewDecoder(w.Body).Decode(&decryptResp)
	decryptedData := decryptResp.Data.(map[string]interface{})
	if decryptedData["decrypted_password"].(string) != "git-password" {
		t.Errorf("Expected decrypted 'git-password', got %s", decryptedData["decrypted_password"])
	}
}

func TestAPIUnauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/passwords", nil)
	w := httptest.NewRecorder()

	APIListPasswordsHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
	}
}
