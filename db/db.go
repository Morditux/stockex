package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

func InitDB(dataSourceName string) {
	var err error
	DB, err = sql.Open("sqlite3", dataSourceName)
	if err != nil {
		log.Fatal(err)
	}

	createTables := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT DEFAULT 'user',
		salt TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS passwords (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		site TEXT NOT NULL,
		username TEXT NOT NULL,
		encrypted_password TEXT NOT NULL,
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	`

	_, err = DB.Exec(createTables)
	if err != nil {
		log.Fatalf("Error creating tables: %v", err)
	}

	// Create default admin if not exists
	var count int
	err = DB.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
	if err != nil {
		log.Fatalf("Error checking for admin user: %v", err)
	}

	if count == 0 {
		// Default admin
		adminPassword := os.Getenv("STOCKEX_ADMIN_PASSWORD")
		if adminPassword == "" {
			randomBytes := make([]byte, 16)
			if _, err := rand.Read(randomBytes); err != nil {
				log.Fatalf("Error generating random password: %v", err)
			}
			adminPassword = hex.EncodeToString(randomBytes)
		}

		hashedPassword, _ := HashPassword(adminPassword)
		salt, _ := GenerateSalt()
		_, err = DB.Exec("INSERT INTO users (username, password_hash, role, salt) VALUES (?, ?, ?, ?)", "admin", hashedPassword, "admin", salt)
		if err != nil {
			log.Fatalf("Error creating default admin: %v", err)
		}
		log.Printf("Default admin created: admin / %s", adminPassword)
	}

	_, err = DB.Exec(`CREATE TABLE IF NOT EXISTS api_sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		role TEXT NOT NULL,
		encrypted_master_key TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id)
	)`)
	if err != nil {
		log.Fatal(err)
	}
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateSalt() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
