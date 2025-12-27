package models

import "time"

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"` // "admin" or "user"
	Salt         string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	Validated    bool      `json:"validated"`
}

type PasswordEntry struct {
	ID                int       `json:"id"`
	UserID            int       `json:"user_id"`
	Site              string    `json:"site"`
	Username          string    `json:"username"`
	EncryptedPassword string    `json:"encrypted_password"`
	Notes             string    `json:"notes"`
	CreatedAt         time.Time `json:"created_at"`
}
