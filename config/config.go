package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
)

type Config struct {
	AppName    string `json:"app_name"`
	ListenIP   string `json:"listen_ip"`
	ListenPort int    `json:"listen_port"`
	SessionKey string `json:"session_key"`
}

var AppConfig Config

func LoadConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&AppConfig); err != nil {
		return err
	}

	// Override with environment variable if present
	if envKey := os.Getenv("STOCKEX_SESSION_KEY"); envKey != "" {
		AppConfig.SessionKey = envKey
	}

	// If no key is provided or it's the placeholder, generate a secure random one
	if AppConfig.SessionKey == "" || AppConfig.SessionKey == "CHANGE_ME_IN_PRODUCTION" {
		log.Println("WARNING: No session key configured. Generating a random key. Sessions will be invalidated on restart.")
		randomKey := make([]byte, 32)
		if _, err := rand.Read(randomKey); err != nil {
			return err
		}
		AppConfig.SessionKey = hex.EncodeToString(randomKey)
	}

	return nil
}
