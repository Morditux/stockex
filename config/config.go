package config

import (
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

	// Security Warning for default key
	if AppConfig.SessionKey == "super-secret-session-key-change-me" {
		log.Println("WARNING: Using default insecure session key. Set STOCKEX_SESSION_KEY environment variable in production!")
	}

	return nil
}
