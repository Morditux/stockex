package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	AppName        string   `json:"app_name"`
	ListenIP       string   `json:"listen_ip"`
	ListenPort     int      `json:"listen_port"`
	SessionKey     string   `json:"session_key"`
	AllowedOrigins []string `json:"allowed_origins"`
}

var AppConfig Config

func LoadConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&AppConfig)
	return err
}
