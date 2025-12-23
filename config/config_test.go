package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	configContent := `{
		"app_name": "TestApp",
		"listen_ip": "127.0.0.1",
		"listen_port": 9090,
		"session_key": "test-session-key"
	}`
	tmpfile, err := os.CreateTemp("", "config.json")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temporary file: %v", err)
	}

	// Test loading the config
	err = LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if AppConfig.AppName != "TestApp" {
		t.Errorf("Expected AppName 'TestApp', got '%s'", AppConfig.AppName)
	}
	if AppConfig.ListenIP != "127.0.0.1" {
		t.Errorf("Expected ListenIP '127.0.0.1', got '%s'", AppConfig.ListenIP)
	}
	if AppConfig.ListenPort != 9090 {
		t.Errorf("Expected ListenPort 9090, got %d", AppConfig.ListenPort)
	}
	if AppConfig.SessionKey != "test-session-key" {
		t.Errorf("Expected SessionKey 'test-session-key', got '%s'", AppConfig.SessionKey)
	}
}

func TestLoadConfigInvalidPath(t *testing.T) {
	err := LoadConfig("non-existent-path.json")
	if err == nil {
		t.Error("LoadConfig with non-existent path should have failed")
	}
}

func TestLoadConfigInvalidJSON(t *testing.T) {
	tmpfile, _ := os.CreateTemp("", "invalid_config.json")
	defer os.Remove(tmpfile.Name())
	tmpfile.Write([]byte(`{ "invalid": json }`))
	tmpfile.Close()

	err := LoadConfig(tmpfile.Name())
	if err == nil {
		t.Error("LoadConfig with invalid JSON should have failed")
	}
}
