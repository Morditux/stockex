package i18n

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

var translations = make(map[string]map[string]string)
var DefaultLang = "en"

func LoadTranslations(path string) error {
	files := []string{"en", "fr"}
	for _, lang := range files {
		data, err := os.ReadFile(fmt.Sprintf("%s/%s.json", path, lang))
		if err != nil {
			return err
		}
		var t map[string]string
		if err := json.Unmarshal(data, &t); err != nil {
			return err
		}
		translations[lang] = t
	}
	return nil
}

func T(lang, key string) string {
	if t, ok := translations[lang]; ok {
		if val, ok := t[key]; ok {
			return val
		}
	}
	// Fallback to English
	if lang != DefaultLang {
		return T(DefaultLang, key)
	}
	return key
}

func DetectLanguage(r *http.Request) string {
	// 1. Check Accept-Language header
	accept := r.Header.Get("Accept-Language")
	if accept != "" {
		// Example: fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5
		parts := strings.Split(accept, ",")
		for _, part := range parts {
			lang := strings.TrimSpace(strings.Split(part, ";")[0])
			if len(lang) >= 2 {
				lang = lang[:2] // e.g., "en-US" -> "en"
				if _, ok := translations[lang]; ok {
					return lang
				}
			}
		}
	}

	return DefaultLang
}
