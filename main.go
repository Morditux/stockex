package main

import (
	"fmt"
	"log"
	"net/http"
	"stockex/auth"
	"stockex/config"
	"stockex/db"
	"stockex/handlers"
	"stockex/i18n"

	"github.com/gorilla/csrf"
)

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow any origin for the API as it's an extension/mobile use case
		// In production, you might want to be more restrictive
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-API-Token")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	if err := config.LoadConfig("config.json"); err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	if err := i18n.LoadTranslations("i18n"); err != nil {
		log.Fatalf("Error loading translations: %v", err)
	}

	auth.InitStore()

	db.InitDB("./stockex.db")
	defer db.DB.Close()

	mux := http.NewServeMux()

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Register application handlers
	handlers.RegisterHandlers(mux)

	addr := fmt.Sprintf("%s:%d", config.AppConfig.ListenIP, config.AppConfig.ListenPort)
	log.Printf("Server starting on %s (%s)", addr, config.AppConfig.AppName)

	// CSRF Protection
	// We need a 32-byte key. Using session key for now, assuming it's suitable.
	// In production, this should be a separate key.
	csrfMiddleware := csrf.Protect(
		[]byte(config.AppConfig.SessionKey),
		csrf.Secure(false), // Set to true in production with HTTPS
		csrf.Path("/"),
	)

	if err := http.ListenAndServe(addr, CORSMiddleware(csrfMiddleware(mux))); err != nil {
		log.Fatal(err)
	}
}
