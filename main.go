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
		csrf.TrustedOrigins([]string{"localhost:8080", "127.0.0.1:8080"}),
		csrf.SameSite(csrf.SameSiteLaxMode),
	)

	if err := http.ListenAndServe(addr, handlers.SecurityHeadersMiddleware(handlers.CORSMiddleware(csrfMiddleware(mux)))); err != nil {
		log.Fatal(err)
	}
}
