package main

import (
	"fmt"
	"log"
	"net/http"
	"stockex/auth"
	"stockex/config"
	"stockex/db"
	"stockex/handlers"
)

func main() {
	if err := config.LoadConfig("config.json"); err != nil {
		log.Fatalf("Error loading config: %v", err)
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
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
