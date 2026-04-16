package main

import (
	"log"

	"modintel/services/auth-service/api"
	"modintel/services/auth-service/bootstrap"
	"modintel/services/auth-service/config"
	"modintel/services/auth-service/db"
)

func main() {
	cfg := config.Load()
	database := db.Connect(cfg)
	bootstrap.EnsureAdmin(cfg, database)

	router := api.SetupRouter(cfg, database)
	log.Printf("Starting Auth Service on port %s", cfg.Port)
	log.Fatal(router.Run(":" + cfg.Port))
}
