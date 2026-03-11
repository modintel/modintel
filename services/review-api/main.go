package main

import (
	"log"
	"modintel/services/review-api/api"
	"modintel/services/review-api/db"
	"os"
)

func main() {
	db.Connect()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	log.Printf("Starting Review API on port %s", port)
	router := api.SetupRouter()
	log.Fatal(router.Run(":" + port))
}
