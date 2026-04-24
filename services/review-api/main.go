package main

import (
	"context"
	"log"
	"modintel/services/review-api/api"
	"modintel/services/review-api/db"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Connect to database
	db.Connect()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	log.Printf("Starting Review API on port %s", port)

	// Setup router (without logger for now to avoid dependency issues)
	router := api.SetupRouter(nil)

	// Create HTTP server
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Setup graceful shutdown
	setupGracefulShutdown(srv)
}

func setupGracefulShutdown(srv *http.Server) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	log.Println("Shutdown signal received, initiating graceful shutdown")

	// Create shutdown context with 30 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Forced shutdown due to timeout: %v", err)
	} else {
		log.Println("Graceful shutdown completed successfully")
	}
}
