package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/nxadm/tail"
	"modintel.local/log-collector/api"
	"modintel.local/log-collector/db"
	"modintel.local/log-collector/parsers"
)

func main() {
	_ = godotenv.Load("../../.env")

	db.Connect()

	go api.Serve()

	logFile := "/var/log/coraza/audit.json"
	if envLog := os.Getenv("LOG_FILE_PATH"); envLog != "" {
		logFile = envLog
	}

	log.Printf("Starting Log Collector, reading from %s", logFile)

	for {
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			log.Printf("Waiting for log file %s to be created...", logFile)
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}

	t, err := tail.TailFile(logFile, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      true,
	})

	if err != nil {
		log.Fatalf("Failed to tail log file: %v", err)
	}

	collection := db.GetCollection("modintel", "alerts")

	for line := range t.Lines {
		if line.Err != nil {
			log.Printf("Error reading tail line: %v", line.Err)
			continue
		}

		if line.Text == "" {
			continue
		}

		doc, err := parsers.ParseCorazaLog([]byte(line.Text))
		if err != nil {
			log.Printf("Failed to parse log line: %v (line: %s)", err, line.Text)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = collection.InsertOne(ctx, doc)
		cancel()

		if err != nil {
			log.Printf("Failed to insert alert to MongoDB: %v", err)
		} else {
			log.Printf("Successfully ingested WAF log: %s", doc.URI)
		}
	}
}
