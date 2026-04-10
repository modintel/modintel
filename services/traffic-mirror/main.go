package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	corazaURL       string
	mlServiceURL    string
	logCollectorURL string
	listenPort      string
	timeout         time.Duration
	corazaURLParsed *url.URL
)

type RequestPayload struct {
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func init() {
	flag.StringVar(&corazaURL, "coraza-url", getEnv("CORAZA_URL", "http://proxy-waf:80"), "URL of the Coraza/Caddy service")
	flag.StringVar(&mlServiceURL, "ml-url", getEnv("ML_URL", "http://inference-engine:8083"), "URL of the ML Inference service")
	flag.StringVar(&listenPort, "port", getEnv("PORT", "8080"), "Port to listen on")
	flag.StringVar(&logCollectorURL, "log-collector-url", getEnv("LOG_COLLECTOR_URL", "http://log-collector:8081"), "URL of the Log Collector service")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "Request timeout")
	flag.Parse()

	var err error
	corazaURLParsed, err = url.Parse(corazaURL)
	if err != nil {
		log.Fatalf("Invalid coraza-url: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func main() {
	log.Printf("Starting Traffic Mirror Service on port %s", listenPort)
	log.Printf("Forwarding to Coraza: %s", corazaURL)
	log.Printf("Duplicating to ML Service: %s", mlServiceURL)

	http.HandleFunc("/", handleRequest)

	if err := http.ListenAndServe(":"+listenPort, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	bodyBytes, _ := io.ReadAll(r.Body)
	bodyStr := string(bodyBytes)
	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = strings.Join(v, ", ")
	}

	payload := RequestPayload{
		Method:  r.Method,
		URI:     r.RequestURI,
		Headers: headers,
		Body:    bodyStr,
	}

	mlChan := make(chan map[string]interface{}, 1)
	mlErrChan := make(chan error, 1)

	go func() {
		resp, err := sendToMLService(payload)
		if err != nil {
			mlErrChan <- err
			return
		}
		mlChan <- resp
	}()

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	proxy := httputil.NewSingleHostReverseProxy(corazaURLParsed)

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, r)

	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	w.Write(rec.Body.Bytes())

	duration := time.Since(startTime)

	select {
	case mlResp := <-mlChan:
		if mlResp != nil {
			log.Printf("ML Response: %v", mlResp)

			if isSuspicious, ok := mlResp["is_suspicious"].(bool); ok && isSuspicious {
				logData := map[string]interface{}{
					"method":       payload.Method,
					"uri":          payload.URI,
					"body":         payload.Body,
					"headers":      payload.Headers,
					"ml_detection": mlResp,
				}

				go func() {
					if err := logToCollector(logData); err != nil {
						log.Printf("Failed to log FN candidate: %v", err)
					}
				}()
			}
		}
	case err := <-mlErrChan:
		log.Printf("ML Service error (non-blocking): %v", err)
	default:
	}

	log.Printf("%s %s - %d (%s)", r.Method, r.RequestURI, rec.Code, duration)
}

func sendToMLService(payload RequestPayload) (map[string]interface{}, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", mlServiceURL+"/predict", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ML service returned status %d", resp.StatusCode)
	}

	var mlResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&mlResp); err != nil {
		return nil, err
	}

	return mlResp, nil
}

func logToCollector(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", logCollectorURL+"/api/ingest", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Log collector returned status %d", resp.StatusCode)
	}

	return nil
}
