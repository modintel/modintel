package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type serviceState struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Source    string    `json:"source"`
	UpdatedAt time.Time `json:"updated_at"`
	Details   string    `json:"details,omitempty"`
}

type dockerEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time int64 `json:"time"`
}

type aggregator struct {
	mu       sync.RWMutex
	services map[string]serviceState
	tracked  map[string]struct{}
	project  string
}

func newAggregator(project string) *aggregator {
	now := time.Now().UTC()
	return &aggregator{
		project: project,
		services: map[string]serviceState{
			"proxy-waf":        {Name: "proxy-waf", Status: "unknown", Source: "init", UpdatedAt: now},
			"review-api":       {Name: "review-api", Status: "unknown", Source: "init", UpdatedAt: now},
			"log-collector":    {Name: "log-collector", Status: "unknown", Source: "init", UpdatedAt: now},
			"inference-engine": {Name: "inference-engine", Status: "unknown", Source: "init", UpdatedAt: now},
			"auth-service":     {Name: "auth-service", Status: "unknown", Source: "init", UpdatedAt: now},
		},
		tracked: map[string]struct{}{
			"proxy-waf":        {},
			"review-api":       {},
			"log-collector":    {},
			"inference-engine": {},
			"auth-service":     {},
		},
	}
}

func (a *aggregator) set(name, status, source, details string) {
	if _, ok := a.tracked[name]; !ok {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	cur, ok := a.services[name]
	if !ok {
		cur = serviceState{Name: name}
	}
	cur.Status = status
	cur.Source = source
	cur.Details = details
	cur.UpdatedAt = time.Now().UTC()
	a.services[name] = cur
}

func (a *aggregator) snapshot() map[string]serviceState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make(map[string]serviceState, len(a.services))
	for k, v := range a.services {
		out[k] = v
	}
	return out
}

func dockerClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
		},
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func (a *aggregator) eventLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}

		if err := a.consumeDockerEvents(ctx); err != nil {
			log.Printf("event stream error: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(1200 * time.Millisecond):
			}
		}
	}
}

func (a *aggregator) consumeDockerEvents(ctx context.Context) error {
	filter := fmt.Sprintf(`{"type":["container"],"label":["com.docker.compose.project=%s"]}`, a.project)
	endpoint := fmt.Sprintf("http://docker/events?filters=%s", url.QueryEscape(filter))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}

	resp, err := dockerClient(0).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("docker events status %d", resp.StatusCode)
	}

	s := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var ev dockerEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		service := ev.Actor.Attributes["com.docker.compose.service"]
		if service == "" {
			continue
		}
		a.applyEvent(service, ev.Action)
	}
	if err := s.Err(); err != nil {
		return err
	}

	return fmt.Errorf("docker event stream closed")
}

func (a *aggregator) applyEvent(service, action string) {
	action = strings.ToLower(action)
	switch {
	case action == "die" || action == "kill" || action == "stop" || strings.HasPrefix(action, "health_status: unhealthy"):
		a.set(service, "down", "docker-event", action)
	case action == "restart" || action == "start" || strings.HasPrefix(action, "health_status: starting"):
		a.set(service, "restarting", "docker-event", action)
	case strings.HasPrefix(action, "health_status: healthy"):
		a.set(service, "ok", "docker-event", action)
	}
}

func (a *aggregator) probeLoop(ctx context.Context) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.runProbes(ctx)
		}
	}
}

func probeHTTP(ctx context.Context, rawURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "down"
	}
	r, err := (&http.Client{Timeout: 850 * time.Millisecond}).Do(req)
	if err != nil {
		return "down"
	}
	defer r.Body.Close()
	if r.StatusCode >= 200 && r.StatusCode < 400 {
		return "ok"
	}
	return "degraded"
}

func probeTCP(host string, port int) string {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 850*time.Millisecond)
	if err != nil {
		return "down"
	}
	_ = c.Close()
	return "ok"
}

func (a *aggregator) runProbes(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	a.set("review-api", probeHTTP(pctx, "http://review-api:8082/health"), "probe", "http")
	a.set("log-collector", probeHTTP(pctx, "http://log-collector:8081/health"), "probe", "http")
	a.set("inference-engine", probeHTTP(pctx, "http://inference-engine:8083/health"), "probe", "http")
	a.set("auth-service", probeHTTP(pctx, "http://auth-service:8084/health"), "probe", "http")
	a.set("proxy-waf", probeTCP("proxy-waf", 8080), "probe", "tcp")
}

func (a *aggregator) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	services := a.snapshot()
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make(map[string]string, len(names))
	for _, n := range names {
		s := services[n].Status
		if s == "restarting" {
			s = "degraded"
		}
		out[n] = s
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"services":  out,
		"timestamp": time.Now().UTC(),
	})
}

func (a *aggregator) handleDetailed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"services":  a.snapshot(),
		"timestamp": time.Now().UTC(),
	})
}

func main() {
	project := strings.TrimSpace(os.Getenv("COMPOSE_PROJECT_NAME"))
	if project == "" {
		project = strings.TrimSpace(os.Getenv("PROJECT_NAME"))
	}
	if project == "" {
		project = "joab"
	}

	addr := strings.TrimSpace(os.Getenv("HEALTH_AGG_ADDR"))
	if addr == "" {
		addr = ":8090"
	}

	agg := newAggregator(project)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go agg.eventLoop(ctx)
	go agg.probeLoop(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "health-aggregator"})
	})
	mux.HandleFunc("/aggregate/health", agg.handleHealth)
	mux.HandleFunc("/aggregate/health/detailed", agg.handleDetailed)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	log.Printf("health-aggregator listening on %s (project=%s)", addr, project)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("health-aggregator failed: %v", err)
	}
}
