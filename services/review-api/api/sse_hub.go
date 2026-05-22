package api

import (
	"log"
	"sync"
	"time"
)

type SSEEvent struct {
	Type string
	Data string
}

type sseClient struct {
	ch       chan SSEEvent
	dropped  int
	lastDrop time.Time
}

type SSEHub struct {
	mu      sync.RWMutex
	clients map[string]*sseClient
}

var Hub *SSEHub

func InitHub() {
	Hub = &SSEHub{
		clients: make(map[string]*sseClient),
	}
	log.Println("SSE hub initialized")
}

func (h *SSEHub) Register(id string) chan SSEEvent {
	ch := make(chan SSEEvent, 1024)
	h.mu.Lock()
	h.clients[id] = &sseClient{ch: ch}
	h.mu.Unlock()
	log.Printf("SSE client registered: %s (total: %d)", id, h.ClientCount())
	return ch
}

func (h *SSEHub) Unregister(id string) {
	h.mu.Lock()
	if c, ok := h.clients[id]; ok {
		close(c.ch)
		delete(h.clients, id)
	}
	h.mu.Unlock()
	log.Printf("SSE client unregistered: %s (total: %d)", id, h.ClientCount())
}

var lastBroadcastMu sync.Mutex
var lastHealthTS time.Time
var lastStatsTS time.Time

func (h *SSEHub) Broadcast(event SSEEvent) {
	if event.Type == "health" {
		lastBroadcastMu.Lock()
		if time.Since(lastHealthTS) < time.Second {
			lastBroadcastMu.Unlock()
			return
		}
		lastHealthTS = time.Now()
		lastBroadcastMu.Unlock()
	}
	if event.Type == "stats" {
		lastBroadcastMu.Lock()
		if time.Since(lastStatsTS) < time.Second {
			lastBroadcastMu.Unlock()
			return
		}
		lastStatsTS = time.Now()
		lastBroadcastMu.Unlock()
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	for id, c := range h.clients {
		select {
		case c.ch <- event:
		default:
			c.dropped++
			c.lastDrop = time.Now()
			if c.dropped >= 50 && time.Since(c.lastDrop) < 10*time.Second {
				go h.Unregister(id)
				log.Printf("SSE client %s disconnected: %d drops in 10s", id, c.dropped)
				continue
			}
			log.Printf("SSE client %s channel full, dropping event (%d total)", id, c.dropped)
		}
	}
}

func (h *SSEHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
