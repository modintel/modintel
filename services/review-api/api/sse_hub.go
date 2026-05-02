package api

import (
	"log"
	"sync"
)

type SSEEvent struct {
	Type string
	Data string
}

type SSEHub struct {
	mu      sync.RWMutex
	clients map[string]chan SSEEvent
}

var Hub *SSEHub

func InitHub() {
	Hub = &SSEHub{
		clients: make(map[string]chan SSEEvent),
	}
	log.Println("SSE hub initialized")
}

func (h *SSEHub) Register(id string) chan SSEEvent {
	ch := make(chan SSEEvent, 256)
	h.mu.Lock()
	h.clients[id] = ch
	h.mu.Unlock()
	log.Printf("SSE client registered: %s (total: %d)", id, h.ClientCount())
	return ch
}

func (h *SSEHub) Unregister(id string) {
	h.mu.Lock()
	if ch, ok := h.clients[id]; ok {
		close(ch)
		delete(h.clients, id)
	}
	h.mu.Unlock()
	log.Printf("SSE client unregistered: %s (total: %d)", id, h.ClientCount())
}

func (h *SSEHub) Broadcast(event SSEEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for id, ch := range h.clients {
		select {
		case ch <- event:
		default:
			log.Printf("SSE client %s channel full, dropping event", id)
		}
	}
}

func (h *SSEHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
