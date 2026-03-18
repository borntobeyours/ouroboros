package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// SSEBroker manages Server-Sent Events fan-out for a single scan.
// It replays history to late-joining subscribers and closes cleanly when done.
type SSEBroker struct {
	mu      sync.Mutex
	subs    map[chan SSEEvent]struct{}
	closed  bool
	history []SSEEvent
}

// NewSSEBroker creates a new SSE broker.
func NewSSEBroker() *SSEBroker {
	return &SSEBroker{
		subs: make(map[chan SSEEvent]struct{}),
	}
}

// Subscribe registers a new subscriber channel and replays history.
// Returns the channel and an unsubscribe function.
// If the broker is already closed, the returned channel is already closed.
func (b *SSEBroker) Subscribe() (chan SSEEvent, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan SSEEvent, 64)

	// Replay history to the new subscriber
	for _, ev := range b.history {
		select {
		case ch <- ev:
		default:
		}
	}

	if b.closed {
		close(ch)
		return ch, func() {}
	}

	b.subs[ch] = struct{}{}
	unsub := func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
	return ch, unsub
}

// Publish sends an event to all current subscribers and records it in history.
func (b *SSEBroker) Publish(event SSEEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.history = append(b.history, event)
	for ch := range b.subs {
		select {
		case ch <- event:
		default:
			// Slow subscriber — drop event rather than block
		}
	}
}

// Close marks the broker as closed and signals all subscribers by closing their channels.
func (b *SSEBroker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}
	b.closed = true
	for ch := range b.subs {
		close(ch)
	}
	b.subs = make(map[chan SSEEvent]struct{})
}

// ServeSSE handles an SSE HTTP connection for a scan, streaming events until
// the scan completes or the client disconnects.
func ServeSSE(w http.ResponseWriter, r *http.Request, broker *SSEBroker) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := broker.Subscribe()
	defer unsub()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, open := <-ch:
			if !open {
				// Broker closed (scan finished)
				return
			}
			data, err := json.Marshal(event.Data)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
			flusher.Flush()
		}
	}
}
