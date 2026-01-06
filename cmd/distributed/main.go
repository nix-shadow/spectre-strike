package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"spectre-strike/pkg/distributed"
)

func main() {
	role := flag.String("role", getEnv("ROLE", "worker"), "Role: coordinator or worker")
	backend := flag.String("backend", getEnv("BACKEND", "redis"), "Backend: redis or nats")
	redisURL := flag.String("redis", getEnv("REDIS_URL", "redis://localhost:6379"), "Redis URL")
	natsURL := flag.String("nats", getEnv("NATS_URL", "nats://localhost:4222"), "NATS URL")
	workerID := flag.String("worker-id", getEnv("WORKER_ID", ""), "Worker ID (auto-generated if empty)")
	flag.Parse()

	// Build transport config
	tcfg := distributed.TransportConfig{
		Backend:           distributed.BackendType(*backend),
		RedisURL:          *redisURL,
		NATSURL:           *natsURL,
		CommandChannel:    "attack",
		ResultChannel:     "attack",
		HeartbeatChannel:  "attack",
		HeartbeatInterval: 10 * time.Second,
		DialTimeout:       5 * time.Second,
	}

	transport, err := distributed.NewTransport(tcfg)
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}
	defer transport.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	switch *role {
	case "coordinator":
		runCoordinator(ctx, transport)
	case "worker":
		runWorker(ctx, transport, *workerID)
	default:
		log.Fatalf("Unknown role: %s", *role)
	}
}

type SimpleCoordinator struct {
	transport distributed.Transport
	workers   map[string]time.Time
	mu        sync.RWMutex
	wg        sync.WaitGroup
}

func runCoordinator(ctx context.Context, transport distributed.Transport) {
	log.Println("Starting coordinator...")

	coord := &SimpleCoordinator{
		transport: transport,
		workers:   make(map[string]time.Time),
	}

	// Subscribe to heartbeats
	hbChan, hbCancel, err := transport.SubscribeHeartbeats(ctx)
	if err != nil {
		log.Fatalf("Failed to subscribe heartbeats: %v", err)
	}
	defer hbCancel()

	// Subscribe to results
	resChan, resCancel, err := transport.SubscribeResults(ctx)
	if err != nil {
		log.Fatalf("Failed to subscribe results: %v", err)
	}
	defer resCancel()

	// Heartbeat processor
	coord.wg.Add(1)
	go func() {
		defer coord.wg.Done()
		for {
			select {
			case hb := <-hbChan:
				coord.mu.Lock()
				coord.workers[hb.WorkerID] = time.Now()
				coord.mu.Unlock()
				log.Printf("[Coordinator] Heartbeat from worker: %s (caps: %v)", hb.WorkerID, hb.Capabilities)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Result processor
	coord.wg.Add(1)
	go func() {
		defer coord.wg.Done()
		for {
			select {
			case res := <-resChan:
				log.Printf("[Coordinator] Result: cmd=%s worker=%s success=%v", res.CommandID, res.WorkerID, res.Success)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Demo: Submit test command every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			coord.mu.RLock()
			activeWorkers := len(coord.workers)
			coord.mu.RUnlock()
			log.Printf("[Coordinator] Active workers: %d", activeWorkers)

			// Submit demo command
			cmd := distributed.CommandEnvelope{
				ID:        fmt.Sprintf("test-%d", time.Now().Unix()),
				Target:    "demo",
				Command:   "noop",
				Payload:   []byte("test payload"),
				CreatedAt: time.Now(),
			}
			if err := transport.PublishCommand(ctx, cmd); err != nil {
				log.Printf("[Coordinator] Failed to publish command: %v", err)
			}

		case <-ctx.Done():
			log.Println("[Coordinator] Shutting down...")
			coord.wg.Wait()
			return
		}
	}
}

func runWorker(ctx context.Context, transport distributed.Transport, workerID string) {
	log.Println("Starting worker...")

	capabilities := parseCapabilities(getEnv("CAPABILITIES", "shell,http,scan"))

	worker, err := distributed.NewWorker(distributed.WorkerConfig{
		WorkerID:      workerID,
		Transport:     transport,
		Capabilities:  capabilities,
		HeartbeatTick: 5 * time.Second,
		Metadata: map[string]string{
			"hostname": getHostname(),
			"version":  "1.0.0",
		},
	})
	if err != nil {
		log.Fatalf("Failed to create worker: %v", err)
	}

	if err := worker.Start(); err != nil {
		log.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	<-ctx.Done()
	log.Println("Worker shutting down...")
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func parseCapabilities(s string) []string {
	if s == "" {
		return []string{}
	}
	var caps []string
	for _, c := range splitString(s, ",") {
		if c != "" {
			caps = append(caps, c)
		}
	}
	return caps
}

func splitString(s, sep string) []string {
	var result []string
	current := ""
	for _, r := range s {
		if string(r) == sep {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(r)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func getHostname() string {
	h, _ := os.Hostname()
	return h
}
