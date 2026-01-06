package distributed

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Worker executes commands received from coordinator.
type Worker struct {
	id            string
	capabilities  []string
	transport     Transport
	handlers      map[string]CommandHandler
	handlersMu    sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	heartbeatTick time.Duration
	metadata      map[string]string
}

// CommandHandler processes specific command types.
type CommandHandler func(ctx context.Context, cmd CommandEnvelope) ResultEnvelope

// WorkerConfig configures worker behavior.
type WorkerConfig struct {
	WorkerID      string
	Transport     Transport
	Capabilities  []string
	HeartbeatTick time.Duration
	Metadata      map[string]string
}

// NewWorker creates a worker instance.
func NewWorker(cfg WorkerConfig) (*Worker, error) {
	if cfg.WorkerID == "" {
		cfg.WorkerID = uuid.New().String()
	}
	if cfg.HeartbeatTick == 0 {
		cfg.HeartbeatTick = 5 * time.Second
	}
	if cfg.Capabilities == nil {
		cfg.Capabilities = []string{"shell", "http", "scan"}
	}
	if cfg.Metadata == nil {
		cfg.Metadata = make(map[string]string)
	}

	ctx, cancel := context.WithCancel(context.Background())
	w := &Worker{
		id:            cfg.WorkerID,
		capabilities:  cfg.Capabilities,
		transport:     cfg.Transport,
		handlers:      make(map[string]CommandHandler),
		ctx:           ctx,
		cancel:        cancel,
		heartbeatTick: cfg.HeartbeatTick,
		metadata:      cfg.Metadata,
	}

	// Register default handlers
	w.RegisterHandler("shell", w.handleShell)
	w.RegisterHandler("http", w.handleHTTP)
	w.RegisterHandler("noop", w.handleNoop)

	return w, nil
}

// RegisterHandler adds a command handler.
func (w *Worker) RegisterHandler(command string, handler CommandHandler) {
	w.handlersMu.Lock()
	w.handlers[command] = handler
	w.handlersMu.Unlock()
}

// Start launches worker goroutines.
func (w *Worker) Start() error {
	// Subscribe to commands
	cmdChan, cmdCancel, err := w.transport.SubscribeCommands(w.ctx)
	if err != nil {
		return fmt.Errorf("subscribe commands: %w", err)
	}

	// Command processor
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer cmdCancel()
		w.processCommands(cmdChan)
	}()

	// Heartbeat emitter
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.sendHeartbeats()
	}()

	log.Printf("[Worker %s] Started with capabilities: %v", w.id, w.capabilities)
	return nil
}

// Stop gracefully shuts down worker.
func (w *Worker) Stop() {
	w.cancel()
	w.wg.Wait()
	log.Printf("[Worker %s] Stopped", w.id)
}

// processCommands receives and executes commands.
func (w *Worker) processCommands(cmdChan <-chan CommandEnvelope) {
	for {
		select {
		case cmd, ok := <-cmdChan:
			if !ok {
				return
			}
			go w.executeCommand(cmd)

		case <-w.ctx.Done():
			return
		}
	}
}

// executeCommand runs a command and publishes result.
func (w *Worker) executeCommand(cmd CommandEnvelope) {
	start := time.Now()
	ctx := w.ctx
	if !cmd.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, cmd.Deadline)
		defer cancel()
	}

	w.handlersMu.RLock()
	handler, exists := w.handlers[cmd.Command]
	w.handlersMu.RUnlock()

	var result ResultEnvelope
	if !exists {
		result = ResultEnvelope{
			CommandID: cmd.ID,
			WorkerID:  w.id,
			Success:   false,
			Error:     fmt.Sprintf("unknown command: %s", cmd.Command),
			Finished:  time.Now(),
		}
	} else {
		result = handler(ctx, cmd)
		result.CommandID = cmd.ID
		result.WorkerID = w.id
		result.Finished = time.Now()
	}

	if result.Metadata == nil {
		result.Metadata = make(map[string]string)
	}
	result.Metadata["execution_time"] = time.Since(start).String()

	if err := w.transport.PublishResult(w.ctx, result); err != nil {
		log.Printf("[Worker %s] Failed to publish result for %s: %v", w.id, cmd.ID, err)
	}
}

// sendHeartbeats periodically announces worker presence.
func (w *Worker) sendHeartbeats() {
	ticker := time.NewTicker(w.heartbeatTick)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hb := Heartbeat{
				WorkerID:     w.id,
				Capabilities: w.capabilities,
				Metadata:     w.metadata,
				Timestamp:    time.Now(),
			}
			if err := w.transport.PublishHeartbeat(w.ctx, hb); err != nil {
				log.Printf("[Worker %s] Failed to publish heartbeat: %v", w.id, err)
			}

		case <-w.ctx.Done():
			return
		}
	}
}

// Default handlers

func (w *Worker) handleShell(ctx context.Context, cmd CommandEnvelope) ResultEnvelope {
	cmdStr := string(cmd.Payload)
	out, err := exec.CommandContext(ctx, "sh", "-c", cmdStr).CombinedOutput()
	return ResultEnvelope{
		Success: err == nil,
		Output:  out,
		Error:   errString(err),
	}
}

func (w *Worker) handleHTTP(ctx context.Context, cmd CommandEnvelope) ResultEnvelope {
	// Placeholder: implement HTTP request handling
	return ResultEnvelope{
		Success: true,
		Output:  []byte("HTTP handler not implemented"),
	}
}

func (w *Worker) handleNoop(ctx context.Context, cmd CommandEnvelope) ResultEnvelope {
	return ResultEnvelope{
		Success: true,
		Output:  []byte("noop"),
	}
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
