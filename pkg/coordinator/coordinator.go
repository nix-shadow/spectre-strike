package coordinator

import (
	"fmt"
	"sync"
	"time"

	"spectre-strike/pkg/logger"
	"spectre-strike/pkg/monitor"
)

// Coordinator manages operations across all modules
type Coordinator struct {
	mu           sync.Mutex
	operations   map[string]*Operation
	globalConfig *GlobalConfig
	isRunning    bool
}

// Operation represents a running operation
type Operation struct {
	ID         string
	Type       string
	Target     string
	StartTime  time.Time
	Status     string
	Cancel     chan bool
	ResultChan chan Result
}

// GlobalConfig holds global configuration
type GlobalConfig struct {
	LogLevel        string
	LogFile         string
	AntiForensics   bool
	MetricsEnabled  bool
	MonitorEnabled  bool
	MonitorInterval time.Duration
	MaxOperations   int
}

// Result represents operation result
type Result struct {
	OperationID string
	Success     bool
	Message     string
	Data        interface{}
	Error       error
}

var globalCoordinator *Coordinator

// Init initializes the coordinator
func Init(config *GlobalConfig) error {
	globalCoordinator = &Coordinator{
		operations:   make(map[string]*Operation),
		globalConfig: config,
		isRunning:    true,
	}

	// Initialize logger
	logLevel := logger.INFO
	switch config.LogLevel {
	case "debug":
		logLevel = logger.DEBUG
	case "warning":
		logLevel = logger.WARNING
	case "error":
		logLevel = logger.ERROR
	case "critical":
		logLevel = logger.CRITICAL
	}

	if err := logger.Init(logLevel, config.LogFile, config.AntiForensics); err != nil {
		return fmt.Errorf("failed to initialize logger: %v", err)
	}

	// Initialize metrics
	// Metrics package initializes automatically when used

	// Start monitor
	if config.MonitorEnabled {
		monitor.Start(config.MonitorInterval, monitor.DisplayAll)
	}

	logger.Info("Coordinator initialized")
	return nil
}

// RegisterOperation registers a new operation
func RegisterOperation(opType, target string) *Operation {
	if globalCoordinator == nil {
		return nil
	}

	globalCoordinator.mu.Lock()
	defer globalCoordinator.mu.Unlock()

	op := &Operation{
		ID:         fmt.Sprintf("%s-%d", opType, time.Now().Unix()),
		Type:       opType,
		Target:     target,
		StartTime:  time.Now(),
		Status:     "running",
		Cancel:     make(chan bool, 1),
		ResultChan: make(chan Result, 1),
	}

	globalCoordinator.operations[op.ID] = op
	logger.Info("Operation registered: %s on %s", opType, target)

	return op
}

// CancelOperation cancels an operation
func CancelOperation(opID string) error {
	if globalCoordinator == nil {
		return fmt.Errorf("coordinator not initialized")
	}

	globalCoordinator.mu.Lock()
	defer globalCoordinator.mu.Unlock()

	op, exists := globalCoordinator.operations[opID]
	if !exists {
		return fmt.Errorf("operation not found: %s", opID)
	}

	op.Cancel <- true
	op.Status = "cancelled"
	logger.Warning("Operation cancelled: %s", opID)

	return nil
}

// CompleteOperation marks operation as complete
func CompleteOperation(opID string, result Result) {
	if globalCoordinator == nil {
		return
	}

	globalCoordinator.mu.Lock()
	defer globalCoordinator.mu.Unlock()

	op, exists := globalCoordinator.operations[opID]
	if !exists {
		return
	}

	op.Status = "completed"
	op.ResultChan <- result

	if result.Success {
		logger.Info("Operation completed successfully: %s", opID)
	} else {
		logger.Error("Operation failed: %s - %v", opID, result.Error)
	}
}

// GetActiveOperations returns all active operations
func GetActiveOperations() []*Operation {
	if globalCoordinator == nil {
		return nil
	}

	globalCoordinator.mu.Lock()
	defer globalCoordinator.mu.Unlock()

	var active []*Operation
	for _, op := range globalCoordinator.operations {
		if op.Status == "running" {
			active = append(active, op)
		}
	}

	return active
}

// Shutdown shuts down the coordinator
func Shutdown() {
	if globalCoordinator == nil {
		return
	}

	globalCoordinator.mu.Lock()
	globalCoordinator.isRunning = false
	globalCoordinator.mu.Unlock()

	// Cancel all active operations
	for opID := range globalCoordinator.operations {
		CancelOperation(opID)
	}

	// Stop monitoring
	monitor.Stop()
	monitor.PrintFinalReport()

	// Close logger
	logger.Close()

	logger.Info("Coordinator shutdown complete")
}

// SetupDefaults sets up default configuration
func SetupDefaults() *GlobalConfig {
	return &GlobalConfig{
		LogLevel:        "info",
		LogFile:         "./logs/operations.log",
		AntiForensics:   false,
		MetricsEnabled:  true,
		MonitorEnabled:  true,
		MonitorInterval: 2 * time.Second,
		MaxOperations:   10,
	}
}

// SetupStealth sets up stealth configuration
func SetupStealth() *GlobalConfig {
	return &GlobalConfig{
		LogLevel:        "error",
		LogFile:         "/dev/shm/ops.log", // Memory-only
		AntiForensics:   true,
		MetricsEnabled:  true,
		MonitorEnabled:  false, // No display
		MonitorInterval: 5 * time.Second,
		MaxOperations:   5,
	}
}

// SetupAggressive sets up aggressive configuration
func SetupAggressive() *GlobalConfig {
	return &GlobalConfig{
		LogLevel:        "debug",
		LogFile:         "./logs/operations-detailed.log",
		AntiForensics:   false,
		MetricsEnabled:  true,
		MonitorEnabled:  true,
		MonitorInterval: 1 * time.Second,
		MaxOperations:   20,
	}
}

// WaitForOperation waits for operation to complete
func WaitForOperation(op *Operation, timeout time.Duration) (*Result, error) {
	select {
	case result := <-op.ResultChan:
		return &result, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("operation timed out")
	case <-op.Cancel:
		return nil, fmt.Errorf("operation cancelled")
	}
}

// HealthCheck performs health check on all systems
func HealthCheck() map[string]bool {
	health := make(map[string]bool)

	health["coordinator"] = globalCoordinator != nil && globalCoordinator.isRunning
	health["logger"] = true // Logger is always available
	health["metrics"] = globalCoordinator != nil && globalCoordinator.globalConfig.MetricsEnabled
	health["monitor"] = true // Monitor is optional

	return health
}
