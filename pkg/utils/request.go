package utils

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var userAgents = []string{
	// Chrome (Latest)
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",

	// Firefox (Latest)
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",

	// Safari (Latest)
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",

	// Edge (Latest)
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",

	// Opera
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",

	// Mobile browsers
	"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}

var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9",
	"en-US,en;q=0.9,es;q=0.8,fr;q=0.7",
	"en-US,en;q=0.8,es;q=0.7",
	"en,es;q=0.9,fr;q=0.8,de;q=0.7",
	"de-DE,de;q=0.9,en;q=0.8",
	"fr-FR,fr;q=0.9,en;q=0.8",
	"ja-JP,ja;q=0.9,en;q=0.8",
	"zh-CN,zh;q=0.9,en;q=0.8",
	"es-ES,es;q=0.9,en;q=0.8",
	"ru-RU,ru;q=0.9,en;q=0.8",
	"pt-BR,pt;q=0.9,en;q=0.8",
	"it-IT,it;q=0.9,en;q=0.8",
	"ko-KR,ko;q=0.9,en;q=0.8",
	"nl-NL,nl;q=0.9,en;q=0.8",
	"sv-SE,sv;q=0.9,en;q=0.8",
}

var acceptEncodings = []string{
	"gzip, deflate, br, zstd",
	"gzip, deflate, br",
	"gzip, deflate",
	"br, gzip, deflate",
	"gzip",
	"deflate",
}

var acceptTypes = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"application/json,text/plain,*/*;q=0.9",
}

func GenerateRandomHeaders(host string) map[string]string {
	headers := make(map[string]string)

	// Core headers
	headers["Host"] = host
	userAgent := userAgents[rand.Intn(len(userAgents))]
	headers["User-Agent"] = userAgent
	headers["Accept"] = acceptTypes[rand.Intn(len(acceptTypes))]
	headers["Accept-Language"] = acceptLanguages[rand.Intn(len(acceptLanguages))]
	headers["Accept-Encoding"] = acceptEncodings[rand.Intn(len(acceptEncodings))]

	// Connection settings
	if rand.Intn(10) < 8 {
		headers["Connection"] = "keep-alive"
	} else {
		headers["Connection"] = "close"
	}

	headers["Cache-Control"] = randomCacheControl()
	headers["Upgrade-Insecure-Requests"] = "1"

	// Detect browser type from User-Agent
	browserType := detectBrowserType(userAgent)

	// Chrome/Edge-specific headers
	if strings.Contains(browserType, "chrome") || strings.Contains(browserType, "edge") {
		addChromeHeaders(headers, userAgent)
	}

	// Firefox-specific headers
	if strings.Contains(browserType, "firefox") {
		addFirefoxHeaders(headers)
	}

	// Safari-specific headers
	if strings.Contains(browserType, "safari") && !strings.Contains(browserType, "chrome") {
		addSafariHeaders(headers)
	}

	// Modern browser security headers (randomly include)
	if rand.Intn(3) < 2 {
		headers["Sec-Fetch-Dest"] = randomFetchDest()
		headers["Sec-Fetch-Mode"] = randomFetchMode()
		headers["Sec-Fetch-Site"] = randomFetchSite()

		if rand.Intn(2) == 0 {
			headers["Sec-Fetch-User"] = "?1"
		}
	}

	// Random referer (occasionally)
	if rand.Intn(4) < 3 {
		headers["Referer"] = randomReferer(host)
	}

	// DNT header (some users have this)
	if rand.Intn(5) == 0 {
		headers["DNT"] = "1"
	}

	// Priority hints (HTTP/2+)
	if rand.Intn(3) == 0 {
		headers["Priority"] = randomPriority()
	}

	return headers
}

func detectBrowserType(userAgent string) string {
	ua := strings.ToLower(userAgent)
	if strings.Contains(ua, "edg/") {
		return "edge"
	}
	if strings.Contains(ua, "chrome/") && !strings.Contains(ua, "edg/") {
		return "chrome"
	}
	if strings.Contains(ua, "firefox/") {
		return "firefox"
	}
	if strings.Contains(ua, "safari/") && !strings.Contains(ua, "chrome/") {
		return "safari"
	}
	return "unknown"
}

func addChromeHeaders(headers map[string]string, userAgent string) {
	// Extract Chrome version
	chromeVersion := extractChromeVersion(userAgent)

	// Client Hints
	headers["Sec-CH-UA"] = fmt.Sprintf(`"Not_A Brand";v="8", "Chromium";v="%d", "Google Chrome";v="%d"`, chromeVersion, chromeVersion)
	headers["Sec-CH-UA-Mobile"] = "?0"
	headers["Sec-CH-UA-Platform"] = randomPlatform()

	// Enhanced Client Hints (randomly)
	if rand.Intn(2) == 0 {
		headers["Sec-CH-UA-Platform-Version"] = randomPlatformVersion()
		headers["Sec-CH-UA-Full-Version-List"] = fmt.Sprintf(`"Google Chrome";v="%d.0.6261.112", "Chromium";v="%d.0.6261.112", "Not_A Brand";v="8.0.0.0"`, chromeVersion, chromeVersion)
	}

	if rand.Intn(3) == 0 {
		headers["Sec-CH-UA-Arch"] = randomArch()
		headers["Sec-CH-UA-Bitness"] = "64"
		headers["Sec-CH-UA-Model"] = ""
	}
}

func addFirefoxHeaders(headers map[string]string) {
	// Firefox doesn't use Client Hints but has its own patterns
	if rand.Intn(2) == 0 {
		headers["TE"] = "trailers"
	}
}

func addSafariHeaders(headers map[string]string) {
	// Safari-specific patterns
	if rand.Intn(2) == 0 {
		headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	}
}

func extractChromeVersion(userAgent string) int {
	// Extract Chrome version from UA
	if idx := strings.Index(userAgent, "Chrome/"); idx != -1 {
		versionStr := userAgent[idx+7:]
		if dotIdx := strings.Index(versionStr, "."); dotIdx != -1 {
			versionStr = versionStr[:dotIdx]
			if version, err := strconv.Atoi(versionStr); err == nil {
				return version
			}
		}
	}
	return 122 // Default to recent version
}

func randomCacheControl() string {
	options := []string{
		"max-age=0",
		"no-cache",
		"no-cache, no-store, must-revalidate",
		"max-age=31536000",
		"no-store",
		"public, max-age=3600",
	}
	return options[rand.Intn(len(options))]
}

func randomFetchDest() string {
	dests := []string{"document", "empty", "iframe", "script", "style", "image"}
	return dests[rand.Intn(len(dests))]
}

func randomFetchMode() string {
	modes := []string{"navigate", "cors", "no-cors", "same-origin"}
	return modes[rand.Intn(len(modes))]
}

func randomFetchSite() string {
	options := []string{"none", "same-origin", "same-site", "cross-site"}
	return options[rand.Intn(len(options))]
}

func randomPlatform() string {
	platforms := []string{`"Windows"`, `"macOS"`, `"Linux"`}
	return platforms[rand.Intn(len(platforms))]
}

func randomPlatformVersion() string {
	versions := map[string][]string{
		"Windows": {"10.0.0", "11.0.0", "10.0.19045"},
		"macOS":   {"14.0.0", "13.5.0", "12.6.0"},
		"Linux":   {"6.2.0", "5.15.0", "5.19.0"},
	}
	os := []string{"Windows", "macOS", "Linux"}
	selected := os[rand.Intn(len(os))]
	version := versions[selected][rand.Intn(len(versions[selected]))]
	return `"` + version + `"`
}

func randomArch() string {
	archs := []string{`"x86"`, `"arm"`}
	return archs[rand.Intn(len(archs))]
}

func randomPriority() string {
	priorities := []string{"u=0, i", "u=1, i", "u=2", "u=3"}
	return priorities[rand.Intn(len(priorities))]
}

func randomReferer(host string) string {
	referers := []string{
		"https://www.google.com/search?q=" + host,
		"https://www.google.com/",
		"https://www.bing.com/search?q=" + host,
		"https://www.bing.com/",
		"https://duckduckgo.com/?q=" + host,
		"https://duckduckgo.com/",
		"https://" + host + "/",
		"https://" + host + "/home",
		"https://www.facebook.com/",
		"https://twitter.com/",
		"https://www.reddit.com/",
		"https://www.linkedin.com/",
		"https://github.com/",
	}
	return referers[rand.Intn(len(referers))]
}

func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func RandomHex(length int) string {
	const hexchars = "0123456789abcdef"
	result := make([]byte, length)
	for i := range result {
		result[i] = hexchars[rand.Intn(len(hexchars))]
	}
	return string(result)
}

func RandomIP() string {
	// Generate realistic IPs (avoid reserved ranges)
	firstOctet := rand.Intn(223) + 1
	// Avoid 10.x.x.x, 172.16-31.x.x, 192.168.x.x
	for firstOctet == 10 || firstOctet == 127 || (firstOctet == 172) || (firstOctet == 192) {
		firstOctet = rand.Intn(223) + 1
	}

	return fmt.Sprintf("%d.%d.%d.%d",
		firstOctet,
		rand.Intn(256),
		rand.Intn(256),
		rand.Intn(254)+1,
	)
}

func RandomIPv6() string {
	// Generate random IPv6 address
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		rand.Intn(65536), rand.Intn(65536), rand.Intn(65536), rand.Intn(65536),
		rand.Intn(65536), rand.Intn(65536), rand.Intn(65536), rand.Intn(65536))
}

func ParseVectors(vectorsStr string) []string {
	vectors := strings.Split(vectorsStr, ",")
	result := make([]string, 0, len(vectors))
	for _, v := range vectors {
		v = strings.TrimSpace(v)
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}
