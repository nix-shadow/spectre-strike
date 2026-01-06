package validator

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	ipv4Regex  = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

func IsValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsValidPort(port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return p >= 1 && p <= 65535
}

func IsValidPortRange(portRange string) bool {
	parts := strings.Split(portRange, "-")
	if len(parts) != 2 {
		return false
	}
	start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return false
	}
	return start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end
}

func IsValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func IsValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

func IsValidDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9-]+$`).MatchString(label) {
			return false
		}
	}
	return true
}

func ValidateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	if IsValidURL(target) {
		return nil
	}

	if IsValidIP(target) {
		return nil
	}

	if IsValidDomain(target) {
		return nil
	}

	return fmt.Errorf("invalid target format: must be URL, IP, or domain")
}

func ValidateThreadCount(threads int) error {
	if threads < 1 {
		return fmt.Errorf("thread count must be at least 1")
	}
	if threads > 1000 {
		return fmt.Errorf("thread count cannot exceed 1000")
	}
	return nil
}

func ValidateTimeout(timeout int) error {
	if timeout < 1 {
		return fmt.Errorf("timeout must be at least 1 second")
	}
	if timeout > 300 {
		return fmt.Errorf("timeout cannot exceed 300 seconds")
	}
	return nil
}

func SanitizeInput(input string) string {
	input = strings.TrimSpace(input)
	input = regexp.MustCompile(`[^a-zA-Z0-9./_:?&=-]`).ReplaceAllString(input, "")
	return input
}
