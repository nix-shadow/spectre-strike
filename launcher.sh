#!/bin/bash

# Spectre Strike - Interactive Launcher (Bash Edition)
# Professional Edition v3.0

# Colors
CYAN='\033[96m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
BLUE='\033[94m'
MAGENTA='\033[95m'
WHITE='\033[97m'
BOLD='\033[1m'
RESET='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_banner() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║                                                                   ║${RESET}"
    echo -e "${CYAN}║      ADVANCED ATTACK TOOL - PROFESSIONAL EDITION v3.0             ║${RESET}"
    echo -e "${CYAN}║              Next-Gen Layer 7 Framework                           ║${RESET}"
    echo -e "${CYAN}║                                                                   ║${RESET}"
    echo -e "${CYAN}║  🎯 Multi-Purpose Pentesting & Security Assessment Tool           ║${RESET}"
    echo -e "${CYAN}║                                                                   ║${RESET}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

check_dependencies() {
    echo -e "\n${YELLOW}[*] Checking dependencies...${RESET}"
    
    # Check Go installation
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version)
        echo -e "${GREEN}✅ Go is installed: $GO_VERSION${RESET}"
    else
        echo -e "${RED}❌ Go is not installed. Please install Go 1.20+${RESET}"
        return 1
    fi
    
    # Check if attack binary exists
    if [ ! -f "./attack" ]; then
        echo -e "${YELLOW}⚠️  Attack binary not found. Building...${RESET}"
        build_project
        return $?
    else
        echo -e "${GREEN}✅ Attack binary found${RESET}"
    fi
    
    return 0
}

build_project() {
    echo -e "\n${CYAN}[*] Building project...${RESET}"
    
    if go build -o attack ./cmd/main.go 2>&1; then
        echo -e "${GREEN}✅ Build successful!${RESET}"
        return 0
    else
        echo -e "${RED}❌ Build failed${RESET}"
        return 1
    fi
}

show_main_menu() {
    echo -e "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${CYAN}                    MAIN MENU${RESET}"
    echo -e "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "${GREEN}[1]${RESET}  🌐 Web Exploitation"
    echo -e "${GREEN}[2]${RESET}  🔐 Password Attacks"
    echo -e "${GREEN}[3]${RESET}  🔍 Network Operations"
    echo -e "${GREEN}[4]${RESET}  🎯 DDoS/Stress Testing"
    echo -e "${GREEN}[5]${RESET}  🕵️  Red Team Operations"
    echo -e "${GREEN}[6]${RESET}  📚 View Full Documentation"
    echo -e "${GREEN}[7]${RESET}  🔧 Build/Rebuild Project"
    echo -e "${GREEN}[8]${RESET}  ℹ️  Show Help & Usage Guide"
    echo -e "${GREEN}[9]${RESET}  📊 Quick Examples"
    echo -e "${GREEN}[0]${RESET}  🚪 Exit"
    echo ""
    echo -e "${BOLD}${WHITE}═══════════════════════════════════════════════════════════════${RESET}"
    echo ""
}

web_exploitation_menu() {
    clear
    print_banner
    echo -e "${CYAN}═══════════════ WEB EXPLOITATION ══════════════════${RESET}"
    echo ""
    echo -e "${GREEN}[1]${RESET} 🔍 Full Vulnerability Scan"
    echo -e "${GREEN}[2]${RESET} 💉 SQL Injection Testing"
    echo -e "${GREEN}[3]${RESET} 🎨 XSS (Cross-Site Scripting) Testing"
    echo -e "${GREEN}[4]${RESET} 📁 LFI/RFI (File Inclusion) Testing"
    echo -e "${GREEN}[5]${RESET} 🗂️  Directory/File Brute Force"
    echo -e "${GREEN}[0]${RESET} ⬅️  Back to Main Menu"
    echo ""
    
    read -p "$(echo -e ${YELLOW}Select option: ${RESET})" choice
    
    case $choice in
        1)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Scan depth \(light/medium/deep\) [medium]: ${RESET})" depth
            depth=${depth:-medium}
            run_command "./attack web-scan -target $target -depth $depth"
            ;;
        2)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            run_command "./attack sqli -target $target"
            ;;
        3)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            run_command "./attack xss -target $target"
            ;;
        4)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            run_command "./attack lfi -target $target"
            ;;
        5)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Wordlist [wordlists/directories.txt]: ${RESET})" wordlist
            wordlist=${wordlist:-wordlists/directories.txt}
            read -p "$(echo -e ${CYAN}Threads [20]: ${RESET})" threads
            threads=${threads:-20}
            run_command "./attack dir-brute -target $target -wordlist $wordlist -threads $threads"
            ;;
        0)
            return
            ;;
    esac
}

password_attacks_menu() {
    clear
    print_banner
    echo -e "${CYAN}═══════════════ PASSWORD ATTACKS ══════════════════${RESET}"
    echo ""
    echo -e "${GREEN}[1]${RESET} 🔓 HTTP Basic Auth Brute Force"
    echo -e "${GREEN}[2]${RESET} 🌐 HTTP Form-Based Brute Force"
    echo -e "${GREEN}[3]${RESET} 🔐 SSH Brute Force"
    echo -e "${GREEN}[4]${RESET} 📂 FTP Brute Force"
    echo -e "${GREEN}[5]${RESET} #️⃣  Hash Cracking (MD5/SHA1/SHA256/SHA512)"
    echo -e "${GREEN}[0]${RESET} ⬅️  Back to Main Menu"
    echo ""
    
    read -p "$(echo -e ${YELLOW}Select option: ${RESET})" choice
    
    case $choice in
        1)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Username\(s\) or file [admin]: ${RESET})" users
            users=${users:-admin}
            read -p "$(echo -e ${CYAN}Password wordlist [wordlists/passwords.txt]: ${RESET})" passwords
            passwords=${passwords:-wordlists/passwords.txt}
            read -p "$(echo -e ${CYAN}Threads [10]: ${RESET})" threads
            threads=${threads:-10}
            run_command "./attack password-brute -target $target -users $users -passwords $passwords -protocol http-basic -threads $threads"
            ;;
        2)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Login form URL: ${RESET})" login_url
            read -p "$(echo -e ${CYAN}Username\(s\) or file [admin]: ${RESET})" users
            users=${users:-admin}
            read -p "$(echo -e ${CYAN}Password wordlist [wordlists/passwords.txt]: ${RESET})" passwords
            passwords=${passwords:-wordlists/passwords.txt}
            read -p "$(echo -e ${CYAN}Username field name [username]: ${RESET})" user_field
            user_field=${user_field:-username}
            read -p "$(echo -e ${CYAN}Password field name [password]: ${RESET})" pass_field
            pass_field=${pass_field:-password}
            run_command "./attack password-brute -target $target -users $users -passwords $passwords -protocol http-form -login-url $login_url -user-field $user_field -pass-field $pass_field"
            ;;
        3)
            read -p "$(echo -e ${CYAN}Enter target host:port: ${RESET})" target
            read -p "$(echo -e ${CYAN}Username\(s\) or file [root]: ${RESET})" users
            users=${users:-root}
            read -p "$(echo -e ${CYAN}Password wordlist [wordlists/passwords.txt]: ${RESET})" passwords
            passwords=${passwords:-wordlists/passwords.txt}
            run_command "./attack password-brute -target $target -users $users -passwords $passwords -protocol ssh"
            ;;
        4)
            read -p "$(echo -e ${CYAN}Enter target host:port: ${RESET})" target
            read -p "$(echo -e ${CYAN}Username\(s\) or file [anonymous]: ${RESET})" users
            users=${users:-anonymous}
            read -p "$(echo -e ${CYAN}Password wordlist [wordlists/passwords.txt]: ${RESET})" passwords
            passwords=${passwords:-wordlists/passwords.txt}
            run_command "./attack password-brute -target $target -users $users -passwords $passwords -protocol ftp"
            ;;
        5)
            read -p "$(echo -e ${CYAN}Hash or file with hashes: ${RESET})" hash_input
            read -p "$(echo -e ${CYAN}Hash type \(md5/sha1/sha256/sha512\) [md5]: ${RESET})" hash_type
            hash_type=${hash_type:-md5}
            read -p "$(echo -e ${CYAN}Wordlist [wordlists/passwords.txt]: ${RESET})" wordlist
            wordlist=${wordlist:-wordlists/passwords.txt}
            read -p "$(echo -e ${CYAN}Threads [10]: ${RESET})" threads
            threads=${threads:-10}
            run_command "./attack hash-crack -hash $hash_input -type $hash_type -wordlist $wordlist -threads $threads"
            ;;
        0)
            return
            ;;
    esac
}

network_operations_menu() {
    clear
    print_banner
    echo -e "${CYAN}═══════════════ NETWORK OPERATIONS ════════════════${RESET}"
    echo ""
    echo -e "${GREEN}[1]${RESET} 🔌 Port Scanning"
    echo -e "${GREEN}[2]${RESET} 🔍 Service Enumeration"
    echo -e "${GREEN}[3]${RESET} 🌐 Subnet/Host Discovery"
    echo -e "${GREEN}[4]${RESET} 📊 Quick Vulnerability Scan"
    echo -e "${GREEN}[0]${RESET} ⬅️  Back to Main Menu"
    echo ""
    
    read -p "$(echo -e ${YELLOW}Select option: ${RESET})" choice
    
    case $choice in
        1)
            read -p "$(echo -e ${CYAN}Enter target host/IP: ${RESET})" target
            read -p "$(echo -e ${CYAN}Port range \(e.g., 1-1000, 80,443\) or leave empty for top ports: ${RESET})" ports
            read -p "$(echo -e ${CYAN}Threads [50]: ${RESET})" threads
            threads=${threads:-50}
            read -p "$(echo -e ${CYAN}Enable service detection? \(y/n\) [y]: ${RESET})" service
            service=${service:-y}
            
            if [ -z "$ports" ]; then
                cmd="./attack port-scan -target $target -threads $threads -top-ports 100"
            else
                cmd="./attack port-scan -target $target -threads $threads -ports $ports"
            fi
            
            if [ "$service" = "y" ]; then
                cmd="$cmd -service"
            fi
            
            run_command "$cmd"
            ;;
        2)
            read -p "$(echo -e ${CYAN}Enter target host/IP: ${RESET})" target
            read -p "$(echo -e ${CYAN}Ports to enumerate \(e.g., 22,80,443\) [common]: ${RESET})" ports
            if [ -z "$ports" ]; then
                run_command "./attack service-enum -target $target"
            else
                run_command "./attack service-enum -target $target -ports $ports"
            fi
            ;;
        3)
            read -p "$(echo -e ${CYAN}Enter subnet \(e.g., 192.168.1.0/24\): ${RESET})" subnet
            read -p "$(echo -e ${CYAN}Threads [50]: ${RESET})" threads
            threads=${threads:-50}
            run_command "./attack subnet-scan -subnet $subnet -threads $threads"
            ;;
        4)
            read -p "$(echo -e ${CYAN}Enter target URL or IP: ${RESET})" target
            run_command "./attack scan -target $target"
            ;;
        0)
            return
            ;;
    esac
}

ddos_menu() {
    clear
    print_banner
    echo -e "${RED}═══════════════ DDoS/STRESS TESTING ═══════════════${RESET}"
    echo -e "${YELLOW}⚠️  WARNING: Only use on authorized targets!${RESET}"
    echo ""
    echo -e "${GREEN}[1]${RESET} 🐢 Slowloris Attack"
    echo -e "${GREEN}[2]${RESET} 🧠 Adaptive ML-Powered Attack"
    echo -e "${GREEN}[3]${RESET} 🔌 WebSocket Flood"
    echo -e "${GREEN}[4]${RESET} 🛡️  WAF Bypass Attack"
    echo -e "${GREEN}[5]${RESET} ⚡ Hybrid Multi-Vector Attack"
    echo -e "${GREEN}[0]${RESET} ⬅️  Back to Main Menu"
    echo ""
    
    read -p "$(echo -e ${YELLOW}Select option: ${RESET})" choice
    
    case $choice in
        1)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Duration \(seconds\) [60]: ${RESET})" duration
            duration=${duration:-60}
            read -p "$(echo -e ${CYAN}Connections [200]: ${RESET})" connections
            connections=${connections:-200}
            run_command "./attack slowloris -target $target -duration $duration -connections $connections"
            ;;
        2)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Duration \(seconds\) [180]: ${RESET})" duration
            duration=${duration:-180}
            run_command "./attack adaptive -target $target -duration $duration"
            ;;
        3)
            read -p "$(echo -e ${CYAN}Enter target WebSocket URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Duration \(seconds\) [120]: ${RESET})" duration
            duration=${duration:-120}
            run_command "./attack websocket -target $target -duration $duration"
            ;;
        4)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Duration \(seconds\) [120]: ${RESET})" duration
            duration=${duration:-120}
            run_command "./attack waf-bypass -target $target -duration $duration"
            ;;
        5)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Duration \(seconds\) [180]: ${RESET})" duration
            duration=${duration:-180}
            read -p "$(echo -e ${CYAN}Vectors \(comma-separated\) [slowloris,http2,adaptive]: ${RESET})" vectors
            vectors=${vectors:-slowloris,http2,adaptive}
            run_command "./attack hybrid -target $target -duration $duration -vectors $vectors"
            ;;
        0)
            return
            ;;
    esac
}

redteam_menu() {
    clear
    print_banner
    echo -e "${MAGENTA}═══════════════ RED TEAM OPERATIONS ═══════════════${RESET}"
    echo ""
    echo -e "${GREEN}[1]${RESET} 🔍 Advanced Reconnaissance"
    echo -e "${GREEN}[2]${RESET} 🥷 Stealth Attack Mode"
    echo -e "${GREEN}[3]${RESET} 📡 Start C2 Server"
    echo -e "${GREEN}[4]${RESET} 📤 Data Exfiltration"
    echo -e "${GREEN}[5]${RESET} 🔄 Pivot Attack"
    echo -e "${GREEN}[6]${RESET} 🌐 Distributed Attack"
    echo -e "${GREEN}[0]${RESET} ⬅️  Back to Main Menu"
    echo ""
    
    read -p "$(echo -e ${YELLOW}Select option: ${RESET})" choice
    
    case $choice in
        1)
            read -p "$(echo -e ${CYAN}Enter target domain: ${RESET})" target
            read -p "$(echo -e ${CYAN}Port range [1-1000]: ${RESET})" ports
            ports=${ports:-1-1000}
            run_command "./attack recon -target $target -ports $ports"
            ;;
        2)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Duration \(seconds\) [600]: ${RESET})" duration
            duration=${duration:-600}
            read -p "$(echo -e ${CYAN}SOCKS5 proxy \(e.g., 127.0.0.1:9050\) [optional]: ${RESET})" proxy
            if [ -z "$proxy" ]; then
                run_command "./attack stealth -target $target -duration $duration"
            else
                run_command "./attack stealth -target $target -duration $duration -proxy $proxy"
            fi
            ;;
        3)
            read -p "$(echo -e ${CYAN}C2 port [8443]: ${RESET})" port
            port=${port:-8443}
            run_command "./attack c2 -c2-port $port"
            ;;
        4)
            read -p "$(echo -e ${CYAN}Enter target: ${RESET})" target
            read -p "$(echo -e ${CYAN}Method \(dns/icmp/http\) [dns]: ${RESET})" method
            method=${method:-dns}
            run_command "./attack exfil -target $target -method $method"
            ;;
        5)
            read -p "$(echo -e ${CYAN}Enter target: ${RESET})" target
            read -p "$(echo -e ${CYAN}Duration \(seconds\) [300]: ${RESET})" duration
            duration=${duration:-300}
            run_command "./attack pivot -target $target -duration $duration"
            ;;
        6)
            read -p "$(echo -e ${CYAN}Enter target URL: ${RESET})" target
            read -p "$(echo -e ${CYAN}Attack nodes \(comma-separated IPs\): ${RESET})" nodes
            read -p "$(echo -e ${CYAN}Duration \(seconds\) [300]: ${RESET})" duration
            duration=${duration:-300}
            run_command "./attack distributed -target $target -nodes $nodes -duration $duration"
            ;;
        0)
            return
            ;;
    esac
}

show_documentation() {
    clear
    print_banner
    echo -e "${CYAN}═══════════════ DOCUMENTATION ═════════════════${RESET}\n"
    
    declare -A docs
    docs=(
        ["README.md"]="Main project documentation"
        ["FEATURES.md"]="Complete features list"
        ["USAGE.md"]="Usage guide and examples"
        ["REDTEAM.md"]="Red team operations guide"
        ["MULTIPURPOSE.md"]="Multi-purpose capabilities"
        ["configs/README.md"]="Configuration profiles"
        ["wordlists/README.md"]="Wordlists documentation"
    )
    
    for doc in "${!docs[@]}"; do
        if [ -f "$doc" ]; then
            echo -e "${GREEN}✓${RESET} ${doc:0:25} - ${docs[$doc]}"
        else
            echo -e "${RED}✗${RESET} ${doc:0:25} - ${docs[$doc]}"
        fi
    done
    
    echo ""
    read -p "$(echo -e ${YELLOW}Enter filename to view, or press Enter to continue: ${RESET})" choice
    
    if [ -n "$choice" ] && [ -f "$choice" ]; then
        echo -e "\n${CYAN}============================================================${RESET}"
        cat "$choice"
        echo -e "${CYAN}============================================================${RESET}"
        read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
    fi
}

show_help() {
    ./attack help
    read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
}

show_examples() {
    clear
    print_banner
    cat << EOF
${CYAN}═══════════════════════════════════════════════════════════════${RESET}
${BOLD}                    QUICK EXAMPLES${RESET}
${CYAN}═══════════════════════════════════════════════════════════════${RESET}

${GREEN}🌐 Web Vulnerability Scanning:${RESET}
   ./attack web-scan -target https://example.com -depth medium
   ./attack sqli -target https://example.com/page?id=1
   ./attack xss -target https://example.com/search?q=test

${GREEN}📁 Directory Brute Force:${RESET}
   ./attack dir-brute -target https://example.com -wordlist wordlists/directories.txt -threads 20

${GREEN}🔐 Password Attacks:${RESET}
   ./attack password-brute -target https://example.com/login -protocol http-form -users admin -passwords wordlists/passwords.txt
   ./attack hash-crack -hash 5f4dcc3b5aa765d61d8327deb882cf99 -type md5 -wordlist wordlists/passwords.txt

${GREEN}🔍 Network Scanning:${RESET}
   ./attack port-scan -target 192.168.1.100 -top-ports 100 -service -threads 50
   ./attack service-enum -target 192.168.1.100 -ports 22,80,443
   ./attack subnet-scan -subnet 192.168.1.0/24 -threads 50

${GREEN}🎯 DDoS/Stress Testing:${RESET}
   ./attack slowloris -target https://example.com -duration 120 -connections 200
   ./attack adaptive -target https://example.com -duration 180
   ./attack hybrid -target https://example.com -vectors slowloris,http2,adaptive

${GREEN}🕵️ Red Team Operations:${RESET}
   ./attack recon -target example.com -ports 1-1000
   ./attack stealth -target https://example.com -proxy 127.0.0.1:9050 -duration 600
   ./attack c2 -c2-port 8443

${CYAN}═══════════════════════════════════════════════════════════════${RESET}
EOF
    read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
}

run_command() {
    echo -e "\n${YELLOW}[*] Executing: $1${RESET}\n"
    sleep 1
    
    eval "$1" || true
    
    echo ""
    read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
}

# Main loop
main() {
    CHECKED=false
    
    while true; do
        print_banner
        
        # Check dependencies on first run
        if [ "$CHECKED" = false ]; then
            if ! check_dependencies; then
                echo -e "\n${RED}❌ Dependency check failed. Please fix issues and try again.${RESET}"
                exit 1
            fi
            CHECKED=true
            echo -e "\n${GREEN}✅ All checks passed! Starting launcher...${RESET}"
            sleep 2
            continue
        fi
        
        show_main_menu
        read -p "$(echo -e ${BOLD}${YELLOW}Select option: ${RESET})" choice
        
        case $choice in
            1) web_exploitation_menu ;;
            2) password_attacks_menu ;;
            3) network_operations_menu ;;
            4) ddos_menu ;;
            5) redteam_menu ;;
            6) show_documentation ;;
            7) 
                build_project
                read -p "$(echo -e ${YELLOW}Press Enter to continue...${RESET})"
                ;;
            8) show_help ;;
            9) show_examples ;;
            0)
                echo -e "\n${GREEN}👋 Thank you for using Spectre Strike!${RESET}"
                echo -e "${CYAN}Stay safe and happy hacking! 🔐${RESET}\n"
                exit 0
                ;;
            *)
                echo -e "\n${RED}❌ Invalid option. Please try again.${RESET}"
                sleep 1
                ;;
        esac
    done
}

# Trap Ctrl+C
trap ctrl_c INT

ctrl_c() {
    echo -e "\n\n${YELLOW}[!] Launcher interrupted by user${RESET}"
    echo -e "${GREEN}Goodbye! 👋${RESET}\n"
    exit 0
}

# Run main
main
