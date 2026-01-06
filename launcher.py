#!/usr/bin/env python3
"""
Spectre Strike - Direct Command Launcher
Professional Edition v4.0
"""

import os
import sys
import subprocess
import json
import time
import argparse
import random
from pathlib import Path
from datetime import datetime

# Color codes
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'

# Configuration
CONFIG_FILE = '.launcher_config.json'
HISTORY_FILE = '.launcher_history.json'

# Configuration
CONFIG_FILE = '.launcher_config.json'
HISTORY_FILE = '.launcher_history.json'

class Config:
    """Configuration manager"""
    def __init__(self):
        self.config = self.load()
        self._ensure_defaults()
        
    def _ensure_defaults(self):
        """Ensure all required keys exist"""
        defaults = {
            'favorites': [],
            'history': [],
            'presets': {},
            'last_run': None,
            'stats': {
                'total_runs': 0,
                'successful_runs': 0,
                'failed_runs': 0
            },
            'settings': {
                'auto_build': True,
                'show_tips': True,
                'animation_speed': 0.03,
                'max_history': 50
            }
        }
        for key, value in defaults.items():
            if key not in self.config:
                self.config[key] = value
            elif isinstance(value, dict):
                for k, v in value.items():
                    if k not in self.config[key]:
                        self.config[key][k] = v
        
    def load(self):
        """Load configuration"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            'favorites': [],
            'history': [],
            'presets': {},
            'last_run': None,
            'stats': {
                'total_runs': 0,
                'successful_runs': 0,
                'failed_runs': 0
            },
            'settings': {
                'auto_build': True,
                'show_tips': True,
                'animation_speed': 0.03,
                'max_history': 50
            }
        }
    
    def save(self):
        """Save configuration"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"{Colors.RED}Failed to save config: {e}{Colors.RESET}")
    
    def add_to_history(self, command: str):
        """Add command to history"""
        history = self.config.get('history', [])
        entry = {
            'command': command,
            'timestamp': datetime.now().isoformat(),
            'success': True
        }
        history.insert(0, entry)
        self.config['history'] = history[:self.config['settings']['max_history']]
        self.save()
    
    def add_favorite(self, name: str, command: str, description: str = ""):
        """Add command to favorites"""
        favorites = self.config.get('favorites', [])
        favorites.append({
            'name': name,
            'command': command,
            'description': description,
            'created': datetime.now().isoformat()
        })
        self.config['favorites'] = favorites
        self.save()
    
    def get_favorites(self):
        """Get all favorites"""
        return self.config.get('favorites', [])
    
    def update_stats(self, success: bool = True):
        """Update statistics"""
        stats = self.config.get('stats', {})
        stats['total_runs'] = stats.get('total_runs', 0) + 1
        if success:
            stats['successful_runs'] = stats.get('successful_runs', 0) + 1
        else:
            stats['failed_runs'] = stats.get('failed_runs', 0) + 1
        self.config['stats'] = stats
        self.config['last_run'] = datetime.now().isoformat()
        self.save()

# Global config instance
config = Config()

def animate_text(text: str, speed: float = 0.03):
    """Animate text character by character"""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(speed)
    print()

def loading_animation(text: str = "Loading", duration: float = 1.5):
    """Show loading animation"""
    animation = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end_time = time.time() + duration
    idx = 0
    while time.time() < end_time:
        print(f"\r{Colors.CYAN}{animation[idx % len(animation)]} {text}...{Colors.RESET}", end='', flush=True)
        time.sleep(0.1)
        idx += 1
    print(f"\r{' ' * (len(text) + 10)}\r", end='')

def print_banner():
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║      {Colors.RED}███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗{Colors.CYAN}            ║
║      {Colors.RED}██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝{Colors.CYAN}            ║
║      {Colors.RED}███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗{Colors.CYAN}              ║
║      {Colors.RED}╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝{Colors.CYAN}              ║
║      {Colors.RED}███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗{Colors.CYAN}            ║
║      {Colors.RED}╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝{Colors.CYAN}            ║
║                                                                           ║
║          {Colors.YELLOW}███████╗████████╗██████╗ ██╗██╗  ██╗███████╗{Colors.CYAN}                     ║
║          {Colors.YELLOW}██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝{Colors.CYAN}                     ║
║          {Colors.YELLOW}███████╗   ██║   ██████╔╝██║█████╔╝ █████╗{Colors.CYAN}                       ║
║          {Colors.YELLOW}╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝{Colors.CYAN}                       ║
║          {Colors.YELLOW}███████║   ██║   ██║  ██║██║██║  ██╗███████╗{Colors.CYAN}                     ║
║          {Colors.YELLOW}╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝{Colors.CYAN}                     ║
║                                                                           ║
║               {Colors.MAGENTA}⚡ Professional Edition v3.0 ULTIMATE ⚡{Colors.CYAN}                    ║
║               {Colors.GREEN}🔥 Next-Gen Cyber Warfare Framework 🔥{Colors.CYAN}                      ║
║                                                                           ║
║  {Colors.WHITE}🎯 Elite Pentesting & Advanced Security Assessment{Colors.CYAN}                       ║
║  {Colors.WHITE}🚀 ML-Powered Attack Intelligence & Automation{Colors.CYAN}                           ║
║  {Colors.WHITE}⚡ Stealth Operations & Advanced Red Team Tactics{Colors.CYAN}                        ║
║  {Colors.WHITE}💀 Zero-Day Exploitation & Vulnerability Research{Colors.CYAN}                        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)
    
    # Show tip of the day
    if config.config['settings'].get('show_tips', True):
        tips = [
            "💡 Tip: Use 'Quick Launch' mode with --quick for instant access!",
            "💡 Tip: Save your favorite commands for quick access later!",
            "💡 Tip: Check command history to re-run previous attacks!",
            "💡 Tip: Use presets to quickly configure common attack scenarios!",
            "💡 Tip: Export results in JSON/CSV format for easy reporting!",
            "💡 Tip: Press Ctrl+C to safely interrupt any operation!",
            "💡 Tip: Use '--help' with any command for detailed usage info!",
            "💡 Tip: Check the stats dashboard to track your testing activities!"
        ]
        tip = random.choice(tips)
        print(f"{Colors.DIM}{tip}{Colors.RESET}\n")

def print_stats_banner():
    """Print statistics banner"""
    stats = config.config.get('stats', {})
    total = stats.get('total_runs', 0)
    success = stats.get('successful_runs', 0)
    failed = stats.get('failed_runs', 0)
    last_run = config.config.get('last_run')
    
    if total > 0:
        success_rate = (success / total * 100) if total > 0 else 0
        print(f"{Colors.DIM}╭{'─' * 73}╮{Colors.RESET}")
        print(f"{Colors.DIM}│ {Colors.WHITE}📊 Statistics:{Colors.DIM} Total: {Colors.YELLOW}{total}{Colors.DIM} | Success: {Colors.GREEN}{success}{Colors.DIM} | Failed: {Colors.RED}{failed}{Colors.DIM} | Rate: {Colors.CYAN}{success_rate:.1f}%{Colors.DIM} │{Colors.RESET}")
        if last_run:
            last_time = datetime.fromisoformat(last_run).strftime('%Y-%m-%d %H:%M:%S')
            print(f"{Colors.DIM}│ {Colors.WHITE}⏱️  Last Run:{Colors.DIM} {last_time}{' ' * (55 - len(last_time))}│{Colors.RESET}")
        print(f"{Colors.DIM}╰{'─' * 73}╯{Colors.RESET}\n")

def check_dependencies():
    """Check if Go is installed and project is ready"""
    print(f"\n{Colors.YELLOW}[*] Checking dependencies...{Colors.RESET}")
    loading_animation("Validating environment", 1.0)
    
    # Check Go installation
    try:
        result = subprocess.run(['go', 'version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"{Colors.GREEN}✅ Go is installed: {result.stdout.strip()}{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Go is not properly installed{Colors.RESET}")
            return False
    except FileNotFoundError:
        print(f"{Colors.RED}❌ Go is not installed. Please install Go 1.20+{Colors.RESET}")
        print(f"{Colors.YELLOW}💡 Install: https://golang.org/doc/install{Colors.RESET}")
        return False
    
    # Check if attack binary exists
    if not os.path.exists('attack'):
        if config.config['settings'].get('auto_build', True):
            print(f"{Colors.YELLOW}⚠️  Attack binary not found. Auto-building...{Colors.RESET}")
            return build_project()
        else:
            print(f"{Colors.RED}❌ Attack binary not found. Run option [7] to build.{Colors.RESET}")
            return False
    else:
        # Check binary age
        binary_age = time.time() - os.path.getmtime('attack')
        if binary_age > 86400:  # older than 1 day
            print(f"{Colors.YELLOW}⚠️  Binary is {int(binary_age/3600)}h old. Consider rebuilding.{Colors.RESET}")
        print(f"{Colors.GREEN}✅ Attack binary found{Colors.RESET}")
    
    return True

def build_project():
    """Build the project"""
    print(f"\n{Colors.CYAN}[*] Building project...{Colors.RESET}")
    loading_animation("Compiling Go binary", 2.0)
    try:
        result = subprocess.run(
            ['go', 'build', '-o', 'attack', './cmd/main.go'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            # Get binary size
            size = os.path.getsize('attack') / (1024 * 1024)
            print(f"{Colors.GREEN}✅ Build successful! ({size:.2f} MB){Colors.RESET}")
            return True
        else:
            print(f"{Colors.RED}❌ Build failed:{Colors.RESET}")
            print(result.stderr)
            print(f"\n{Colors.YELLOW}💡 Tip: Check for syntax errors or missing dependencies{Colors.RESET}")
            return False
    except Exception as e:
        print(f"{Colors.RED}❌ Build error: {e}{Colors.RESET}")
        return False

def show_main_menu():
    """Display main interactive menu"""
    menu = f"""
{Colors.BOLD}{Colors.WHITE}═══════════════════════════════════════════════════════════════{Colors.RESET}
{Colors.CYAN}                    MAIN MENU{Colors.RESET}
{Colors.BOLD}{Colors.WHITE}═══════════════════════════════════════════════════════════════{Colors.RESET}

{Colors.GREEN}[1]{Colors.RESET}   🌐 Web Exploitation           {Colors.GREEN}[11]{Colors.RESET}  ⭐ Favorites
{Colors.GREEN}[2]{Colors.RESET}   🔐 Password Attacks            {Colors.GREEN}[12]{Colors.RESET}  📜 Command History
{Colors.GREEN}[3]{Colors.RESET}   🔍 Network Operations          {Colors.GREEN}[13]{Colors.RESET}  🎯 Attack Presets
{Colors.GREEN}[4]{Colors.RESET}   🎯 DDoS/Stress Testing         {Colors.GREEN}[14]{Colors.RESET}  📊 Statistics Dashboard
{Colors.GREEN}[5]{Colors.RESET}   🕵️  Red Team Operations         {Colors.GREEN}[15]{Colors.RESET}  💾 Export Results
{Colors.GREEN}[6]{Colors.RESET}   🧠 ML Intelligence             {Colors.GREEN}[16]{Colors.RESET}  ⚙️  Settings
{Colors.GREEN}[7]{Colors.RESET}   🔧 Build/Rebuild Project       {Colors.GREEN}[17]{Colors.RESET}  🚀 Quick Launch
{Colors.GREEN}[8]{Colors.RESET}   📚 View Documentation          {Colors.GREEN}[18]{Colors.RESET}  🧪 Benchmark Mode
{Colors.GREEN}[9]{Colors.RESET}   📊 Quick Examples              {Colors.GREEN}[19]{Colors.RESET}  🔄 Check Updates
{Colors.GREEN}[10]{Colors.RESET}  🌐 API Server                  {Colors.GREEN}[20]{Colors.RESET}  💻 Direct Command
{Colors.GREEN}[0]{Colors.RESET}   🚪 Exit                        {Colors.GREEN}[?]{Colors.RESET}   ℹ️  Help

{Colors.BOLD}{Colors.WHITE}═══════════════════════════════════════════════════════════════{Colors.RESET}
"""
    print(menu)

def web_exploitation_menu():
    """Web exploitation submenu"""
    clear_screen()
    print_banner()
    menu = f"""
{Colors.CYAN}═══════════════ WEB EXPLOITATION ══════════════════{Colors.RESET}

{Colors.GREEN}[1]{Colors.RESET} 🔍 Full Vulnerability Scan
{Colors.GREEN}[2]{Colors.RESET} 💉 SQL Injection Testing
{Colors.GREEN}[3]{Colors.RESET} 🎨 XSS (Cross-Site Scripting) Testing
{Colors.GREEN}[4]{Colors.RESET} 📁 LFI/RFI (File Inclusion) Testing
{Colors.GREEN}[5]{Colors.RESET} 🗂️  Directory/File Brute Force
{Colors.GREEN}[0]{Colors.RESET} ⬅️  Back to Main Menu
"""
    print(menu)
    choice = input(f"{Colors.YELLOW}Select option: {Colors.RESET}").strip()
    
    if choice == '1':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        depth = input(f"{Colors.CYAN}Scan depth (light/medium/deep) [medium]: {Colors.RESET}").strip() or "medium"
        run_command(['./attack', 'web-scan', '-target', target, '-depth', depth])
    elif choice == '2':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        run_command(['./attack', 'sqli', '-target', target])
    elif choice == '3':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        run_command(['./attack', 'xss', '-target', target])
    elif choice == '4':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        run_command(['./attack', 'lfi', '-target', target])
    elif choice == '5':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        wordlist = input(f"{Colors.CYAN}Wordlist [wordlists/directories.txt]: {Colors.RESET}").strip() or "wordlists/directories.txt"
        threads = input(f"{Colors.CYAN}Threads [20]: {Colors.RESET}").strip() or "20"
        run_command(['./attack', 'dir-brute', '-target', target, '-wordlist', wordlist, '-threads', threads])

def password_attacks_menu():
    """Password attacks submenu"""
    clear_screen()
    print_banner()
    menu = f"""
{Colors.CYAN}═══════════════ PASSWORD ATTACKS ══════════════════{Colors.RESET}

{Colors.GREEN}[1]{Colors.RESET} 🔓 HTTP Basic Auth Brute Force
{Colors.GREEN}[2]{Colors.RESET} 🌐 HTTP Form-Based Brute Force
{Colors.GREEN}[3]{Colors.RESET} 🔐 SSH Brute Force
{Colors.GREEN}[4]{Colors.RESET} 📂 FTP Brute Force
{Colors.GREEN}[5]{Colors.RESET} #️⃣  Hash Cracking (MD5/SHA1/SHA256/SHA512)
{Colors.GREEN}[0]{Colors.RESET} ⬅️  Back to Main Menu
"""
    print(menu)
    choice = input(f"{Colors.YELLOW}Select option: {Colors.RESET}").strip()
    
    if choice == '1':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        users = input(f"{Colors.CYAN}Username(s) or file [admin]: {Colors.RESET}").strip() or "admin"
        passwords = input(f"{Colors.CYAN}Password wordlist [wordlists/passwords.txt]: {Colors.RESET}").strip() or "wordlists/passwords.txt"
        threads = input(f"{Colors.CYAN}Threads [10]: {Colors.RESET}").strip() or "10"
        run_command(['./attack', 'password-brute', '-target', target, '-users', users, 
                    '-passwords', passwords, '-protocol', 'http-basic', '-threads', threads])
    elif choice == '2':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        login_url = input(f"{Colors.CYAN}Login form URL: {Colors.RESET}").strip()
        users = input(f"{Colors.CYAN}Username(s) or file [admin]: {Colors.RESET}").strip() or "admin"
        passwords = input(f"{Colors.CYAN}Password wordlist [wordlists/passwords.txt]: {Colors.RESET}").strip() or "wordlists/passwords.txt"
        user_field = input(f"{Colors.CYAN}Username field name [username]: {Colors.RESET}").strip() or "username"
        pass_field = input(f"{Colors.CYAN}Password field name [password]: {Colors.RESET}").strip() or "password"
        run_command(['./attack', 'password-brute', '-target', target, '-users', users,
                    '-passwords', passwords, '-protocol', 'http-form', '-login-url', login_url,
                    '-user-field', user_field, '-pass-field', pass_field])
    elif choice == '3':
        target = input(f"{Colors.CYAN}Enter target host:port: {Colors.RESET}").strip()
        users = input(f"{Colors.CYAN}Username(s) or file [root]: {Colors.RESET}").strip() or "root"
        passwords = input(f"{Colors.CYAN}Password wordlist [wordlists/passwords.txt]: {Colors.RESET}").strip() or "wordlists/passwords.txt"
        run_command(['./attack', 'password-brute', '-target', target, '-users', users,
                    '-passwords', passwords, '-protocol', 'ssh'])
    elif choice == '4':
        target = input(f"{Colors.CYAN}Enter target host:port: {Colors.RESET}").strip()
        users = input(f"{Colors.CYAN}Username(s) or file [anonymous]: {Colors.RESET}").strip() or "anonymous"
        passwords = input(f"{Colors.CYAN}Password wordlist [wordlists/passwords.txt]: {Colors.RESET}").strip() or "wordlists/passwords.txt"
        run_command(['./attack', 'password-brute', '-target', target, '-users', users,
                    '-passwords', passwords, '-protocol', 'ftp'])
    elif choice == '5':
        hash_input = input(f"{Colors.CYAN}Hash or file with hashes: {Colors.RESET}").strip()
        hash_type = input(f"{Colors.CYAN}Hash type (md5/sha1/sha256/sha512) [md5]: {Colors.RESET}").strip() or "md5"
        wordlist = input(f"{Colors.CYAN}Wordlist [wordlists/passwords.txt]: {Colors.RESET}").strip() or "wordlists/passwords.txt"
        threads = input(f"{Colors.CYAN}Threads [10]: {Colors.RESET}").strip() or "10"
        run_command(['./attack', 'hash-crack', '-hash', hash_input, '-type', hash_type,
                    '-wordlist', wordlist, '-threads', threads])

def network_operations_menu():
    """Network operations submenu"""
    clear_screen()
    print_banner()
    menu = f"""
{Colors.CYAN}═══════════════ NETWORK OPERATIONS ════════════════{Colors.RESET}

{Colors.GREEN}[1]{Colors.RESET} 🔌 Port Scanning
{Colors.GREEN}[2]{Colors.RESET} 🔍 Service Enumeration
{Colors.GREEN}[3]{Colors.RESET} 🌐 Subnet/Host Discovery
{Colors.GREEN}[4]{Colors.RESET} 📊 Quick Vulnerability Scan
{Colors.GREEN}[0]{Colors.RESET} ⬅️  Back to Main Menu
"""
    print(menu)
    choice = input(f"{Colors.YELLOW}Select option: {Colors.RESET}").strip()
    
    if choice == '1':
        target = input(f"{Colors.CYAN}Enter target host/IP: {Colors.RESET}").strip()
        ports = input(f"{Colors.CYAN}Port range (e.g., 1-1000, 80,443) or leave empty for top ports: {Colors.RESET}").strip()
        threads = input(f"{Colors.CYAN}Threads [50]: {Colors.RESET}").strip() or "50"
        service = input(f"{Colors.CYAN}Enable service detection? (y/n) [y]: {Colors.RESET}").strip() or "y"
        
        cmd = ['./attack', 'port-scan', '-target', target, '-threads', threads]
        if ports:
            cmd.extend(['-ports', ports])
        else:
            cmd.extend(['-top-ports', '100'])
        if service.lower() == 'y':
            cmd.append('-service')
        run_command(cmd)
    elif choice == '2':
        target = input(f"{Colors.CYAN}Enter target host/IP: {Colors.RESET}").strip()
        ports = input(f"{Colors.CYAN}Ports to enumerate (e.g., 22,80,443) [common]: {Colors.RESET}").strip()
        cmd = ['./attack', 'service-enum', '-target', target]
        if ports:
            cmd.extend(['-ports', ports])
        run_command(cmd)
    elif choice == '3':
        subnet = input(f"{Colors.CYAN}Enter subnet (e.g., 192.168.1.0/24): {Colors.RESET}").strip()
        threads = input(f"{Colors.CYAN}Threads [50]: {Colors.RESET}").strip() or "50"
        run_command(['./attack', 'subnet-scan', '-subnet', subnet, '-threads', threads])
    elif choice == '4':
        target = input(f"{Colors.CYAN}Enter target URL or IP: {Colors.RESET}").strip()
        run_command(['./attack', 'scan', '-target', target])

def ddos_menu():
    """DDoS/Stress testing submenu"""
    clear_screen()
    print_banner()
    menu = f"""
{Colors.RED}═══════════════ DDoS/STRESS TESTING ═══════════════{Colors.RESET}
{Colors.YELLOW}⚠️  WARNING: Only use on authorized targets!{Colors.RESET}

{Colors.GREEN}[1]{Colors.RESET} 🐢 Slowloris Attack
{Colors.GREEN}[2]{Colors.RESET} 🧠 Adaptive ML-Powered Attack
{Colors.GREEN}[3]{Colors.RESET} 🔌 WebSocket Flood
{Colors.GREEN}[4]{Colors.RESET} 🛡️  WAF Bypass Attack
{Colors.GREEN}[5]{Colors.RESET} ⚡ Hybrid Multi-Vector Attack
{Colors.GREEN}[6]{Colors.RESET} 📈 Spike Test (Sudden Bursts)
{Colors.GREEN}[7]{Colors.RESET} 📊 Ramp Test (Gradual Increase)
{Colors.GREEN}[8]{Colors.RESET} 🎲 Chaos Mode (Random Patterns)
{Colors.GREEN}[0]{Colors.RESET} ⬅️  Back to Main Menu
"""
    print(menu)
    choice = input(f"{Colors.YELLOW}Select option: {Colors.RESET}").strip()
    
    if choice == '1':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [60]: {Colors.RESET}").strip() or "60"
        connections = input(f"{Colors.CYAN}Connections [200]: {Colors.RESET}").strip() or "200"
        run_command(['./attack', 'slowloris', '-target', target, '-duration', duration, '-connections', connections])
    elif choice == '2':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [180]: {Colors.RESET}").strip() or "180"
        mode = input(f"{Colors.CYAN}Mode (find-limit/sustained/spike/ramp/chaos) [find-limit]: {Colors.RESET}").strip() or "find-limit"
        max_rate = input(f"{Colors.CYAN}Max RPS [1000]: {Colors.RESET}").strip() or "1000"
        max_threads = input(f"{Colors.CYAN}Max Threads [200]: {Colors.RESET}").strip() or "200"
        run_command(['./attack', 'adaptive', '-target', target, '-duration', duration, 
                    '-mode', mode, '-max-rate', max_rate, '-max-threads', max_threads])
    elif choice == '3':
        target = input(f"{Colors.CYAN}Enter target WebSocket URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [120]: {Colors.RESET}").strip() or "120"
        run_command(['./attack', 'websocket', '-target', target, '-duration', duration])
    elif choice == '4':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [120]: {Colors.RESET}").strip() or "120"
        run_command(['./attack', 'waf-bypass', '-target', target, '-duration', duration])
    elif choice == '5':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [180]: {Colors.RESET}").strip() or "180"
        vectors = input(f"{Colors.CYAN}Vectors (comma-separated) [slowloris,http2,adaptive]: {Colors.RESET}").strip() or "slowloris,http2,adaptive"
        run_command(['./attack', 'hybrid', '-target', target, '-duration', duration, '-vectors', vectors])
    elif choice == '6':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [180]: {Colors.RESET}").strip() or "180"
        run_command(['./attack', 'adaptive', '-target', target, '-duration', duration, '-mode', 'spike'])
    elif choice == '7':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [180]: {Colors.RESET}").strip() or "180"
        run_command(['./attack', 'adaptive', '-target', target, '-duration', duration, '-mode', 'ramp'])
    elif choice == '8':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [180]: {Colors.RESET}").strip() or "180"
        run_command(['./attack', 'adaptive', '-target', target, '-duration', duration, '-mode', 'chaos'])

def redteam_menu():
    """Red team operations submenu"""
    clear_screen()
    print_banner()
    menu = f"""
{Colors.MAGENTA}═══════════════ RED TEAM OPERATIONS ═══════════════{Colors.RESET}

{Colors.GREEN}[1]{Colors.RESET} 🔍 Advanced Reconnaissance
{Colors.GREEN}[2]{Colors.RESET} 🥷 Stealth Attack Mode
{Colors.GREEN}[3]{Colors.RESET} 📡 Start C2 Server
{Colors.GREEN}[4]{Colors.RESET} 📤 Data Exfiltration
{Colors.GREEN}[5]{Colors.RESET} 🔄 Pivot Attack
{Colors.GREEN}[6]{Colors.RESET} 🌐 Distributed Attack
{Colors.GREEN}[0]{Colors.RESET} ⬅️  Back to Main Menu
"""
    print(menu)
    choice = input(f"{Colors.YELLOW}Select option: {Colors.RESET}").strip()
    
    if choice == '1':
        target = input(f"{Colors.CYAN}Enter target domain: {Colors.RESET}").strip()
        ports = input(f"{Colors.CYAN}Port range [1-1000]: {Colors.RESET}").strip() or "1-1000"
        run_command(['./attack', 'recon', '-target', target, '-ports', ports])
    elif choice == '2':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [600]: {Colors.RESET}").strip() or "600"
        proxy = input(f"{Colors.CYAN}SOCKS5 proxy (e.g., 127.0.0.1:9050) [optional]: {Colors.RESET}").strip()
        cmd = ['./attack', 'stealth', '-target', target, '-duration', duration]
        if proxy:
            cmd.extend(['-proxy', proxy])
        run_command(cmd)
    elif choice == '3':
        port = input(f"{Colors.CYAN}C2 port [8443]: {Colors.RESET}").strip() or "8443"
        run_command(['./attack', 'c2', '-c2-port', port])
    elif choice == '4':
        target = input(f"{Colors.CYAN}Enter target: {Colors.RESET}").strip()
        method = input(f"{Colors.CYAN}Method (dns/icmp/http) [dns]: {Colors.RESET}").strip() or "dns"
        run_command(['./attack', 'exfil', '-target', target, '-method', method])
    elif choice == '5':
        target = input(f"{Colors.CYAN}Enter target: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [300]: {Colors.RESET}").strip() or "300"
        run_command(['./attack', 'pivot', '-target', target, '-duration', duration])
    elif choice == '6':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        nodes = input(f"{Colors.CYAN}Attack nodes (comma-separated IPs): {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [300]: {Colors.RESET}").strip() or "300"
        run_command(['./attack', 'distributed', '-target', target, '-nodes', nodes, '-duration', duration])

def ml_intelligence_menu():
    """ML Intelligence submenu"""
    clear_screen()
    print_banner()
    menu = f"""
{Colors.CYAN}═══════════════ 🧠 ML INTELLIGENCE ════════════════{Colors.RESET}

{Colors.GREEN}[1]{Colors.RESET} 🧠 ML-Powered Attack (Full Auto)
{Colors.GREEN}[2]{Colors.RESET} 📊 ML Target Analysis (Deep Scan)
{Colors.GREEN}[3]{Colors.RESET} ⚡ Aggressive ML Attack
{Colors.GREEN}[4]{Colors.RESET} 🥷 Stealth ML Attack
{Colors.GREEN}[5]{Colors.RESET} 📈 Custom ML Attack
{Colors.GREEN}[0]{Colors.RESET} ⬅️  Back to Main Menu

{Colors.DIM}ML Intelligence Features:
  • Neural network-based attack optimization
  • Real-time learning and adaptation
  • WAF/CDN detection and bypass
  • Automatic parameter tuning
  • Vulnerability scoring
  • Defense mechanism detection{Colors.RESET}
"""
    print(menu)
    choice = input(f"{Colors.YELLOW}Select option: {Colors.RESET}").strip()
    
    if choice == '1':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Total duration (seconds) [300]: {Colors.RESET}").strip() or "300"
        learn = input(f"{Colors.CYAN}Learning phase (seconds) [60]: {Colors.RESET}").strip() or "60"
        run_command(['./attack', 'ml-attack', '-target', target, '-duration', duration, '-learn', learn])
    elif choice == '2':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Analysis duration (seconds) [120]: {Colors.RESET}").strip() or "120"
        run_command(['./attack', 'ml-analyze', '-target', target, '-duration', duration])
    elif choice == '3':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [300]: {Colors.RESET}").strip() or "300"
        run_command(['./attack', 'ml-attack', '-target', target, '-duration', duration, '-aggressive'])
    elif choice == '4':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Duration (seconds) [600]: {Colors.RESET}").strip() or "600"
        run_command(['./attack', 'ml-attack', '-target', target, '-duration', duration, '-stealth'])
    elif choice == '5':
        target = input(f"{Colors.CYAN}Enter target URL: {Colors.RESET}").strip()
        duration = input(f"{Colors.CYAN}Total duration (seconds) [300]: {Colors.RESET}").strip() or "300"
        learn = input(f"{Colors.CYAN}Learning phase (seconds) [60]: {Colors.RESET}").strip() or "60"
        aggressive = input(f"{Colors.CYAN}Aggressive mode? (y/n) [n]: {Colors.RESET}").strip().lower() == 'y'
        stealth = input(f"{Colors.CYAN}Stealth mode? (y/n) [n]: {Colors.RESET}").strip().lower() == 'y'
        
        cmd = ['./attack', 'ml-attack', '-target', target, '-duration', duration, '-learn', learn]
        if aggressive:
            cmd.append('-aggressive')
        if stealth:
            cmd.append('-stealth')
        run_command(cmd)

def api_server_menu():
    """API Server menu"""
    clear_screen()
    print_banner()
    menu = f"""
{Colors.CYAN}═══════════════ 🌐 API SERVER ════════════════{Colors.RESET}

{Colors.GREEN}[1]{Colors.RESET} 🚀 Start API Server (Default: 0.0.0.0:8080)
{Colors.GREEN}[2]{Colors.RESET} 🔧 Start with Custom Settings
{Colors.GREEN}[0]{Colors.RESET} ⬅️  Back to Main Menu

{Colors.DIM}API Endpoints:
  POST /attack/adaptive    - Launch adaptive attack
  POST /attack/ml          - Launch ML attack
  POST /scan/port          - Port scan
  POST /scan/web           - Web vulnerability scan
  GET  /health             - Health check
  GET  /stats              - Get statistics{Colors.RESET}
"""
    print(menu)
    choice = input(f"{Colors.YELLOW}Select option: {Colors.RESET}").strip()
    
    if choice == '1':
        run_command(['./attack', 'api-server'])
    elif choice == '2':
        host = input(f"{Colors.CYAN}Host [0.0.0.0]: {Colors.RESET}").strip() or "0.0.0.0"
        port = input(f"{Colors.CYAN}Port [8080]: {Colors.RESET}").strip() or "8080"
        run_command(['./attack', 'api-server', '-host', host, '-port', port])

def show_documentation():
    """Show available documentation"""
    clear_screen()
    print_banner()
    print(f"\n{Colors.CYAN}═══════════════ DOCUMENTATION ═════════════════{Colors.RESET}\n")
    
    docs = {
        'README.md': 'Main project documentation',
        'FEATURES.md': 'Complete features list',
        'USAGE.md': 'Usage guide and examples',
        'REDTEAM.md': 'Red team operations guide',
        'MULTIPURPOSE.md': 'Multi-purpose capabilities',
        'configs/README.md': 'Configuration profiles',
        'wordlists/README.md': 'Wordlists documentation'
    }
    
    for doc, description in docs.items():
        if os.path.exists(doc):
            print(f"{Colors.GREEN}✓{Colors.RESET} {doc:25} - {description}")
        else:
            print(f"{Colors.RED}✗{Colors.RESET} {doc:25} - {description}")
    
    print(f"\n{Colors.YELLOW}Enter filename to view, or press Enter to continue: {Colors.RESET}", end='')
    choice = input().strip()
    
    if choice and os.path.exists(choice):
        with open(choice, 'r') as f:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f.read())
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")

def show_help():
    """Show comprehensive help"""
    run_command(['./attack', 'help'])
    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")

def show_examples():
    """Show quick examples"""
    examples = f"""
{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.RESET}
{Colors.BOLD}                    QUICK EXAMPLES{Colors.RESET}
{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.RESET}

{Colors.GREEN}🌐 Web Vulnerability Scanning:{Colors.RESET}
   ./attack web-scan -target https://example.com -depth medium
   ./attack sqli -target https://example.com/page?id=1
   ./attack xss -target https://example.com/search?q=test

{Colors.GREEN}📁 Directory Brute Force:{Colors.RESET}
   ./attack dir-brute -target https://example.com -wordlist wordlists/directories.txt -threads 20

{Colors.GREEN}🔐 Password Attacks:{Colors.RESET}
   ./attack password-brute -target https://example.com/login -protocol http-form -users admin -passwords wordlists/passwords.txt
   ./attack hash-crack -hash 5f4dcc3b5aa765d61d8327deb882cf99 -type md5 -wordlist wordlists/passwords.txt

{Colors.GREEN}🔍 Network Scanning:{Colors.RESET}
   ./attack port-scan -target 192.168.1.100 -top-ports 100 -service -threads 50
   ./attack service-enum -target 192.168.1.100 -ports 22,80,443
   ./attack subnet-scan -subnet 192.168.1.0/24 -threads 50

{Colors.GREEN}🎯 DDoS/Stress Testing:{Colors.RESET}
   ./attack slowloris -target https://example.com -duration 120 -connections 200
   ./attack adaptive -target https://example.com -duration 180 -mode find-limit
   ./attack adaptive -target https://example.com -duration 180 -mode spike
   ./attack adaptive -target https://example.com -duration 180 -mode chaos
   ./attack hybrid -target https://example.com -vectors slowloris,http2,adaptive

{Colors.GREEN}🧠 ML Intelligence:{Colors.RESET}
   ./attack ml-attack -target https://example.com -duration 300 -learn 60
   ./attack ml-attack -target https://example.com -duration 300 -aggressive
   ./attack ml-attack -target https://example.com -duration 600 -stealth
   ./attack ml-analyze -target https://example.com -duration 120

{Colors.GREEN}🕵️ Red Team Operations:{Colors.RESET}
   ./attack recon -target example.com -ports 1-1000
   ./attack stealth -target https://example.com -proxy 127.0.0.1:9050 -duration 600
   ./attack c2 -c2-port 8443

{Colors.GREEN}🌐 API Server:{Colors.RESET}
   ./attack api-server -port 8080 -host 0.0.0.0

{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.RESET}
"""
    print(examples)
    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")

def show_favorites():
    """Show and manage favorites"""
    clear_screen()
    print_banner()
    print(f"{Colors.CYAN}═══════════════ ⭐ FAVORITES ══════════════════{Colors.RESET}\n")
    
    favorites = config.get_favorites()
    
    if not favorites:
        print(f"{Colors.YELLOW}No favorites saved yet.{Colors.RESET}")
        print(f"{Colors.DIM}Tip: Run a command and save it as favorite!{Colors.RESET}\n")
        input(f"{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
        return
    
    for idx, fav in enumerate(favorites, 1):
        print(f"{Colors.GREEN}[{idx}]{Colors.RESET} {Colors.BOLD}{fav['name']}{Colors.RESET}")
        print(f"    {Colors.DIM}Command: {fav['command']}{Colors.RESET}")
        if fav.get('description'):
            print(f"    {Colors.DIM}Description: {fav['description']}{Colors.RESET}")
        print()
    
    print(f"{Colors.GREEN}[R]{Colors.RESET} Remove a favorite")
    print(f"{Colors.GREEN}[0]{Colors.RESET} Back to main menu\n")
    
    choice = input(f"{Colors.YELLOW}Select favorite to run (or R/0): {Colors.RESET}").strip()
    
    if choice == '0':
        return
    elif choice.upper() == 'R':
        remove_idx = input(f"{Colors.YELLOW}Enter favorite number to remove: {Colors.RESET}").strip()
        try:
            idx = int(remove_idx) - 1
            if 0 <= idx < len(favorites):
                removed = favorites.pop(idx)
                config.config['favorites'] = favorites
                config.save()
                print(f"{Colors.GREEN}✅ Removed: {removed['name']}{Colors.RESET}")
            else:
                print(f"{Colors.RED}Invalid favorite number{Colors.RESET}")
        except:
            print(f"{Colors.RED}Invalid input{Colors.RESET}")
        time.sleep(1)
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(favorites):
                fav = favorites[idx]
                run_command(fav['command'])
            else:
                print(f"{Colors.RED}Invalid favorite number{Colors.RESET}")
                time.sleep(1)
        except:
            print(f"{Colors.RED}Invalid input{Colors.RESET}")
            time.sleep(1)

def show_history():
    """Show command history"""
    clear_screen()
    print_banner()
    print(f"{Colors.CYAN}═══════════════ 📜 COMMAND HISTORY ═══════════════{Colors.RESET}\n")
    
    history = config.config.get('history', [])
    
    if not history:
        print(f"{Colors.YELLOW}No command history yet.{Colors.RESET}\n")
        input(f"{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
        return
    
    # Show last 20
    display_history = history[:20]
    
    for idx, entry in enumerate(display_history, 1):
        timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        status = f"{Colors.GREEN}✓{Colors.RESET}" if entry.get('success', True) else f"{Colors.RED}✗{Colors.RESET}"
        print(f"{Colors.GREEN}[{idx}]{Colors.RESET} {status} {Colors.DIM}{timestamp}{Colors.RESET}")
        print(f"    {entry['command']}\n")
    
    print(f"{Colors.GREEN}[C]{Colors.RESET} Clear history")
    print(f"{Colors.GREEN}[0]{Colors.RESET} Back to main menu\n")
    
    choice = input(f"{Colors.YELLOW}Select command to re-run (or C/0): {Colors.RESET}").strip()
    
    if choice == '0':
        return
    elif choice.upper() == 'C':
        confirm = input(f"{Colors.RED}Clear all history? (y/n): {Colors.RESET}").strip().lower()
        if confirm == 'y':
            config.config['history'] = []
            config.save()
            print(f"{Colors.GREEN}✅ History cleared{Colors.RESET}")
            time.sleep(1)
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(display_history):
                entry = display_history[idx]
                run_command(entry['command'])
            else:
                print(f"{Colors.RED}Invalid history number{Colors.RESET}")
                time.sleep(1)
        except:
            print(f"{Colors.RED}Invalid input{Colors.RESET}")
            time.sleep(1)

def show_presets():
    """Show and manage attack presets"""
    clear_screen()
    print_banner()
    print(f"{Colors.CYAN}═══════════════ 🎯 ATTACK PRESETS ═══════════════{Colors.RESET}\n")
    
    presets = {
        '1': {
            'name': 'Quick Web Scan',
            'command': './attack web-scan -target TARGET -depth light -threads 10',
            'description': 'Fast web vulnerability scan'
        },
        '2': {
            'name': 'Deep Web Scan',
            'command': './attack web-scan -target TARGET -depth deep -threads 20',
            'description': 'Comprehensive web vulnerability scan'
        },
        '3': {
            'name': 'Port Scan - Top 100',
            'command': './attack port-scan -target TARGET -top-ports 100 -service -threads 50',
            'description': 'Scan top 100 ports with service detection'
        },
        '4': {
            'name': 'Port Scan - Full',
            'command': './attack port-scan -target TARGET -ports 1-65535 -service -threads 100',
            'description': 'Full port scan (all 65535 ports)'
        },
        '5': {
            'name': 'Password Brute - SSH',
            'command': './attack password-brute -target TARGET -protocol ssh -users wordlists/usernames.txt -passwords wordlists/passwords.txt -threads 5',
            'description': 'SSH brute force attack'
        },
        '6': {
            'name': 'Hash Crack - MD5',
            'command': './attack hash-crack -hash HASH -type md5 -wordlist wordlists/passwords.txt -threads 10',
            'description': 'MD5 hash cracking'
        },
        '7': {
            'name': 'Subnet Discovery',
            'command': './attack subnet-scan -subnet SUBNET -threads 50',
            'description': 'Discover hosts in subnet (e.g., 192.168.1.0/24)'
        },
        '8': {
            'name': 'Directory Brute Force',
            'command': './attack dir-brute -target TARGET -wordlist wordlists/directories.txt -threads 20 -extensions php,html,txt',
            'description': 'Brute force directories and files'
        }
    }
    
    for key, preset in presets.items():
        print(f"{Colors.GREEN}[{key}]{Colors.RESET} {Colors.BOLD}{preset['name']}{Colors.RESET}")
        print(f"    {Colors.DIM}{preset['description']}{Colors.RESET}")
        print(f"    {Colors.CYAN}{preset['command']}{Colors.RESET}\n")
    
    print(f"{Colors.GREEN}[0]{Colors.RESET} Back to main menu\n")
    
    choice = input(f"{Colors.YELLOW}Select preset: {Colors.RESET}").strip()
    
    if choice == '0':
        return
    elif choice in presets:
        preset = presets[choice]
        print(f"\n{Colors.CYAN}Selected: {preset['name']}{Colors.RESET}")
        
        # Get required parameters
        command = preset['command']
        if 'TARGET' in command:
            target = input(f"{Colors.YELLOW}Enter target: {Colors.RESET}").strip()
            if not target:
                print(f"{Colors.RED}Target required{Colors.RESET}")
                time.sleep(1)
                return
            command = command.replace('TARGET', target)
        
        if 'HASH' in command:
            hash_val = input(f"{Colors.YELLOW}Enter hash: {Colors.RESET}").strip()
            if not hash_val:
                print(f"{Colors.RED}Hash required{Colors.RESET}")
                time.sleep(1)
                return
            command = command.replace('HASH', hash_val)
        
        if 'SUBNET' in command:
            subnet = input(f"{Colors.YELLOW}Enter subnet (e.g., 192.168.1.0/24): {Colors.RESET}").strip()
            if not subnet:
                print(f"{Colors.RED}Subnet required{Colors.RESET}")
                time.sleep(1)
                return
            command = command.replace('SUBNET', subnet)
        
        run_command(command)
    else:
        print(f"{Colors.RED}Invalid preset{Colors.RESET}")
        time.sleep(1)

def show_statistics():
    """Show detailed statistics"""
    clear_screen()
    print_banner()
    print(f"{Colors.CYAN}═══════════════ 📊 STATISTICS DASHBOARD ═══════════════{Colors.RESET}\n")
    
    stats = config.config.get('stats', {})
    history = config.config.get('history', [])
    favorites = config.get_favorites()
    
    total = stats.get('total_runs', 0)
    success = stats.get('successful_runs', 0)
    failed = stats.get('failed_runs', 0)
    success_rate = (success / total * 100) if total > 0 else 0
    
    print(f"{Colors.BOLD}Overall Statistics:{Colors.RESET}")
    print(f"  Total Commands Run: {Colors.CYAN}{total}{Colors.RESET}")
    print(f"  Successful: {Colors.GREEN}{success}{Colors.RESET}")
    print(f"  Failed: {Colors.RED}{failed}{Colors.RESET}")
    print(f"  Success Rate: {Colors.YELLOW}{success_rate:.1f}%{Colors.RESET}\n")
    
    if config.config.get('last_run'):
        last_time = datetime.fromisoformat(config.config['last_run']).strftime('%Y-%m-%d %H:%M:%S')
        print(f"  Last Run: {Colors.DIM}{last_time}{Colors.RESET}\n")
    
    print(f"{Colors.BOLD}Storage:{Colors.RESET}")
    print(f"  Command History: {Colors.CYAN}{len(history)}{Colors.RESET} entries")
    print(f"  Saved Favorites: {Colors.CYAN}{len(favorites)}{Colors.RESET} commands\n")
    
    if history:
        print(f"{Colors.BOLD}Recent Activity:{Colors.RESET}")
        for entry in history[:5]:
            timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%H:%M:%S')
            status = f"{Colors.GREEN}✓{Colors.RESET}" if entry.get('success', True) else f"{Colors.RED}✗{Colors.RESET}"
            cmd = entry['command'][:50] + '...' if len(entry['command']) > 50 else entry['command']
            print(f"  {status} {Colors.DIM}{timestamp}{Colors.RESET} - {cmd}")
        print()
    
    input(f"{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")

def export_results():
    """Export results and history"""
    clear_screen()
    print_banner()
    print(f"{Colors.CYAN}═══════════════ 💾 EXPORT RESULTS ═══════════════{Colors.RESET}\n")
    
    print(f"{Colors.GREEN}[1]{Colors.RESET} Export command history (JSON)")
    print(f"{Colors.GREEN}[2]{Colors.RESET} Export favorites (JSON)")
    print(f"{Colors.GREEN}[3]{Colors.RESET} Export statistics (JSON)")
    print(f"{Colors.GREEN}[4]{Colors.RESET} Export full config (JSON)")
    print(f"{Colors.GREEN}[5]{Colors.RESET} Generate report (TXT)")
    print(f"{Colors.GREEN}[0]{Colors.RESET} Back to main menu\n")
    
    choice = input(f"{Colors.YELLOW}Select export option: {Colors.RESET}").strip()
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    try:
        if choice == '1':
            filename = f'history_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(config.config.get('history', []), f, indent=2)
            print(f"{Colors.GREEN}✅ Exported to {filename}{Colors.RESET}")
        elif choice == '2':
            filename = f'favorites_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(config.get_favorites(), f, indent=2)
            print(f"{Colors.GREEN}✅ Exported to {filename}{Colors.RESET}")
        elif choice == '3':
            filename = f'statistics_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(config.config.get('stats', {}), f, indent=2)
            print(f"{Colors.GREEN}✅ Exported to {filename}{Colors.RESET}")
        elif choice == '4':
            filename = f'config_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(config.config, f, indent=2)
            print(f"{Colors.GREEN}✅ Exported to {filename}{Colors.RESET}")
        elif choice == '5':
            filename = f'report_{timestamp}.txt'
            with open(filename, 'w') as f:
                f.write("ADVANCED ATTACK TOOL - ACTIVITY REPORT\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                stats = config.config.get('stats', {})
                f.write("STATISTICS:\n")
                f.write(f"  Total Commands: {stats.get('total_runs', 0)}\n")
                f.write(f"  Successful: {stats.get('successful_runs', 0)}\n")
                f.write(f"  Failed: {stats.get('failed_runs', 0)}\n\n")
                
                f.write("RECENT HISTORY:\n")
                for entry in config.config.get('history', [])[:20]:
                    timestamp = entry['timestamp']
                    status = "SUCCESS" if entry.get('success', True) else "FAILED"
                    f.write(f"  [{timestamp}] {status}: {entry['command']}\n")
                
                f.write("\n" + "=" * 60 + "\n")
            print(f"{Colors.GREEN}✅ Generated report: {filename}{Colors.RESET}")
        elif choice == '0':
            return
        else:
            print(f"{Colors.RED}Invalid option{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}❌ Export failed: {e}{Colors.RESET}")
    
    time.sleep(2)

def show_settings():
    """Show and modify settings"""
    clear_screen()
    print_banner()
    print(f"{Colors.CYAN}═══════════════ ⚙️  SETTINGS ═══════════════{Colors.RESET}\n")
    
    settings = config.config.get('settings', {})
    
    print(f"{Colors.BOLD}Current Settings:{Colors.RESET}\n")
    print(f"{Colors.GREEN}[1]{Colors.RESET} Auto-build on start: {Colors.CYAN}{settings.get('auto_build', True)}{Colors.RESET}")
    print(f"{Colors.GREEN}[2]{Colors.RESET} Show tips: {Colors.CYAN}{settings.get('show_tips', True)}{Colors.RESET}")
    print(f"{Colors.GREEN}[3]{Colors.RESET} Animation speed: {Colors.CYAN}{settings.get('animation_speed', 0.03)}{Colors.RESET}")
    print(f"{Colors.GREEN}[4]{Colors.RESET} Max history size: {Colors.CYAN}{settings.get('max_history', 50)}{Colors.RESET}")
    print(f"{Colors.GREEN}[5]{Colors.RESET} Reset to defaults")
    print(f"{Colors.GREEN}[0]{Colors.RESET} Back to main menu\n")
    
    choice = input(f"{Colors.YELLOW}Select setting to change: {Colors.RESET}").strip()
    
    if choice == '1':
        settings['auto_build'] = not settings.get('auto_build', True)
        print(f"{Colors.GREEN}✅ Auto-build: {settings['auto_build']}{Colors.RESET}")
    elif choice == '2':
        settings['show_tips'] = not settings.get('show_tips', True)
        print(f"{Colors.GREEN}✅ Show tips: {settings['show_tips']}{Colors.RESET}")
    elif choice == '3':
        speed = input(f"{Colors.YELLOW}Enter animation speed (0.01-0.1) [0.03]: {Colors.RESET}").strip()
        try:
            speed = float(speed) if speed else 0.03
            settings['animation_speed'] = max(0.01, min(0.1, speed))
            print(f"{Colors.GREEN}✅ Animation speed: {settings['animation_speed']}{Colors.RESET}")
        except:
            print(f"{Colors.RED}Invalid value{Colors.RESET}")
    elif choice == '4':
        size = input(f"{Colors.YELLOW}Enter max history size (10-500) [50]: {Colors.RESET}").strip()
        try:
            size = int(size) if size else 50
            settings['max_history'] = max(10, min(500, size))
            print(f"{Colors.GREEN}✅ Max history: {settings['max_history']}{Colors.RESET}")
        except:
            print(f"{Colors.RED}Invalid value{Colors.RESET}")
    elif choice == '5':
        settings = {
            'auto_build': True,
            'show_tips': True,
            'animation_speed': 0.03,
            'max_history': 50
        }
        print(f"{Colors.GREEN}✅ Settings reset to defaults{Colors.RESET}")
    elif choice == '0':
        return
    
    config.config['settings'] = settings
    config.save()
    time.sleep(1)

def quick_launch():
    """Quick launch mode"""
    clear_screen()
    print_banner()
    print(f"{Colors.CYAN}═══════════════ 🚀 QUICK LAUNCH ═══════════════{Colors.RESET}\n")
    print(f"{Colors.YELLOW}Enter command directly (without './attack'):{Colors.RESET}\n")
    
    cmd = input(f"{Colors.GREEN}>{Colors.RESET} ").strip()
    
    if cmd:
        if not cmd.startswith('./attack'):
            cmd = './attack ' + cmd
        run_command(cmd)

def benchmark_mode():
    """Benchmark system performance"""
    clear_screen()
    print_banner()
    print(f"{Colors.CYAN}═══════════════ 🧪 BENCHMARK MODE ═══════════════{Colors.RESET}\n")
    
    print(f"{Colors.YELLOW}Running system benchmarks...{Colors.RESET}\n")
    
    # Test hash cracking speed
    print(f"{Colors.CYAN}[*] Testing hash cracking performance...{Colors.RESET}")
    loading_animation("Benchmarking", 1.0)
    
    test_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5 of "password"
    start = time.time()
    result = subprocess.run(
        ['./attack', 'hash-crack', '-hash', test_hash, '-type', 'md5', 
         '-wordlist', 'wordlists/passwords.txt', '-threads', '10'],
        capture_output=True,
        text=True
    )
    duration = time.time() - start
    
    # Parse hash rate from output
    hash_rate = "N/A"
    for line in result.stdout.split('\n'):
        if 'H/s' in line:
            hash_rate = line.split()[-2] + " H/s"
            break
    
    print(f"{Colors.GREEN}✅ Hash cracking: {hash_rate} (completed in {duration:.2f}s){Colors.RESET}\n")
    
    # Test port scanning speed
    print(f"{Colors.CYAN}[*] Testing port scanning performance...{Colors.RESET}")
    loading_animation("Scanning", 1.0)
    
    start = time.time()
    result = subprocess.run(
        ['./attack', 'port-scan', '-target', '127.0.0.1', '-ports', '1-100', '-threads', '50'],
        capture_output=True,
        text=True,
        timeout=30
    )
    duration = time.time() - start
    ports_per_sec = 100 / duration if duration > 0 else 0
    
    print(f"{Colors.GREEN}✅ Port scanning: {ports_per_sec:.1f} ports/sec{Colors.RESET}\n")
    
    print(f"\n{Colors.BOLD}System Performance Summary:{Colors.RESET}")
    print(f"  Hash Rate: {Colors.CYAN}{hash_rate}{Colors.RESET}")
    print(f"  Scan Speed: {Colors.CYAN}{ports_per_sec:.1f} ports/sec{Colors.RESET}")
    print(f"  Binary Size: {Colors.CYAN}{os.path.getsize('attack') / (1024*1024):.2f} MB{Colors.RESET}\n")
    
    input(f"{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")

def check_updates():
    """Check for updates and download from GitHub"""
    clear_screen()
    print_banner()
    print(f"{Colors.CYAN}═══════════════ 🔄 UPDATE CENTER ═══════════════{Colors.RESET}\n")
    
    menu = f"""
{Colors.GREEN}[1]{Colors.RESET} 📦 Check Go Dependencies
{Colors.GREEN}[2]{Colors.RESET} 🔄 Update Go Dependencies  
{Colors.GREEN}[3]{Colors.RESET} 🌐 Pull Latest from GitHub
{Colors.GREEN}[4]{Colors.RESET} 🔧 Full Update (GitHub + Dependencies + Rebuild)
{Colors.GREEN}[5]{Colors.RESET} 📊 Check Version Info
{Colors.GREEN}[0]{Colors.RESET} ⬅️  Back to Main Menu
"""
    print(menu)
    choice = input(f"{Colors.YELLOW}Select option: {Colors.RESET}").strip()
    
    if choice == '1':
        check_go_dependencies()
    elif choice == '2':
        update_go_dependencies()
    elif choice == '3':
        pull_from_github()
    elif choice == '4':
        full_update()
    elif choice == '5':
        show_version_info()
    elif choice == '0':
        return
    
    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")

def check_go_dependencies():
    """Check Go module updates"""
    print(f"\n{Colors.YELLOW}[*] Checking Go dependencies...{Colors.RESET}")
    loading_animation("Scanning modules", 1.5)
    
    try:
        result = subprocess.run(
            ['go', 'list', '-m', '-u', 'all'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            updates_available = False
            print(f"\n{Colors.BOLD}Dependency Status:{Colors.RESET}\n")
            for line in result.stdout.split('\n'):
                if '[' in line and ']' in line:
                    updates_available = True
                    print(f"  {Colors.YELLOW}⚠️  {line}{Colors.RESET}")
                elif line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        print(f"  {Colors.GREEN}✓{Colors.RESET} {parts[0]} {Colors.DIM}{parts[1]}{Colors.RESET}")
            
            if updates_available:
                print(f"\n{Colors.CYAN}💡 Run option [2] to update dependencies{Colors.RESET}")
            else:
                print(f"\n{Colors.GREEN}✅ All dependencies are up to date!{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Failed to check dependencies{Colors.RESET}")
            if result.stderr:
                print(f"{Colors.DIM}{result.stderr}{Colors.RESET}")
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}❌ Timeout checking dependencies{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")

def update_go_dependencies():
    """Update all Go dependencies"""
    print(f"\n{Colors.YELLOW}[*] Updating Go dependencies...{Colors.RESET}")
    
    try:
        # Update all dependencies
        print(f"{Colors.CYAN}Running: go get -u ./...{Colors.RESET}")
        result = subprocess.run(
            ['go', 'get', '-u', './...'],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            print(f"{Colors.GREEN}✅ Dependencies updated!{Colors.RESET}")
            
            # Tidy up
            print(f"\n{Colors.CYAN}Running: go mod tidy{Colors.RESET}")
            subprocess.run(['go', 'mod', 'tidy'], capture_output=True, timeout=30)
            print(f"{Colors.GREEN}✅ Module tidied!{Colors.RESET}")
            
            # Rebuild
            rebuild = input(f"\n{Colors.YELLOW}Rebuild binary? (y/n) [y]: {Colors.RESET}").strip().lower()
            if rebuild != 'n':
                build_project()
        else:
            print(f"{Colors.RED}❌ Update failed{Colors.RESET}")
            if result.stderr:
                print(f"{Colors.DIM}{result.stderr}{Colors.RESET}")
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}❌ Update timed out{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")

def pull_from_github():
    """Pull latest changes from GitHub"""
    print(f"\n{Colors.YELLOW}[*] Pulling from GitHub...{Colors.RESET}")
    
    # Check if git repo exists
    if not os.path.exists('.git'):
        print(f"{Colors.RED}❌ Not a git repository{Colors.RESET}")
        print(f"{Colors.YELLOW}💡 Initialize with: git init && git remote add origin <url>{Colors.RESET}")
        return False
    
    try:
        # Fetch latest
        print(f"{Colors.CYAN}Fetching updates...{Colors.RESET}")
        fetch_result = subprocess.run(
            ['git', 'fetch', '--all'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # Check for changes
        status_result = subprocess.run(
            ['git', 'status', '-uno'],
            capture_output=True,
            text=True
        )
        
        if 'Your branch is behind' in status_result.stdout:
            print(f"{Colors.YELLOW}⚠️  Updates available!{Colors.RESET}")
            
            # Show what's new
            log_result = subprocess.run(
                ['git', 'log', '--oneline', 'HEAD..@{u}', '-10'],
                capture_output=True,
                text=True
            )
            if log_result.stdout:
                print(f"\n{Colors.BOLD}New commits:{Colors.RESET}")
                for line in log_result.stdout.strip().split('\n'):
                    print(f"  {Colors.GREEN}•{Colors.RESET} {line}")
            
            confirm = input(f"\n{Colors.YELLOW}Pull changes? (y/n) [y]: {Colors.RESET}").strip().lower()
            if confirm != 'n':
                # Stash local changes
                subprocess.run(['git', 'stash'], capture_output=True)
                
                # Pull
                pull_result = subprocess.run(
                    ['git', 'pull', '--rebase'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if pull_result.returncode == 0:
                    print(f"{Colors.GREEN}✅ Successfully pulled latest changes!{Colors.RESET}")
                    
                    # Pop stash if any
                    subprocess.run(['git', 'stash', 'pop'], capture_output=True)
                    return True
                else:
                    print(f"{Colors.RED}❌ Pull failed{Colors.RESET}")
                    print(f"{Colors.DIM}{pull_result.stderr}{Colors.RESET}")
                    return False
        elif 'Your branch is up to date' in status_result.stdout:
            print(f"{Colors.GREEN}✅ Already up to date!{Colors.RESET}")
            return True
        else:
            print(f"{Colors.CYAN}Status: {status_result.stdout[:200]}{Colors.RESET}")
            return True
            
    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}❌ Git operation timed out{Colors.RESET}")
        return False
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")
        return False

def full_update():
    """Full update: GitHub + Dependencies + Rebuild"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}═══ FULL UPDATE PROCESS ═══{Colors.RESET}\n")
    
    steps = [
        ("Pulling from GitHub", pull_from_github),
        ("Updating Go dependencies", lambda: subprocess.run(['go', 'get', '-u', './...'], capture_output=True).returncode == 0),
        ("Tidying modules", lambda: subprocess.run(['go', 'mod', 'tidy'], capture_output=True).returncode == 0),
        ("Rebuilding binary", build_project),
    ]
    
    results = []
    for step_name, step_func in steps:
        print(f"\n{Colors.YELLOW}[{len(results)+1}/{len(steps)}] {step_name}...{Colors.RESET}")
        try:
            success = step_func()
            results.append((step_name, success if success is not None else True))
            if success or success is None:
                print(f"{Colors.GREEN}✓ {step_name} completed{Colors.RESET}")
            else:
                print(f"{Colors.RED}✗ {step_name} failed{Colors.RESET}")
        except Exception as e:
            results.append((step_name, False))
            print(f"{Colors.RED}✗ {step_name} failed: {e}{Colors.RESET}")
    
    # Summary
    print(f"\n{Colors.BOLD}═══ UPDATE SUMMARY ═══{Colors.RESET}")
    success_count = sum(1 for _, s in results if s)
    for step_name, success in results:
        status = f"{Colors.GREEN}✓{Colors.RESET}" if success else f"{Colors.RED}✗{Colors.RESET}"
        print(f"  {status} {step_name}")
    
    print(f"\n{Colors.CYAN}Completed: {success_count}/{len(results)} steps{Colors.RESET}")

def show_version_info():
    """Show version information"""
    print(f"\n{Colors.BOLD}Version Information:{Colors.RESET}\n")
    print(f"  Launcher: {Colors.CYAN}v4.0 ULTIMATE{Colors.RESET}")
    print(f"  Framework: {Colors.CYAN}v4.0{Colors.RESET}")
    
    # Get Go version
    try:
        go_ver = subprocess.run(['go', 'version'], capture_output=True, text=True)
        if go_ver.returncode == 0:
            print(f"  Go: {Colors.CYAN}{go_ver.stdout.strip()}{Colors.RESET}")
    except:
        pass
    
    # Get git info
    try:
        commit = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True)
        if commit.returncode == 0:
            print(f"  Git Commit: {Colors.CYAN}{commit.stdout.strip()}{Colors.RESET}")
        
        branch = subprocess.run(['git', 'branch', '--show-current'], capture_output=True, text=True)
        if branch.returncode == 0:
            print(f"  Git Branch: {Colors.CYAN}{branch.stdout.strip()}{Colors.RESET}")
        
        remote = subprocess.run(['git', 'remote', 'get-url', 'origin'], capture_output=True, text=True)
        if remote.returncode == 0:
            print(f"  Remote: {Colors.CYAN}{remote.stdout.strip()}{Colors.RESET}")
    except:
        pass
    
    # Binary info
    if os.path.exists('attack'):
        size = os.path.getsize('attack') / (1024 * 1024)
        mtime = datetime.fromtimestamp(os.path.getmtime('attack')).strftime('%Y-%m-%d %H:%M:%S')
        print(f"\n  Binary Size: {Colors.CYAN}{size:.2f} MB{Colors.RESET}")
        print(f"  Last Built: {Colors.CYAN}{mtime}{Colors.RESET}")

def direct_command():
    """Execute direct command"""
    clear_screen()
    print_banner()
    print(f"{Colors.CYAN}═══════════════ 💻 DIRECT COMMAND ═══════════════{Colors.RESET}\n")
    print(f"{Colors.YELLOW}Enter full command with './attack':{Colors.RESET}\n")
    
    cmd = input(f"{Colors.GREEN}>{Colors.RESET} ").strip()
    
    if cmd:
        run_command(cmd)

def clear_screen():
    """Clear the screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

def run_command(cmd):
    """Run a command and display output"""
    if isinstance(cmd, list):
        cmd_str = ' '.join(cmd)
    else:
        cmd_str = cmd
        cmd = cmd.split()
    
    print(f"\n{Colors.CYAN}╭{'─' * 70}╮{Colors.RESET}")
    print(f"{Colors.CYAN}│{Colors.YELLOW} ⚡ Executing: {cmd_str[:56]}{' ' * max(0, 56-len(cmd_str[:56]))} {Colors.CYAN}│{Colors.RESET}")
    print(f"{Colors.CYAN}╰{'─' * 70}╯{Colors.RESET}\n")
    
    # Add to history
    config.add_to_history(cmd_str)
    
    start_time = time.time()
    success = True
    
    try:
        result = subprocess.run(cmd)
        exit_code = result.returncode
        
        if exit_code != 0:
            success = False
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Operation interrupted by user{Colors.RESET}")
        success = False
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error: {e}{Colors.RESET}")
        success = False
    
    duration = time.time() - start_time
    
    print(f"\n{Colors.CYAN}╭{'─' * 70}╮{Colors.RESET}")
    if success:
        print(f"{Colors.CYAN}│{Colors.GREEN} ✅ Command completed successfully in {duration:.2f}s{' ' * (34 - len(f'{duration:.2f}'))} {Colors.CYAN}│{Colors.RESET}")
    else:
        print(f"{Colors.CYAN}│{Colors.RED} ❌ Command failed or was interrupted{' ' * 33} {Colors.CYAN}│{Colors.RESET}")
    print(f"{Colors.CYAN}╰{'─' * 70}╯{Colors.RESET}")
    
    # Update stats
    config.update_stats(success)
    
    # Ask to save as favorite
    if success:
        save_fav = input(f"\n{Colors.YELLOW}💾 Save this command as favorite? (y/n): {Colors.RESET}").strip().lower()
        if save_fav == 'y':
            name = input(f"{Colors.CYAN}Enter name: {Colors.RESET}").strip()
            desc = input(f"{Colors.CYAN}Enter description (optional): {Colors.RESET}").strip()
            if name:
                config.add_favorite(name, cmd_str, desc)
                print(f"{Colors.GREEN}✅ Saved to favorites!{Colors.RESET}")
    
    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")

def main():
    """Main launcher function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Spectre Strike Launcher')
    parser.add_argument('--quick', '-q', action='store_true', help='Quick launch mode')
    parser.add_argument('--command', '-c', help='Execute command directly')
    parser.add_argument('--preset', '-p', help='Run preset by number')
    parser.add_argument('--favorite', '-f', help='Run favorite by name')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner')
    args = parser.parse_args()
    
    os.chdir(Path(__file__).parent)
    
    # Handle command line modes
    if args.command:
        if not args.command.startswith('./attack'):
            args.command = './attack ' + args.command
        run_command(args.command)
        return
    
    if args.favorite:
        favorites = config.get_favorites()
        fav = next((f for f in favorites if f['name'] == args.favorite), None)
        if fav:
            run_command(fav['command'])
        else:
            print(f"{Colors.RED}Favorite '{args.favorite}' not found{Colors.RESET}")
        return
    
    while True:
        clear_screen()
        
        if not args.no_banner:
            print_banner()
            print_stats_banner()
        
        # Check dependencies on first run
        if not hasattr(main, 'checked'):
            if not check_dependencies():
                print(f"\n{Colors.RED}❌ Dependency check failed. Please fix issues and try again.{Colors.RESET}")
                sys.exit(1)
            main.checked = True
            print(f"\n{Colors.GREEN}✅ All checks passed! Starting launcher...{Colors.RESET}")
            time.sleep(2)
            continue
        
        if args.quick:
            quick_launch()
            break
        
        show_main_menu()
        choice = input(f"{Colors.BOLD}{Colors.YELLOW}Select option: {Colors.RESET}").strip()
        
        if choice == '1':
            web_exploitation_menu()
        elif choice == '2':
            password_attacks_menu()
        elif choice == '3':
            network_operations_menu()
        elif choice == '4':
            ddos_menu()
        elif choice == '5':
            redteam_menu()
        elif choice == '6':
            ml_intelligence_menu()
        elif choice == '7':
            build_project()
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
        elif choice == '8':
            show_documentation()
        elif choice == '9':
            show_examples()
        elif choice == '10':
            api_server_menu()
        elif choice == '11':
            show_favorites()
        elif choice == '12':
            show_history()
        elif choice == '13':
            show_presets()
        elif choice == '14':
            show_statistics()
        elif choice == '15':
            export_results()
        elif choice == '16':
            show_settings()
        elif choice == '17':
            quick_launch()
        elif choice == '18':
            benchmark_mode()
        elif choice == '19':
            check_updates()
        elif choice == '20':
            direct_command()
        elif choice == '?':
            show_help()
        elif choice == '0':
            print(f"\n{Colors.GREEN}👋 Thank you for using Spectre Strike!{Colors.RESET}")
            print(f"{Colors.CYAN}Stay safe and happy hacking! 🔐{Colors.RESET}")
            
            # Show final stats
            stats = config.config.get('stats', {})
            if stats.get('total_runs', 0) > 0:
                print(f"\n{Colors.DIM}Session Stats: {stats.get('total_runs', 0)} commands | "
                      f"{stats.get('successful_runs', 0)} successful | "
                      f"{stats.get('failed_runs', 0)} failed{Colors.RESET}")
            print()
            sys.exit(0)
        else:
            print(f"\n{Colors.RED}❌ Invalid option. Please try again.{Colors.RESET}")
            time.sleep(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Launcher interrupted by user{Colors.RESET}")
        print(f"{Colors.GREEN}Goodbye! 👋{Colors.RESET}\n")
        sys.exit(0)
