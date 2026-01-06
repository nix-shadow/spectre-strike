#!/usr/bin/env python3
"""
Spectre Strike - Direct Command Launcher
Professional Edition v4.0
"""

import os
import sys
import subprocess
from pathlib import Path

BINARY = "./attack"
BIN_DIR = Path.cwd() / "bin"

COMMANDS = [
    "webhook", "api-attack", "graphql", "nosql", "cors", "fuzzer", "dns", "ssl", "jwt", "session",
    "slowloris", "adaptive", "websocket", "waf-bypass", "hybrid",
    "recon", "stealth", "c2", "exfil", "pivot", "distributed",
    "web-scan", "sqli", "xss", "lfi", "dir-brute",
    "password-brute", "hash-crack",
    "scan", "port-scan", "service-enum", "subnet-scan"
]

def create_launchers():
    """Create individual launcher scripts for each command"""
    BIN_DIR.mkdir(exist_ok=True)
    
    for cmd in COMMANDS:
        launcher = BIN_DIR / cmd
        script = f"""#!/bin/bash
DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)"
"$DIR/attack" "{cmd}" "$@"
"""
        launcher.write_text(script)
        launcher.chmod(0o755)
    
    print(f"✓ Created {len(COMMANDS)} launchers in {BIN_DIR}")
    print(f"Add to PATH: export PATH=$PATH:{BIN_DIR}")
    
    # Add to shell RC files
    shell_rc = Path.home() / ".zshrc"
    path_line = f'export PATH=$PATH:{BIN_DIR}\n'
    
    if shell_rc.exists():
        content = shell_rc.read_text()
        if str(BIN_DIR) not in content:
            with shell_rc.open('a') as f:
                f.write(f'\n# Spectre Strike\n{path_line}')
            print(f"✓ Added to {shell_rc}")

if __name__ == "__main__":
    if not Path(BINARY).exists():
        print("❌ Binary not found. Run: ./build.sh")
        sys.exit(1)
    
    create_launchers()
    print("\nUsage examples:")
    print("  jwt -token eyJ... -attack all")
    print("  waf-bypass -target https://example.com")
    print("  c2 -c2-port 8443")
    print("  scan -target example.com")
