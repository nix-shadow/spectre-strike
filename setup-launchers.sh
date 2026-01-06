#!/bin/bash

BINARY="./attack"
BIN_DIR="$(pwd)/bin"

mkdir -p "$BIN_DIR"

commands=(
    "webhook" "api-attack" "graphql" "nosql" "cors" "fuzzer" "dns" "ssl" "jwt" "session"
    "slowloris" "adaptive" "websocket" "waf-bypass" "hybrid"
    "recon" "stealth" "c2" "exfil" "pivot" "distributed"
    "web-scan" "sqli" "xss" "lfi" "dir-brute"
    "password-brute" "hash-crack"
    "scan" "port-scan" "service-enum" "subnet-scan"
)

for cmd in "${commands[@]}"; do
    launcher="$BIN_DIR/$cmd"
    cat > "$launcher" << EOF
#!/bin/bash
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
"\$DIR/attack" "$cmd" "\$@"
EOF
    chmod +x "$launcher"
done

echo "✓ Created launchers in $BIN_DIR"
echo "Add to PATH: export PATH=\$PATH:$BIN_DIR"
