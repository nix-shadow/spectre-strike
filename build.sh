#!/bin/bash

echo "🚀 Building Spectre Strike..."
echo ""

# Create build directory
mkdir -p bin

# Build the binary
echo "📦 Compiling Go binary..."
go build -o bin/attack -ldflags="-s -w" cmd/main.go

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Build successful!"
    echo ""
    echo "📍 Binary location: bin/attack"
    echo ""
    echo "🎯 Quick Start:"
    echo "   ./bin/attack slowloris -target https://example.com -duration 60"
    echo "   ./bin/attack adaptive -target https://example.com -duration 120"
    echo "   ./bin/attack websocket -target wss://example.com/ws -duration 60"
    echo "   ./bin/attack waf-bypass -target https://example.com -duration 60"
    echo "   ./bin/attack scan -target example.com"
    echo "   ./bin/attack hybrid -target https://example.com -duration 300"
    echo ""
    echo "📖 For more help: ./bin/attack help"
else
    echo ""
    echo "❌ Build failed!"
    exit 1
fi
