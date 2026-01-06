#!/bin/bash

echo "⚙️  Installing Spectre Strike..."
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21 or higher."
    echo "   Visit: https://go.dev/doc/install"
    exit 1
fi

# Get Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "✅ Go version: $GO_VERSION"
echo ""

# Download dependencies
echo "📥 Downloading dependencies..."
go mod tidy

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
    echo ""
    
    # Make build script executable
    chmod +x build.sh
    
    # Run build
    ./build.sh
else
    echo "❌ Failed to install dependencies"
    exit 1
fi
