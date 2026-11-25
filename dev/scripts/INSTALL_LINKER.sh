#!/bin/bash
# Quick installer for mold linker (most impactful optimization)
# Run: bash .cargo/INSTALL_LINKER.sh

set -e

echo "=== Installing mold linker for faster Rust builds ==="
echo ""

if command -v mold &> /dev/null; then
    echo "✅ mold is already installed: $(mold --version)"
    echo ""
else
    echo "Installing mold..."
    
    # Detect OS
    if [ -f /etc/debian_version ]; then
        echo "Detected Debian/Ubuntu"
        sudo apt update && sudo apt install -y mold
    elif [ -f /etc/arch-release ]; then
        echo "Detected Arch Linux"
        sudo pacman -S --noconfirm mold
    elif command -v brew &> /dev/null; then
        echo "Detected macOS with Homebrew"
        brew install mold
    else
        echo "⚠️  Unable to auto-install. Please install manually:"
        echo "   https://github.com/rui314/mold#installation"
        exit 1
    fi
    
    echo "✅ mold installed successfully"
    echo ""
fi

# Check for clang (required for mold)
if ! command -v clang &> /dev/null; then
    echo "⚠️  clang not found. Installing..."
    if [ -f /etc/debian_version ]; then
        sudo apt install -y clang
    elif [ -f /etc/arch-release ]; then
        sudo pacman -S --noconfirm clang
    fi
fi

echo "=== Enabling mold in Cargo config ==="

CONFIG_FILE="$(dirname "$0")/config.toml"

# Uncomment mold configuration
if grep -q "# \[target.x86_64-unknown-linux-gnu\]" "$CONFIG_FILE"; then
    sed -i 's/# \[target.x86_64-unknown-linux-gnu\]/[target.x86_64-unknown-linux-gnu]/' "$CONFIG_FILE"
    sed -i 's/# linker = "clang"/linker = "clang"/' "$CONFIG_FILE"
    sed -i 's/# rustflags = \["-C", "link-arg=-fuse-ld=mold"\]/rustflags = ["-C", "link-arg=-fuse-ld=mold"]/' "$CONFIG_FILE"
    echo "✅ mold enabled in .cargo/config.toml"
else
    echo "ℹ️  mold already enabled in config"
fi

echo ""
echo "=== Testing configuration ==="
cd "$(dirname "$0")/.."
echo "Running: cargo build --lib"
if cargo build --lib 2>&1 | grep -q "Finished"; then
    echo "✅ Build successful with mold linker!"
else
    echo "⚠️  Build had issues. Check output above."
fi

echo ""
echo "=== Setup Complete ==="
echo "Expected improvement: 50-80% faster linking"
echo "Test with: cargo clean && time cargo build"
