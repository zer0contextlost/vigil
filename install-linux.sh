#!/usr/bin/env bash
set -e

echo "=== vigil Linux installer ==="

# Install system dependencies
echo "[1/4] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y build-essential pkg-config libssl-dev curl git xterm wmctrl

# Install Rust if not present
if ! command -v cargo &>/dev/null; then
    echo "[2/4] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "[2/4] Rust already installed ($(rustc --version))"
fi

source "$HOME/.cargo/env"

# Install Claude Code if not present
if ! command -v claude &>/dev/null; then
    echo "[3/4] Installing Claude Code..."
    if ! command -v node &>/dev/null; then
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
        export NVM_DIR="$HOME/.nvm"
        source "$NVM_DIR/nvm.sh"
        nvm install --lts
    fi
    npm install -g @anthropic-ai/claude-code
else
    echo "[3/4] Claude Code already installed ($(claude --version 2>/dev/null || echo 'unknown version'))"
fi

# Build and install vigil
echo "[4/4] Building and installing vigil..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cargo install --path "$SCRIPT_DIR/crates/vigil-cli"

echo ""
echo "=== Done ==="
echo "vigil installed to ~/.cargo/bin/vigil"
echo ""
echo "Quick start:"
echo "  vigil run -- claude"
echo ""
echo "If 'vigil' is not found, add Rust to your PATH:"
echo "  source \$HOME/.cargo/env"
echo "  echo 'source \$HOME/.cargo/env' >> ~/.bashrc"
