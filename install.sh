#!/usr/bin/env bash
set -euo pipefail

echo "Installing vigil..."
cargo install --git https://github.com/vigil-dev/vigil vigil
echo ""
echo "vigil installed successfully."
echo "Run: vigil run -- claude"
