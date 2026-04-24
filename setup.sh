#!/usr/bin/env bash
# GOD'S EYE — Kali Linux / Debian setup
set -e

echo "============================================"
echo " GOD'S EYE v1.0.0 - Setup"
echo " For authorized security testing only"
echo "============================================"
echo

# Check Python version
python3 -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11+ required'" || {
    echo "ERROR: Python 3.11+ is required."
    exit 1
}

echo "Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3-pip python3-venv libpango-1.0-0 libcairo2 \
    libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info 2>/dev/null || true

echo "Installing Python dependencies..."
pip3 install --break-system-packages -r requirements.txt

echo "Installing Playwright browser..."
playwright install chromium || echo "WARNING: Playwright install failed. Screenshots will be disabled."

echo "Creating directories..."
mkdir -p reports/screenshots logs config/wordlists

echo "Installing as editable package (godseye command)..."
pip3 install --break-system-packages -e . 2>/dev/null || echo "NOTE: pip install -e . failed — use python3 main.py directly"

echo "Adding ~/.local/bin to PATH..."
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc 2>/dev/null || true
source ~/.bashrc 2>/dev/null || true

echo
echo "============================================"
echo " Setup complete!"
echo "============================================"
echo
echo "Usage:"
echo "  python3 main.py --target 127.0.0.1 --mode pentest"
echo "  godseye --target TARGET --mode redteam --stealth --subdomains --screenshot"
echo

echo "Testing godseye command..."
godseye --help && echo "SUCCESS: godseye is ready!" || echo "Run: export PATH=\$HOME/.local/bin:\$PATH"
