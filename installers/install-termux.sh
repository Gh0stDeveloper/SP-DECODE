#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

REPO_URL="https://github.com/Gh0stDeveloper/SP-DECODE.git"
DEFAULT_TARGET="$HOME/SP-DECODE"
TARGET_DIR="${SPDECODE_HOME:-$DEFAULT_TARGET}"

echo "============================================================"
echo " SP-DECODE - TERMUX INSTALLER"
echo "============================================================"

if ! command -v pkg >/dev/null 2>&1; then
    echo "ERROR: this installer must be executed inside Termux."
    exit 1
fi

echo "[1/8] Updating Termux packages..."
pkg update -y

echo "[2/8] Installing runtimes and build dependencies..."
pkg install -y git python php clang make pkg-config libffi openssl rust

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    echo "Node.js/npm not detected; installing the Termux LTS package..."
    pkg install -y nodejs-lts
else
    echo "Node.js $(node --version) and npm $(npm --version) already available."
fi

if [[ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)/main.py" ]]; then
    PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    echo "[3/8] Using current repository: $PROJECT_DIR"
else
    PROJECT_DIR="$TARGET_DIR"
    if [[ ! -d "$PROJECT_DIR/.git" ]]; then
        echo "[3/8] Cloning SP-DECODE into $PROJECT_DIR..."
        git clone "$REPO_URL" "$PROJECT_DIR"
    else
        echo "[3/8] Existing repository found at $PROJECT_DIR."
    fi
fi

cd "$PROJECT_DIR"

echo "[4/8] Creating Python virtual environment..."
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools wheel

echo "[5/8] Installing Python dependencies (PyCryptodome, Telegram API, Argon2, MessagePack, Requests)..."
.venv/bin/pip install -r requirements.txt

echo "[6/8] Installing Node.js decoder dependencies..."
npm ci --omit=dev

echo "[7/8] Validating SP-DECODE..."
.venv/bin/python validate_project.py
.venv/bin/python -m unittest discover -s tests -v

echo "[8/8] Configuring Telegram access..."
.venv/bin/python installers/configure.py </dev/tty

mkdir -p logs run
chmod +x scripts/spdecode-termux.sh
ln -sf "$PROJECT_DIR/scripts/spdecode-termux.sh" "$PREFIX/bin/spdecode"

echo
echo "Starting SP-DECODE..."
spdecode restart

echo
echo "Installation complete."
echo "Project: $PROJECT_DIR"
echo
echo "Management commands:"
echo "  spdecode status"
echo "  spdecode start"
echo "  spdecode stop"
echo "  spdecode restart"
echo "  spdecode logs"
echo "  spdecode config"
echo "  spdecode update"
echo "  spdecode validate"
echo
echo "Android may suspend Termux in the background. For long-running use,"
echo "disable battery optimization for Termux in Android settings."
