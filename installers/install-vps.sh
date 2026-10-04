#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/Gh0stDeveloper/SP-DECODE.git"
SERVICE_NAME="${SPDECODE_SERVICE:-spdecode}"
CALLER_USER="${SUDO_USER:-$(id -un)}"
CALLER_HOME="$(getent passwd "$CALLER_USER" 2>/dev/null | cut -d: -f6)"
CALLER_HOME="${CALLER_HOME:-$HOME}"
TARGET_DIR="${SPDECODE_HOME:-$CALLER_HOME/SP-DECODE}"

if [[ "${EUID:-$(id -u)}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    echo "ERROR: do not run the whole installer with sudo."
    echo "Run: bash installers/install-vps.sh"
    echo "The installer requests sudo only for system package/service operations."
    exit 2
fi

run_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

echo "============================================================"
echo " SP-DECODE - VPS INSTALLER"
echo "============================================================"

echo "[1/9] Installing system packages..."
if command -v apt-get >/dev/null 2>&1; then
    run_root apt-get update
    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        git curl ca-certificates \
        python3 python3-venv python3-pip \
        php-cli \
        build-essential pkg-config libffi-dev libssl-dev
elif command -v dnf >/dev/null 2>&1; then
    run_root dnf install -y \
        git curl ca-certificates \
        python3 python3-pip \
        php-cli \
        gcc gcc-c++ make pkgconf-pkg-config libffi-devel openssl-devel
elif command -v yum >/dev/null 2>&1; then
    run_root yum install -y \
        git curl ca-certificates \
        python3 python3-pip \
        php-cli \
        gcc gcc-c++ make pkgconfig libffi-devel openssl-devel
else
    echo "ERROR: unsupported package manager. Debian/Ubuntu, Fedora/RHEL and compatible systems are supported."
    exit 1
fi

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    echo "Node.js/npm not detected; installing distribution packages..."
    if command -v apt-get >/dev/null 2>&1; then
        run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs npm
    elif command -v dnf >/dev/null 2>&1; then
        run_root dnf install -y nodejs npm
    else
        run_root yum install -y nodejs npm
    fi
else
    echo "Node.js $(node --version) and npm $(npm --version) already available."
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "ERROR: systemd/systemctl is required by the VPS activator."
    exit 1
fi

if [[ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)/main.py" ]]; then
    PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    echo "[2/9] Using current repository: $PROJECT_DIR"
else
    PROJECT_DIR="$TARGET_DIR"
    if [[ ! -d "$PROJECT_DIR/.git" ]]; then
        echo "[2/9] Cloning SP-DECODE into $PROJECT_DIR..."
        git clone "$REPO_URL" "$PROJECT_DIR"
    else
        echo "[2/9] Existing repository found at $PROJECT_DIR."
    fi
fi

cd "$PROJECT_DIR"

echo "[3/9] Creating Python virtual environment..."
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools wheel

echo "[4/9] Installing Python dependencies..."
.venv/bin/pip install -r requirements.txt

echo "[5/9] Installing Node.js decoder dependencies..."
npm ci --omit=dev

echo "[6/9] Validating SP-DECODE..."
.venv/bin/python validate_project.py
.venv/bin/python -m unittest discover -s tests -v

echo "[7/9] Configuring Telegram access..."
.venv/bin/python installers/configure.py </dev/tty
chmod 600 config.json 2>/dev/null || true

echo "[8/9] Installing systemd service..."
chmod +x scripts/spdecode-vps.sh

SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
run_root tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=SP-DECODE Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$CALLER_USER
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/.venv/bin/python $PROJECT_DIR/main.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

run_root ln -sf "$PROJECT_DIR/scripts/spdecode-vps.sh" /usr/local/bin/spdecode
run_root systemctl daemon-reload
run_root systemctl enable "$SERVICE_NAME"

echo "[9/9] Starting SP-DECODE..."
run_root systemctl restart "$SERVICE_NAME"

echo
echo "Installation complete."
echo "Project: $PROJECT_DIR"
echo "Service: $SERVICE_NAME"
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
run_root systemctl --no-pager --full status "$SERVICE_NAME" || true
