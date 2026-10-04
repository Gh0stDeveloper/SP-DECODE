#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
PROJECT_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
SERVICE_NAME="${SPDECODE_SERVICE:-spdecode}"
PYTHON="$PROJECT_DIR/.venv/bin/python"

run_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

case "${1:-status}" in
    start)
        run_root systemctl start "$SERVICE_NAME"
        run_root systemctl --no-pager --full status "$SERVICE_NAME"
        ;;
    stop)
        run_root systemctl stop "$SERVICE_NAME"
        ;;
    restart)
        run_root systemctl restart "$SERVICE_NAME"
        run_root systemctl --no-pager --full status "$SERVICE_NAME"
        ;;
    status)
        run_root systemctl --no-pager --full status "$SERVICE_NAME"
        ;;
    logs)
        run_root journalctl -u "$SERVICE_NAME" -n 100 -f
        ;;
    config|configure)
        was_active=0
        if run_root systemctl is-active --quiet "$SERVICE_NAME"; then
            was_active=1
            run_root systemctl stop "$SERVICE_NAME"
        fi
        "$PYTHON" "$PROJECT_DIR/installers/configure.py" </dev/tty
        if [[ "$was_active" -eq 1 ]]; then
            run_root systemctl start "$SERVICE_NAME"
        fi
        ;;
    update)
        was_active=0
        if run_root systemctl is-active --quiet "$SERVICE_NAME"; then
            was_active=1
            run_root systemctl stop "$SERVICE_NAME"
        fi
        cd "$PROJECT_DIR"
        git pull --ff-only
        "$PROJECT_DIR/.venv/bin/pip" install -r requirements.txt
        npm ci --omit=dev
        "$PYTHON" validate_project.py
        "$PYTHON" -m unittest discover -s tests -v
        if [[ "$was_active" -eq 1 ]]; then
            run_root systemctl start "$SERVICE_NAME"
        fi
        ;;
    validate)
        cd "$PROJECT_DIR"
        "$PYTHON" validate_project.py
        "$PYTHON" -m unittest discover -s tests -v
        ;;
    *)
        echo "Usage: spdecode {start|stop|restart|status|logs|config|update|validate}"
        exit 2
        ;;
esac
