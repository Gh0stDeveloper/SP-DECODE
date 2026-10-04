#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
PROJECT_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
PYTHON="$PROJECT_DIR/.venv/bin/python"
PID_FILE="$PROJECT_DIR/run/spdecode.pid"
LOG_FILE="$PROJECT_DIR/logs/spdecode.log"

mkdir -p "$PROJECT_DIR/run" "$PROJECT_DIR/logs"

is_running() {
    [[ -f "$PID_FILE" ]] || return 1
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

start_bot() {
    if is_running; then
        echo "SP-DECODE is already running (PID $(cat "$PID_FILE"))."
        return 0
    fi

    rm -f "$PID_FILE"
    cd "$PROJECT_DIR"
    nohup "$PYTHON" main.py >>"$LOG_FILE" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    sleep 1

    if kill -0 "$pid" 2>/dev/null; then
        echo "SP-DECODE started successfully (PID $pid)."
        echo "Logs: $LOG_FILE"
    else
        echo "SP-DECODE failed to start. Last log lines:"
        tail -n 30 "$LOG_FILE" || true
        rm -f "$PID_FILE"
        return 1
    fi
}

stop_bot() {
    if ! is_running; then
        echo "SP-DECODE is not running."
        rm -f "$PID_FILE"
        return 0
    fi

    local pid
    pid="$(cat "$PID_FILE")"
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$PID_FILE"
            echo "SP-DECODE stopped."
            return 0
        fi
        sleep 0.5
    done
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    echo "SP-DECODE was force-stopped."
}

status_bot() {
    if is_running; then
        echo "SP-DECODE is running (PID $(cat "$PID_FILE"))."
    else
        echo "SP-DECODE is stopped."
        return 1
    fi
}

configure_bot() {
    local was_running=0
    if is_running; then
        was_running=1
        stop_bot
    fi
    "$PYTHON" "$PROJECT_DIR/installers/configure.py" </dev/tty
    if [[ "$was_running" -eq 1 ]]; then
        start_bot
    fi
}

update_bot() {
    local was_running=0
    if is_running; then
        was_running=1
        stop_bot
    fi
    cd "$PROJECT_DIR"
    git pull --ff-only
    "$PROJECT_DIR/.venv/bin/pip" install -r requirements.txt
    npm ci --omit=dev
    "$PYTHON" validate_project.py
    "$PYTHON" -m unittest discover -s tests -v
    if [[ "$was_running" -eq 1 ]]; then
        start_bot
    fi
}

case "${1:-status}" in
    start) start_bot ;;
    stop) stop_bot ;;
    restart) stop_bot; start_bot ;;
    status) status_bot ;;
    logs) touch "$LOG_FILE"; tail -n 100 -f "$LOG_FILE" ;;
    config|configure) configure_bot ;;
    update) update_bot ;;
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
