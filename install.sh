#!/usr/bin/env bash
# ============================================================
#  Multi-Format Password Cracker — One-Line Installer
#  Repo: https://github.com/NRXQuantum/telegram-bot-zip
#
#  Supports: Termux, Debian/Ubuntu/Kali/Colab, Arch, Fedora, macOS
#
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/NRXQuantum/telegram-bot-zip/main/install.sh | bash
# ============================================================
set -euo pipefail

# ---------------------- Config ----------------------
REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/NRXQuantum/telegram-bot-zip/main}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.zip_cracker}"
PY_SCRIPT="zip_cracker.py"
MAX_TOKEN_ATTEMPTS=3

# ---------------------- Colors ----------------------
if [ -t 1 ]; then
    CYN=$'\033[0;36m'; GRN=$'\033[0;32m'; YEL=$'\033[1;33m'
    RED=$'\033[0;31m'; BLD=$'\033[1m'; NC=$'\033[0m'
else
    CYN=""; GRN=""; YEL=""; RED=""; BLD=""; NC=""
fi
log()  { printf '%s[*]%s %s\n' "$CYN" "$NC" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$GRN" "$NC" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YEL" "$NC" "$*"; }
die()  { printf '%s[✗]%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

banner() {
cat <<'EOF'
   ______               ____                _
  |__  (_)_ __       / ___|_ __ __ _  ___| | _____ _ __
    / /| | '_ \     | |   | '__/ _ |/ __| |/ / _ \ '__|
   / /_| | |_) |    | |___| | | (_| | (__|   <  __/ |
  /____|_| .__/      \____|_|  \__,_|\___|_|\_\___|_|
         |_|        telegram-bot-zip
EOF
echo
}

ask() {
    local prompt="$1" varname="$2" default="${3:-}" ans=""
    if [ -t 0 ]; then
        read -rp "$prompt" ans || true
    elif [ -c /dev/tty ] && [ -r /dev/tty ]; then
        read -rp "$prompt" ans < /dev/tty || true
    else
        ans="$default"
    fi
    eval "$varname=\$ans"
}

run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        "$@"
    fi
}

# ---------------------- Token validation ----------------------
validate_token() {
    local token="$1"
    [ -z "$token" ] && return 1
    local resp=""
    if command -v curl >/dev/null 2>&1; then
        resp=$(curl -fsSL --max-time 10 \
            "https://api.telegram.org/bot${token}/getMe" 2>/dev/null || echo "")
    elif command -v wget >/dev/null 2>&1; then
        resp=$(wget -q -O - --timeout=10 \
            "https://api.telegram.org/bot${token}/getMe" 2>/dev/null || echo "")
    else
        return 0
    fi
    echo "$resp" | grep -q '"ok":true'
}

extract_username() {
    local token="$1"
    local resp=""
    if command -v curl >/dev/null 2>&1; then
        resp=$(curl -fsSL --max-time 10 \
            "https://api.telegram.org/bot${token}/getMe" 2>/dev/null || echo "")
    fi
    echo "$resp" | sed -n 's/.*"username":"\([^"]*\)".*/\1/p'
}

read_token_from_env_file() {
    local envf="$1"
    [ -f "$envf" ] || return 1
    grep -E '^[[:space:]]*TELEGRAM_BOT_TOKEN[[:space:]]*=' "$envf" 2>/dev/null \
        | grep -v '^[[:space:]]*#' \
        | head -n1 \
        | sed -E 's/^[[:space:]]*TELEGRAM_BOT_TOKEN[[:space:]]*=[[:space:]]*//' \
        | tr -d '\r\n' \
        | sed -E 's/^"(.*)"$/\1/' \
        | sed -E "s/^'(.*)'\$/\1/" \
        | xargs 2>/dev/null || true
}

# ---------------------- Token gate ----------------------
token_gate() {
    local env_file="$INSTALL_DIR/.env"
    local attempt=0
    local current_token=""

    while [ "$attempt" -lt "$MAX_TOKEN_ATTEMPTS" ]; do
        attempt=$((attempt + 1))
        current_token=$(read_token_from_env_file "$env_file" || true)

        if [ -n "$current_token" ] && [ "$current_token" != "PASTE_YOUR_TOKEN_HERE" ]; then
            log "Validating token (attempt $attempt/$MAX_TOKEN_ATTEMPTS)..."
            if validate_token "$current_token"; then
                local uname
                uname=$(extract_username "$current_token")
                echo
                ok "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                ok "  ✅ TOKEN IS VALID"
                ok "     Bot: @${uname}"
                ok "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo
                return 0
            else
                echo
                warn "❌ Token invalid (attempt $attempt)"
                warn "   Preview: ${current_token:0:12}...${current_token: -4}"
                echo
            fi
        else
            warn "No valid token in $env_file"
        fi

        if [ -t 1 ] && { [ -t 0 ] || [ -c /dev/tty ]; }; then
            echo "BotFather → @BotFather → /newbot → টোকেন কপি"
            echo
            ask "Paste NEW TELEGRAM_BOT_TOKEN (Ctrl+C to abort): " NEW_TOKEN ""
            if [ -z "${NEW_TOKEN:-}" ]; then
                continue
            fi
            umask 077
            echo "TELEGRAM_BOT_TOKEN=$NEW_TOKEN" > "$env_file"
            chmod 600 "$env_file" 2>/dev/null || true
            ok "Token saved — validating next attempt..."
            echo
        else
            die "Token invalid and no TTY. Update $env_file manually."
        fi
    done

    die "Token validation failed after $MAX_TOKEN_ATTEMPTS attempts."
}

# ---------------------- Environment ----------------------
kill_previous_bot() {
    if command -v pgrep >/dev/null 2>&1; then
        local PIDS
        PIDS=$(pgrep -f "$PY_SCRIPT" 2>/dev/null || true)
        if [ -n "$PIDS" ]; then
            warn "Old instance(s): $PIDS — killing..."
            kill $PIDS 2>/dev/null || true
            sleep 2
            local STILL
            STILL=$(pgrep -f "$PY_SCRIPT" 2>/dev/null || true)
            [ -n "$STILL" ] && kill -9 $STILL 2>/dev/null || true
            ok "Previous instance cleared."
        fi
    fi
}

detect_env() {
    if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]; then
        ENV_TYPE="termux"
    elif [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
        ENV_TYPE="macos"
    elif command -v apt-get >/dev/null 2>&1; then
        ENV_TYPE="debian"
    elif command -v pacman >/dev/null 2>&1; then
        ENV_TYPE="arch"
    elif command -v dnf >/dev/null 2>&1; then
        ENV_TYPE="fedora"
    else
        ENV_TYPE="unknown"
    fi
    ok "Environment: $ENV_TYPE"
    if [ -d "/content" ] && [ "$(id -u)" -eq 0 ]; then
        warn "Detected Google Colab / Docker root environment."
    fi
}

ensure_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        log "python3 not found — installing..."
        case "$ENV_TYPE" in
            termux)  pkg install -y python ;;
            debian)  run_as_root apt-get install -y python3 ;;
            arch)    run_as_root pacman -Sy --noconfirm python ;;
            fedora)  run_as_root dnf install -y python3 ;;
            macos)   brew install python ;;
            *)       die "python3 missing" ;;
        esac
    fi
    ok "Python: $(python3 --version 2>&1)"

    if ! python3 -m pip --version >/dev/null 2>&1; then
        log "pip missing — installing..."
        case "$ENV_TYPE" in
            termux)  pkg install -y python-pip ;;
            debian)  run_as_root apt-get install -y python3-pip ;;
            arch)    run_as_root pacman -Sy --noconfirm python-pip ;;
            fedora)  run_as_root dnf install -y python3-pip ;;
            macos)   python3 -m ensurepip --upgrade || brew install python ;;
            *)       python3 -m ensurepip --upgrade || true ;;
        esac
    fi
}

install_system_deps() {
    log "Installing system dependencies..."
    case "$ENV_TYPE" in
        termux)
            pkg update -y >/dev/null 2>&1 || true
            pkg install -y python unrar p7zip clang make libffi openssl \
                python-psutil >/dev/null 2>&1 || warn "Some termux packages failed"
            ;;
        debian)
            run_as_root apt-get update -qq >/dev/null 2>&1 || true
            run_as_root apt-get install -y \
                python3 python3-venv python3-pip \
                unrar-free p7zip-full build-essential \
                libffi-dev libssl-dev python3-dev \
                >/dev/null 2>&1 || warn "Some apt packages failed"
            ;;
        arch)
            run_as_root pacman -Sy --noconfirm \
                python python-pip unrar p7zip base-devel \
                >/dev/null 2>&1 || warn "Some pacman packages failed"
            ;;
        fedora)
            run_as_root dnf install -y \
                python3 python3-pip python3-devel \
                unrar p7zip p7zip-plugins gcc \
                libffi-devel openssl-devel \
                >/dev/null 2>&1 || warn "Some dnf packages failed"
            ;;
        macos)
            brew install python unrar p7zip >/dev/null 2>&1 || true
            ;;
        *)
            warn "Unknown OS — skipping system packages."
            ;;
    esac
    ok "System deps done."
}

install_python_deps() {
    log "Setting up Python environment..."
    cd "$INSTALL_DIR"

    if ! python3 -m venv --help >/dev/null 2>&1; then
        warn "python3-venv missing — installing..."
        case "$ENV_TYPE" in
            termux)  pkg install -y python ;;
            debian)  run_as_root apt-get install -y python3-venv || true ;;
            arch)    run_as_root pacman -Sy --noconfirm python || true ;;
            fedora)  run_as_root dnf install -y python3 || true ;;
            macos)   brew install python || true ;;
        esac
    fi

    if [ -d ".venv" ] && [ ! -f ".venv/bin/activate" ]; then
        warn "Broken .venv — removing."
        rm -rf .venv
    fi

    VENV_OK=0
    if [ -f ".venv/bin/activate" ]; then
        VENV_OK=1
        ok "Existing virtualenv valid."
    else
        log "Creating virtualenv..."
        if python3 -m venv .venv 2>/dev/null && [ -f ".venv/bin/activate" ]; then
            VENV_OK=1
            ok "Virtualenv created."
        else
            warn "venv failed — system pip fallback."
            rm -rf .venv
        fi
    fi

    local PIP_EXTRA=""
    if [ "$VENV_OK" = "1" ]; then
        # shellcheck disable=SC1091
        source .venv/bin/activate
        PIP="pip"
        PIP_EXTRA=""
    elif [ "$(id -u)" -eq 0 ]; then
        PIP="pip3"
        PIP_EXTRA="--break-system-packages"
        warn "Root — using --break-system-packages"
    else
        PIP="pip3"
        PIP_EXTRA="--user"
        warn "Using user pip"
    fi

    log "Installing Python packages..."
    $PIP install $PIP_EXTRA --upgrade pip wheel >/dev/null 2>&1 || true

    if [ "$ENV_TYPE" = "termux" ]; then
        pkg install -y python-psutil >/dev/null 2>&1 || true
    fi

    $PIP install $PIP_EXTRA \
        pyzipper rarfile py7zr PyPDF2 flask python-telegram-bot \
        2>&1 | tail -3 || {
        warn "Bulk failed — retrying individually..."
        for pkg in pyzipper rarfile py7zr PyPDF2 flask python-telegram-bot; do
            $PIP install $PIP_EXTRA "$pkg" >/dev/null 2>&1 || \
                warn "  → Failed: $pkg"
        done
    }

    log "Verifying..."
    local CHECK_PY
    [ "$VENV_OK" = "1" ] && CHECK_PY=".venv/bin/python" || CHECK_PY="python3"
    local MISSING=""
    for mod in pyzipper rarfile py7zr PyPDF2 flask telegram; do
        $CHECK_PY -c "import $mod" 2>/dev/null || MISSING="$MISSING $mod"
    done
    if [ -n "$MISSING" ]; then
        warn "Missing modules:$MISSING"
    else
        ok "All Python modules verified."
    fi
    ok "Python deps done."
}

fetch_script() {
    cd "$INSTALL_DIR"
    if [ ! -f "$PY_SCRIPT" ]; then
        log "Downloading $PY_SCRIPT ..."
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$REPO_RAW/$PY_SCRIPT" -o "$PY_SCRIPT"
        elif command -v wget >/dev/null 2>&1; then
            wget -q "$REPO_RAW/$PY_SCRIPT" -O "$PY_SCRIPT"
        else
            die "Neither curl nor wget found."
        fi
        [ -s "$PY_SCRIPT" ] || die "Download failed."
        ok "$PY_SCRIPT downloaded."
    else
        ok "$PY_SCRIPT already present."
    fi
}

setup_env_file() {
    local ENV_FILE="$INSTALL_DIR/.env"

    # Priority 1: env var
    if [ -n "${TELEGRAM_BOT_TOKEN:-}" ]; then
        ok "Token from env var."
        umask 077
        echo "TELEGRAM_BOT_TOKEN=$TELEGRAM_BOT_TOKEN" > "$ENV_FILE"
        chmod 600 "$ENV_FILE" 2>/dev/null || true
        return
    fi

    # Priority 2: existing .env
    if [ -f "$ENV_FILE" ]; then
        ok "Existing .env found."
        chmod 600 "$ENV_FILE" 2>/dev/null || true
        return
    fi

    # Priority 3: ask
    echo
    warn "Telegram Bot Token required."
    echo "  Get from @BotFather → /newbot"
    echo
    ask "Paste token (or blank to abort): " TOKEN ""
    [ -z "${TOKEN:-}" ] && die "No token provided."
    umask 077
    echo "TELEGRAM_BOT_TOKEN=$TOKEN" > "$ENV_FILE"
    chmod 600 "$ENV_FILE" 2>/dev/null || true
    ok "Token saved."
}

create_launcher() {
    local LAUNCHER="$INSTALL_DIR/run.sh"
    cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
cd "\$(dirname "\$0")"

SCRIPT_NAME="$PY_SCRIPT"

if command -v pgrep >/dev/null 2>&1; then
    PIDS=\$(pgrep -f "\$SCRIPT_NAME" 2>/dev/null || true)
    if [ -n "\$PIDS" ]; then
        echo "[!] Killing old: \$PIDS"
        kill \$PIDS 2>/dev/null || true
        sleep 2
        STILL=\$(pgrep -f "\$SCRIPT_NAME" 2>/dev/null || true)
        [ -n "\$STILL" ] && kill -9 \$STILL 2>/dev/null || true
    fi
fi

if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

if [ -f ".venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
    exec python "\$SCRIPT_NAME" "\$@"
else
    exec python3 "\$SCRIPT_NAME" "\$@"
fi
EOF
    chmod +x "$LAUNCHER"
    ok "Launcher created: $LAUNCHER"
}

main() {
    banner
    detect_env
    ensure_python
    install_system_deps

    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"

    kill_previous_bot
    fetch_script
    install_python_deps
    setup_env_file
    create_launcher

    echo
    log "═══════════════════════════════════════════════════════"
    log "  Pre-launch token validation"
    log "═══════════════════════════════════════════════════════"
    token_gate

    echo
    ok "Installation complete!"
    echo "  ~/.zip_cracker/run.sh --web --port 5000   # web only"
    echo "  ~/.zip_cracker/run.sh --all               # bot + web"
    echo "  ~/.zip_cracker/run.sh archive.zip         # CLI"
    echo

    if command -v pgrep >/dev/null 2>&1 && pgrep -f "$PY_SCRIPT" >/dev/null 2>&1; then
        warn "Waiting 10s for Telegram to release old session..."
        sleep 10
    fi

    echo
    ok "Starting bot (Ctrl+C to stop)..."
    echo
    exec "$INSTALL_DIR/run.sh" --bot
}

main "$@"
