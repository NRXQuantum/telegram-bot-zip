#!/usr/bin/env bash
# ============================================================
#  Multi-Format Password Cracker — One-Line Installer
#  Repo: https://github.com/NRXQuantum/telegram-bot-zip
#
#  Mode: Bot-only auto-start
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
DICT_FILE="password_list.txt"

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

# ---------------------- Banner ----------------------
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

# ---------------------- Ask (works via curl | bash) ----------------------
ask() {
    local prompt="$1" varname="$2" default="${3:-}" ans=""
    if [ -t 0 ]; then
        read -rp "$prompt" ans || true
    elif [ -r /dev/tty ]; then
        read -rp "$prompt" ans < /dev/tty || true
    else
        ans="$default"
    fi
    eval "$varname=\$ans"
}

# ---------------------- Root / sudo helper ----------------------
run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        "$@"
    fi
}

# ---------------------- Kill previous bot ----------------------
kill_previous_bot() {
    if command -v pgrep >/dev/null 2>&1; then
        local PIDS
        PIDS=$(pgrep -f "$PY_SCRIPT" 2>/dev/null || true)
        if [ -n "$PIDS" ]; then
            warn "Old instance(s) running: $PIDS — killing..."
            kill $PIDS 2>/dev/null || true
            sleep 2
            local STILL
            STILL=$(pgrep -f "$PY_SCRIPT" 2>/dev/null || true)
            if [ -n "$STILL" ]; then
                kill -9 $STILL 2>/dev/null || true
            fi
            ok "Previous instance cleared."
        fi
    fi
}

# ---------------------- Detect environment ----------------------
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

# ---------------------- Ensure python ----------------------
ensure_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        log "python3 not found — installing..."
        case "$ENV_TYPE" in
            termux)  pkg install -y python ;;
            debian)  run_as_root apt-get install -y python3 ;;
            arch)    run_as_root pacman -Sy --noconfirm python ;;
            fedora)  run_as_root dnf install -y python3 ;;
            macos)   brew install python ;;
            *)       die "python3 not found. Install manually." ;;
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

# ---------------------- System packages ----------------------
install_system_deps() {
    log "Installing system dependencies..."
    case "$ENV_TYPE" in
        termux)
            pkg update -y >/dev/null 2>&1 || true
            pkg install -y python unrar p7zip clang make libffi openssl \
                python-psutil >/dev/null 2>&1 || \
                warn "Some termux packages failed"
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
            brew install python unrar p7zip >/dev/null 2>&1 || \
                warn "brew install had issues"
            ;;
        *)
            warn "Unknown OS — skipping system packages."
            ;;
    esac
    ok "System deps done."
}

# ---------------------- Python deps (robust) ----------------------
install_python_deps() {
    log "Setting up Python environment..."
    cd "$INSTALL_DIR"

    # Ensure python3-venv available
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

    # Clean broken venv
    if [ -d ".venv" ] && [ ! -f ".venv/bin/activate" ]; then
        warn "Broken .venv detected — removing."
        rm -rf .venv
    fi

    VENV_OK=0
    if [ -f ".venv/bin/activate" ]; then
        VENV_OK=1
        ok "Existing virtualenv is valid."
    else
        log "Creating virtualenv..."
        if python3 -m venv .venv 2>/dev/null && [ -f ".venv/bin/activate" ]; then
            VENV_OK=1
            ok "Virtualenv created."
        else
            warn "venv creation failed — using system pip fallback."
            rm -rf .venv
        fi
    fi

    PIP_EXTRA=""
    if [ "$VENV_OK" = "1" ]; then
        # shellcheck disable=SC1091
        source .venv/bin/activate
        PIP="pip"
        PIP_EXTRA=""
        ok "Activated virtualenv."
    elif [ "$(id -u)" -eq 0 ]; then
        PIP="pip3"
        PIP_EXTRA="--break-system-packages"
        warn "Running as root — using --break-system-packages"
    else
        PIP="pip3"
        PIP_EXTRA="--user"
        warn "Falling back to user pip"
    fi

    log "Installing Python packages (may take a few minutes)..."
    $PIP install $PIP_EXTRA --upgrade pip wheel >/dev/null 2>&1 || \
        warn "pip upgrade failed (continuing)"

    if [ "$ENV_TYPE" = "termux" ]; then
        log "Termux — using system psutil..."
        pkg install -y python-psutil >/dev/null 2>&1 || true
    fi

    $PIP install $PIP_EXTRA \
        pyzipper rarfile py7zr PyPDF2 flask python-telegram-bot \
        2>&1 | tail -3 || {
        warn "Bulk install failed. Retrying individually..."
        for pkg in pyzipper rarfile py7zr PyPDF2 flask python-telegram-bot; do
            $PIP install $PIP_EXTRA "$pkg" >/dev/null 2>&1 || \
                warn "  → Failed: $pkg"
        done
    }

    log "Verifying..."
    if [ "$VENV_OK" = "1" ]; then
        CHECK_PY=".venv/bin/python"
    else
        CHECK_PY="python3"
    fi

    MISSING=""
    for mod in pyzipper rarfile py7zr PyPDF2 flask telegram; do
        if ! $CHECK_PY -c "import $mod" 2>/dev/null; then
            MISSING="$MISSING $mod"
        fi
    done

    if [ -n "$MISSING" ]; then
        warn "Missing modules:$MISSING"
        warn "Some formats may not work, but bot should start."
    else
        ok "All Python modules verified."
    fi

    ok "Python deps done."
}

# ---------------------- Fetch script ----------------------
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

    if [ ! -f "$DICT_FILE" ]; then
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$REPO_RAW/$DICT_FILE" -o "$DICT_FILE" 2>/dev/null || true
        elif command -v wget >/dev/null 2>&1; then
            wget -q "$REPO_RAW/$DICT_FILE" -O "$DICT_FILE" 2>/dev/null || true
        fi
        [ -s "$DICT_FILE" ] && ok "$DICT_FILE downloaded." || true
    fi
}

# ---------------------- Token / .env (ROBUST) ----------------------
setup_env_file() {
    ENV_FILE="$INSTALL_DIR/.env"
    local EXISTING_TOKEN=""

    # ---- Robust extraction ----
    # Ignores: comments (#), leading/trailing spaces, quotes, CR (\r)
    if [ -f "$ENV_FILE" ]; then
        EXISTING_TOKEN=$(
            grep -E '^[[:space:]]*TELEGRAM_BOT_TOKEN[[:space:]]*=' "$ENV_FILE" 2>/dev/null \
            | grep -v '^[[:space:]]*#' \
            | head -n1 \
            | sed -E 's/^[[:space:]]*TELEGRAM_BOT_TOKEN[[:space:]]*=[[:space:]]*//' \
            | tr -d '\r\n' \
            | sed -E 's/^"(.*)"$/\1/' \
            | sed -E "s/^'(.*)'\$/\1/" \
            | xargs 2>/dev/null || true
        )
    fi

    # ---- If valid token found, offer to reuse ----
    if [ -n "$EXISTING_TOKEN" ] && [ "$EXISTING_TOKEN" != "your_token_here" ]; then
        ok "Existing token found in $ENV_FILE"
        local PREVIEW="${EXISTING_TOKEN:0:12}...${EXISTING_TOKEN: -4}"
        echo "    Preview: $PREVIEW"
        echo

        if [ -t 1 ] && { [ -t 0 ] || [ -r /dev/tty ]; }; then
            ask "Use this token? [Y/n]: " USE_EXISTING "Y"
            case "${USE_EXISTING:-Y}" in
                [Yy]*|"")
                    ok "Reusing existing token."
                    return
                    ;;
                *)
                    warn "Will ask for a new token."
                    ;;
            esac
        else
            ok "Non-interactive mode — reusing existing token."
            return
        fi
    fi

    # ---- Ask for token ----
    echo
    warn "Telegram Bot Token is REQUIRED for bot mode."
    echo "  • Get one from @BotFather → /newbot"
    echo
    ask "Paste your TELEGRAM_BOT_TOKEN: " TOKEN ""

    if [ -z "${TOKEN:-}" ]; then
        die "No token provided. Bot mode cannot start."
    fi

    umask 077
    {
        echo "# Auto-generated by install.sh"
        echo "TELEGRAM_BOT_TOKEN=$TOKEN"
    } > "$ENV_FILE"
    chmod 600 "$ENV_FILE" 2>/dev/null || true
    ok "Token saved to $ENV_FILE (permissions 600)."
}

# ---------------------- Launcher ----------------------
create_launcher() {
    LAUNCHER="$INSTALL_DIR/run.sh"
    cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# Launcher for zip_cracker (auto-kills previous instance)
cd "\$(dirname "\$0")"

SCRIPT_NAME="$PY_SCRIPT"

# Kill previous instance to avoid Telegram conflict
if command -v pgrep >/dev/null 2>&1; then
    PIDS=\$(pgrep -f "\$SCRIPT_NAME" 2>/dev/null || true)
    if [ -n "\$PIDS" ]; then
        echo "[!] Killing old instance(s): \$PIDS"
        kill \$PIDS 2>/dev/null || true
        sleep 2
        STILL=\$(pgrep -f "\$SCRIPT_NAME" 2>/dev/null || true)
        [ -n "\$STILL" ] && kill -9 \$STILL 2>/dev/null || true
    fi
fi

# Load .env
if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

# Activate venv if present
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

# ---------------------- Main ----------------------
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
    ok "Installation complete!"
    echo
    printf '%sOther commands (later):%s\n' "$BLD" "$NC"
    echo "  ${CYN}~/.zip_cracker/run.sh --web --port 5000${NC}   # web only"
    echo "  ${CYN}~/.zip_cracker/run.sh --all${NC}              # bot + web"
    echo "  ${CYN}~/.zip_cracker/run.sh archive.zip${NC}        # CLI"
    echo "  ${CYN}nano ~/.zip_cracker/.env${NC}                 # edit token"
    echo

    # Wait for Telegram to release old session
    if command -v pgrep >/dev/null 2>&1 && pgrep -f "$PY_SCRIPT" >/dev/null 2>&1; then
        warn "Waiting 10s for Telegram to release the old session..."
        sleep 10
    fi

    echo
    ok "Starting bot (Ctrl+C to stop)..."
    echo

    # Run bot in foreground
    exec "$INSTALL_DIR/run.sh" --bot
}

main "$@"
