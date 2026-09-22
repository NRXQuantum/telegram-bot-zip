#!/usr/bin/env bash
# ============================================================
#  Multi-Format Password Cracker — One-Line Installer
#  Repo: https://github.com/NRXQuantum/telegram-bot-zip
#
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/NRXQuantum/telegram-bot-zip/main/install.sh | bash
# ============================================================
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/NRXQuantum/telegram-bot-zip/main"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.zip_cracker}"
PORT="${PORT:-5000}"
PY_SCRIPT="zip_cracker.py"

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
    elif [ -r /dev/tty ]; then
        read -rp "$prompt" ans < /dev/tty || true
    else
        ans="$default"
    fi
    eval "$varname=\$ans"
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
}

ensure_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        case "$ENV_TYPE" in
            termux)  pkg install -y python ;;
            debian)  sudo apt-get install -y python3 ;;
            arch)    sudo pacman -Sy --noconfirm python ;;
            fedora)  sudo dnf install -y python3 ;;
            macos)   brew install python ;;
            *)       die "python3 not found. Install it manually." ;;
        esac
    fi
    ok "Python: $(python3 --version 2>&1)"
}

install_system_deps() {
    log "Installing system dependencies..."
    case "$ENV_TYPE" in
        termux)
            pkg update -y >/dev/null 2>&1 || true
            pkg install -y python unrar p7zip clang make libffi openssl \
                >/dev/null 2>&1 || warn "Some termux packages failed"
            ;;
        debian)
            sudo apt-get update -y >/dev/null 2>&1 || true
            sudo apt-get install -y python3 python3-venv python3-pip \
                unrar-free p7zip-full build-essential libffi-dev libssl-dev \
                >/dev/null 2>&1 || warn "Some apt packages failed"
            ;;
        arch)
            sudo pacman -Sy --noconfirm python python-pip unrar p7zip base-devel \
                >/dev/null 2>&1 || warn "Some pacman packages failed"
            ;;
        fedora)
            sudo dnf install -y python3 python3-pip unrar p7zip p7zip-plugins \
                gcc libffi-devel openssl-devel >/dev/null 2>&1 || \
                warn "Some dnf packages failed"
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

install_python_deps() {
    log "Setting up Python virtualenv at $INSTALL_DIR/.venv ..."
    cd "$INSTALL_DIR"

    if [ ! -d ".venv" ]; then
        python3 -m venv .venv 2>/dev/null || {
            warn "venv failed — falling back to user pip"
            PIP="pip3 install --user"
        }
    fi

    if [ -d ".venv" ]; then
        # shellcheck disable=SC1091
        source .venv/bin/activate
        PIP="pip"
    fi

    log "Installing Python packages (may take a few minutes)..."
    $PIP install --upgrade pip wheel >/dev/null 2>&1 || true
    $PIP install pyzipper rarfile py7zr PyPDF2 flask python-telegram-bot \
        2>&1 | tail -3
    ok "Python deps installed."
}

fetch_script() {
    cd "$INSTALL_DIR"
    if [ -f "$PY_SCRIPT" ]; then
        ok "$PY_SCRIPT already present — keeping it."
        return
    fi
    log "Downloading $PY_SCRIPT ..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$REPO_RAW/$PY_SCRIPT" -o "$PY_SCRIPT"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$REPO_RAW/$PY_SCRIPT" -O "$PY_SCRIPT"
    else
        die "Neither curl nor wget found."
    fi
    [ -s "$PY_SCRIPT" ] || die "Download failed or empty file."
    ok "$PY_SCRIPT downloaded."

    # Optional: built-in dictionary
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$REPO_RAW/password_list.txt" -o password_list.txt 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$REPO_RAW/password_list.txt" -O password_list.txt 2>/dev/null || true
    fi
    [ -s password_list.txt ] && ok "password_list.txt downloaded." || true
}

setup_env_file() {
    ENV_FILE="$INSTALL_DIR/.env"

    if [ -f "$ENV_FILE" ] && grep -q '^TELEGRAM_BOT_TOKEN=' "$ENV_FILE" 2>/dev/null; then
        ok "Existing .env found at $ENV_FILE — reusing token."
        return
    fi

    echo
    warn "Telegram Bot Token is required for --all / --bot mode."
    echo "  • Get one from @BotFather → /newbot"
    echo "  • Leave blank to run web-only mode."
    echo

    ask "Paste your TELEGRAM_BOT_TOKEN (or blank): " TOKEN ""

    if [ -n "${TOKEN:-}" ]; then
        umask 077
        {
            echo "# Auto-generated by install.sh"
            echo "TELEGRAM_BOT_TOKEN=$TOKEN"
        } > "$ENV_FILE"
        chmod 600 "$ENV_FILE" 2>/dev/null || true
        ok "Token saved to $ENV_FILE (permissions 600)."
    else
        warn "No token provided — will run web-only mode."
        umask 077
        {
            echo "# Auto-generated by install.sh"
            echo "# TELEGRAM_BOT_TOKEN=your_token_here"
        } > "$ENV_FILE"
        chmod 600 "$ENV_FILE" 2>/dev/null || true
    fi
}

create_launcher() {
    LAUNCHER="$INSTALL_DIR/run.sh"
    cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
cd "\$(dirname "\$0")"
if [ -f ".env" ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi
if [ -d ".venv" ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
fi
exec python $PY_SCRIPT "\$@"
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

    fetch_script
    install_python_deps
    setup_env_file
    create_launcher

    echo
    ok "Installation complete!"
    echo
    echo "${BLD}Next steps:${NC}"
    echo "  ${CYN}cd $INSTALL_DIR${NC}"
    echo "  ${CYN}./run.sh --all --port $PORT${NC}    # bot + web"
    echo "  ${CYN}./run.sh --web --port $PORT${NC}    # web only"
    echo "  ${CYN}./run.sh --bot${NC}                 # bot only"
    echo "  ${CYN}./run.sh archive.zip${NC}            # CLI"
    echo
    echo "Edit token anytime: ${CYN}nano $INSTALL_DIR/.env${NC}"
    echo

    if [ -t 1 ] && { [ -t 0 ] || [ -r /dev/tty ]; }; then
        ask "Start now with --all --port $PORT ? [Y/n]: " START "Y"
        case "${START:-Y}" in
            [Yy]*|"")
                echo
                ok "Starting cracker (Ctrl+C to stop)..."
                exec "$INSTALL_DIR/run.sh" --all --port "$PORT"
                ;;
            *)
                ok "Run manually later: $INSTALL_DIR/run.sh --all"
                ;;
        esac
    fi
}

main "$@"