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
PORT="${PORT:-5000}"
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

# ---------------------- Interactive ask (works via curl | bash) ----------------------
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

# ---------------------- Root / sudo detection ----------------------
# Colab and Docker containers run as root with no sudo.
run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        "$@"
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

    # Warn if Colab
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
            *)       die "python3 not found. Install it manually." ;;
        esac
    fi
    ok "Python: $(python3 --version 2>&1)"

    # Ensure pip module
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

# ---------------------- Install system packages ----------------------
install_system_deps() {
    log "Installing system dependencies..."
    case "$ENV_TYPE" in
        termux)
            pkg update -y >/dev/null 2>&1 || true
            pkg install -y python unrar p7zip clang make libffi openssl \
                python-psutil >/dev/null 2>&1 || \
                warn "Some termux packages failed (continuing)"
            ;;
        debian)
            # Colab-এ apt-get সরাসরি চলে; অন্যথায় sudo লাগবে
            run_as_root apt-get update -qq >/dev/null 2>&1 || true
            run_as_root apt-get install -y \
                python3 python3-venv python3-pip \
                unrar-free p7zip-full build-essential \
                libffi-dev libssl-dev python3-dev \
                >/dev/null 2>&1 || \
                warn "Some apt packages failed (continuing)"
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

# ---------------------- Python venv + packages (FIXED) ----------------------
install_python_deps() {
    log "Setting up Python environment..."
    cd "$INSTALL_DIR"

    # ---- Step 1: Ensure python3-venv is available ----
    if ! python3 -m venv --help >/dev/null 2>&1; then
        warn "python3-venv module missing — attempting install..."
        case "$ENV_TYPE" in
            termux)  pkg install -y python ;;
            debian)  run_as_root apt-get install -y python3-venv || true ;;
            arch)    run_as_root pacman -Sy --noconfirm python || true ;;
            fedora)  run_as_root dnf install -y python3 || true ;;
            macos)   brew install python || true ;;
            *)       warn "Cannot install python3-venv automatically" ;;
        esac
    fi

    # ---- Step 2: Detect & clean broken venv ----
    if [ -d ".venv" ] && [ ! -f ".venv/bin/activate" ]; then
        warn "Broken .venv detected (missing activate) — removing."
        rm -rf .venv
    fi

    # ---- Step 3: Try to create venv ----
    VENV_OK=0
    if [ -f ".venv/bin/activate" ]; then
        VENV_OK=1
        ok "Existing valid virtualenv found."
    else
        log "Creating virtualenv at .venv ..."
        if python3 -m venv .venv 2>/dev/null && [ -f ".venv/bin/activate" ]; then
            VENV_OK=1
            ok "Virtualenv created."
        else
            warn "venv creation failed — using system pip fallback."
            rm -rf .venv
        fi
    fi

    # ---- Step 4: Choose pip strategy ----
    PIP_EXTRA=""
    if [ "$VENV_OK" = "1" ]; then
        # shellcheck disable=SC1091
        source .venv/bin/activate
        PIP="pip"
        PIP_EXTRA=""
        ok "Activated virtualenv."
    elif [ "$(id -u)" -eq 0 ]; then
        # Root (Colab/Docker) — bypass PEP 668
        PIP="pip3"
        PIP_EXTRA="--break-system-packages"
        warn "Running as root — using --break-system-packages"
    else
        # Normal user
        PIP="pip3"
        PIP_EXTRA="--user"
        warn "Falling back to user-level pip install"
    fi

    # ---- Step 5: Install packages ----
    log "Installing Python packages (this may take a few minutes)..."

    # Upgrade pip / wheel (best-effort)
    $PIP install $PIP_EXTRA --upgrade pip wheel >/dev/null 2>&1 || \
        warn "pip upgrade failed (continuing)"

    # Termux: use pkg-provided psutil to avoid build errors
    if [ "$ENV_TYPE" = "termux" ]; then
        log "Termux detected — using system psutil..."
        pkg install -y python-psutil >/dev/null 2>&1 || true
        # If venv, link system psutil into venv
        if [ "$VENV_OK" = "1" ]; then
            SYSTEM_SITE=$(python3 -c "import sysconfig; print(sysconfig.get_paths()['purelib'])" 2>/dev/null || true)
            if [ -d "$SYSTEM_SITE/psutil" ]; then
                cp -r "$SYSTEM_SITE/psutil" .venv/lib/python*/site-packages/ 2>/dev/null || true
            fi
        fi
    fi

    # Core packages
    $PIP install $PIP_EXTRA \
        pyzipper rarfile py7zr PyPDF2 flask python-telegram-bot \
        2>&1 | tail -3 || {
        warn "Some packages failed. Retrying individually..."
        for pkg in pyzipper rarfile py7zr PyPDF2 flask python-telegram-bot; do
            $PIP install $PIP_EXTRA "$pkg" >/dev/null 2>&1 || \
                warn "  → Failed: $pkg"
        done
    }

    # ---- Step 6: Verify ----
    log "Verifying installation..."
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
        warn "The tool will still run, but those formats may be unavailable."
    else
        ok "All Python modules verified."
    fi

    ok "Python deps done."
}

# ---------------------- Download main script ----------------------
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
        [ -s "$PY_SCRIPT" ] || die "Download failed or empty file."
        ok "$PY_SCRIPT downloaded."
    else
        ok "$PY_SCRIPT already present — keeping it."
    fi

    # Optional: built-in dictionary
    if [ ! -f "$DICT_FILE" ]; then
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$REPO_RAW/$DICT_FILE" -o "$DICT_FILE" 2>/dev/null || true
        elif command -v wget >/dev/null 2>&1; then
            wget -q "$REPO_RAW/$DICT_FILE" -O "$DICT_FILE" 2>/dev/null || true
        fi
        [ -s "$DICT_FILE" ] && ok "$DICT_FILE downloaded." || true
    fi
}

# ---------------------- .env / token ----------------------
setup_env_file() {
    ENV_FILE="$INSTALL_DIR/.env"

    if [ -f "$ENV_FILE" ] && grep -q '^TELEGRAM_BOT_TOKEN=' "$ENV_FILE" 2>/dev/null; then
        ok "Existing .env found — reusing token."
        return
    fi

    echo
    warn "Telegram Bot Token is required for --all / --bot mode."
    echo "  • Get one from @BotFather → /newbot"
    echo "  • Leave blank to run web-only mode."
    echo

    ask "Paste your TELEGRAM_BOT_TOKEN (or blank): " TOKEN ""

    umask 077
    if [ -n "${TOKEN:-}" ]; then
        {
            echo "# Auto-generated by install.sh"
            echo "TELEGRAM_BOT_TOKEN=$TOKEN"
        } > "$ENV_FILE"
        chmod 600 "$ENV_FILE" 2>/dev/null || true
        ok "Token saved to $ENV_FILE (permissions 600)."
    else
        {
            echo "# Auto-generated by install.sh"
            echo "# TELEGRAM_BOT_TOKEN=your_token_here"
        } > "$ENV_FILE"
        chmod 600 "$ENV_FILE" 2>/dev/null || true
        warn "No token — will run in web-only mode."
    fi
}

# ---------------------- Launcher wrapper ----------------------
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

if [ -f ".venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
    exec python $PY_SCRIPT "\$@"
else
    exec python3 $PY_SCRIPT "\$@"
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

    fetch_script
    install_python_deps
    setup_env_file
    create_launcher

    echo
    ok "Installation complete!"
    echo
    printf '%sNext steps:%s\n' "$BLD" "$NC"
    echo "  ${CYN}cd $INSTALL_DIR${NC}"
    echo "  ${CYN}./run.sh --all --port $PORT${NC}    # bot + web"
    echo "  ${CYN}./run.sh --web --port $PORT${NC}    # web only"
    echo "  ${CYN}./run.sh --bot${NC}                 # bot only"
    echo "  ${CYN}./run.sh archive.zip${NC}            # CLI"
    echo
    echo "Edit token: ${CYN}nano $INSTALL_DIR/.env${NC}"
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
                ok "Start manually later: $INSTALL_DIR/run.sh --all"
                ;;
        esac
    fi
}

main "$@"
