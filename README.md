<div align="center">

# 🔓 telegram-bot-zip

**Multi-Format Password Cracker — ZIP · RAR · 7z · PDF**

Telegram Bot · Web Interface · Command Line — all in one tool

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20macOS-orange)]()
[![Telegram](https://img.shields.io/badge/Telegram-Bot-blue?logo=telegram)](https://t.me/BotFather)

</div>

---

## 📖 Overview

`telegram-bot-zip` is a powerful, multi-format password recovery tool that works across **Termux**, **Linux**, and **macOS**. It bundles three interfaces into a single script:

- 🖥️ **Command Line Interface (CLI)** — for automation and scripting
- 🌐 **Web Interface** — for browser-based use
- 🤖 **Telegram Bot** — for remote cracking from anywhere

Whether you've forgotten a password on your own archive or need to test the strength of your files, this tool handles it — quickly, safely, and with full transparency.

---

## ✨ Features

### 🔐 Multi-Format Support

| Format | Cracking | Auto-Extract | Library |
|--------|:--------:|:------------:|---------|
| **ZIP** | ✅ | ✅ | `pyzipper` / `zipfile` |
| **RAR** | ✅ | ✅ | `rarfile` + `unrar` |
| **7z** | ✅ | ✅ | `py7zr` |
| **PDF** | ✅ | — | `PyPDF2` |

### 🧩 Attack Modes

- **Dictionary Attack** — Try passwords from a `.txt` wordlist
- **Mask Attack** — Pattern-based (e.g., `?u?l?l?l?d?d` → `Abcd12`)
- **Numeric Attack** — Brute-force 1-6 digit PINs
- **CRC32 Collision** — Instant recovery for tiny ZIP files (≤3 bytes)
- **Pseudo-Encryption Fix** — Auto-detects fake ZIP encryption

### ⚡ Performance

- Multi-threaded (uses all CPU cores)
- Chunked processing (memory-safe for large dictionaries)
- Lazy numeric generation (never loads full space into RAM)
- Real-time progress with speed & ETA

### 🛡️ Security Hardened

- No hardcoded secrets — token via environment variable
- Path-traversal protection on all uploads
- `.env` file with `chmod 600` permissions
- Unique temp filenames (no race conditions)
- Auto-cleanup of temp files after inactivity

### 🎨 Three Interfaces

| Interface | Best For | Start Command |
|-----------|----------|---------------|
| CLI | Scripting, servers | `run.sh archive.zip` |
| Web | Browser users, remote | `run.sh --web` |
| Bot | Mobile, remote | `run.sh --bot` |

---

## 🚀 Installation

### One-Line Install (Recommended)

Works on **Termux**, **Debian/Ubuntu/Kali**, **Arch/Manjaro**, **Fedora**, and **macOS**:

```bash
curl -fsSL https://raw.githubusercontent.com/NRXQuantum/telegram-bot-zip/main/install.sh | bash
```

The installer will:

1. 🔍 Detect your operating system
2. 📦 Install system dependencies (`unrar`, `p7zip`, Python, compilers)
3. 🐍 Create a Python virtual environment
4. 📥 Download `zip_cracker.py` and the built-in dictionary
5. 🔑 Ask for your Telegram Bot Token (optional)
6. 🎯 Create a launcher (`run.sh`)
7. ▶️ Optionally start in `--all` mode (bot + web)

**After installation, run:**

```bash
~/.zip_cracker/run.sh --all --port 5000
```

### Manual Installation

If you prefer full control:

```bash
# 1. Clone
git clone https://github.com/NRXQuantum/telegram-bot-zip.git
cd telegram-bot-zip

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Python packages
pip install -r requirements.txt

# 4. (Termux only) Install psutil from pkg to avoid build errors
pkg install python-psutil -y

# 5. Run
python zip_cracker.py --help
```

### Termux Extra Step

Termux users **must** install `python-psutil` via pkg (Python 3.14 has a known build issue):

```bash
pkg install python-psutil -y
```

---

## 🔑 Telegram Bot Token Setup

The bot requires a token from [@BotFather](https://t.me/BotFather).

### Getting a Token

1. Open Telegram → search `@BotFather`
2. Send `/newbot`
3. Choose a name and username
4. Copy the token (format: `1234567890:ABCdef...`)

### Where the Token Lives

| Item | Value |
|------|-------|
| **File path** | `~/.zip_cracker/.env` |
| **Format** | `TELEGRAM_BOT_TOKEN=123456:ABC...` |
| **Permissions** | `600` (owner-only read/write) |
| **Edit manually** | `nano ~/.zip_cracker/.env` |

The installer writes it automatically. To change later:

```bash
nano ~/.zip_cracker/.env
# Replace the token, save (Ctrl+O, Enter, Ctrl+X)
```

### Revoking a Leaked Token

If your token is ever exposed:

1. Open `@BotFather` → `/mybots`
2. Select your bot → **API Token** → **Revoke current token**
3. Copy the new token into `~/.zip_cracker/.env`

---

## 🎮 Usage

### 🖥️ CLI Mode

```bash
run.sh <file> [options]
```

**Examples:**

```bash
# Built-in dictionary
run.sh archive.zip

# Custom dictionary
run.sh archive.rar mydict.txt

# Mask attack
run.sh file.pdf -m '?u?l?l?l?d?d'

# Numeric fallback after dictionary
run.sh archive.7z --numeric

# Custom output dir, 8 threads, no extraction
run.sh archive.zip -o /tmp/out --threads 8 --no-extract
```

**All CLI Options:**

| Option | Description |
|--------|-------------|
| `-m, --mask MASK` | Mask attack pattern |
| `--numeric` | Also try 1-6 digit numbers |
| `-o, --out DIR` | Output directory (default: `unzipped`) |
| `--threads N` | Worker threads (default: auto) |
| `--no-extract` | Find password only, skip extraction |
| `--log FILE` | Also write logs to a file |
| `YourDict.txt` | Custom dictionary path |
| `YourDictDir/` | Directory of `.txt` dictionaries |

### 🌐 Web Interface

```bash
run.sh --web --port 5000
```

Then open **http://localhost:5000** in a browser.

**Features:**

- Drag-and-drop file upload
- Optional custom dictionary
- Mask / numeric / thread controls
- Real-time progress updates (every 3 seconds)
- Auto-download of extracted files

> ⚠️ **Security warning:** The web server binds to `0.0.0.0`. Do not expose it to the public internet without a reverse proxy and authentication.

### 🤖 Telegram Bot

```bash
run.sh --bot
```

**Bot Commands:**

| Command | Description |
|---------|-------------|
| `/start` | Welcome message |
| `/help` | Detailed usage guide |
| `/status` | Show current cracking progress |
| `/numeric` | Enable numeric fallback (1-6 digits) |
| `/default` | Reset to dictionary-only mode |

**How to Use the Bot:**

1. Send a `.txt` file → saved as your custom dictionary
2. Send a target file (ZIP / RAR / 7z / PDF)
3. Optionally add a caption:
   - `mask: ?u?l?l?l?d?d` → use mask attack
   - `dict: mylist.txt` → use uploaded dictionary
4. Wait — the bot auto-updates every 5 minutes
5. Receive the password (and extracted files for archives)

### 🎯 Run Bot + Web Together

```bash
run.sh --all --port 5000
```

- Web server runs in a background thread
- Telegram bot runs in the main thread (required for signal handling)
- Both share the same codebase and configuration

---

## 🧩 Mask Attack Reference

| Placeholder | Meaning | Example |
|-------------|---------|---------|
| `?d` | Digit (0-9) | `7` |
| `?l` | Lowercase letter (a-z) | `k` |
| `?u` | Uppercase letter (A-Z) | `R` |
| `?s` | Symbol | `@` |
| `??` | Literal `?` | `?` |

**Example mask:** `?u?l?l?l?d?d` → `Abcd12`, `Xyz99`, `Klm42` ...

**Estimate combinations:**

```
?d?d?d?d          → 10,000
?l?l?l?l          → 456,976
?u?l?l?l?d?d      → 45,697,600
?s?s?s?s          → 4,096
```

Use [this formula](https://en.wikipedia.org/wiki/Rule_of_product) for custom masks.

---

## 📁 Dictionary Format

- Plain text file (`.txt`)
- One password per line
- UTF-8 encoding recommended
- Blank lines and whitespace are ignored

**Sample `password_list.txt`:**

```
123456
password
admin
letmein
qwerty
```

---

## 🛠️ Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `psutil build failed` | Python 3.14 + Termux | `pkg install python-psutil -y` |
| `rarfile errors` | `unrar` not installed | `pkg install unrar` (Termux) |
| `Bot doesn't start` | Missing token or library | Check `~/.zip_cracker/.env` and `pip list` |
| `Web interface blank` | Flask missing | `pip install flask` |
| `set_wakeup_fd error` | Bot not in main thread | Use `--all` or `--bot` alone |
| `Large files fail on bot` | Telegram 50 MB limit | Use web interface or CLI |
| `Permission denied on .env` | Wrong ownership | `chmod 600 ~/.zip_cracker/.env` |
| `404 on install.sh` | Repo private or file missing | Make repo public, push `install.sh` |
| `Command 'python' not found` | Only `python3` installed | Use `python3` or install `python` |

---

## 🔐 Security Notes

This tool is designed with security in mind. Please follow these rules:

### ✅ Do

- Keep `~/.zip_cracker/.env` at `chmod 600`
- Revoke tokens immediately if leaked
- Run behind a firewall if exposing the web UI
- Use only on files you own

### ❌ Don't

- Commit `.env` to Git (`.gitignore` already blocks it)
- Expose the web server to the public internet without auth
- Share your bot token with anyone
- Use this tool on files you don't own — it's illegal in most jurisdictions

### Hardening Checklist

- [ ] `.env` is in `.gitignore`
- [ ] Token uses `chmod 600`
- [ ] Web server behind reverse proxy (nginx/Caddy)
- [ ] Regular `@BotFather` token rotation
- [ ] HTTPS for web UI (use Caddy for auto-TLS)

---

## ⚠️ Legal Disclaimer

> **This tool is intended for legitimate password recovery on files you own.**
>
> Unauthorized access to protected files is illegal in most countries and
> violates computer-misuse laws. The author assumes no liability for misuse.
>
> **You are solely responsible for how you use this software.**

---

## 🏗️ Project Structure

```
telegram-bot-zip/
├── install.sh            # One-line installer
├── zip_cracker.py        # Main application
├── requirements.txt      # Python dependencies
├── password_list.txt     # Built-in dictionary
├── .gitignore            # Git exclusions
├── .env.example          # Token template
├── README.md             # This file
└── LICENSE               # MIT
```

---

## 🔧 Development

### Adding a New Format

1. Implement `_xxx_verify(file_path, password) -> bool`
2. Register it in `FormatCrackerFactory.get_cracker()`
3. (Optional) Add extraction in `AttackEngine._extract()`

### Adjusting Auto-Status Interval

In `zip_cracker.py`, find:

```python
await asyncio.sleep(300)   # 5 minutes
```

Change to your preferred interval in seconds.

### Changing Thread Count

```bash
run.sh archive.zip --threads 16
```

Or set a default in `AttackEngine._calculate_threads()`.

---

## 🤝 Contributing

Pull requests welcome! For major changes, please open an issue first.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing`)
5. Open a Pull Request

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Credits

- **Coded by** [rebnX](https://github.com/rebnX)
- Extended with Web + Bot support
- Enhanced & security-hardened by community contributors
- Icons by [Shields.io](https://shields.io)

---

<div align="center">

**⭐ If this tool helped you, star the repo!**

[Report Bug](https://github.com/NRXQuantum/telegram-bot-zip/issues) · [Request Feature](https://github.com/NRXQuantum/telegram-bot-zip/issues)

</div>
