
```markdown
# 🔓 Multi-Format Password Cracker

A powerful password cracking tool for **ZIP**, **RAR**, **7z**, and **PDF** files.  
Supports **command‑line**, **Telegram bot**, and a **web interface** – all in one script.

---

## ✨ Features

- 🔐 **Multi‑format** – Crack passwords for ZIP, RAR, 7z, and PDF files.
- 🧩 **Attack modes** – Dictionary, mask (`?u?l?l?l?d?d`), and numeric (1‑6 digits).
- 📂 **Custom dictionaries** – Upload your own `.txt` wordlist.
- 🤖 **Telegram bot** – Send files via chat, get progress updates, and receive the password.
- 🌐 **Web interface** – Upload files in your browser, track progress in real‑time.
- ⚡ **Multi‑threaded** – Uses all CPU cores for fast cracking.
- 📊 **Progress display** – Shows percentage, speed, and estimated time remaining.
- 🔄 **Auto‑status updates** – Bot sends periodic progress messages (every 5 minutes).
- 📝 **CLI mode** – Traditional command‑line usage for advanced users.

---

## 📦 Installation

### 1. Clone or download the script
Save the script as `zip_cracker.py`.

### 2. Install dependencies

```bash
# Update package manager (Termux)
pkg update && pkg upgrade

# Install required system packages (for RAR support)
pkg install unrar

# Install Python libraries
pip install pyzipper rarfile py7zr PyPDF2 flask python-telegram-bot
```

Note:

· rarfile requires unrar (non‑free) to be installed.
· If you don't need a particular format, you can skip its library – the script will show a warning.

---

🚀 Usage

1. Command‑Line Interface (CLI)

```bash
python zip_cracker.py <file.ext> [options]
```

Examples:

Command Description
python zip_cracker.py archive.zip Try password_list.txt (if present) and stop.
python zip_cracker.py archive.rar --numeric Try dictionary, then 1‑6 digit numbers.
python zip_cracker.py file.pdf -m '?u?l?l?l?d?d' Use a mask attack.
python zip_cracker.py archive.7z mydict.txt Use a custom dictionary.
python zip_cracker.py archive.zip -o /path/to/extract Specify extraction directory.

CLI options:

Option Description
-m MASK or --mask MASK Use mask attack (e.g., ?u?l?l?l?d?d).
--numeric Also try 1‑6 digit numeric after dictionary.
-o DIR or --out DIR Output directory for extracted files (default: unzipped).
YourDict.txt Use a custom dictionary file.
YourDictDirectory/ Use all .txt files inside a directory.

---

2. Telegram Bot

Start the bot with:

```bash
python zip_cracker.py --bot
```

The bot token is hardcoded in the script. You can also set it via the environment variable:

```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
python zip_cracker.py --bot
```

Bot commands:

Command Description
/start Welcome message.
/help Detailed usage instructions.
/status Show current cracking progress.
/numeric Enable numeric fallback (1‑6 digits).
/default Reset to dictionary‑only mode.

How to use:

1. Upload a dictionary file (.txt) – the bot will store it.
2. Upload your target file (ZIP, RAR, 7z, PDF).
   · Optionally, add a caption:
     · mask: ?u?l?l?l?d?d – use a mask attack.
     · dict: filename.txt – use the uploaded dictionary (must match the filename).
3. Wait for the result. The bot will reply with the password and extracted files (for ZIP only).

---

3. Web Interface

Start the web server with:

```bash
python zip_cracker.py --web --port 5000
```

Then open http://localhost:5000 (or your custom port) in a browser.

Web features:

· Upload a supported file.
· Optionally upload a dictionary (.txt).
· Set a mask or enable numeric fallback.
· Click Start Cracking – you'll be redirected to a status page that auto‑updates every 3 seconds.
· When done, the password and extracted files (if ZIP) are displayed.

---

4. Run Both Bot and Web Server Together

```bash
python zip_cracker.py --all --port 5000
```

· The web server runs in the background.
· The Telegram bot runs in the main thread (to avoid signal‑handling issues).

---

🧩 Supported Placeholders (Mask Attack)

Placeholder Meaning
?d Digit (0‑9)
?l Lowercase letter (a‑z)
?u Uppercase letter (A‑Z)
?s Symbol (e.g., !@#$)
?? Literal ?

Example mask: ?u?l?l?l?d?d generates passwords like Abc12, Xyz99, etc.

---

📁 Dictionary Format

· Plain text file (.txt).
· One password per line.
· UTF‑8 encoding is recommended.

---

⚠️ Troubleshooting

Problem Solution
rarfile errors Install unrar (Termux: pkg install unrar).
Bot doesn't start Ensure python-telegram-bot is installed.
Web interface not loading Check that Flask is installed and the port is free.
set_wakeup_fd error The bot must run in the main thread – use --all or --bot without threading.
Large files (>50 MB) Telegram has a 50 MB limit – use the web interface or CLI for large files.

---

🛠️ Development & Customization

· Add new formats: Extend the FormatCrackerFactory and implement a new verify_password method.
· Change default dictionary: Replace password_list.txt in the same directory.
· Adjust auto‑status interval: Modify asyncio.sleep(300) (in seconds) inside handle_document.

---

📄 License

This project is open‑source and available under the MIT License.

---

🙏 Credits

Coded by rebnX – enhanced with multi‑format, bot, and web support.
