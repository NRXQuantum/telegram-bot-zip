"""
Telegram Bot Configuration
==========================
এই ফাইলে আপনার bot টোকেন বসান।
BotFather (@BotFather on Telegram) থেকে টোকেন নিন।

Format: "<bot_id>:<random_string>"
Example: "1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ"
"""

# === REQUIRED ===
TELEGRAM_BOT_TOKEN = "8840306599:AAGQsAzRhftywjWELB6NNX1xc5jMvWOkG4Y"


# === OPTIONAL SETTINGS ===
DEFAULT_PORT = 5000          # Web server port
MAX_WORKERS = 128            # Max cracking threads
MAX_CRC_FILE_SIZE = 3        # CRC attack limit (bytes)
MASK_CHUNK_SIZE = 100000     # Chunk size for mask attacks
CLEANUP_INTERVAL = 3600      # Cleanup check (seconds)
IDLE_TIMEOUT = 3600          # Idle time before cleanup (seconds)
JOB_TTL = 3600               # Web job keep-alive (seconds)
