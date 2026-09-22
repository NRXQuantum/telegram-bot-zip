#!/usr/bin/env python3
"""
Multi-Format Password Cracker (ZIP / RAR / 7z / PDF)
Modes: CLI, Telegram Bot, Web Interface
Coded by rebnX — Extended + Security Hardened
"""

import os
import sys
import shutil
import signal
import logging
import threading
import time
import zipfile
import binascii
import string
import itertools
import multiprocessing
import asyncio
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Tuple, Dict, Generator, Callable, Any

# ============================== Optional: Flask ============================
try:
    from flask import Flask, request, render_template_string, jsonify, redirect, url_for
    from werkzeug.utils import secure_filename
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = None
    def secure_filename(name: str) -> str:
        name = (name or "").replace("\x00", "")
        name = os.path.basename(name)
        name = name.replace("/", "_").replace("\\", "_").strip().lstrip(".")
        return name or "upload"

# ============================== Optional: Telegram ============================
try:
    from telegram import Update
    from telegram.ext import (
        Application, CommandHandler, MessageHandler, filters, ContextTypes
    )
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

# ============================== Optional: archive libs ============================
try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    pyzipper = None
    HAS_PYZIPPER = False

try:
    import rarfile
    HAS_RARFILE = True
except ImportError:
    rarfile = None
    HAS_RARFILE = False

try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    py7zr = None
    HAS_PY7ZR = False

try:
    import PyPDF2
    HAS_PYPDF2 = True
except ImportError:
    PyPDF2 = None
    HAS_PYPDF2 = False

# ============================== Constants ============================
OUT_DIR_DEFAULT = "unzipped"
MAX_CRC_FILE_SIZE = 3
CHUNK_SIZE = 1_000_000
MASK_CHUNK_SIZE = 100_000
MAX_MASK_COMBINATIONS = 100_000_000_000

CHARSET_DIGITS = string.digits
CHARSET_LOWER = string.ascii_lowercase
CHARSET_UPPER = string.ascii_uppercase
CHARSET_SYMBOLS = string.punctuation

MASK_PLACEHOLDERS = {
    'd': CHARSET_DIGITS,
    'l': CHARSET_LOWER,
    'u': CHARSET_UPPER,
    's': CHARSET_SYMBOLS,
    '?': '?',
}

SUPPORTED_EXTS = {'.zip', '.rar', '.7z', '.pdf'}

# ============================== Logging ============================
logger = logging.getLogger("zip_cracker")

def setup_logging(log_file: Optional[str] = None) -> None:
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(threadName)s: %(message)s"))
        logger.addHandler(fh)

def log_info(msg: str) -> None:
    logger.info(msg)

def log_error(msg: str) -> None:
    logger.error(msg)

# ============================== .env auto-loader ============================
def _load_dotenv() -> None:
    """Load key=value pairs from .env (script-dir or ~/.zip_cracker/.env)."""
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        os.path.expanduser("~/.zip_cracker/.env"),
    ]
    for env_path in candidates:
        if not os.path.isfile(env_path):
            continue
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key and val and key not in os.environ:
                        os.environ[key] = val
            return
        except Exception:
            continue

def _get_bot_token() -> str:
    """Return TELEGRAM_BOT_TOKEN or exit with a clear message."""
    _load_dotenv()
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    if not token or token == "PASTE_YOUR_TOKEN_HERE":
        log_error(
            "[!] TELEGRAM_BOT_TOKEN not set.\n"
            "    Create ~/.zip_cracker/.env with:\n"
            "        TELEGRAM_BOT_TOKEN=your_bot_token_here\n"
            "    Or set env var:\n"
            "        export TELEGRAM_BOT_TOKEN=your_bot_token_here"
        )
        sys.exit(1)
    return token

def _validate_bot_token(token: str) -> Optional[str]:
    """Return bot username if token valid, else None."""
    try:
        import urllib.request as _u
        import json as _j
        r = _j.loads(_u.urlopen(
            f"https://api.telegram.org/bot{token}/getMe", timeout=10).read())
        if r.get("ok"):
            return r["result"]["username"]
    except Exception as e:
        log_info(f"[!] Token validation failed: {e}")
    return None

# ============================== Exceptions ============================
class CrackerError(Exception): pass
class DictionaryError(CrackerError): pass
class UnsupportedFormatError(CrackerError): pass
class MissingLibraryError(CrackerError): pass

# ============================== Cleanup ============================
CLEANUP_INTERVAL = 3600
IDLE_TIMEOUT = 3600
last_activity_time = time.time()
cleanup_lock = threading.Lock()

def update_activity() -> None:
    global last_activity_time
    with cleanup_lock:
        last_activity_time = time.time()

def cleanup_old_temp_dirs() -> None:
    now = time.time()
    try:
        for item in os.listdir('.'):
            if item.startswith('temp_') and os.path.isdir(item):
                path = os.path.abspath(item)
                try:
                    if now - os.path.getmtime(path) > 7200:
                        shutil.rmtree(path, ignore_errors=True)
                except OSError:
                    pass
    except OSError:
        pass

    sys_temp = tempfile.gettempdir()
    try:
        for item in os.listdir(sys_temp):
            if item.startswith('web_job_'):
                path = os.path.join(sys_temp, item)
                if os.path.isdir(path):
                    try:
                        if now - os.path.getmtime(path) > 7200:
                            shutil.rmtree(path, ignore_errors=True)
                    except OSError:
                        pass
    except OSError:
        pass

    try:
        for f in os.listdir('.'):
            if f.endswith('.fixed.tmp') and os.path.isfile(f):
                try:
                    os.remove(f)
                except OSError:
                    pass
    except OSError:
        pass

def cleanup_worker() -> None:
    while True:
        time.sleep(CLEANUP_INTERVAL)
        with cleanup_lock:
            idle = time.time() - last_activity_time
        if idle > IDLE_TIMEOUT:
            try:
                cleanup_old_temp_dirs()
            except Exception:
                pass

# ============================== Helpers ============================
def safe_name(name: str) -> str:
    if not name:
        return "upload"
    name = name.replace("\x00", "")
    name = os.path.basename(name)
    name = name.replace("/", "_").replace("\\", "_").strip().lstrip(".")
    return name or "upload"

def safe_ext(name: str) -> str:
    return os.path.splitext(safe_name(name))[1].lower()

# ============================== ZIP checkers ============================
class ZipEncryptionChecker:
    @staticmethod
    def is_encrypted(file_path: str) -> bool:
        try:
            with zipfile.ZipFile(file_path) as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        return True
            return False
        except Exception:
            return False

    @staticmethod
    def fix_pseudo_encryption(file_path: str, temp_path: str) -> None:
        with zipfile.ZipFile(file_path) as source_zf, \
             zipfile.ZipFile(temp_path, "w") as target_zf:
            for info in source_zf.infolist():
                clean_info = info
                if clean_info.flag_bits & 0x1:
                    clean_info.flag_bits ^= 0x1
                target_zf.writestr(clean_info, source_zf.read(info.filename))

# ============================== CRC ============================
class CRCCracker:
    @staticmethod
    def analyze_zip(zip_file, zf, callback=None) -> bool:
        small = [info for info in zf.infolist()
                 if not info.filename.endswith('/')
                 and 0 < info.file_size <= MAX_CRC_FILE_SIZE]
        if not small:
            return False
        cracked = 0
        for info in small:
            if callback:
                callback(f'[!] CRC: "{info.filename}" ({info.file_size}b)')
            if CRCCracker.crack(info.filename, info.CRC, info.file_size, callback):
                cracked += 1
        return cracked == len(small)

    @staticmethod
    def crack(filename, target_crc, size, callback=None) -> bool:
        if size > MAX_CRC_FILE_SIZE:
            return False
        for combo in itertools.product(string.printable, repeat=size):
            content = ''.join(combo).encode()
            if binascii.crc32(content) == target_crc:
                if callback:
                    callback(f"[*] CRC cracked: {content.decode(errors='replace')}")
                return True
        return False

# ============================== ZIP extract ============================
def find_first_file(zf) -> Optional[str]:
    try:
        for info in zf.infolist():
            if not info.filename.endswith('/'):
                return info.filename
    except Exception:
        pass
    try:
        for name in zf.namelist():
            if not name.endswith('/'):
                return name
    except Exception:
        pass
    return None

class PasswordCracker:
    def __init__(self, zip_file: str, out_dir: str):
        self.zip_file = zip_file
        self.out_dir = out_dir

    def extract(self, password: str, callback=None) -> List[str]:
        pwd_bytes = password.encode('utf-8')
        if os.path.exists(self.out_dir):
            shutil.rmtree(self.out_dir, ignore_errors=True)
        os.makedirs(self.out_dir, exist_ok=True)
        if HAS_PYZIPPER:
            with pyzipper.AESZipFile(self.zip_file, 'r') as zf:
                zf.extractall(path=self.out_dir, pwd=pwd_bytes)
                names = zf.namelist()
        else:
            with zipfile.ZipFile(self.zip_file, 'r') as zf:
                zf.extractall(path=self.out_dir, pwd=pwd_bytes)
                names = zf.namelist()
        if callback:
            callback(f"[*] Extracted {len(names)} file(s)")
        return names

# ============================== Format crackers ============================
def _zip_verify(file_path, password) -> bool:
    pwd_bytes = password.encode('utf-8')
    try:
        if HAS_PYZIPPER:
            with pyzipper.AESZipFile(file_path, 'r') as zf:
                first = find_first_file(zf)
                if first:
                    zf.read(first, pwd=pwd_bytes)
                else:
                    zf.testzip(pwd=pwd_bytes)
        else:
            with zipfile.ZipFile(file_path, 'r') as zf:
                first = find_first_file(zf)
                if first:
                    zf.read(first, pwd=pwd_bytes)
                else:
                    zf.testzip(pwd=pwd_bytes)
        return True
    except Exception:
        return False

def _rar_verify(file_path, password) -> bool:
    if not HAS_RARFILE:
        raise MissingLibraryError("rarfile not installed")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            with rarfile.RarFile(file_path) as rf:
                rf.extractall(path=tmpdir, pwd=password)
        return True
    except Exception:
        return False

def _7z_verify(file_path, password) -> bool:
    if not HAS_PY7ZR:
        raise MissingLibraryError("py7zr not installed")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            with py7zr.SevenZipFile(file_path, mode='r', password=password) as szf:
                szf.extractall(path=tmpdir)
        return True
    except Exception:
        return False

def _pdf_verify(file_path, password) -> bool:
    if not HAS_PYPDF2:
        raise MissingLibraryError("PyPDF2 not installed")
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            if reader.is_encrypted:
                return reader.decrypt(password) == 1
            return True
    except Exception:
        return False

class FormatCrackerFactory:
    @staticmethod
    def get_cracker(ext):
        return {
            '.zip': _zip_verify,
            '.rar': _rar_verify,
            '.7z':  _7z_verify,
            '.pdf': _pdf_verify,
        }.get(ext.lower())

# ============================== Attack state ============================
class AttackStatus:
    def __init__(self):
        self.stop = False
        self.tried_count = 0
        self.last_tried = ""
        self.total_passwords = 0
        self.lock = threading.Lock()
        self.last_status = ""

    def add_tried_password(self, p):
        with self.lock:
            self.tried_count += 1
            self.last_tried = p

    def should_stop(self):
        with self.lock:
            return self.stop

    def set_stop(self):
        with self.lock:
            self.stop = True

    def get_progress(self):
        with self.lock:
            return self.tried_count, self.total_passwords, self.last_tried

    def set_last_status(self, msg):
        with self.lock:
            self.last_status = msg

    def get_last_status(self):
        with self.lock:
            return self.last_status

class ProgressDisplay:
    def __init__(self, status, start_time, callback=None):
        self.status = status
        self.start_time = start_time
        self.callback = callback
        self._stop_evt = threading.Event()
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self._loop, name="ProgressDisplay", daemon=True)
        self.thread.start()

    def stop(self):
        self._stop_evt.set()
        if self.thread:
            self.thread.join(timeout=3.0)

    def _loop(self):
        while not self._stop_evt.is_set():
            if self.status.should_stop():
                break
            if self._stop_evt.wait(2):
                break
            self._update()

    def _update(self):
        tried, total, last = self.status.get_progress()
        elapsed = time.time() - self.start_time
        speed = int(tried / elapsed) if elapsed > 0 else 0
        if total > 0:
            progress = (tried / total) * 100
            remaining = (total - tried) / speed if speed > 0 else 0
            remaining_str = time.strftime('%H:%M:%S', time.gmtime(remaining))
        else:
            progress = 0.0
            remaining_str = "N/A"
        msg = (f"Progress: {progress:.2f}% | Left: {remaining_str} | "
               f"Speed: {speed} p/s | Trying: {last}")
        self.status.set_last_status(msg)
        if self.callback:
            self.callback(msg)
        else:
            print(f"\r[-] {msg}", end="", flush=True)

# ============================== Mask / dict ============================
class MaskParser:
    @staticmethod
    def parse(mask):
        charsets = []
        i = 0
        while i < len(mask):
            if mask[i] == '?':
                if i + 1 < len(mask):
                    ph = mask[i + 1]
                    charsets.append(MASK_PLACEHOLDERS.get(ph, mask[i:i+2]))
                    i += 2
                else:
                    charsets.append('?')
                    i += 1
            else:
                charsets.append(mask[i])
                i += 1
        total = 1
        for cs in charsets:
            if len(cs) > 0:
                total *= len(cs)
        return charsets, max(total, 1)

class DictionaryGenerator:
    @staticmethod
    def iterate_numeric(min_len=1, max_len=6):
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(string.digits, repeat=length):
                yield ''.join(combo)

    @staticmethod
    def numeric_total(min_len=1, max_len=6):
        return sum(10 ** L for L in range(min_len, max_len + 1))

    @staticmethod
    def load_from_file(file_path, chunk_size=CHUNK_SIZE):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                chunk = []
                for line in f:
                    chunk.append(line.strip())
                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []
                if chunk:
                    yield chunk
        except OSError as e:
            raise DictionaryError(f"Failed to load {file_path}: {e}") from e

    @staticmethod
    def count_passwords(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except OSError:
            return 0

# ============================== Attack engine ============================
class AttackEngine:
    def __init__(self, file_path, out_dir, file_ext, status_callback=None,
                 max_threads=None, no_extract=False, status=None):
        self.file_path = file_path
        self.out_dir = out_dir
        self.file_ext = file_ext.lower()
        self.cracker = FormatCrackerFactory.get_cracker(self.file_ext)
        if self.cracker is None:
            raise UnsupportedFormatError(f"Unsupported: {file_ext}")
        self.status = status if status else AttackStatus()
        self.max_threads = max_threads or self._calc_threads()
        self.status_callback = status_callback
        self.no_extract = no_extract
        self.found_password = None
        self.extracted_files = []

    def _log(self, msg):
        if self.status_callback:
            self.status_callback(msg)
        else:
            log_info(msg)

    @staticmethod
    def _calc_threads(max_limit=128):
        try:
            return min(max_limit, multiprocessing.cpu_count() * 4)
        except NotImplementedError:
            return 16

    def _try_password(self, password):
        if self.status.should_stop():
            return False
        try:
            ok = self.cracker(self.file_path, password)
        except MissingLibraryError as e:
            self._log(f"[!] {e}")
            self.status.set_stop()
            return False
        if ok:
            self.found_password = password
            self.status.set_stop()
            self._log(f"\n[+] SUCCESS! Password: {password}")
            if not self.no_extract:
                self._extract(password)
            return True
        self.status.add_tried_password(password)
        return False

    def _extract(self, password):
        try:
            if self.file_ext == '.zip':
                c = PasswordCracker(self.file_path, self.out_dir)
                self.extracted_files = c.extract(password, callback=self._log)
            elif self.file_ext == '.rar' and HAS_RARFILE:
                if os.path.exists(self.out_dir):
                    shutil.rmtree(self.out_dir, ignore_errors=True)
                os.makedirs(self.out_dir, exist_ok=True)
                with rarfile.RarFile(self.file_path) as rf:
                    rf.extractall(path=self.out_dir, pwd=password)
                    self.extracted_files = rf.namelist()
                self._log(f"[*] Extracted {len(self.extracted_files)} file(s)")
            elif self.file_ext == '.7z' and HAS_PY7ZR:
                if os.path.exists(self.out_dir):
                    shutil.rmtree(self.out_dir, ignore_errors=True)
                os.makedirs(self.out_dir, exist_ok=True)
                with py7zr.SevenZipFile(self.file_path, 'r', password=password) as szf:
                    szf.extractall(path=self.out_dir)
                    self.extracted_files = szf.getnames()
                self._log(f"[*] Extracted {len(self.extracted_files)} file(s)")
        except Exception as e:
            self._log(f"[!] Extraction failed: {e}")

    def attack_with_mask(self, mask):
        charsets, total = MaskParser.parse(mask)
        self._log(f"\n[+] Mask: '{mask}' — {total:,} combinations, {self.max_threads} threads")
        self.status.total_passwords = total
        progress = ProgressDisplay(self.status, time.time(), callback=self._log)
        progress.start()
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
                gen = (''.join(p) for p in itertools.product(*charsets))
                while not self.status.should_stop():
                    chunk = list(itertools.islice(gen, MASK_CHUNK_SIZE))
                    if not chunk:
                        break
                    futures = [ex.submit(self._try_password, p) for p in chunk]
                    for f in as_completed(futures):
                        if self.status.should_stop():
                            break
        finally:
            progress.stop()

    def attack_with_dictionary(self, dict_path, dict_name="Dictionary"):
        try:
            total = DictionaryGenerator.count_passwords(dict_path)
            self._log(f"\n[+] {dict_name}: {dict_path} ({total:,} passwords), {self.max_threads} threads")
            self.status.total_passwords = total
            progress = ProgressDisplay(self.status, time.time(), callback=self._log)
            progress.start()
            try:
                with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
                    for chunk in DictionaryGenerator.load_from_file(dict_path):
                        if self.status.should_stop():
                            break
                        futures = [ex.submit(self._try_password, p) for p in chunk]
                        for f in as_completed(futures):
                            if self.status.should_stop():
                                break
            finally:
                progress.stop()
        except DictionaryError as e:
            self._log(f"[!] {e}")

    def attack_with_numeric(self, min_len=1, max_len=6):
        total = DictionaryGenerator.numeric_total(min_len, max_len)
        self._log(f"\n[+] Numeric {min_len}-{max_len} digits ({total:,}), {self.max_threads} threads")
        self.status.total_passwords = total
        progress = ProgressDisplay(self.status, time.time(), callback=self._log)
        progress.start()
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
                gen = DictionaryGenerator.iterate_numeric(min_len, max_len)
                while not self.status.should_stop():
                    chunk = list(itertools.islice(gen, MASK_CHUNK_SIZE))
                    if not chunk:
                        break
                    futures = [ex.submit(self._try_password, p) for p in chunk]
                    for f in as_completed(futures):
                        if self.status.should_stop():
                            break
        finally:
            progress.stop()

    def attack_with_directory(self, dir_path):
        if os.path.isfile(dir_path):
            self.attack_with_dictionary(dir_path, "Custom Dictionary")
        elif os.path.isdir(dir_path):
            for filename in sorted(os.listdir(dir_path)):
                if self.status.should_stop():
                    return
                self.attack_with_directory(os.path.join(dir_path, filename))

# ============================== Web interface ============================
if FLASK_AVAILABLE:
    app = Flask(__name__)
    jobs = {}
    jobs_lock = threading.Lock()
    JOB_TTL = 3600

    def _reap_jobs():
        while True:
            time.sleep(600)
            now = time.time()
            with jobs_lock:
                dead = [jid for jid, j in jobs.items()
                        if j.get('status') == 'done'
                        and now - j.get('finished_at', now) > JOB_TTL]
                for jid in dead:
                    jobs.pop(jid, None)

    threading.Thread(target=_reap_jobs, name="JobsReaper", daemon=True).start()

    def _finish_job(job_id, result):
        with jobs_lock:
            if job_id in jobs:
                jobs[job_id]['status'] = 'done'
                jobs[job_id]['result'] = result
                jobs[job_id]['finished_at'] = time.time()

    def run_cracking_job(job_id, file_path, out_dir, ext, mask, dict_file,
                         numeric, max_threads, no_extract):
        try:
            if ext == '.zip':
                checker = ZipEncryptionChecker()
                if not checker.is_encrypted(file_path):
                    os.makedirs(out_dir, exist_ok=True)
                    with zipfile.ZipFile(file_path) as zf:
                        zf.extractall(path=out_dir)
                        names = zf.namelist()
                    _finish_job(job_id, {'password': None, 'files': names, 'error': None})
                    return
                fixed = f"{file_path}.{uuid.uuid4().hex}.fixed.tmp"
                try:
                    checker.fix_pseudo_encryption(file_path, fixed)
                    with zipfile.ZipFile(fixed) as zf:
                        zf.testzip()
                    os.makedirs(out_dir, exist_ok=True)
                    with zipfile.ZipFile(fixed) as zf:
                        zf.extractall(path=out_dir)
                        names = zf.namelist()
                    _finish_job(job_id, {'password': None, 'files': names, 'error': None})
                    return
                except Exception:
                    pass
                finally:
                    if os.path.exists(fixed):
                        try:
                            os.remove(fixed)
                        except OSError:
                            pass

            status_obj = AttackStatus()
            def cb(msg):
                status_obj.set_last_status(msg)
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]['progress'] = msg

            engine = AttackEngine(file_path, out_dir, ext,
                                  status_callback=cb, max_threads=max_threads,
                                  no_extract=no_extract, status=status_obj)

            if mask:
                engine.attack_with_mask(mask)
            elif dict_file:
                engine.attack_with_dictionary(dict_file, "Uploaded Dictionary")
            else:
                if os.path.exists('password_list.txt'):
                    engine.attack_with_dictionary('password_list.txt', "Built-in")
                if numeric and not engine.found_password:
                    engine.attack_with_numeric(1, 6)

            if engine.found_password:
                _finish_job(job_id, {'password': engine.found_password,
                                     'files': engine.extracted_files, 'error': None})
            else:
                _finish_job(job_id, {'password': None, 'files': [],
                                     'error': 'Password not found.'})
        except Exception as e:
            log_error(f"[web] {e}")
            _finish_job(job_id, {'password': None, 'files': [], 'error': str(e)})
        finally:
            try:
                shutil.rmtree(os.path.dirname(file_path), ignore_errors=True)
            except Exception:
                pass

    HTML_TEMPLATE = """
    <!DOCTYPE html><html><head><title>Cracker</title><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    </head><body><div class="container mt-5">
    <h1 class="text-center">🔓 Password Cracker</h1>
    <form action="/upload" method="post" enctype="multipart/form-data" class="mt-4">
    <div class="form-group"><label>File (ZIP/RAR/7z/PDF):</label>
    <input type="file" class="form-control-file" name="file" required></div>
    <div class="form-group"><label>Dictionary (optional .txt):</label>
    <input type="file" class="form-control-file" name="dict" accept=".txt"></div>
    <div class="form-group"><label>Mask (e.g. ?u?l?l?l?d?d):</label>
    <input type="text" class="form-control" name="mask"></div>
    <div class="form-check"><input type="checkbox" name="numeric" value="yes">
    <label>Try numeric 1-6 digits</label></div>
    <button type="submit" class="btn btn-primary mt-3">Start</button></form>
    <div id="status" class="mt-4"></div></div>
    <script>
    function ck(id){$.get('/status/'+id,function(d){
      if(d.status==='running'){$('#status').html('<div class="alert alert-info">⏳ '+d.progress+'</div>');setTimeout(function(){ck(id)},3000);}
      else if(d.status==='done'){var r=d.result;
        if(r.error){$('#status').html('<div class="alert alert-danger">❌ '+r.error+'</div>');}
        else if(r.password){$('#status').html('<div class="alert alert-success">✅ Password: <b>'+r.password+'</b></div>');}
        else{$('#status').html('<div class="alert alert-success">📂 Not encrypted</div>');}
      }});}
    $(function(){var j=new URLSearchParams(window.location.search).get('job');
      if(j){$('#status').html('Loading...');ck(j);}});
    </script></body></html>
    """

    @app.route('/')
    def index():
        return render_template_string(HTML_TEMPLATE)

    @app.route('/upload', methods=['POST'])
    def upload():
        update_activity()
        if 'file' not in request.files:
            return "No file", 400
        uploaded = request.files['file']
        if not uploaded.filename:
            return "Empty filename", 400
        raw = uploaded.filename
        clean = secure_filename(raw) or safe_name(raw)
        ext = os.path.splitext(clean)[1].lower()
        if ext not in SUPPORTED_EXTS:
            return "Unsupported", 400

        job_id = str(uuid.uuid4())
        temp_dir = os.path.join(tempfile.gettempdir(), f"web_job_{job_id}")
        os.makedirs(temp_dir, exist_ok=True)
        file_path = os.path.join(temp_dir, clean)
        uploaded.save(file_path)

        dict_file = None
        du = request.files.get('dict')
        if du and du.filename:
            dclean = secure_filename(du.filename) or safe_name(du.filename)
            if not dclean.lower().endswith('.txt'):
                dclean += '.txt'
            dict_path = os.path.join(temp_dir, dclean)
            du.save(dict_path)
            dict_file = dict_path

        mask = (request.form.get('mask') or '').strip() or None
        numeric = request.form.get('numeric') == 'yes'
        no_extract = request.form.get('no_extract') == 'yes'
        try:
            tr = (request.form.get('threads') or '').strip()
            max_threads = int(tr) if tr else None
            if max_threads and (max_threads < 1 or max_threads > 512):
                max_threads = None
        except ValueError:
            max_threads = None

        out_dir = os.path.join(temp_dir, "extracted")
        with jobs_lock:
            jobs[job_id] = {'status': 'running', 'progress': 'Starting...',
                            'result': None, 'finished_at': None}

        threading.Thread(target=run_cracking_job,
                         args=(job_id, file_path, out_dir, ext, mask, dict_file,
                               numeric, max_threads, no_extract),
                         name=f"WebJob-{job_id[:8]}", daemon=True).start()
        return redirect(url_for('index', job=job_id))

    @app.route('/status/<job_id>')
    def status_route(job_id):
        with jobs_lock:
            job = jobs.get(job_id)
            if job is None:
                return jsonify({'status': 'unknown'}), 404
            if job['status'] == 'running':
                return jsonify({'status': 'running', 'progress': job.get('progress', '')})
            return jsonify({'status': 'done', 'result': job['result']})

    def run_web_server(port=5000):
        log_info(f"[*] Web server on http://0.0.0.0:{port}")
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True, use_reloader=False)

# ============================== Telegram bot ============================
if TELEGRAM_AVAILABLE:
    class ZipCrackerBot:
        def __init__(self, token):
            if not token:
                raise ValueError("Token required")
            self.token = token
            self.application = Application.builder().token(token).build()
            self.user_data = {}
            self._register_handlers()

        def _register_handlers(self):
            self.application.add_handler(CommandHandler("start", self.cmd_start))
            self.application.add_handler(CommandHandler("help", self.cmd_help))
            self.application.add_handler(CommandHandler("status", self.cmd_status))
            self.application.add_handler(CommandHandler("numeric", self.cmd_numeric))
            self.application.add_handler(CommandHandler("default", self.cmd_default))
            self.application.add_handler(MessageHandler(filters.Document.ALL, self.handle_doc))

        async def cmd_start(self, update, context):
            await update.message.reply_text(
                "👋 Multi-format password cracker.\n"
                "Supported: ZIP, RAR, 7z, PDF.\n"
                "Send me a file. /help for details.")

        async def cmd_help(self, update, context):
            await update.message.reply_text(
                "📖 How to use:\n"
                "• Send a ZIP/RAR/7z/PDF → I'll try password_list.txt\n"
                "• /numeric → also try 1-6 digit PINs\n"
                "• Caption `mask: ?u?l?l?l?d?d` → mask attack\n"
                "• Upload a .txt first, then caption target `dict: name.txt`\n"
                "• /status → progress\n"
                "• /default → reset")

        async def cmd_status(self, update, context):
            uid = update.effective_user.id
            st = self.user_data.get(uid, {}).get('status')
            if st:
                last = st.get_last_status()
                await update.message.reply_text(f"📊 {last}" if last else "⏳ Started...")
            else:
                await update.message.reply_text("❌ No active job.")

        async def cmd_numeric(self, update, context):
            uid = update.effective_user.id
            self.user_data.setdefault(uid, {})['mode'] = 'numeric'
            await update.message.reply_text("✅ Numeric mode on.")

        async def cmd_default(self, update, context):
            uid = update.effective_user.id
            self.user_data.setdefault(uid, {})['mode'] = 'default'
            await update.message.reply_text("✅ Default mode.")

        async def handle_doc(self, update, context):
            update_activity()
            uid = update.effective_user.id
            self.user_data.setdefault(uid, {})
            doc = update.message.document
            caption = update.message.caption or ""
            raw_name = doc.file_name or "file"
            clean_name = safe_name(raw_name)
            ext = safe_ext(clean_name)

            if ext == '.txt':
                temp_dir = f"temp_{uid}"
                os.makedirs(temp_dir, exist_ok=True)
                dict_path = os.path.join(temp_dir, clean_name)
                f = await doc.get_file()
                await f.download_to_drive(dict_path)
                self.user_data[uid]['dict_file'] = dict_path
                await update.message.reply_text(f"✅ Dictionary '{clean_name}' saved. Send target.")
                return

            if ext not in SUPPORTED_EXTS:
                await update.message.reply_text("❌ Only ZIP/RAR/7z/PDF.")
                return
            if ext == '.rar' and not HAS_RARFILE:
                await update.message.reply_text("❌ RAR support missing.")
                return
            if ext == '.7z' and not HAS_PY7ZR:
                await update.message.reply_text("❌ 7z support missing.")
                return
            if ext == '.pdf' and not HAS_PYPDF2:
                await update.message.reply_text("❌ PDF support missing.")
                return

            dict_file = self.user_data[uid].get('dict_file')
            mask = None
            custom_dict = None
            if caption:
                if caption.startswith('mask:'):
                    mask = caption.split('mask:', 1)[1].strip() or None
                elif caption.startswith('dict:'):
                    if dict_file:
                        custom_dict = dict_file
                    else:
                        await update.message.reply_text("❌ Upload a .txt first.")
                        return

            mode = self.user_data[uid].get('mode', 'default')
            await update.message.reply_text(f"📥 Downloading {ext}...")
            temp_dir = f"temp_{uid}"
            os.makedirs(temp_dir, exist_ok=True)
            file_path = os.path.join(temp_dir, clean_name)
            f = await doc.get_file()
            await f.download_to_drive(file_path)

            await update.message.reply_text("🔍 Cracking... (/status for updates)")

            out_dir = os.path.join(temp_dir, "extracted")
            result = {'password': None, 'files': [], 'error': None, 'finished': False}
            status_obj = AttackStatus()
            self.user_data[uid]['status'] = status_obj

            def cb(msg):
                status_obj.set_last_status(msg)

            def crack_task():
                try:
                    if ext == '.zip':
                        checker = ZipEncryptionChecker()
                        if not checker.is_encrypted(file_path):
                            os.makedirs(out_dir, exist_ok=True)
                            with zipfile.ZipFile(file_path) as zf:
                                zf.extractall(path=out_dir)
                                result['files'] = zf.namelist()
                            result['finished'] = True
                            return
                        fixed = f"{file_path}.{uuid.uuid4().hex}.fixed.tmp"
                        try:
                            checker.fix_pseudo_encryption(file_path, fixed)
                            with zipfile.ZipFile(fixed) as zf:
                                zf.testzip()
                            os.makedirs(out_dir, exist_ok=True)
                            with zipfile.ZipFile(fixed) as zf:
                                zf.extractall(path=out_dir)
                                result['files'] = zf.namelist()
                            result['finished'] = True
                            return
                        except Exception:
                            pass
                        finally:
                            if os.path.exists(fixed):
                                try:
                                    os.remove(fixed)
                                except OSError:
                                    pass

                    engine = AttackEngine(file_path, out_dir, ext,
                                          status_callback=cb, status=status_obj)
                    if mask:
                        engine.attack_with_mask(mask)
                    elif custom_dict:
                        engine.attack_with_dictionary(custom_dict, "Custom")
                    elif dict_file:
                        engine.attack_with_dictionary(dict_file, "Uploaded")
                    else:
                        if os.path.exists('password_list.txt'):
                            engine.attack_with_dictionary('password_list.txt', "Built-in")
                        if mode == 'numeric' and not engine.found_password:
                            engine.attack_with_numeric(1, 6)

                    if engine.found_password:
                        result['password'] = engine.found_password
                        result['files'] = engine.extracted_files
                    else:
                        result['error'] = "Password not found."
                    result['finished'] = True
                except Exception as e:
                    result['error'] = str(e)
                    result['finished'] = True

            threading.Thread(target=crack_task, name=f"BotCrack-{uid}", daemon=True).start()
            chat_id = update.effective_chat.id

            async def auto_status():
                while not result['finished']:
                    await asyncio.sleep(300)
                    if not result['finished']:
                        last = status_obj.get_last_status()
                        if last:
                            try:
                                await context.bot.send_message(chat_id, f"⏳ {last}")
                            except Exception:
                                pass

            task = asyncio.create_task(auto_status())
            try:
                while not result['finished']:
                    await asyncio.sleep(1)
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            if result['error']:
                await update.message.reply_text(f"❌ {result['error']}")
            elif result['password']:
                fl = "\n".join(result['files']) or "(none)"
                await update.message.reply_text(
                    f"✅ Password: `{result['password']}`\n\n"
                    f"📂 {len(result['files'])} file(s):\n{fl}",
                    parse_mode='Markdown')
            else:
                fl = "\n".join(result['files']) or "(none)"
                await update.message.reply_text(
                    f"📂 Not encrypted.\n{len(result['files'])} file(s):\n{fl}")

            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

        def run(self):
            log_info("[*] Starting Telegram bot (long polling)...")
            self.application.run_polling()

# ============================== CLI ============================
def print_banner():
    print(r"""
     ______               ____                _
    |__  (_)_ __       / ___|_ __ __ _  ___| | _____ _ __
      / /| | '_ \     | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) |    | |___| | | (_| | (__|   <  __/ |
    /____|_| .__/      \____|_|  \__,_|\___|_|\_\___|_|
           |_|        Coded by rebnX
    """)

def print_usage():
    p = sys.argv[0]
    print(f"""
Usage: python {p} <file> [options]

Options:
  -m, --mask MASK       Mask attack (e.g. ?u?l?l?l?d?d)
  --numeric             Try 1-6 digit numbers
  -o, --out DIR         Output dir (default: unzipped)
  --threads N           Worker threads
  --no-extract          Password only, no extraction
  --log FILE            Log to file
  YourDict.txt          Custom dictionary
  YourDictDir/          Directory of .txt dictionaries

Other modes:
  python {p} --bot      Telegram bot
  python {p} --web      Web server
  python {p} --all      Bot + Web
""")

def parse_arguments():
    if len(sys.argv) < 2:
        return {}
    args = {'file': None, 'out_dir': OUT_DIR_DEFAULT, 'dict_path': None,
            'mask': None, 'numeric': False, 'bot': False, 'web': False,
            'port': 5000, 'all': False, 'threads': None,
            'no_extract': False, 'log': None}
    i = 1
    argv = sys.argv
    while i < len(argv):
        a = argv[i]
        if a == '--bot': args['bot'] = True; i += 1
        elif a == '--web':
            args['web'] = True; i += 1
            if i < len(argv) and argv[i].isdigit():
                args['port'] = int(argv[i]); i += 1
        elif a == '--all':
            args['all'] = True; i += 1
            if i < len(argv) and argv[i].isdigit():
                args['port'] = int(argv[i]); i += 1
        elif a == '--port':
            if i + 1 < len(argv) and argv[i+1].isdigit():
                args['port'] = int(argv[i+1]); i += 2
            else:
                print("[!] --port needs a number"); sys.exit(1)
        elif a == '--numeric': args['numeric'] = True; i += 1
        elif a == '--no-extract': args['no_extract'] = True; i += 1
        elif a == '--threads':
            if i + 1 < len(argv):
                try: args['threads'] = int(argv[i+1])
                except ValueError: print("[!] --threads needs number"); sys.exit(1)
                i += 2
            else: print("[!] --threads needs value"); sys.exit(1)
        elif a == '--log':
            if i + 1 < len(argv): args['log'] = argv[i+1]; i += 2
            else: print("[!] --log needs filename"); sys.exit(1)
        elif a in ('-o', '--out'):
            if i + 1 < len(argv): args['out_dir'] = argv[i+1]; i += 2
            else: print("[!] -o needs dir"); sys.exit(1)
        elif a in ('-m', '--mask'):
            if i + 1 < len(argv): args['mask'] = argv[i+1]; i += 2
            else: print("[!] -m needs mask"); sys.exit(1)
        else:
            if args['file'] is None: args['file'] = a
            elif args['dict_path'] is None: args['dict_path'] = a
            i += 1
    return args

def main_cli(args):
    file_path = args.get('file')
    if not file_path:
        print_usage(); return
    if not os.path.exists(file_path):
        log_error(f"[!] Not found: {file_path}"); sys.exit(1)
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in SUPPORTED_EXTS:
        log_error(f"[!] Unsupported: {ext}"); sys.exit(1)
    if ext == '.rar' and not HAS_RARFILE:
        log_error("[!] rarfile needed."); sys.exit(1)
    if ext == '.7z' and not HAS_PY7ZR:
        log_error("[!] py7zr needed."); sys.exit(1)
    if ext == '.pdf' and not HAS_PYPDF2:
        log_error("[!] PyPDF2 needed."); sys.exit(1)

    out_dir = args.get('out_dir', OUT_DIR_DEFAULT)

    if ext == '.zip':
        checker = ZipEncryptionChecker()
        if not checker.is_encrypted(file_path):
            log_info(f"[!] {file_path} not encrypted. Extracting...")
            if os.path.exists(out_dir):
                shutil.rmtree(out_dir, ignore_errors=True)
            os.makedirs(out_dir, exist_ok=True)
            with zipfile.ZipFile(file_path) as zf:
                zf.extractall(path=out_dir)
            return
        log_info("[!] Encryption detected. Checking pseudo...")
        fixed = f"{file_path}.{uuid.uuid4().hex}.fixed.tmp"
        try:
            checker.fix_pseudo_encryption(file_path, fixed)
            with zipfile.ZipFile(fixed) as zf:
                zf.testzip()
            log_info("[*] Pseudo-encryption fixed.")
            if os.path.exists(out_dir):
                shutil.rmtree(out_dir, ignore_errors=True)
            os.makedirs(out_dir, exist_ok=True)
            with zipfile.ZipFile(fixed) as zf:
                zf.extractall(path=out_dir)
            return
        except Exception:
            log_info("[+] Truly encrypted. Cracking...")
        finally:
            if os.path.exists(fixed):
                try: os.remove(fixed)
                except OSError: pass

        try:
            with zipfile.ZipFile(file_path) as zf:
                if CRCCracker.analyze_zip(file_path, zf, callback=log_info):
                    return
        except zipfile.BadZipFile:
            log_error(f"[!] Corrupted: {file_path}"); sys.exit(1)

    try:
        engine = AttackEngine(file_path, out_dir, ext,
                              max_threads=args.get('threads'),
                              no_extract=args.get('no_extract', False))
    except UnsupportedFormatError as e:
        log_error(f"[!] {e}"); sys.exit(1)

    if args.get('mask'):
        engine.attack_with_mask(args['mask'])
    elif args.get('dict_path'):
        engine.attack_with_directory(args['dict_path'])
    else:
        if os.path.exists('password_list.txt'):
            engine.attack_with_dictionary('password_list.txt', "Built-in")
        if args.get('numeric') and not engine.status.should_stop():
            engine.attack_with_numeric(1, 6)

    if not engine.found_password:
        log_info("\n[-] Not found.")
    else:
        log_info(f"\n[+] Password: {engine.found_password}")

# ============================== Main ============================
_shutdown_event = threading.Event()

def _sigint(signum, frame):
    if not _shutdown_event.is_set():
        print("\n[!] Shutting down...")
        _shutdown_event.set()

def main():
    try:
        signal.signal(signal.SIGINT, _sigint)
        signal.signal(signal.SIGTERM, _sigint)
        print_banner()
        args = parse_arguments()
        setup_logging(args.get('log'))
        _load_dotenv()

        if not (args.get('bot') or args.get('web') or args.get('all')):
            main_cli(args)
            return

        if (args.get('bot') or args.get('all')) and not TELEGRAM_AVAILABLE:
            log_error("[!] python-telegram-bot missing."); sys.exit(1)
        if (args.get('web') or args.get('all')) and not FLASK_AVAILABLE:
            log_error("[!] Flask missing."); sys.exit(1)

        port = args.get('port', 5000)
        threading.Thread(target=cleanup_worker, name="Cleanup", daemon=True).start()

        if args.get('web') or args.get('all'):
            threading.Thread(target=run_web_server, args=(port,),
                             name="WebServer", daemon=True).start()

        if args.get('bot') or args.get('all'):
            token = _get_bot_token()
            uname = _validate_bot_token(token)
            if uname:
                log_info(f"[*] Token OK: @{uname}")
            else:
                log_error("[!] Token validation failed.")
                if not args.get('web'):
                    sys.exit(1)
            else:
                bot = ZipCrackerBot(token)
                log_info("[*] Starting bot in main thread...")
                bot.run()
                return

        try:
            while not _shutdown_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        log_info("[!] Shutdown complete.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as e:
        log_error(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
