#!/usr/bin/env python3
"""
Multi-Format Password Cracker (ZIP / RAR / 7z / PDF)
Modes: CLI, Telegram Bot, Web Interface
Coded by rebnX - Extended + Security Hardened
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
import base64
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
        # Minimal fallback
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
MAX_CRC_FILE_SIZE = 3          # CRC32 attack only feasible for very small files
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
    """Setup root logger. Console stays pretty; file gets everything."""
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
            "%(asctime)s [%(levelname)s] %(threadName)s: %(message)s"
        ))
        logger.addHandler(fh)


def log_info(msg: str) -> None:
    logger.info(msg)


def log_error(msg: str) -> None:
    logger.error(msg)


# ============================== Exceptions ============================
class CrackerError(Exception):
    """Base class for cracker errors."""


class DictionaryError(CrackerError):
    """Raised when a dictionary file cannot be loaded."""


class UnsupportedFormatError(CrackerError):
    """Raised for unsupported file formats."""


class MissingLibraryError(CrackerError):
    """Raised when a required library is not installed."""


# ============================== Cleanup mechanism ============================
CLEANUP_INTERVAL = 3600      # 1 hour between cleanup checks
IDLE_TIMEOUT = 3600          # 1 hour of inactivity triggers cleanup
last_activity_time = time.time()
cleanup_lock = threading.Lock()


def update_activity() -> None:
    global last_activity_time
    with cleanup_lock:
        last_activity_time = time.time()


def cleanup_old_temp_dirs() -> None:
    """Delete temp dirs / files older than 2 hours."""
    now = time.time()

    # Bot temp dirs in cwd
    try:
        for item in os.listdir('.'):
            if item.startswith('temp_') and os.path.isdir(item):
                path = os.path.abspath(item)
                try:
                    if now - os.path.getmtime(path) > 7200:
                        shutil.rmtree(path, ignore_errors=True)
                        log_info(f"[cleanup] Removed old temp dir: {path}")
                except OSError:
                    pass
    except OSError:
        pass

    # Web jobs in system temp
    sys_temp = tempfile.gettempdir()
    try:
        for item in os.listdir(sys_temp):
            if item.startswith('web_job_'):
                path = os.path.join(sys_temp, item)
                if os.path.isdir(path):
                    try:
                        if now - os.path.getmtime(path) > 7200:
                            shutil.rmtree(path, ignore_errors=True)
                            log_info(f"[cleanup] Removed old web job dir: {path}")
                    except OSError:
                        pass
    except OSError:
        pass

    # Leftover .fixed.tmp files
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
    global last_activity_time
    while True:
        time.sleep(CLEANUP_INTERVAL)
        with cleanup_lock:
            idle = time.time() - last_activity_time
        if idle > IDLE_TIMEOUT:
            try:
                cleanup_old_temp_dirs()
            except Exception as e:  # noqa: BLE001
                log_error(f"[cleanup] error: {e}")


# ============================== Helper: safe filenames ============================
def safe_name(name: str) -> str:
    """Sanitize a filename from any untrusted source."""
    if not name:
        return "upload"
    # kill null bytes and path separators
    name = name.replace("\x00", "")
    name = os.path.basename(name)
    name = name.replace("/", "_").replace("\\", "_").strip().lstrip(".")
    return name or "upload"


def safe_ext(name: str) -> str:
    return os.path.splitext(safe_name(name))[1].lower()


# ============================== Core: Encryption checkers ============================
class ZipEncryptionChecker:
    @staticmethod
    def is_encrypted(file_path: str) -> bool:
        try:
            with zipfile.ZipFile(file_path) as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        return True
            return False
        except Exception:  # noqa: BLE001
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


# ============================== CRC32 collision (small files only) ============================
class CRCCracker:
    @staticmethod
    def analyze_zip(zip_file: str, zf: zipfile.ZipFile,
                    callback: Optional[Callable[[str], None]] = None) -> bool:
        """
        Attempt CRC32 collision attack on small files only.
        Returns True only if *all* small files were cracked.
        """
        small = [
            info for info in zf.infolist()
            if not info.filename.endswith('/')
            and 0 < info.file_size <= MAX_CRC_FILE_SIZE
        ]
        if not small:
            return False

        cracked = 0
        for info in small:
            if callback:
                callback(
                    f'[!] CRC attack: "{info.filename}" '
                    f'({info.file_size} bytes, CRC={info.CRC})'
                )
            if CRCCracker.crack(info.filename, info.CRC, info.file_size, callback):
                cracked += 1

        all_done = cracked == len(small)
        if all_done and callback:
            callback("[*] All small files cracked via CRC32. Skipping dictionary.")
        return all_done

    @staticmethod
    def crack(filename: str, target_crc: int, size: int,
              callback: Optional[Callable[[str], None]] = None) -> bool:
        if size > MAX_CRC_FILE_SIZE:
            if callback:
                callback(f"[-] Skip CRC for {filename}: size {size} too large")
            return False

        if callback:
            callback(f"[+] CRC32 collision attempt on {filename}...")
        for combo in itertools.product(string.printable, repeat=size):
            content = ''.join(combo).encode()
            if binascii.crc32(content) == target_crc:
                if callback:
                    callback(f"[*] CRC cracked! Content: {content.decode(errors='replace')}")
                return True
        if callback:
            callback(f"[-] CRC attack failed for {filename}")
        return False


# ============================== ZIP extraction helpers ============================
def find_first_file(zf) -> Optional[str]:
    try:
        for info in zf.infolist():
            if not info.filename.endswith('/'):
                return info.filename
    except Exception:  # noqa: BLE001
        pass
    try:
        for name in zf.namelist():
            if not name.endswith('/'):
                return name
    except Exception:  # noqa: BLE001
        pass
    return None


class PasswordCracker:
    """ZIP-specific extraction helper."""

    def __init__(self, zip_file: str, out_dir: str):
        self.zip_file = zip_file
        self.out_dir = out_dir

    def extract(self, password: str,
                callback: Optional[Callable[[str], None]] = None) -> List[str]:
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
            callback(f"[*] Extracted {len(names)} file(s) to '{self.out_dir}'")
        return names


# ============================== Format crackers ============================
def _zip_verify(file_path: str, password: str) -> bool:
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
    except RuntimeError:
        return False
    except zipfile.BadZipFile:
        return False
    except Exception:  # noqa: BLE001
        return False


def _rar_verify(file_path: str, password: str) -> bool:
    if not HAS_RARFILE:
        raise MissingLibraryError("rarfile library not installed.")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            with rarfile.RarFile(file_path) as rf:
                rf.extractall(path=tmpdir, pwd=password)
        return True
    except Exception:  # noqa: BLE001
        return False


def _7z_verify(file_path: str, password: str) -> bool:
    if not HAS_PY7ZR:
        raise MissingLibraryError("py7zr library not installed.")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            with py7zr.SevenZipFile(file_path, mode='r', password=password) as szf:
                szf.extractall(path=tmpdir)
        return True
    except Exception:  # noqa: BLE001
        return False


def _pdf_verify(file_path: str, password: str) -> bool:
    if not HAS_PYPDF2:
        raise MissingLibraryError("PyPDF2 library not installed.")
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            if reader.is_encrypted:
                return reader.decrypt(password) == 1
            return True
    except Exception:  # noqa: BLE001
        return False


class FormatCrackerFactory:
    @staticmethod
    def get_cracker(ext: str) -> Optional[Callable[[str, str], bool]]:
        ext = ext.lower()
        return {
            '.zip': _zip_verify,
            '.rar': _rar_verify,
            '.7z':  _7z_verify,
            '.pdf': _pdf_verify,
        }.get(ext)


# ============================== Attack state ============================
class AttackStatus:
    def __init__(self):
        self.stop = False
        self.tried_count = 0
        self.last_tried = ""
        self.total_passwords = 0
        self.lock = threading.Lock()
        self.last_status = ""

    def add_tried_password(self, password: str) -> None:
        with self.lock:
            self.tried_count += 1
            self.last_tried = password

    def should_stop(self) -> bool:
        with self.lock:
            return self.stop

    def set_stop(self) -> None:
        with self.lock:
            self.stop = True

    def get_progress(self) -> Tuple[int, int, str]:
        with self.lock:
            return self.tried_count, self.total_passwords, self.last_tried

    def set_last_status(self, msg: str) -> None:
        with self.lock:
            self.last_status = msg

    def get_last_status(self) -> str:
        with self.lock:
            return self.last_status


class ProgressDisplay:
    """Background thread that reports cracking progress. Must be stopped."""

    def __init__(self, status: AttackStatus, start_time: float,
                 callback: Optional[Callable[[str], None]] = None):
        self.status = status
        self.start_time = start_time
        self.callback = callback
        self._stop_evt = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.thread = threading.Thread(
            target=self._display_loop, name="ProgressDisplay", daemon=True
        )
        self.thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        if self.thread is not None:
            self.thread.join(timeout=3.0)

    def _display_loop(self) -> None:
        while not self._stop_evt.is_set():
            if self.status.should_stop():
                break
            # use Event.wait so stop() is immediate
            if self._stop_evt.wait(2):
                break
            self._update_display()

    def _update_display(self) -> None:
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

        msg = (
            f"Progress: {progress:.2f}% | Time Left: {remaining_str} | "
            f"Speed: {speed} pass/s | Trying: {last}"
        )
        self.status.set_last_status(msg)
        if self.callback:
            self.callback(msg)
        else:
            print(f"\r[-] {msg}", end="", flush=True)


# ============================== Mask / dictionary ============================
class MaskParser:
    @staticmethod
    def parse(mask: str) -> Tuple[List[str], int]:
        charsets: List[str] = []
        i = 0
        while i < len(mask):
            if mask[i] == '?':
                if i + 1 < len(mask):
                    ph = mask[i + 1]
                    if ph in MASK_PLACEHOLDERS:
                        charsets.append(MASK_PLACEHOLDERS[ph])
                    else:
                        charsets.append(mask[i:i + 2])
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
    def iterate_numeric(min_len: int = 1,
                        max_len: int = 6) -> Generator[str, None, None]:
        """Lazy generator so we never hold the full numeric space in RAM."""
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(string.digits, repeat=length):
                yield ''.join(combo)

    @staticmethod
    def numeric_total(min_len: int = 1, max_len: int = 6) -> int:
        return sum(10 ** L for L in range(min_len, max_len + 1))

    @staticmethod
    def load_from_file(file_path: str,
                       chunk_size: int = CHUNK_SIZE) -> Generator[List[str], None, None]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                chunk: List[str] = []
                for line in f:
                    chunk.append(line.strip())
                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []
                if chunk:
                    yield chunk
        except OSError as e:
            raise DictionaryError(f"Failed to load dictionary '{file_path}': {e}") from e

    @staticmethod
    def count_passwords(file_path: str) -> int:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except OSError:
            return 0


# ============================== Attack engine ============================
class AttackEngine:
    def __init__(self, file_path: str, out_dir: str, file_ext: str,
                 status_callback: Optional[Callable[[str], None]] = None,
                 max_threads: Optional[int] = None,
                 no_extract: bool = False,
                 status: Optional[AttackStatus] = None):
        self.file_path = file_path
        self.out_dir = out_dir
        self.file_ext = file_ext.lower()
        self.cracker = FormatCrackerFactory.get_cracker(self.file_ext)
        if self.cracker is None:
            raise UnsupportedFormatError(f"Unsupported file format: {file_ext}")

        self.status = status if status is not None else AttackStatus()
        self.max_threads = max_threads or self._calculate_threads()
        self.status_callback = status_callback
        self.no_extract = no_extract
        self.found_password: Optional[str] = None
        self.extracted_files: List[str] = []

    def _log(self, msg: str) -> None:
        if self.status_callback:
            self.status_callback(msg)
        else:
            log_info(msg)

    @staticmethod
    def _calculate_threads(max_limit: int = 128) -> int:
        try:
            return min(max_limit, multiprocessing.cpu_count() * 4)
        except NotImplementedError:
            return 16

    # ---------- password try ----------
    def _try_password(self, password: str) -> bool:
        if self.status.should_stop():
            return False
        try:
            ok = self.cracker(self.file_path, password)
        except MissingLibraryError as e:
            self._log(f"[!] Missing library: {e}. Stopping.")
            self.status.set_stop()
            return False

        if ok:
            self.found_password = password
            self.status.set_stop()
            self._log(f"\n[+] SUCCESS! Password found: {password}")
            if not self.no_extract:
                self._extract(password)
            else:
                self._log("[*] Extraction skipped (--no-extract).")
            return True

        self.status.add_tried_password(password)
        return False

    def _extract(self, password: str) -> None:
        try:
            if self.file_ext == '.zip':
                cracker = PasswordCracker(self.file_path, self.out_dir)
                self.extracted_files = cracker.extract(password, callback=self._log)
            elif self.file_ext == '.rar':
                self._extract_rar(password)
            elif self.file_ext == '.7z':
                self._extract_7z(password)
            elif self.file_ext == '.pdf':
                self._log("[*] PDF is not an archive - password only, no extraction.")
        except Exception as e:  # noqa: BLE001
            self._log(f"[!] Extraction failed: {e}")

    def _extract_rar(self, password: str) -> None:
        if not HAS_RARFILE:
            raise MissingLibraryError("rarfile not installed")
        if os.path.exists(self.out_dir):
            shutil.rmtree(self.out_dir, ignore_errors=True)
        os.makedirs(self.out_dir, exist_ok=True)
        with rarfile.RarFile(self.file_path) as rf:
            rf.extractall(path=self.out_dir, pwd=password)
            names = rf.namelist()
        self.extracted_files = names
        self._log(f"[*] Extracted {len(names)} file(s) to '{self.out_dir}'")

    def _extract_7z(self, password: str) -> None:
        if not HAS_PY7ZR:
            raise MissingLibraryError("py7zr not installed")
        if os.path.exists(self.out_dir):
            shutil.rmtree(self.out_dir, ignore_errors=True)
        os.makedirs(self.out_dir, exist_ok=True)
        with py7zr.SevenZipFile(self.file_path, mode='r', password=password) as szf:
            szf.extractall(path=self.out_dir)
            names = szf.getnames()
        self.extracted_files = names
        self._log(f"[*] Extracted {len(names)} file(s) to '{self.out_dir}'")

    # ---------- attacks ----------
    def attack_with_mask(self, mask: str) -> None:
        charsets, total = MaskParser.parse(mask)
        if total > MAX_MASK_COMBINATIONS:
            self._log(
                f"[!] Warning: mask '{mask}' generates {total:,} combinations. "
                f"This may take a very long time."
            )
        self._log(f"\n[+] Mask attack: '{mask}'")
        self._log(f"[+] Total combinations: {total:,}")
        self._log(f"[+] Using {self.max_threads} threads")
        self.status.total_passwords = total

        start = time.time()
        progress = ProgressDisplay(self.status, start, callback=self._log)
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
            if not self.status.should_stop():
                self._log('\n[-] All mask combinations tried. Password not found.')

    def attack_with_dictionary(self, dict_path: str, dict_name: str = "Dictionary") -> None:
        try:
            total = DictionaryGenerator.count_passwords(dict_path)
            self._log(f"\n[+] Loaded {dict_name}: {dict_path}")
            self._log(f"[+] Total passwords: {total:,}")
            self._log(f"[+] Using {self.max_threads} threads")
            self.status.total_passwords = total

            start = time.time()
            progress = ProgressDisplay(self.status, start, callback=self._log)
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
                if not self.status.should_stop():
                    self._log(f'\n[-] All passwords in {dict_path} tried. Not found.')
        except DictionaryError as e:
            self._log(f"[!] {e}")

    def attack_with_numeric(self, min_len: int = 1, max_len: int = 6) -> None:
        total = DictionaryGenerator.numeric_total(min_len, max_len)
        self._log(f"\n[+] Trying {min_len}-{max_len} digit numeric ({total:,} passwords)")
        self._log(f"[+] Using {self.max_threads} threads")
        self.status.total_passwords = total

        start = time.time()
        progress = ProgressDisplay(self.status, start, callback=self._log)
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
            if not self.status.should_stop():
                self._log('\n[-] All numeric passwords tried. Password not found.')

    def attack_with_directory(self, dir_path: str) -> None:
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
    jobs: Dict[str, Dict[str, Any]] = {}
    jobs_lock = threading.Lock()
    JOB_TTL = 3600  # keep finished jobs 1 hour, then reap

    def _reap_jobs() -> None:
        while True:
            time.sleep(600)
            now = time.time()
            with jobs_lock:
                dead = [
                    jid for jid, j in jobs.items()
                    if j.get('status') == 'done'
                    and now - j.get('finished_at', now) > JOB_TTL
                ]
                for jid in dead:
                    jobs.pop(jid, None)

    # start the reaper once
    threading.Thread(target=_reap_jobs, name="JobsReaper", daemon=True).start()

    def _finish_job(job_id: str, result: Dict[str, Any]) -> None:
        with jobs_lock:
            if job_id in jobs:
                jobs[job_id]['status'] = 'done'
                jobs[job_id]['result'] = result
                jobs[job_id]['finished_at'] = time.time()

    def run_cracking_job(job_id: str, file_path: str, out_dir: str, ext: str,
                         mask: Optional[str], dict_file: Optional[str],
                         numeric: bool, max_threads: Optional[int],
                         no_extract: bool) -> None:
        try:
            # ZIP pseudo-encryption handling
            if ext == '.zip':
                checker = ZipEncryptionChecker()
                if not checker.is_encrypted(file_path):
                    os.makedirs(out_dir, exist_ok=True)
                    with zipfile.ZipFile(file_path) as zf:
                        zf.extractall(path=out_dir)
                        names = zf.namelist()
                    _finish_job(job_id, {'password': None, 'files': names, 'error': None})
                    return

                fixed_zip = f"{file_path}.{uuid.uuid4().hex}.fixed.tmp"
                try:
                    checker.fix_pseudo_encryption(file_path, fixed_zip)
                    with zipfile.ZipFile(fixed_zip) as zf:
                        zf.testzip()
                    os.makedirs(out_dir, exist_ok=True)
                    with zipfile.ZipFile(fixed_zip) as zf:
                        zf.extractall(path=out_dir)
                        names = zf.namelist()
                    _finish_job(job_id, {'password': None, 'files': names, 'error': None})
                    return
                except Exception:  # noqa: BLE001
                    pass
                finally:
                    if os.path.exists(fixed_zip):
                        try:
                            os.remove(fixed_zip)
                        except OSError:
                            pass

            status_obj = AttackStatus()

            def cb(msg: str) -> None:
                status_obj.set_last_status(msg)
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]['progress'] = msg

            engine = AttackEngine(
                file_path, out_dir, ext,
                status_callback=cb,
                max_threads=max_threads,
                no_extract=no_extract,
                status=status_obj,
            )

            if mask:
                engine.attack_with_mask(mask)
            elif dict_file:
                engine.attack_with_dictionary(dict_file, "Uploaded Dictionary")
            else:
                if os.path.exists('password_list.txt'):
                    engine.attack_with_dictionary('password_list.txt', "Built-in Dictionary")
                else:
                    cb("[!] password_list.txt not found. Skipping dictionary.")
                if numeric and not engine.found_password:
                    engine.attack_with_numeric(1, 6)

            if engine.found_password:
                _finish_job(job_id, {
                    'password': engine.found_password,
                    'files': engine.extracted_files,
                    'error': None,
                })
            else:
                _finish_job(job_id, {
                    'password': None, 'files': [],
                    'error': 'Password not found after all attempts.',
                })

        except Exception as e:  # noqa: BLE001
            log_error(f"[web] job error: {e}")
            _finish_job(job_id, {'password': None, 'files': [], 'error': str(e)})
        finally:
            try:
                shutil.rmtree(os.path.dirname(file_path), ignore_errors=True)
            except Exception:  # noqa: BLE001
                pass

    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Password Cracker</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </head>
    <body>
        <div class="container mt-5">
            <h1 class="text-center">🔓 ZIP / RAR / 7z / PDF Password Cracker</h1>
            <form action="/upload" method="post" enctype="multipart/form-data" class="mt-4">
                <div class="form-group">
                    <label>Upload file (ZIP, RAR, 7z, PDF):</label>
                    <input type="file" class="form-control-file" name="file" required>
                </div>
                <div class="form-group">
                    <label>Optional custom dictionary (.txt):</label>
                    <input type="file" class="form-control-file" name="dict" accept=".txt">
                </div>
                <div class="form-group">
                    <label>Mask (e.g., ?u?l?l?l?d?d):</label>
                    <input type="text" class="form-control" name="mask" placeholder="?d?d?d?d">
                    <small class="form-text text-muted">?d=digit, ?l=lower, ?u=upper, ?s=symbol, ??=literal ?</small>
                </div>
                <div class="form-group">
                    <label>Threads (leave blank for auto):</label>
                    <input type="number" class="form-control" name="threads" min="1" max="512" placeholder="auto">
                </div>
                <div class="form-check">
                    <input type="checkbox" class="form-check-input" name="numeric" value="yes">
                    <label class="form-check-label">Also try 1-6 digit numeric (after dictionary)</label>
                </div>
                <div class="form-check">
                    <input type="checkbox" class="form-check-input" name="no_extract" value="yes">
                    <label class="form-check-label">Skip extraction (password only)</label>
                </div>
                <button type="submit" class="btn btn-primary mt-3">Start Cracking</button>
            </form>
            <div id="status" class="mt-4"></div>
        </div>
        <script>
            function checkStatus(jobId) {
                $.get('/status/' + jobId, function(data) {
                    if (data.status === 'running') {
                        $('#status').html('<div class="alert alert-info">⏳ ' + data.progress + '</div>');
                        setTimeout(function() { checkStatus(jobId); }, 3000);
                    } else if (data.status === 'done') {
                        if (data.result.error) {
                            $('#status').html('<div class="alert alert-danger">❌ ' + data.result.error + '</div>');
                        } else if (data.result.password) {
                            var files = (data.result.files || []).join('\\n') || '(none)';
                            $('#status').html('<div class="alert alert-success">✅ Password: <strong>' + data.result.password + '</strong><br>Extracted ' + (data.result.files||[]).length + ' file(s):<br><pre>' + files + '</pre></div>');
                        } else {
                            $('#status').html('<div class="alert alert-success">📂 Not encrypted (or pseudo-encryption fixed).<br>Extracted ' + (data.result.files||[]).length + ' file(s):<br><pre>' + (data.result.files||[]).join('\\n') + '</pre></div>');
                        }
                    } else {
                        $('#status').html('<div class="alert alert-secondary">Waiting...</div>');
                    }
                });
            }
            $(document).ready(function() {
                var jobId = new URLSearchParams(window.location.search).get('job');
                if (jobId) {
                    $('#status').html('<div class="alert alert-secondary">Loading...</div>');
                    checkStatus(jobId);
                }
            });
        </script>
    </body>
    </html>
    """

    @app.route('/')
    def index():
        return render_template_string(HTML_TEMPLATE)

    @app.route('/upload', methods=['POST'])
    def upload():
        update_activity()
        if 'file' not in request.files:
            return "No file uploaded", 400
        uploaded = request.files['file']
        if not uploaded.filename:
            return "Empty filename", 400

        # ==== Path-traversal safe filename ====
        raw = uploaded.filename
        clean = secure_filename(raw) or safe_name(raw)
        ext = os.path.splitext(clean)[1].lower()
        if ext not in SUPPORTED_EXTS:
            return "Unsupported file format", 400

        job_id = str(uuid.uuid4())
        temp_dir = os.path.join(tempfile.gettempdir(), f"web_job_{job_id}")
        os.makedirs(temp_dir, exist_ok=True)
        file_path = os.path.join(temp_dir, clean)
        uploaded.save(file_path)

        # Optional dictionary
        dict_file = None
        dict_up = request.files.get('dict')
        if dict_up and dict_up.filename:
            dclean = secure_filename(dict_up.filename) or safe_name(dict_up.filename)
            if not dclean.lower().endswith('.txt'):
                dclean += '.txt'
            dict_path = os.path.join(temp_dir, dclean)
            dict_up.save(dict_path)
            dict_file = dict_path

        mask = (request.form.get('mask') or '').strip() or None
        numeric = request.form.get('numeric') == 'yes'
        no_extract = request.form.get('no_extract') == 'yes'

        try:
            threads_raw = (request.form.get('threads') or '').strip()
            max_threads = int(threads_raw) if threads_raw else None
            if max_threads is not None and (max_threads < 1 or max_threads > 512):
                max_threads = None
        except ValueError:
            max_threads = None

        out_dir = os.path.join(temp_dir, "extracted")

        with jobs_lock:
            jobs[job_id] = {
                'status': 'running',
                'progress': 'Starting...',
                'result': None,
                'finished_at': None,
            }

        t = threading.Thread(
            target=run_cracking_job,
            args=(job_id, file_path, out_dir, ext, mask, dict_file,
                  numeric, max_threads, no_extract),
            name=f"WebJob-{job_id[:8]}",
            daemon=True,
        )
        t.start()
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

    def run_web_server(port: int = 5000) -> None:
        log_info(f"[*] Web server listening on http://0.0.0.0:{port}")
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True,
                use_reloader=False)


# ============================== Telegram bot ============================
if TELEGRAM_AVAILABLE:
    class ZipCrackerBot:
        def __init__(self, token: str):
            if not token:
                raise ValueError("Telegram bot token is required.")
            self.token = token
            self.application = Application.builder().token(token).build()
            self.user_data: Dict[int, Dict[str, Any]] = {}
            self._register_handlers()

        def _register_handlers(self) -> None:
            self.application.add_handler(CommandHandler("start", self.start_command))
            self.application.add_handler(CommandHandler("help", self.help_command))
            self.application.add_handler(CommandHandler("status", self.status_command))
            self.application.add_handler(CommandHandler("numeric", self.numeric_command))
            self.application.add_handler(CommandHandler("default", self.default_command))
            self.application.add_handler(
                MessageHandler(filters.Document.ALL, self.handle_document)
            )

        async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
            await update.message.reply_text(
                "👋 Hi! Multi-format password cracker.\n"
                "Supported: ZIP, RAR, 7z, PDF.\n"
                "Send me a file to crack. /help for details."
            )

        async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
            help_encoded = (
                "8J+UlyAqSG93IHRvIHVzZSB0aGlzIGJvdCoqCgoxLiDinqggRGVmYXVsdCBNb2RlIChubyBleHRyYSBjb21tYW5kcyk6CiAgIFNlbmQgYSBzdXBwb3J0ZWQgZmlsZSAoWklQLCBSQVIsIDd6LCBQREYpIOKGkiBJ4oCZbGwgdHJ5IGBwYXNzd29yZF9saXN0LnR4dGAgKGlmIHByZXNlbnQpLCB0aGVuIHN0b3AgKG5vIG51bWVyaWMgZmFsbGJhY2spLgoKMi4g4p+pIE51bWVyaWMgTW9kZSAob3B0aW9uYWwpOgogICBUeXBlIGAvbnVtZXJpY2AgdGhlbiBzZW5kIGEgZmlsZSDihpIgSeKAmWxsIHRyeSAxLTYgZGlnaXQgbnVtZXJpYyBQSU5zIGFmdGVyIHRoZSBkaWN0aW9uYXJ5LgoKMy4g4p+qIE1hc2sgQXR0YWNrOgogICBTZW5kIGEgZmlsZSB3aXRoIGNhcHRpb24gYG1hc2s6ID91P2w/bD9sP2Q/ZGAgKG9yIGFueSBtYXNrKS4KICAgUGxhY2Vob2xkZXJzOiBgP2Q9ZGlnaXRzLCBgP2w9bG93ZXJjYXNlLCBgP3U9dXBwZXJjYXNlLCBgP3M9c3ltYm9scywgYD8/PWxpdGVyYWwgJz8nCgo0LiDin6sgQ3VzdG9tIERpY3Rpb25hcnk6CiAgIFVwbG9hZCBhIGAudHh0YCBkaWN0aW9uYXJ5IGZpbGUgYWxvbmcgd2l0aCB0aGUgdGFyZ2V0IGZpbGUsIGFuZCBjYXB0aW9uIHRoZSB0YXJnZXQgd2l0aCBgZGljdDogZmlsZW5hbWUudHh0YC4KCjUuIOKfqyBDaGVjayBQcm9ncmVzczoKICAgYC9zdGF0dXNgIHRvIHNlZSBjdXJyZW50IHByb2dyZXNzLgoKNi4g4p+sIFJlc2V0OgogICBgL2RlZmF1bHRgIOKAlCByZXNldHMgdG8gZGVmYXVsdCBkaWN0aW9uYXJ5LW9ubHkgbW9kZS4="
            )
            try:
                help_text = base64.b64decode(help_encoded).decode('utf-8')
            except Exception:  # noqa: BLE001
                help_text = "Use /numeric, /status, /default. Send a file to crack."
            await update.message.reply_text(help_text)

        async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
            uid = update.effective_user.id
            st = self.user_data.get(uid, {}).get('status')
            if st:
                last = st.get_last_status()
                await update.message.reply_text(
                    f"📊 Progress:\n{last}" if last else "⏳ Started, no update yet."
                )
            else:
                await update.message.reply_text("❌ No active cracking job.")

        async def numeric_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
            uid = update.effective_user.id
            self.user_data.setdefault(uid, {})['mode'] = 'numeric'
            await update.message.reply_text(
                "✅ Numeric mode set. Next file will also try 1-6 digit numbers."
            )

        async def default_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
            uid = update.effective_user.id
            self.user_data.setdefault(uid, {})['mode'] = 'default'
            await update.message.reply_text("✅ Reset to default mode.")

        async def handle_document(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
            update_activity()
            uid = update.effective_user.id
            self.user_data.setdefault(uid, {})

            doc = update.message.document
            caption = update.message.caption or ""

            # ==== Sanitize filename from Telegram ====
            raw_name = doc.file_name or "file"
            clean_name = safe_name(raw_name)
            ext = safe_ext(clean_name)

            # Dictionary upload?
            if ext == '.txt':
                temp_dir = f"temp_{uid}"
                os.makedirs(temp_dir, exist_ok=True)
                dict_path = os.path.join(temp_dir, clean_name)
                f = await doc.get_file()
                await f.download_to_drive(dict_path)
                self.user_data[uid]['dict_file'] = dict_path
                await update.message.reply_text(
                    f"✅ Dictionary '{clean_name}' saved. Now send target file."
                )
                return

            if ext not in SUPPORTED_EXTS:
                await update.message.reply_text(
                    "❌ Unsupported format. Only ZIP/RAR/7z/PDF."
                )
                return

            if ext == '.rar' and not HAS_RARFILE:
                await update.message.reply_text("❌ RAR support missing (install rarfile).")
                return
            if ext == '.7z' and not HAS_PY7ZR:
                await update.message.reply_text("❌ 7z support missing (install py7zr).")
                return
            if ext == '.pdf' and not HAS_PYPDF2:
                await update.message.reply_text("❌ PDF support missing (install PyPDF2).")
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
                        await update.message.reply_text(
                            "❌ No dictionary uploaded yet. Send a .txt first."
                        )
                        return

            mode = self.user_data[uid].get('mode', 'default')

            await update.message.reply_text(f"📥 Downloading {ext} file...")
            temp_dir = f"temp_{uid}"
            os.makedirs(temp_dir, exist_ok=True)
            file_path = os.path.join(temp_dir, clean_name)
            f = await doc.get_file()
            await f.download_to_drive(file_path)

            await update.message.reply_text(
                "🔍 Cracking... (use /status or wait for auto-update)"
            )

            out_dir = os.path.join(temp_dir, "extracted")
            result: Dict[str, Any] = {
                'password': None, 'files': [], 'error': None, 'finished': False,
            }
            status_obj = AttackStatus()
            self.user_data[uid]['status'] = status_obj

            def cb(msg: str) -> None:
                status_obj.set_last_status(msg)

            def crack_task() -> None:
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

                        fixed_zip = f"{file_path}.{uuid.uuid4().hex}.fixed.tmp"
                        try:
                            checker.fix_pseudo_encryption(file_path, fixed_zip)
                            with zipfile.ZipFile(fixed_zip) as zf:
                                zf.testzip()
                            os.makedirs(out_dir, exist_ok=True)
                            with zipfile.ZipFile(fixed_zip) as zf:
                                zf.extractall(path=out_dir)
                                result['files'] = zf.namelist()
                            result['finished'] = True
                            return
                        except Exception:  # noqa: BLE001
                            pass
                        finally:
                            if os.path.exists(fixed_zip):
                                try:
                                    os.remove(fixed_zip)
                                except OSError:
                                    pass

                    engine = AttackEngine(
                        file_path, out_dir, ext,
                        status_callback=cb, status=status_obj,
                    )

                    if mask:
                        engine.attack_with_mask(mask)
                    elif custom_dict:
                        engine.attack_with_dictionary(custom_dict, "Custom Dictionary")
                    elif dict_file:
                        engine.attack_with_dictionary(dict_file, "Uploaded Dictionary")
                    else:
                        if os.path.exists('password_list.txt'):
                            engine.attack_with_dictionary(
                                'password_list.txt', "Built-in Dictionary"
                            )
                        else:
                            cb("[!] password_list.txt not found. Skipping.")
                        if mode == 'numeric' and not engine.found_password:
                            engine.attack_with_numeric(1, 6)

                    if engine.found_password:
                        result['password'] = engine.found_password
                        result['files'] = engine.extracted_files
                    else:
                        result['error'] = "Password not found."
                    result['finished'] = True
                except Exception as e:  # noqa: BLE001
                    result['error'] = str(e)
                    result['finished'] = True

            threading.Thread(
                target=crack_task, name=f"BotCrack-{uid}", daemon=True
            ).start()

            chat_id = update.effective_chat.id

            async def auto_status():
                while not result['finished']:
                    await asyncio.sleep(300)
                    if not result['finished']:
                        last = status_obj.get_last_status()
                        if last:
                            try:
                                await context.bot.send_message(
                                    chat_id=chat_id,
                                    text=f"⏳ Auto-status:\n{last}",
                                )
                            except Exception:  # noqa: BLE001
                                pass

            status_task = asyncio.create_task(auto_status())
            try:
                while not result['finished']:
                    await asyncio.sleep(1)
            finally:
                status_task.cancel()
                try:
                    await status_task
                except asyncio.CancelledError:
                    pass

            if result['error']:
                await update.message.reply_text(f"❌ {result['error']}")
            elif result['password']:
                files_list = "\n".join(result['files']) or "(none)"
                await update.message.reply_text(
                    f"✅ Password: `{result['password']}`\n\n"
                    f"📂 Extracted {len(result['files'])} file(s):\n{files_list}",
                    parse_mode='Markdown',
                )
            else:
                files_list = "\n".join(result['files']) or "(none)"
                await update.message.reply_text(
                    f"📂 Not encrypted (or pseudo-encryption fixed).\n"
                    f"Extracted {len(result['files'])} file(s):\n{files_list}"
                )

            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:  # noqa: BLE001
                pass

        def run(self) -> None:
            log_info("[*] Starting Telegram bot (long polling)...")
            self.application.run_polling()


# ============================== CLI ============================
def print_banner() -> None:
    banner = r"""
     ______               ____                _
    |__  (_)_ __       / ___|_ __ __ _  ___| | _____ _ __
      / /| | '_ \     | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) |    | |___| | | (_| | (__|   <  __/ |
    /____|_| .__/      \____|_|  \__,_|\___|_|\_\___|_|
           |_|        #Coded By rebnX (Web + Bot)
    """
    print(banner)


def print_usage() -> None:
    prog = sys.argv[0]
    print("\n--- Formats: ZIP, RAR, 7z, PDF ---")
    print(f"[*] CLI:  python {prog} YourFile.ext [options]")
    print("    Options:")
    print("      -m, --mask MASK       Mask attack (e.g. ?u?l?l?l?d?d)")
    print("      --numeric             Try 1-6 digit numeric after dictionary")
    print("      -o, --out DIR         Output dir (default: unzipped)")
    print("      --threads N           Worker threads (default: auto)")
    print("      --no-extract          Only find password, skip extraction")
    print("      --log FILE            Also write logs to FILE")
    print("      YourDict.txt          Custom dictionary")
    print("      YourDictDir/          Directory of .txt dictionaries")
    print(f"\n[*] Bot:   python {prog} --bot   (needs TELEGRAM_BOT_TOKEN env)")
    print(f"[*] Web:   python {prog} --web [--port PORT]")
    print(f"[*] Both:  python {prog} --all [--port PORT]")
    print("\nNo flags → CLI mode.")


def parse_arguments() -> Dict[str, Any]:
    if len(sys.argv) < 2:
        return {}
    args: Dict[str, Any] = {
        'file': None, 'out_dir': OUT_DIR_DEFAULT, 'dict_path': None,
        'mask': None, 'numeric': False, 'bot': False, 'web': False,
        'port': 5000, 'all': False, 'threads': None,
        'no_extract': False, 'log': None,
    }
    i = 1
    argv = sys.argv
    while i < len(argv):
        a = argv[i]
        if a == '--bot':
            args['bot'] = True; i += 1
        elif a == '--web':
            args['web'] = True; i += 1
            if i < len(argv) and argv[i].isdigit():
                args['port'] = int(argv[i]); i += 1
        elif a == '--all':
            args['all'] = True; i += 1
            if i < len(argv) and argv[i].isdigit():
                args['port'] = int(argv[i]); i += 1
        elif a == '--port':
            if i + 1 < len(argv) and argv[i + 1].isdigit():
                args['port'] = int(argv[i + 1]); i += 2
            else:
                print("[!] --port requires a number"); sys.exit(1)
        elif a == '--numeric':
            args['numeric'] = True; i += 1
        elif a == '--no-extract':
            args['no_extract'] = True; i += 1
        elif a == '--threads':
            if i + 1 < len(argv):
                try:
                    args['threads'] = int(argv[i + 1])
                except ValueError:
                    print("[!] --threads requires a number"); sys.exit(1)
                i += 2
            else:
                print("[!] --threads requires a value"); sys.exit(1)
        elif a == '--log':
            if i + 1 < len(argv):
                args['log'] = argv[i + 1]; i += 2
            else:
                print("[!] --log requires a filename"); sys.exit(1)
        elif a in ('-o', '--out'):
            if i + 1 < len(argv):
                args['out_dir'] = argv[i + 1]; i += 2
            else:
                print("[!] -o requires a directory"); sys.exit(1)
        elif a in ('-m', '--mask'):
            if i + 1 < len(argv):
                args['mask'] = argv[i + 1]; i += 2
            else:
                print("[!] -m requires a mask"); sys.exit(1)
        else:
            if args['file'] is None:
                args['file'] = a
            elif args['dict_path'] is None:
                args['dict_path'] = a
            i += 1
    return args


def main_cli(args: Dict[str, Any]) -> None:
    file_path = args.get('file')
    if not file_path:
        print_usage()
        return

    if not os.path.exists(file_path):
        log_error(f"[!] File not found: {file_path}")
        sys.exit(1)

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in SUPPORTED_EXTS:
        log_error(f"[!] Unsupported format: {ext}")
        sys.exit(1)

    if ext == '.rar' and not HAS_RARFILE:
        log_error("[!] RAR needs 'rarfile' + unrar."); sys.exit(1)
    if ext == '.7z' and not HAS_PY7ZR:
        log_error("[!] 7z needs 'py7zr'."); sys.exit(1)
    if ext == '.pdf' and not HAS_PYPDF2:
        log_error("[!] PDF needs 'PyPDF2'."); sys.exit(1)

    out_dir = args.get('out_dir', OUT_DIR_DEFAULT)

    # ---- ZIP: pseudo-encryption check ----
    if ext == '.zip':
        checker = ZipEncryptionChecker()
        if not checker.is_encrypted(file_path):
            log_info(f"[!] {file_path} is not encrypted. Extracting directly.")
            if os.path.exists(out_dir):
                shutil.rmtree(out_dir, ignore_errors=True)
            os.makedirs(out_dir, exist_ok=True)
            with zipfile.ZipFile(file_path) as zf:
                zf.extractall(path=out_dir)
            return

        log_info("[!] Encryption detected. Checking pseudo-encryption...")
        fixed_zip = f"{file_path}.{uuid.uuid4().hex}.fixed.tmp"
        try:
            checker.fix_pseudo_encryption(file_path, fixed_zip)
            with zipfile.ZipFile(fixed_zip) as zf:
                zf.testzip()
            log_info("[*] Pseudo-encryption fixed! No password needed.")
            if os.path.exists(out_dir):
                shutil.rmtree(out_dir, ignore_errors=True)
            os.makedirs(out_dir, exist_ok=True)
            with zipfile.ZipFile(fixed_zip) as zf:
                zf.extractall(path=out_dir)
            log_info(f"[*] Extracted to '{out_dir}'")
            return
        except Exception:  # noqa: BLE001
            log_info("[+] Truly encrypted file. Starting crack...")
        finally:
            if os.path.exists(fixed_zip):
                try:
                    os.remove(fixed_zip)
                except OSError:
                    pass

        # CRC attack for tiny files
        try:
            with zipfile.ZipFile(file_path) as zf:
                if CRCCracker.analyze_zip(file_path, zf, callback=log_info):
                    return
        except zipfile.BadZipFile:
            log_error(f"[!] '{file_path}' may be corrupted.")
            sys.exit(1)

    # ---- Build engine ----
    try:
        engine = AttackEngine(
            file_path, out_dir, ext,
            max_threads=args.get('threads'),
            no_extract=args.get('no_extract', False),
        )
    except UnsupportedFormatError as e:
        log_error(f"[!] {e}")
        sys.exit(1)

    if args.get('mask'):
        engine.attack_with_mask(args['mask'])
    elif args.get('dict_path'):
        engine.attack_with_directory(args['dict_path'])
    else:
        if os.path.exists('password_list.txt'):
            engine.attack_with_dictionary('password_list.txt', "Built-in Dictionary")
        else:
            log_info("[!] password_list.txt not found.")
        if args.get('numeric') and not engine.status.should_stop():
            engine.attack_with_numeric(1, 6)

    if not engine.found_password:
        log_info("\n[-] Password not found.")
    else:
        log_info(f"\n[+] Password found: {engine.found_password}")


# ============================== Main entry ============================
_shutdown_event = threading.Event()


def _sigint_handler(signum, frame):  # noqa: ARG001
    if not _shutdown_event.is_set():
        print("\n[!] Interrupted. Shutting down...")
        _shutdown_event.set()


def main() -> None:
    try:
        signal.signal(signal.SIGINT, _sigint_handler)
        signal.signal(signal.SIGTERM, _sigint_handler)

        print_banner()
        args = parse_arguments()

        # Logging (setup early so --log works)
        setup_logging(args.get('log'))

        # CLI-only mode
        if not (args.get('bot') or args.get('web') or args.get('all')):
            main_cli(args)
            return

        # Library checks
        if (args.get('bot') or args.get('all')) and not TELEGRAM_AVAILABLE:
            log_error("[!] python-telegram-bot not installed. Cannot start bot.")
            sys.exit(1)
        if (args.get('web') or args.get('all')) and not FLASK_AVAILABLE:
            log_error("[!] Flask not installed. Cannot start web server.")
            sys.exit(1)

        port = args.get('port', 5000)

        # Start cleanup thread
        threading.Thread(target=cleanup_worker, name="Cleanup", daemon=True).start()

        # Web in background
        if args.get('web') or args.get('all'):
            threading.Thread(
                target=run_web_server, args=(port,),
                name="WebServer", daemon=True,
            ).start()

        # Bot in main thread (required by python-telegram-bot signal handling)
        if args.get('bot') or args.get('all'):
            token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
            if not token:
                log_error(
                    "[!] TELEGRAM_BOT_TOKEN env var is not set. "
                    "Set it (and revoke any previously leaked tokens!) before --bot/--all."
                )
                if not args.get('web'):
                    sys.exit(1)
                log_info("[*] Continuing with web-only mode.")
            else:
                bot = ZipCrackerBot(token)
                log_info("[*] Starting Telegram bot in main thread...")
                bot.run()  # blocks
                return

        # Web-only: keep alive
        try:
            while not _shutdown_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        log_info("[!] Shutdown complete.")

    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as e:  # noqa: BLE001
        log_error(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()