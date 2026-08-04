#!/usr/bin/env python3
"""
Zip Cracker with Telegram Bot and Web Interface
Multi‑format support: ZIP, RAR, 7z, PDF
Coded by rebnX (Extended with Flask)
"""

import os
import shutil
import sys
import threading
import time
import zipfile
import binascii
import string
import itertools
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Tuple, Dict, Generator, Callable, Any
import asyncio
import base64
import tempfile
import uuid
import json

# ============================== Flask imports ============================
try:
    from flask import Flask, request, render_template_string, jsonify, redirect, url_for
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = None

# ============================== Telegram imports ==============================
try:
    from telegram import Update, Document
    from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False
    print("[!] python-telegram-bot not installed. Bot mode unavailable.")
    print("    Install with: pip install python-telegram-bot")

# ============================== Archive‑specific imports ============================
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
MAX_CRC_FILE_SIZE = 6
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
    '?': '?'
}

# ============================== Core Classes (unchanged) ===========================
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

class CRCCracker:
    @staticmethod
    def analyze_zip(zip_file: str, zf: zipfile.ZipFile, callback: Optional[Callable] = None) -> bool:
        file_list = [name for name in zf.namelist() if not name.endswith('/')]
        if not file_list:
            return False
        cracked_count = 0
        for filename in file_list:
            file_info = zf.getinfo(filename)
            file_size = file_info.file_size
            if 0 < file_size <= MAX_CRC_FILE_SIZE:
                if callback:
                    callback(f'[!] File "{filename}" is {file_size} bytes. Attempting CRC32 collision attack...')
                crc_value = file_info.CRC
                if callback:
                    callback(f'[+] CRC32 value for {filename}: {crc_value}')
                if CRCCracker.crack(filename, crc_value, file_size, callback):
                    cracked_count += 1
        if cracked_count >= len(file_list):
            if callback:
                callback('[*] All small files cracked via CRC32 collision. Skipping dictionary attack.')
            return True
        return False

    @staticmethod
    def crack(filename: str, target_crc: int, size: int, callback: Optional[Callable] = None) -> bool:
        if callback:
            callback(f"[+] Starting CRC32 collision attack on {filename}...")
        candidates = itertools.product(string.printable, repeat=size)
        for combination in candidates:
            content = ''.join(combination).encode()
            if binascii.crc32(content) == target_crc:
                if callback:
                    callback(f'[*] Success! Content of {filename}: {content.decode()}')
                return True
        if callback:
            callback(f'[-] CRC32 attack failed for {filename}')
        return False

class PasswordCracker:
    # Only for ZIP extraction; other formats will not auto‑extract
    def __init__(self, zip_file: str, out_dir: str):
        self.zip_file = zip_file
        self.out_dir = out_dir

    @staticmethod
    def _find_first_file(zf) -> Optional[str]:
        try:
            for info in zf.infolist():
                if not info.filename.endswith('/'):
                    return info.filename
        except Exception:
            try:
                for name in zf.namelist():
                    if not name.endswith('/'):
                        return name
            except Exception:
                pass
        return None

    def verify_password(self, password: str) -> bool:
        pwd_bytes = password.encode('utf-8')
        try:
            if HAS_PYZIPPER:
                with pyzipper.AESZipFile(self.zip_file, 'r') as zf:
                    first_file = self._find_first_file(zf)
                    if first_file:
                        zf.read(first_file, pwd=pwd_bytes)
                    else:
                        zf.testzip(pwd=pwd_bytes)
            else:
                with zipfile.ZipFile(self.zip_file, 'r') as zf:
                    first_file = self._find_first_file(zf)
                    if first_file:
                        zf.read(first_file, pwd=pwd_bytes)
                    else:
                        zf.testzip(pwd=pwd_bytes)
            return True
        except RuntimeError:
            return False
        except (zipfile.BadZipFile, Exception):
            return False

    def extract(self, password: str, callback: Optional[Callable] = None) -> List[str]:
        pwd_bytes = password.encode('utf-8')
        if os.path.exists(self.out_dir):
            try:
                shutil.rmtree(self.out_dir)
            except Exception:
                pass
        os.makedirs(self.out_dir, exist_ok=True)
        if HAS_PYZIPPER:
            with pyzipper.AESZipFile(self.zip_file, 'r') as zf:
                zf.extractall(path=self.out_dir, pwd=pwd_bytes)
                filenames = zf.namelist()
        else:
            with zipfile.ZipFile(self.zip_file, 'r') as zf:
                zf.extractall(path=self.out_dir, pwd=pwd_bytes)
                filenames = zf.namelist()
        if callback:
            callback(f"[*] Extracted {len(filenames)} file(s) to '{self.out_dir}'")
        return filenames

class AttackStatus:
    def __init__(self):
        self.stop = False
        self.tried_passwords: List[str] = []
        self.total_passwords = 0
        self.lock = threading.Lock()
        self.last_status = ""

    def add_tried_password(self, password: str) -> None:
        with self.lock:
            self.tried_passwords.append(password)

    def should_stop(self) -> bool:
        with self.lock:
            return self.stop

    def set_stop(self) -> None:
        with self.lock:
            self.stop = True

    def get_progress(self) -> Tuple[int, int]:
        with self.lock:
            return len(self.tried_passwords), self.total_passwords

    def set_last_status(self, msg: str) -> None:
        with self.lock:
            self.last_status = msg

    def get_last_status(self) -> str:
        with self.lock:
            return self.last_status

class ProgressDisplay:
    def __init__(self, status: AttackStatus, start_time: float, callback: Optional[Callable] = None):
        self.status = status
        self.start_time = start_time
        self.callback = callback
        self.thread = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._display_loop)
        self.thread.daemon = True
        self.thread.start()

    def _display_loop(self) -> None:
        while not self.status.should_stop():
            time.sleep(2)
            self._update_display()

    def _update_display(self) -> None:
        passwords_tried, total_passwords = self.status.get_progress()
        elapsed_time = time.time() - self.start_time
        speed = int(passwords_tried / elapsed_time) if elapsed_time > 0 else 0
        if total_passwords > 0:
            progress = (passwords_tried / total_passwords) * 100
            remaining = (total_passwords - passwords_tried) / speed if speed > 0 else 0
            remaining_str = time.strftime('%H:%M:%S', time.gmtime(remaining))
        else:
            progress = 0.0
            remaining_str = "N/A"
        with self.status.lock:
            current = self.status.tried_passwords[-1] if passwords_tried > 0 else ""
        msg = f"Progress: {progress:.2f}% | Time Left: {remaining_str} | Speed: {speed} pass/s | Trying: {current}"
        self.status.set_last_status(msg)
        if self.callback:
            self.callback(msg)
        else:
            print(f"\r[-] {msg}", end="", flush=True)

class MaskParser:
    @staticmethod
    def parse(mask: str) -> Tuple[List[str], int]:
        charsets = []
        i = 0
        while i < len(mask):
            if mask[i] == '?':
                if i + 1 < len(mask):
                    placeholder = mask[i + 1]
                    if placeholder in MASK_PLACEHOLDERS:
                        charsets.append(MASK_PLACEHOLDERS[placeholder])
                    else:
                        charsets.append(mask[i:i+2])
                    i += 2
                else:
                    charsets.append('?')
                    i += 1
            else:
                charsets.append(mask[i])
                i += 1
        total = 1
        for charset in charsets:
            if len(charset) > 0:
                total *= len(charset)
        return charsets, max(total, 1)

class DictionaryGenerator:
    @staticmethod
    def generate_numeric(min_length: int = 1, max_length: int = 6) -> Tuple[List[str], int]:
        passwords = []
        for length in range(min_length, max_length + 1):
            for combination in itertools.product(string.digits, repeat=length):
                passwords.append(''.join(combination))
        return passwords, len(passwords)

    @staticmethod
    def load_from_file(file_path: str, chunk_size: int = CHUNK_SIZE) -> Generator[List[str], None, None]:
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
        except Exception as e:
            print(f"[!] Failed to load dictionary file: {e}")
            sys.exit(1)

    @staticmethod
    def count_passwords(file_path: str) -> int:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0

# ============================== Format‑specific crackers (fixed) ===========================
class ZipCracker:
    @staticmethod
    def verify_password(file_path: str, password: str) -> bool:
        cracker = PasswordCracker(file_path, "dummy")
        return cracker.verify_password(password)

class RarCracker:
    @staticmethod
    def verify_password(file_path: str, password: str) -> bool:
        if not HAS_RARFILE:
            raise ImportError("rarfile library not installed.")
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                with rarfile.RarFile(file_path) as rf:
                    rf.extractall(path=tmpdir, pwd=password)
                return True
        except Exception:
            return False

class SevenZCracker:
    @staticmethod
    def verify_password(file_path: str, password: str) -> bool:
        if not HAS_PY7ZR:
            raise ImportError("py7zr library not installed.")
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                with py7zr.SevenZipFile(file_path, mode='r', password=password) as szf:
                    szf.extractall(path=tmpdir)
                return True
        except Exception:
            return False

class PdfCracker:
    @staticmethod
    def verify_password(file_path: str, password: str) -> bool:
        if not HAS_PYPDF2:
            raise ImportError("PyPDF2 library not installed.")
        try:
            with open(file_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                if reader.is_encrypted:
                    return reader.decrypt(password) == 1
                else:
                    return True
        except Exception:
            return False

# Factory to get the appropriate cracker
class FormatCrackerFactory:
    @staticmethod
    def get_cracker(ext: str):
        ext = ext.lower()
        if ext == '.zip':
            return ZipCracker()
        elif ext == '.rar':
            return RarCracker()
        elif ext == '.7z':
            return SevenZCracker()
        elif ext == '.pdf':
            return PdfCracker()
        else:
            return None

# ============================== AttackEngine (generic) ===========================
class AttackEngine:
    def __init__(self, file_path: str, out_dir: str, file_ext: str, status_callback: Optional[Callable] = None):
        self.file_path = file_path
        self.out_dir = out_dir
        self.file_ext = file_ext.lower()
        self.cracker = FormatCrackerFactory.get_cracker(self.file_ext)
        if self.cracker is None:
            raise ValueError(f"Unsupported file format: {file_ext}")
        self.status = AttackStatus()
        self.max_threads = self._calculate_threads()
        self.status_callback = status_callback
        self.found_password = None

    def _log(self, msg: str) -> None:
        if self.status_callback:
            self.status_callback(msg)
        else:
            print(msg)

    @staticmethod
    def _calculate_threads(max_limit: int = 128) -> int:
        try:
            cpu_count = multiprocessing.cpu_count()
            return min(max_limit, cpu_count * 4)
        except NotImplementedError:
            return 16

    def _try_password(self, password: str) -> bool:
        if self.status.should_stop():
            return False
        try:
            is_correct = self.cracker.verify_password(self.file_path, password)
        except ImportError as e:
            self._log(f"[!] Missing library: {e}. Cannot crack this file type.")
            self.status.set_stop()
            return False

        if is_correct:
            self.found_password = password
            self.status.set_stop()
            self._log(f'\n[+] SUCCESS! Password found: {password}')
            # Extraction only for ZIP files
            if self.file_ext == '.zip':
                try:
                    cracker = PasswordCracker(self.file_path, self.out_dir)
                    filenames = cracker.extract(password, callback=self._log)
                    self._log(f"[*] Extracted files: {filenames}")
                except Exception as e:
                    self._log(f"\n[!] Extraction failed: {e}")
            else:
                self._log(f"[*] File format {self.file_ext} cannot be auto‑extracted. Password found only.")
            return True
        else:
            self.status.add_tried_password(password)
            return False

    def attack_with_mask(self, mask: str) -> None:
        charsets, total = MaskParser.parse(mask)
        if total > MAX_MASK_COMBINATIONS:
            self._log(f"[!] Warning: Mask '{mask}' generates {total:,} combinations. This may take a very long time.")
        self._log(f"\n[+] Starting mask attack: '{mask}'")
        self._log(f"[+] Total combinations: {total:,}")
        self._log(f"[+] Using {self.max_threads} threads")
        self.status.total_passwords = total
        start_time = time.time()
        progress = ProgressDisplay(self.status, start_time, callback=self._log)
        progress.start()
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                password_gen = (''.join(p) for p in itertools.product(*charsets))
                while not self.status.should_stop():
                    chunk = list(itertools.islice(password_gen, MASK_CHUNK_SIZE))
                    if not chunk:
                        break
                    futures = {executor.submit(self._try_password, pwd) for pwd in chunk}
                    for future in as_completed(futures):
                        if self.status.should_stop():
                            break
        finally:
            if not self.status.should_stop():
                self._log('\n[-] All mask combinations tried. Password not found.')

    def attack_with_dictionary(self, dict_path: str, dict_name: str = "Dictionary") -> None:
        total = DictionaryGenerator.count_passwords(dict_path)
        self._log(f"\n[+] Loaded {dict_name}: {dict_path}")
        self._log(f"[+] Total passwords: {total:,}")
        self._log(f"[+] Using {self.max_threads} threads")
        self.status.total_passwords = total
        start_time = time.time()
        progress = ProgressDisplay(self.status, start_time, callback=self._log)
        progress.start()
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                for chunk in DictionaryGenerator.load_from_file(dict_path):
                    if self.status.should_stop():
                        break
                    futures = {executor.submit(self._try_password, pwd) for pwd in chunk}
                    for future in as_completed(futures):
                        if self.status.should_stop():
                            break
        finally:
            if not self.status.should_stop():
                self._log(f'\n[-] All passwords in {dict_path} tried. Password not found.')

    def attack_with_numeric(self, min_len: int = 1, max_len: int = 6) -> None:
        self._log(f"\n[+] Trying {min_len}-{max_len} digit numeric dictionary...")
        numeric_dict, total = DictionaryGenerator.generate_numeric(min_len, max_len)
        self._log(f"[+] Generated numeric dictionary: {total:,} passwords")
        self._log(f"[+] Using {self.max_threads} threads")
        self.status.total_passwords = total
        start_time = time.time()
        progress = ProgressDisplay(self.status, start_time, callback=self._log)
        progress.start()
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(self._try_password, pwd) for pwd in numeric_dict}
                for future in as_completed(futures):
                    if self.status.should_stop():
                        break
        finally:
            if not self.status.should_stop():
                self._log('\n[-] All numeric passwords tried. Password not found.')

    def attack_with_directory(self, dir_path: str) -> None:
        if os.path.isfile(dir_path):
            self.attack_with_dictionary(dir_path, "Custom Dictionary")
        elif os.path.isdir(dir_path):
            for filename in sorted(os.listdir(dir_path)):
                if self.status.should_stop():
                    return
                file_path = os.path.join(dir_path, filename)
                self.attack_with_directory(file_path)

# ============================== Flask Web Interface ===========================
if FLASK_AVAILABLE:
    app = Flask(__name__)
    # Global dictionary to store job status
    jobs = {}
    jobs_lock = threading.Lock()

    def run_cracking_job(job_id: str, file_path: str, out_dir: str, ext: str,
                         mask: Optional[str], dict_file: Optional[str], numeric: bool):
        """Background task for web cracking."""
        try:
            # For ZIP pseudo‑encryption check
            if ext == '.zip':
                checker = ZipEncryptionChecker()
                if not checker.is_encrypted(file_path):
                    with zipfile.ZipFile(file_path) as zf:
                        os.makedirs(out_dir, exist_ok=True)
                        zf.extractall(path=out_dir)
                        filenames = zf.namelist()
                    with jobs_lock:
                        jobs[job_id]['status'] = 'done'
                        jobs[job_id]['result'] = {'password': None, 'files': filenames, 'error': None}
                    return

                fixed_zip = file_path + ".fixed.tmp"
                try:
                    checker.fix_pseudo_encryption(file_path, fixed_zip)
                    with zipfile.ZipFile(fixed_zip) as test_zf:
                        test_zf.testzip()
                    os.makedirs(out_dir, exist_ok=True)
                    with zipfile.ZipFile(fixed_zip) as zf:
                        zf.extractall(path=out_dir)
                        filenames = zf.namelist()
                    os.remove(fixed_zip)
                    with jobs_lock:
                        jobs[job_id]['status'] = 'done'
                        jobs[job_id]['result'] = {'password': None, 'files': filenames, 'error': None}
                    return
                except Exception:
                    if os.path.exists(fixed_zip):
                        os.remove(fixed_zip)
                    # truly encrypted, proceed

            # Set up progress callback
            status_obj = AttackStatus()
            def progress_callback(msg: str):
                status_obj.set_last_status(msg)
                with jobs_lock:
                    jobs[job_id]['progress'] = msg

            engine = AttackEngine(file_path, out_dir, ext, progress_callback)
            engine.status = status_obj

            if mask:
                engine.attack_with_mask(mask)
            elif dict_file:
                engine.attack_with_dictionary(dict_file, "Uploaded Dictionary")
            else:
                # default: try password_list.txt
                if os.path.exists('password_list.txt'):
                    engine.attack_with_dictionary('password_list.txt', "Built-in Dictionary")
                else:
                    progress_callback("[!] password_list.txt not found. Skipping dictionary.")
                if numeric:
                    if not engine.found_password:
                        engine.attack_with_numeric(min_len=1, max_len=6)

            if engine.found_password:
                # If ZIP and not extracted, extract now
                if ext == '.zip':
                    try:
                        cracker = PasswordCracker(file_path, out_dir)
                        filenames = cracker.extract(engine.found_password)
                    except Exception as e:
                        filenames = []
                        progress_callback(f"[!] Extraction failed: {e}")
                else:
                    filenames = []
                with jobs_lock:
                    jobs[job_id]['status'] = 'done'
                    jobs[job_id]['result'] = {'password': engine.found_password, 'files': filenames, 'error': None}
            else:
                with jobs_lock:
                    jobs[job_id]['status'] = 'done'
                    jobs[job_id]['result'] = {'password': None, 'files': [], 'error': 'Password not found after all attempts.'}

        except Exception as e:
            with jobs_lock:
                jobs[job_id]['status'] = 'done'
                jobs[job_id]['result'] = {'password': None, 'files': [], 'error': str(e)}
        finally:
            # Cleanup uploaded file and temp dir
            try:
                shutil.rmtree(os.path.dirname(file_path))
            except Exception:
                pass

    # HTML template for the web interface
    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZIP Password Cracker</title>
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
                    <label for="file">Upload file (ZIP, RAR, 7z, PDF):</label>
                    <input type="file" class="form-control-file" name="file" id="file" required>
                </div>
                <div class="form-group">
                    <label for="dict">Optional custom dictionary (.txt):</label>
                    <input type="file" class="form-control-file" name="dict" id="dict" accept=".txt">
                </div>
                <div class="form-group">
                    <label for="mask">Mask (e.g., ?u?l?l?l?d?d):</label>
                    <input type="text" class="form-control" name="mask" id="mask" placeholder="?d?d?d?d">
                    <small class="form-text text-muted">?d=digit, ?l=lowercase, ?u=uppercase, ?s=symbols, ??=literal '?'</small>
                </div>
                <div class="form-check">
                    <input type="checkbox" class="form-check-input" name="numeric" id="numeric" value="yes">
                    <label class="form-check-label" for="numeric">Also try 1-6 digit numeric (after dictionary)</label>
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
                            var files = data.result.files.join('\\n') || '(none)';
                            $('#status').html('<div class="alert alert-success">✅ Password: <strong>' + data.result.password + '</strong><br>Extracted ' + data.result.files.length + ' file(s):<br><pre>' + files + '</pre></div>');
                        } else {
                            $('#status').html('<div class="alert alert-success">📂 File is not encrypted (or pseudo-encryption fixed).<br>Extracted ' + data.result.files.length + ' file(s):<br><pre>' + data.result.files.join('\\n') + '</pre></div>');
                        }
                    } else {
                        $('#status').html('<div class="alert alert-secondary">Waiting for job to start...</div>');
                    }
                });
            }
            $(document).ready(function() {
                var urlParams = new URLSearchParams(window.location.search);
                var jobId = urlParams.get('job');
                if (jobId) {
                    $('#status').html('<div class="alert alert-secondary">Loading status...</div>');
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
        if 'file' not in request.files:
            return "No file uploaded", 400
        uploaded = request.files['file']
        if uploaded.filename == '':
            return "Empty filename", 400

        # Validate extension
        ext = os.path.splitext(uploaded.filename)[1].lower()
        if ext not in ['.zip', '.rar', '.7z', '.pdf']:
            return "Unsupported file format", 400

        # Save file to temp directory
        job_id = str(uuid.uuid4())
        temp_dir = os.path.join(tempfile.gettempdir(), f"web_job_{job_id}")
        os.makedirs(temp_dir, exist_ok=True)
        file_path = os.path.join(temp_dir, uploaded.filename)
        uploaded.save(file_path)

        # Optional dictionary
        dict_file = None
        if 'dict' in request.files and request.files['dict'].filename != '':
            dict_uploaded = request.files['dict']
            dict_path = os.path.join(temp_dir, dict_uploaded.filename)
            dict_uploaded.save(dict_path)
            dict_file = dict_path

        mask = request.form.get('mask', '').strip()
        if mask == '':
            mask = None
        numeric = request.form.get('numeric') == 'yes'

        out_dir = os.path.join(temp_dir, "extracted")

        # Initialize job entry
        with jobs_lock:
            jobs[job_id] = {
                'status': 'running',
                'progress': 'Starting...',
                'result': None
            }

        # Start cracking in background
        thread = threading.Thread(
            target=run_cracking_job,
            args=(job_id, file_path, out_dir, ext, mask, dict_file, numeric)
        )
        thread.daemon = True
        thread.start()

        return redirect(url_for('index', job=job_id))

    @app.route('/status/<job_id>')
    def status(job_id):
        with jobs_lock:
            if job_id not in jobs:
                return jsonify({'status': 'unknown'}), 404
            job = jobs[job_id]
            if job['status'] == 'running':
                return jsonify({'status': 'running', 'progress': job.get('progress', '')})
            elif job['status'] == 'done':
                return jsonify({'status': 'done', 'result': job['result']})
            else:
                return jsonify({'status': 'unknown'})

    def run_web_server(port=5000):
        print(f"[*] Starting web server on port {port}...")
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

# ============================== Telegram Bot (unchanged) ===========================
class ZipCrackerBot:
    def __init__(self, token: str):
        self.token = token
        self.application = Application.builder().token(token).build()
        self._register_handlers()
        self.user_data = {}

    def _register_handlers(self):
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("status", self.status_command))
        self.application.add_handler(CommandHandler("numeric", self.numeric_command))
        self.application.add_handler(CommandHandler("default", self.default_command))
        self.application.add_handler(MessageHandler(filters.Document.ALL, self.handle_document))

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "👋 Hello! I'm a multi‑format password cracker.\n"
            "Supported: ZIP, RAR, 7z, PDF.\n"
            "Send me a file and I'll try to crack it.\n\n"
            "Use /help for detailed instructions."
        )

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        help_encoded = (
            "8J+UlyAqSG93IHRvIHVzZSB0aGlzIGJvdCoqCgoxLiDinqggRGVmYXVsdCBNb2RlIChubyBleHRyYSBjb21tYW5kcyk6CiAgIFNlbmQgYSBzdXBwb3J0ZWQgZmlsZSAoWklQLCBSQVIsIDd6LCBQREYpIOKGkiBJ4oCZbGwgdHJ5IGBwYXNzd29yZF9saXN0LnR4dGAgKGlmIHByZXNlbnQpLCB0aGVuIHN0b3AgKG5vIG51bWVyaWMgZmFsbGJhY2spLgoKMi4g4p+pIE51bWVyaWMgTW9kZSAob3B0aW9uYWwpOgogICBUeXBlIGAvbnVtZXJpY2AgdGhlbiBzZW5kIGEgZmlsZSDihpIgSeKAmWxsIHRyeSAxLTYgZGlnaXQgbnVtZXJpYyBQSU5zIGFmdGVyIHRoZSBkaWN0aW9uYXJ5LgoKMy4g4p+qIE1hc2sgQXR0YWNrOgogICBTZW5kIGEgZmlsZSB3aXRoIGNhcHRpb24gYG1hc2s6ID91P2w/bD9sP2Q/ZGAgKG9yIGFueSBtYXNrKS4KICAgUGxhY2Vob2xkZXJzOiBgP2Q9ZGlnaXRzLCBgP2w9bG93ZXJjYXNlLCBgP3U9dXBwZXJjYXNlLCBgP3M9c3ltYm9scywgYD8/PWxpdGVyYWwgJz8nCgo0LiDin6sgQ3VzdG9tIERpY3Rpb25hcnk6CiAgIFVwbG9hZCBhIGAudHh0YCBkaWN0aW9uYXJ5IGZpbGUgYWxvbmcgd2l0aCB0aGUgdGFyZ2V0IGZpbGUsIGFuZCBjYXB0aW9uIHRoZSB0YXJnZXQgd2l0aCBgZGljdDogZmlsZW5hbWUudHh0YC4KICAgRXhhbXBsZTogU2VuZCBhIFpJUCB3aXRoIGNhcHRpb24gYGRpY3Q6IG15cGFzc3dvcmRzLnR4dGAgKGFuZCBhbHNvIHVwbG9hZCBteXBhc3N3b3Jkcy50eHQpLgoKNS4g4p+rIENoZWNrIFByb2dyZXNzOgogICBXaGlsZSBjcmFja2luZywgdXNlIGAvc3RhdHVzYCB0byBzZWUgY3VycmVudCBwcm9ncmVzcyAoJSwgc3BlZWQsIHRyaWVkIHBhc3N3b3JkcykuCgo2LiDin6wgUmVzZXQgdG8gRGVmYXVsdDoKICAgYC9kZWZhdWx0YCDigJMgeWVzZXRzIHRvIGRlZmF1bHQgZGljdGlvbmFyeS1vbmx5IG1vZGUuCgrilqAgTm90ZTogVGhlIGJvdCB3aWxsIG9ubHkgY3JhY2sgb25lIGZpbGUgYXQgYSB0aW1lIHBlciB1c2VyLg=="
        )
        help_text = base64.b64decode(help_encoded).decode('utf-8')
        await update.message.reply_text(help_text)

    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if user_id in self.user_data and 'status' in self.user_data[user_id]:
            status_obj = self.user_data[user_id]['status']
            last_msg = status_obj.get_last_status()
            if last_msg:
                await update.message.reply_text(f"📊 Current progress:\n{last_msg}")
            else:
                await update.message.reply_text("⏳ Cracking started, but no progress update yet. Please wait.")
        else:
            await update.message.reply_text("❌ No cracking activity for you right now.")

    async def numeric_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if user_id not in self.user_data:
            self.user_data[user_id] = {}
        self.user_data[user_id]['mode'] = 'numeric'
        await update.message.reply_text("✅ Numeric mode set. Next file will try 1-6 digit numbers after dictionary.")

    async def default_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if user_id not in self.user_data:
            self.user_data[user_id] = {}
        self.user_data[user_id]['mode'] = 'default'
        await update.message.reply_text("✅ Reset to default mode (dictionary only).")

    async def handle_document(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if user_id not in self.user_data:
            self.user_data[user_id] = {}

        document = update.message.document
        caption = update.message.caption or ""

        # Check if it's a dictionary file (.txt)
        if document.file_name.endswith('.txt'):
            temp_dir = f"temp_{user_id}"
            os.makedirs(temp_dir, exist_ok=True)
            dict_path = os.path.join(temp_dir, document.file_name)
            file = await document.get_file()
            await file.download_to_drive(dict_path)
            self.user_data[user_id]['dict_file'] = dict_path
            await update.message.reply_text(f"✅ Dictionary '{document.file_name}' saved. Now send a target file.")
            return

        # Determine file extension
        ext = os.path.splitext(document.file_name)[1].lower()
        if ext not in ['.zip', '.rar', '.7z', '.pdf']:
            await update.message.reply_text("❌ Unsupported file format. Only ZIP, RAR, 7z, and PDF are allowed.")
            return

        # Check for missing libraries
        if ext == '.rar' and not HAS_RARFILE:
            await update.message.reply_text("❌ RAR support is not available. Install 'rarfile' and 'unrar'.")
            return
        if ext == '.7z' and not HAS_PY7ZR:
            await update.message.reply_text("❌ 7z support is not available. Install 'py7zr'.")
            return
        if ext == '.pdf' and not HAS_PYPDF2:
            await update.message.reply_text("❌ PDF support is not available. Install 'PyPDF2'.")
            return

        dict_file = self.user_data[user_id].get('dict_file')
        mask = None
        custom_dict = None
        if caption:
            if caption.startswith('mask:'):
                mask = caption.split('mask:', 1)[1].strip()
            elif caption.startswith('dict:'):
                if dict_file:
                    custom_dict = dict_file
                else:
                    await update.message.reply_text("❌ No dictionary file found. Upload a .txt file first.")
                    return

        mode = self.user_data[user_id].get('mode', 'default')

        await update.message.reply_text(f"📥 Downloading {ext} file...")
        temp_dir = f"temp_{user_id}"
        os.makedirs(temp_dir, exist_ok=True)
        file_path = os.path.join(temp_dir, document.file_name)
        file = await document.get_file()
        await file.download_to_drive(file_path)

        await update.message.reply_text("🔍 Analyzing and cracking... (use /status or wait for auto‑updates)")

        out_dir = os.path.join(temp_dir, "extracted")
        result = {
            'password': None,
            'files': [],
            'error': None,
            'finished': False,
        }

        status_obj = AttackStatus()
        self.user_data[user_id]['status'] = status_obj

        def progress_callback(msg: str):
            status_obj.set_last_status(msg)

        def crack_task():
            try:
                # For ZIP we can do pseudo‑encryption fix, but skip for others
                if ext == '.zip':
                    checker = ZipEncryptionChecker()
                    if not checker.is_encrypted(file_path):
                        with zipfile.ZipFile(file_path) as zf:
                            os.makedirs(out_dir, exist_ok=True)
                            zf.extractall(path=out_dir)
                            filenames = zf.namelist()
                        result['files'] = filenames
                        result['finished'] = True
                        return

                    fixed_zip = file_path + ".fixed.tmp"
                    try:
                        checker.fix_pseudo_encryption(file_path, fixed_zip)
                        with zipfile.ZipFile(fixed_zip) as test_zf:
                            test_zf.testzip()
                        os.makedirs(out_dir, exist_ok=True)
                        with zipfile.ZipFile(fixed_zip) as zf:
                            zf.extractall(path=out_dir)
                            filenames = zf.namelist()
                        os.remove(fixed_zip)
                        result['files'] = filenames
                        result['finished'] = True
                        return
                    except Exception:
                        if os.path.exists(fixed_zip):
                            os.remove(fixed_zip)
                        # truly encrypted, proceed

                # Create the attack engine
                engine = AttackEngine(file_path, out_dir, ext, progress_callback)
                engine.status = status_obj

                if mask:
                    engine.attack_with_mask(mask)
                elif custom_dict:
                    engine.attack_with_dictionary(custom_dict, "Custom Dictionary")
                elif dict_file:
                    engine.attack_with_dictionary(dict_file, "Uploaded Dictionary")
                else:
                    if os.path.exists('password_list.txt'):
                        engine.attack_with_dictionary('password_list.txt', "Built-in Dictionary")
                    else:
                        progress_callback("[!] password_list.txt not found. Skipping dictionary.")

                    if mode == 'numeric':
                        if not engine.found_password:
                            engine.attack_with_numeric(min_len=1, max_len=6)

                if engine.found_password:
                    result['password'] = engine.found_password
                    # If ZIP and not already extracted, extract now
                    if ext == '.zip' and not result['files']:
                        try:
                            cracker = PasswordCracker(file_path, out_dir)
                            result['files'] = cracker.extract(engine.found_password)
                        except Exception as e:
                            progress_callback(f"[!] Extraction failed: {e}")
                else:
                    result['error'] = "Password not found after all attempts."

                result['finished'] = True

            except Exception as e:
                result['error'] = str(e)
                result['finished'] = True

        thread = threading.Thread(target=crack_task)
        thread.start()

        # Auto‑status updater (every 5 minutes)
        chat_id = update.effective_chat.id
        async def auto_status_updater():
            while not result['finished']:
                await asyncio.sleep(300)  # 5 minutes
                if not result['finished']:
                    last = status_obj.get_last_status()
                    if last:
                        await context.bot.send_message(chat_id=chat_id, text=f"⏳ Auto‑status update:\n{last}")

        status_task = asyncio.create_task(auto_status_updater())

        while not result['finished']:
            await asyncio.sleep(1)

        status_task.cancel()
        try:
            await status_task
        except asyncio.CancelledError:
            pass

        # Send final result
        if result['error']:
            await update.message.reply_text(f"❌ {result['error']}")
        elif result['password'] is not None:
            files_list = "\n".join(result['files']) if result['files'] else "(none)"
            await update.message.reply_text(
                f"✅ **Password found:** `{result['password']}`\n\n"
                f"📂 Extracted {len(result['files'])} file(s):\n{files_list}",
                parse_mode='Markdown'
            )
        else:
            files_list = "\n".join(result['files']) if result['files'] else "(none)"
            await update.message.reply_text(
                f"📂 The file is not encrypted (or pseudo‑encryption fixed).\n"
                f"Extracted {len(result['files'])} file(s):\n{files_list}"
            )

        # Cleanup
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass

    def run(self):
        print("[*] Starting Telegram bot...")
        self.application.run_polling()

# ============================== CLI ====================================
def print_banner():
    banner = r"""                          
     ______               ____                _
    |__  (_)_ __       / ___|_ __ __ _  ___| | _____ _ __ 
      / /| | '_ \     | |   | '__/ _ |/ __| |/ / _ \ '__|
     / /_| | |_) |    | |___| | | (_| | (__|   <  __/ |   
    /____|_| .__/      \____|_|  \__,_|\___|_|\_\___|_|   
           |_|                                  
    #Coded By rebnX (Web + Bot)
    """
    print(banner)

def print_usage():
    prog = sys.argv[0]
    print("\n--- Supported formats: ZIP, RAR, 7z, PDF ---")
    print(f"[*] CLI usage: python {prog} YourFile.ext [options]")
    print("    Options: -m MASK, --numeric, -o OUTDIR, YourDict.txt")
    print("\n--- Telegram Bot ---")
    print(f"    python {prog} --bot")
    print("\n--- Web Server ---")
    print(f"    python {prog} --web [--port PORT]")
    print("\n--- Both Bot and Web ---")
    print(f"    python {prog} --all [--port PORT]")
    print("\nIf no flag is given, CLI mode is used.")

def parse_arguments():
    if len(sys.argv) < 2:
        return {}
    args = {
        'file': None,
        'out_dir': OUT_DIR_DEFAULT,
        'dict_path': None,
        'mask': None,
        'numeric': False,
        'bot': False,
        'web': False,
        'port': 5000,
        'all': False
    }
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '--bot':
            args['bot'] = True
            i += 1
        elif sys.argv[i] == '--web':
            args['web'] = True
            i += 1
            if i < len(sys.argv) and sys.argv[i].isdigit():
                args['port'] = int(sys.argv[i])
                i += 1
        elif sys.argv[i] == '--all':
            args['all'] = True
            i += 1
            if i < len(sys.argv) and sys.argv[i].isdigit():
                args['port'] = int(sys.argv[i])
                i += 1
        elif sys.argv[i] == '--port':
            if i + 1 < len(sys.argv) and sys.argv[i+1].isdigit():
                args['port'] = int(sys.argv[i+1])
                i += 2
            else:
                print("[!] Error: --port requires a number")
                sys.exit(1)
        elif sys.argv[i] == '--numeric':
            args['numeric'] = True
            i += 1
        elif sys.argv[i] in ['-o', '--out']:
            if i + 1 < len(sys.argv):
                args['out_dir'] = sys.argv[i + 1]
                i += 2
            else:
                print("[!] Error: No directory after -o")
                sys.exit(1)
        elif sys.argv[i] in ['-m', '--mask']:
            if i + 1 < len(sys.argv):
                args['mask'] = sys.argv[i + 1]
                i += 2
            else:
                print("[!] Error: No mask string after -m")
                sys.exit(1)
        else:
            if args['file'] is None:
                args['file'] = sys.argv[i]
            elif args['dict_path'] is None:
                args['dict_path'] = sys.argv[i]
            i += 1
    return args

def main_cli(args):
    file_path = args.get('file')
    if not file_path:
        print_usage()
        sys.exit(0)

    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' not found.")
        sys.exit(1)

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in ['.zip', '.rar', '.7z', '.pdf']:
        print(f"[!] Unsupported file format: {ext}. Only ZIP, RAR, 7z, PDF are supported.")
        sys.exit(1)

    out_dir = args.get('out_dir', OUT_DIR_DEFAULT)

    # Warn about missing libraries
    if ext == '.rar' and not HAS_RARFILE:
        print("[!] RAR support requires 'rarfile' and 'unrar'. Install them.")
        sys.exit(1)
    if ext == '.7z' and not HAS_PY7ZR:
        print("[!] 7z support requires 'py7zr'. Install it.")
        sys.exit(1)
    if ext == '.pdf' and not HAS_PYPDF2:
        print("[!] PDF support requires 'PyPDF2'. Install it.")
        sys.exit(1)

    # For ZIP, we can use existing pseudo‑encryption check
    if ext == '.zip':
        checker = ZipEncryptionChecker()
        if not checker.is_encrypted(file_path):
            print(f'[!] {file_path} is not encrypted. Extract directly.')
            sys.exit(0)

        print(f'[!] Encryption detected. Checking for pseudo‑encryption...')
        fixed_zip = file_path + ".fixed.tmp"
        is_truly_encrypted = False
        try:
            checker.fix_pseudo_encryption(file_path, fixed_zip)
            with zipfile.ZipFile(fixed_zip) as test_zf:
                test_zf.testzip()
            print(f"[*] Pseudo‑encryption fixed! No password needed.")
            if os.path.exists(out_dir):
                shutil.rmtree(out_dir)
            os.makedirs(out_dir, exist_ok=True)
            with zipfile.ZipFile(fixed_zip) as zf:
                zf.extractall(path=out_dir)
                print(f"[*] Extracted to '{out_dir}'")
            os.remove(fixed_zip)
            sys.exit(0)
        except Exception:
            is_truly_encrypted = True
            print('[+] Truly encrypted file detected. Starting crack...')
            if os.path.exists(fixed_zip):
                os.remove(fixed_zip)

        # For ZIP, we also have CRC attack
        if is_truly_encrypted:
            try:
                with zipfile.ZipFile(file_path) as zf:
                    if CRCCracker.analyze_zip(file_path, zf):
                        sys.exit(0)
            except zipfile.BadZipFile:
                print(f"[!] '{file_path}' may be corrupted.")
                sys.exit(1)

    # Create engine for all formats
    try:
        engine = AttackEngine(file_path, out_dir, ext)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    if args.get('mask'):
        engine.attack_with_mask(args['mask'])
    elif args.get('dict_path'):
        engine.attack_with_directory(args['dict_path'])
    else:
        if os.path.exists('password_list.txt'):
            engine.attack_with_dictionary('password_list.txt', "Built-in Dictionary")
        else:
            print("[!] Built-in dictionary not found.")
        if args.get('numeric') and not engine.status.should_stop():
            engine.attack_with_numeric()

    if not engine.found_password:
        print("\n[-] Password not found.")
    else:
        print(f"\n[+] Password found: {engine.found_password}")

# ============================== Main Entry ====================================
def main():
    try:
        print_banner()
        args = parse_arguments()

        # If no special flags, run CLI
        if not args.get('bot') and not args.get('web') and not args.get('all'):
            main_cli(args)
            return

        # Check required libraries
        if args.get('bot') or args.get('all'):
            if not TELEGRAM_AVAILABLE:
                print("[!] python-telegram-bot not installed. Cannot start bot.")
                sys.exit(1)

        if args.get('web') or args.get('all'):
            if not FLASK_AVAILABLE:
                print("[!] Flask not installed. Cannot start web server.")
                sys.exit(1)

        port = args.get('port', 5000)

        # Start web server in background thread (if requested)
        if args.get('web') or args.get('all'):
            t = threading.Thread(target=run_web_server, args=(port,), daemon=True)
            t.start()
            print(f"[*] Web server started on port {port} (background)")

        # If bot is requested, run it in the main thread (blocking)
        if args.get('bot') or args.get('all'):
            token = os.environ.get("TELEGRAM_BOT_TOKEN", "8469497827:AAF6fhL2EE2-pP3ESRRlWjLq5woWbW3AYIY")
            bot = ZipCrackerBot(token)
            print("[*] Starting Telegram bot in main thread...")
            bot.run()   # This blocks until bot stops
        else:
            # If only web server is running, keep main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[!] Shutting down...")
                sys.exit(0)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    except Exception as e:
        print(f'\n[!] Unexpected error: {e}')
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()