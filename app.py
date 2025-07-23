# --- START OF FILE app.py ---

import os
import uuid
import glob
import subprocess
import sys
import random
import json
import time
import psutil
import math
import re
import shutil
import requests
import threading
import io
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, Response, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, TypeDecorator

# --- App Configuration & DB ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-long-and-random-secret-key-for-gakuma'
# Define the data directory path provided by Render
DATA_DIR = os.path.join(os.environ.get('RENDER_INSTANCE_DIR', '.'), 'data')

# Create the data directory if it doesn't exist
os.makedirs(DATA_DIR, exist_ok=True)

# Set the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(DATA_DIR, "gakuma_panel.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
DATABASE_FOLDERS = ['database', 'database1', 'database2', 'database3', 'database4', 'database5', 'database6']
PRIVATE_DATABASE_FOLDER = 'private'
INFO_DATABASE_FOLDER = 'info_database'
ADMIN_DATABASE_FOLDER = 'admin_database'
CHECKER_RESULTS_PATH = 'checker_results'

db = SQLAlchemy(app)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "kupal"
RUNNING_BOTS_STATE_FILE = os.path.join(DATA_DIR, "running_bots.json")
EVENT_LOG_FILE = os.path.join(DATA_DIR, "events.log")

# --- Bot & Admin Configuration ---
BOT_TOKEN = "7607247495:AAHxmuG9tV_8o5DDm0LhtEGxRHc2WUw8HXw"
ADMIN_TELEGRAM_ID = 5163892491
FEEDBACK_POINTS = 2
INTERNAL_API_SECRET = "a-super-secret-key-for-internal-api-calls"


# --- Concurrency Control for File Access ---
file_locks = {}
lock_for_locks_dict = threading.Lock()

def get_lock_for_file(file_path):
    with lock_for_locks_dict:
        if file_path not in file_locks:
            file_locks[file_path] = threading.Lock()
        return file_locks[file_path]

# --- DB Models & Helpers ---
class TZDateTime(TypeDecorator):
    impl = db.DateTime
    cache_ok = True
    def process_bind_param(self, value, dialect):
        if value is not None:
            if not value.tzinfo: raise TypeError("tzinfo is required")
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    def process_result_value(self, value, dialect):
        if value is not None: value = value.replace(tzinfo=timezone.utc)
        return value

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_string = db.Column(db.String(36), unique=True, nullable=False, default=lambda: f"GAKUMA-{str(uuid.uuid4())[:8].upper()}")
    duration_str = db.Column(db.String(20), nullable=False)
    expires_at = db.Column(TZDateTime, nullable=True)
    is_used = db.Column(db.Boolean, default=False)
    telegram_user_id = db.Column(db.String(100), nullable=True)
    telegram_username = db.Column(db.String(100), nullable=True)
    is_from_points = db.Column(db.Boolean, default=False)

class PrivateKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_string = db.Column(db.String(36), unique=True, nullable=False, default=lambda: f"PRIVATE-{str(uuid.uuid4())[:8].upper()}")
    is_used = db.Column(db.Boolean, default=False)
    used_by_id = db.Column(db.String(100), nullable=True)
    used_at = db.Column(TZDateTime, nullable=True)

class GenerationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_user_id = db.Column(db.String(100), nullable=False)
    service_name = db.Column(db.String(100), nullable=False)
    lines_generated = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc))

class CheckerKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_string = db.Column(db.String(42), unique=True, nullable=False, default=lambda: f"FORUP-{str(uuid.uuid4()).upper()}")
    duration_str = db.Column(db.String(20), nullable=False)
    expires_at = db.Column(TZDateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    hwid = db.Column(db.String(100), nullable=True)
    last_used = db.Column(TZDateTime, nullable=True)
    created_at = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc))

class UserPoints(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_user_id = db.Column(db.String(100), unique=True, nullable=False)
    points = db.Column(db.Integer, default=0, nullable=False)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_user_id = db.Column(db.String(100), nullable=False)
    telegram_username = db.Column(db.String(100), nullable=True)
    caption = db.Column(db.Text, nullable=True)
    file_id = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc))

class TrafficLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(TZDateTime, default=lambda: datetime.now(timezone.utc))
    telegram_user_id = db.Column(db.String(100), nullable=False)

def is_admin(): return session.get('logged_in')

def internal_api_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('X-Internal-Secret') == INTERNAL_API_SECRET:
            return f(*args, **kwargs)
        if is_admin():
            return f(*args, **kwargs)
        app.logger.warning(f"Unauthorized access attempt to {request.path} from IP {request.remote_addr}")
        return jsonify({'error': 'Unauthorized'}), 403
    return decorated_function

def log_event(message):
    with open(EVENT_LOG_FILE, "a") as f: f.write(f"data: {json.dumps({'msg': message, 'time': datetime.now().isoformat()})}\n\n")
def get_file_base_name(filename):
    if not isinstance(filename, str) or not filename.lower().endswith('.txt'): return None
    match = re.match(r'^(.*?)(?:\s*\(\d+\))?\.txt$', filename, re.IGNORECASE)
    if match: return match.group(1).strip()
    return None
def read_bots_state():
    if not os.path.exists(RUNNING_BOTS_STATE_FILE): return []
    try:
        with open(RUNNING_BOTS_STATE_FILE, 'r') as f:
            state = json.load(f); return state if isinstance(state, list) else []
    except (json.JSONDecodeError, FileNotFoundError): return []
def write_bots_state(bots_list):
    with open(RUNNING_BOTS_STATE_FILE, 'w') as f: json.dump(bots_list, f, indent=4)
def format_size(size_bytes):
   if size_bytes == 0: return "0B"
   size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
   try:
       i = int(math.floor(math.log(size_bytes, 1024))); p = math.pow(1024, i)
       s = round(size_bytes / p, 2); return f"{s} {size_name[i]}"
   except (ValueError, IndexError): return "0B"
def format_uptime(seconds):
    m, s = divmod(seconds, 60); h, m = divmod(m, 60); d, h = divmod(h, 24)
    if d > 0: return f"{int(d)}d {int(h)}h {int(m)}m"
    return f"{int(h)}h {int(m)}m {int(s)}s"

def format_to_user_pass(line: str) -> str:
    parts = line.strip().split(':')
    if len(parts) >= 2: return f"{parts[-2]}:{parts[-1]}"
    return line.strip()

def parse_duration_to_hours(duration_str):
    if not isinstance(duration_str, str) or len(duration_str) < 2: return 0
    value_str = duration_str[:-1]; unit = duration_str[-1].lower()
    try: value = int(value_str)
    except ValueError: return 0
    if unit == 'd': return value * 24
    elif unit == 'h': return value
    return 0
    
def parse_duration_to_delta(duration_str):
    if not isinstance(duration_str, str) or len(duration_str) < 2: return None
    value_str = duration_str[:-1]; unit = duration_str[-1].lower()
    try:
        value = int(value_str)
        if unit == 'd': return timedelta(days=value)
        elif unit == 'h': return timedelta(hours=value)
        elif unit == 'm': return timedelta(minutes=value)
    except ValueError: return None
    return None

def format_hours_to_duration_str(total_hours):
    if total_hours <= 0: return "0h"
    if total_hours % 24 == 0: days = total_hours // 24; return f"{days}d"
    else: return f"{total_hours}h"

def send_telegram_message(chat_id, text, parse_mode='HTML'):
    if not BOT_TOKEN: app.logger.warning("BOT_TOKEN is not configured."); return None
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"; payload = {'chat_id': chat_id, 'text': text, 'parse_mode': parse_mode}
    try: response = requests.post(url, json=payload, timeout=10); response.raise_for_status(); return response.json()
    except requests.exceptions.RequestException as e: app.logger.error(f"Failed to send Telegram message to {chat_id}: {e}"); return None

def get_folder_file_stats(folder_path):
    stats = []
    if not os.path.isdir(folder_path): app.logger.warning(f"Stats folder not found: {folder_path}"); return []
    try:
        for filename in os.listdir(folder_path):
            if filename.lower().endswith('.txt'):
                file_path = os.path.join(folder_path, filename)
                try:
                    if os.path.isfile(file_path): stats.append({'name': filename, 'size': format_size(os.path.getsize(file_path))})
                except OSError: continue
    except OSError as e: app.logger.error(f"Could not list directory '{folder_path}': {e}"); return []
    return sorted(stats, key=lambda x: x['name'])

def _secure_join(base_folder, relative_path):
    full_base_path = os.path.join(DATA_DIR, base_folder)
    if not relative_path or '..' in relative_path.split(os.path.sep): return None
    normalized_relative_path = os.path.normpath(relative_path)
    if os.path.isabs(normalized_relative_path): return None
    final_path = os.path.join(full_base_path, normalized_relative_path)
    if not os.path.abspath(final_path).startswith(os.path.abspath(full_base_path)):
        return None
    return final_path

def get_system_stats_dict():
    stats = {"success": True}
    try:
        try:
            mem = psutil.virtual_memory()
            stats.update({"memory": f"{format_size(mem.used)} / {format_size(mem.total)}", "memory_percent": f"{mem.percent:.1f}%", "memory_percent_raw": mem.percent})
        except (PermissionError, RuntimeError) as e:
            app.logger.warning(f"Could not get Memory stats: {e}")
            stats.update({"memory": "N/A", "memory_percent": "N/A", "memory_percent_raw": 0})
        try:
            disk = psutil.disk_usage(DATA_DIR)
            stats.update({"disk": f"{format_size(disk.used)} / {format_size(disk.total)}", "disk_percent": f"{disk.percent:.1f}%", "disk_percent_raw": disk.percent})
        except (PermissionError, RuntimeError, FileNotFoundError) as e:
            app.logger.warning(f"Could not get Disk stats for {DATA_DIR}: {e}")
            stats.update({"disk": "N/A", "disk_percent": "N/A", "disk_percent_raw": 0})
        try:
            net = psutil.net_io_counters()
            stats.update({"network_in": format_size(net.bytes_recv), "network_out": format_size(net.bytes_sent)})
        except (PermissionError, RuntimeError) as e:
            app.logger.warning(f"Could not get Network stats: {e}")
            stats.update({"network_in": "N/A", "network_out": "N/A"})
        return stats
    except Exception as e:
        app.logger.error(f"A general error occurred in get_system_stats_dict: {e}")
        return {"success": False, "error": str(e), "memory": "ERR", "memory_percent": "ERR", "memory_percent_raw": 0, "disk": "ERR", "disk_percent": "ERR", "disk_percent_raw": 0, "network_in": "ERR", "network_out": "ERR"}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_admin(): return redirect(url_for('dashboard'))
    if request.method == 'POST':
        if request.form.get('username') == ADMIN_USERNAME and request.form.get('password') == ADMIN_PASSWORD:
            session['logged_in'] = True; return redirect(url_for('dashboard'))
        else: flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.pop('logged_in', None); flash('You have been logged out.', 'success'); return redirect(url_for('login'))

@app.route('/')
def dashboard():
    if not is_admin(): return redirect(url_for('login'))
    database_stock_by_folder = {}; admin_stock = []; total_db_files = 0; total_db_size_bytes = 0; aggregated_stock = {}
    all_folders_to_scan = DATABASE_FOLDERS + [PRIVATE_DATABASE_FOLDER, INFO_DATABASE_FOLDER, ADMIN_DATABASE_FOLDER]
    for folder_name in all_folders_to_scan:
        folder_path = os.path.join(DATA_DIR, folder_name)
        folder_display_name = {"INFO_DATABASE_FOLDER": "ℹ️ With Info", "PRIVATE_DATABASE_FOLDER": "🔐 Private", "ADMIN_DATABASE_FOLDER": "👑 Admin Stock"}.get(folder_name, f"📁 {folder_name.replace('database', 'DB ').title()}")
        if folder_name != ADMIN_DATABASE_FOLDER:
            database_stock_by_folder[folder_display_name] = []
        
        if not os.path.exists(folder_path): continue
        
        files_to_process = []
        for dirpath, _, filenames in os.walk(folder_path):
            for f in filenames:
                if f.endswith('.txt'): files_to_process.append(os.path.join(dirpath, f))
        
        total_db_files += len(files_to_process)
        
        for full_path in sorted(files_to_process):
            try:
                total_db_size_bytes += os.path.getsize(full_path); item_count = 0
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    if folder_name == INFO_DATABASE_FOLDER: item_count = sum(1 for line in f if 'checking account' in line.lower())
                    else: item_count = sum(1 for line in f if line.strip())
                
                if item_count > 0:
                    relative_path = os.path.relpath(full_path, folder_path); display_filename = relative_path.replace(os.path.sep, ' / '); stock_item = {'filename': display_filename, 'count': item_count}
                    
                    if folder_name == ADMIN_DATABASE_FOLDER:
                        admin_stock.append(stock_item)
                    else:
                        database_stock_by_folder[folder_display_name].append(stock_item)

                    if folder_name in DATABASE_FOLDERS:
                        base_name = get_file_base_name(os.path.basename(relative_path))
                        if base_name: aggregated_stock[base_name] = aggregated_stock.get(base_name, 0) + item_count
            except Exception as e: app.logger.error(f"Could not process file {full_path}: {e}")

    top_tier_databases = sorted(aggregated_stock.items(), key=lambda item: item[1], reverse=True)
    start_of_today = datetime.now(timezone.utc) - timedelta(days=1); generated_today = db.session.query(func.sum(GenerationLog.lines_generated)).filter(GenerationLog.timestamp >= start_of_today).scalar() or 0
    generated_all_time = db.session.query(func.sum(GenerationLog.lines_generated)).scalar() or 0
    bot_stats = {'total_keys': Key.query.count(), 'used_keys': Key.query.filter_by(is_used=True).count(), 'total_users': Key.query.filter(Key.telegram_user_id.isnot(None)).distinct().count(), 'db_files': total_db_files, 'generated_today': generated_today, 'generated_all_time': generated_all_time}
    db_size_limit_gb = 20; db_size_limit_bytes = db_size_limit_gb * (1024**3); db_size_gb = total_db_size_bytes / (1024**3); db_size_percentage = min(100, (total_db_size_bytes / db_size_limit_bytes) * 100) if db_size_limit_bytes > 0 else 0
    all_py_files = glob.glob(os.path.join(os.getcwd(), '*.py')); app_file = os.path.basename(__file__); available_scripts = [os.path.basename(f) for f in all_py_files if os.path.basename(f) != app_file]
    all_gen_folders = DATABASE_FOLDERS + [PRIVATE_DATABASE_FOLDER, ADMIN_DATABASE_FOLDER, INFO_DATABASE_FOLDER]
    return render_template('dashboard.html', bot_stats=bot_stats, database_stock_by_folder=database_stock_by_folder, admin_stock=sorted(admin_stock, key=lambda x: x['filename']), top_tier_databases=top_tier_databases, initial_system_stats=get_system_stats_dict(), database_folders=DATABASE_FOLDERS, all_gen_folders=all_gen_folders, available_scripts=sorted(available_scripts), db_size_gb=f"{db_size_gb:.2f}", db_size_limit_gb=db_size_limit_gb, db_size_percentage=db_size_percentage)

@app.route('/keys')
def manage_keys():
    if not is_admin(): return redirect(url_for('login'))
    return render_template('keys.html', keys=Key.query.order_by(Key.id.desc()).all(), now=datetime.now(timezone.utc))

@app.route('/private_keys')
def manage_private_keys():
    if not is_admin(): return redirect(url_for('login'))
    return render_template('private_keys.html', keys=PrivateKey.query.order_by(PrivateKey.id.desc()).all())

@app.route('/checker_keys')
def manage_checker_keys():
    if not is_admin(): return redirect(url_for('login'))
    keys = CheckerKey.query.order_by(CheckerKey.id.desc()).all()
    return render_template('checker_keys.html', keys=keys, now=datetime.now(timezone.utc))

@app.route('/feedback_monitoring')
def feedback_monitoring():
    if not is_admin(): return redirect(url_for('login'))
    
    users_with_feedback = db.session.query(Key, UserPoints)\
        .join(UserPoints, Key.telegram_user_id == UserPoints.telegram_user_id)\
        .filter(Key.is_used == True, UserPoints.points > 0)\
        .group_by(Key.telegram_user_id)\
        .order_by(UserPoints.points.desc()).all()
    
    all_registered_user_ids = {item[0] for item in db.session.query(Key.telegram_user_id).filter(Key.is_used == True, Key.telegram_user_id.isnot(None)).all()}
    feedback_user_ids = {user.telegram_user_id for user, points in users_with_feedback}
    no_feedback_user_ids = all_registered_user_ids - feedback_user_ids
    
    users_without_feedback = Key.query.filter(Key.telegram_user_id.in_(no_feedback_user_ids))\
        .group_by(Key.telegram_user_id).all()

    return render_template('feedback_monitoring.html', 
                           users_with_feedback=users_with_feedback, 
                           users_without_feedback=users_without_feedback, 
                           feedback_points_value=FEEDBACK_POINTS)

@app.route('/checker_results')
def checker_results():
    if not is_admin(): return redirect(url_for('login'))
    results = {}; total_files = 0; total_size_bytes = 0
    results_path = os.path.join(DATA_DIR, CHECKER_RESULTS_PATH)
    os.makedirs(results_path, exist_ok=True)
    
    if os.path.exists(results_path):
        for country_folder in sorted(os.listdir(results_path), key=str.lower):
            country_path = os.path.join(results_path, country_folder)
            if not os.path.isdir(country_path): continue
            country_data = {'clean': [], 'not_clean': []}
            for status_folder in sorted(os.listdir(country_path)):
                status_path = os.path.join(country_path, status_folder)
                if not os.path.isdir(status_path) or status_folder.lower() not in ['clean', 'not_clean']: continue
                for filename in sorted(os.listdir(status_path)):
                    if not filename.endswith('.txt'): continue
                    file_path = os.path.join(status_path, filename)
                    try:
                        size_bytes = os.path.getsize(file_path); total_size_bytes += size_bytes; total_files += 1
                        level_range_match = re.search(r'level_(\d+-\d+)', filename, re.IGNORECASE)
                        level_single_match = re.search(r'lvl_(\d+)', filename, re.IGNORECASE)
                        level_range = 'unknown'
                        if level_range_match: level_range = level_range_match.group(1)
                        elif level_single_match: level_range = f"{level_single_match.group(1)}-{int(level_single_match.group(1)) + 49}"
                        file_info = {'filename': filename, 'size': format_size(size_bytes), 'level_range': level_range}
                        if status_folder.lower() == 'clean': country_data['clean'].append(file_info)
                        else: country_data['not_clean'].append(file_info)
                    except OSError as e: app.logger.error(f"Could not read file {file_path}: {e}"); continue
            if country_data['clean'] or country_data['not_clean']: results[country_folder] = country_data
    return render_template('checker_results.html', results=results, total_files=total_files, total_size=format_size(total_size_bytes))

@app.route('/download_checker_file/<path:filepath>')
def download_checker_file(filepath):
    if not is_admin(): return redirect(url_for('login'))
    safe_path = _secure_join(CHECKER_RESULTS_PATH, filepath)
    if not safe_path or not os.path.isfile(safe_path):
        flash(f"File not found or access denied.", 'danger'); return redirect(url_for('checker_results'))
    try:
        directory = os.path.dirname(safe_path)
        filename = os.path.basename(safe_path)
        return send_from_directory(directory, filename, as_attachment=True)
    except Exception as e:
        app.logger.error(f"Error downloading checker file {safe_path}: {e}")
        flash(f"Error downloading file: {filename}", 'danger'); return redirect(url_for('checker_results'))

@app.route('/upload_db', methods=['POST'])
def upload_db_file():
    if not is_admin(): return jsonify({'error': 'Unauthorized'}), 403
    files = request.files.getlist('db_file'); upload_target = request.form.get('target_folder')
    allowed_folders = DATABASE_FOLDERS + [PRIVATE_DATABASE_FOLDER, INFO_DATABASE_FOLDER, ADMIN_DATABASE_FOLDER]
    if not upload_target or upload_target not in allowed_folders: flash('Invalid target folder selected.', 'danger'); return redirect(url_for('dashboard'))
    
    target_path = os.path.join(DATA_DIR, upload_target)

    if not files or all(f.filename == '' for f in files): flash('No selected files', 'warning'); return redirect(url_for('dashboard'))
    uploaded_count, failed_count = 0, 0
    for file in files:
        if file and file.filename.endswith('.txt'):
            filename = secure_filename(file.filename)
            if '..' in filename or filename.startswith(('/', '\\')): failed_count += 1; continue
            os.makedirs(target_path, exist_ok=True); file.save(os.path.join(target_path, filename)); uploaded_count += 1
        elif file: failed_count += 1
    if uploaded_count > 0:
        flash(f'Successfully uploaded {uploaded_count} file(s) to "{upload_target}".', 'success')
        if upload_target in DATABASE_FOLDERS:
            user_ids = [item[0] for item in db.session.query(Key.telegram_user_id).filter(Key.is_used == True, Key.telegram_user_id.isnot(None)).distinct().all()]
            if user_ids:
                message = "🔥 *Database Update*\n\nNew stock has been added to the public databases. Go generate some fresh accounts!"
                for user_id in user_ids: send_telegram_message(user_id, message, parse_mode='Markdown'); time.sleep(0.05)
                log_event(f"Sent database update notification to {len(user_ids)} users.")
    if failed_count > 0: flash(f'{failed_count} file(s) had an invalid type or name.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/upload_bot_script', methods=['POST'])
def upload_bot_script():
    if not is_admin(): return jsonify({'error': 'Unauthorized'}), 403
    file = request.files.get('bot_script')
    if not file or file.filename == '': flash('No selected file.', 'warning'); return redirect(url_for('dashboard'))
    if file and file.filename.endswith('.py'):
        filename = secure_filename(file.filename); file.save(os.path.join(os.getcwd(), filename))
        flash(f'Bot script "{filename}" uploaded successfully.', 'success'); log_event(f'Admin uploaded a new bot script: {filename}')
    else: flash('Invalid file type. Only .py files are allowed.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/manage_user/<int:key_id>')
def manage_user(key_id):
    if not is_admin(): return redirect(url_for('login'))
    return render_template('manage_user.html', key=Key.query.get_or_404(key_id), now=datetime.now(timezone.utc))

@app.route('/adjust_time/<int:key_id>', methods=['POST'])
def adjust_time(key_id):
    if not is_admin(): return redirect(url_for('login'))
    key = Key.query.get_or_404(key_id)
    if key.expires_at is None: flash('Cannot adjust time for a lifetime key.', 'warning'); return redirect(url_for('manage_user', key_id=key_id))
    action = request.form.get('action'); duration_adjustment_str = request.form.get('duration'); verb = ""
    try:
        adj_val = int(duration_adjustment_str[:-1]); adj_unit = duration_adjustment_str[-1].lower()
        if adj_unit not in ['d', 'h']: raise ValueError("Invalid unit")
        delta = timedelta(days=adj_val) if adj_unit == 'd' else timedelta(hours=adj_val); cur_hrs = parse_duration_to_hours(key.duration_str); adj_hrs = adj_val * 24 if adj_unit == 'd' else adj_val
        if action == 'add': key.expires_at += delta; new_total_hours = max(0, cur_hrs + adj_hrs); verb = "added"; flash(f'Successfully added {duration_adjustment_str}.', 'success')
        elif action == 'deduct': key.expires_at -= delta; new_total_hours = max(0, cur_hrs - adj_hrs); verb = "deducted"; flash(f'Successfully deducted {duration_adjustment_str}.', 'success')
        else: raise ValueError("Invalid action")
        key.duration_str = format_hours_to_duration_str(new_total_hours); db.session.commit()
        if key.telegram_user_id and verb:
            user_message = f"🔔 *Subscription Update*\n\nAn admin has adjusted your subscription.\n\nTime Update: *{duration_adjustment_str.title()}* has been *{verb}*.\nNew Expiry Date: `{key.expires_at.strftime('%Y-%m-%d %H:%M UTC')}`"
            send_telegram_message(key.telegram_user_id, user_message, parse_mode='Markdown'); log_event(f"Admin {verb} {duration_adjustment_str} for user {key.telegram_user_id}.")
    except (ValueError, TypeError, IndexError): flash('Invalid duration format.', 'danger')
    return redirect(url_for('manage_user', key_id=key_id))

@app.route('/revoke_key/<int:key_id>', methods=['POST'])
def revoke_key(key_id):
    if not is_admin(): return redirect(url_for('login'))
    key_to_revoke = Key.query.get_or_404(key_id); user_id_to_notify = key_to_revoke.telegram_user_id; key_string = key_to_revoke.key_string
    db.session.delete(key_to_revoke); db.session.commit()
    if user_id_to_notify:
        message = f"🚫 *Access Revoked*\n\nYour key `{key_string}` has been permanently revoked by an administrator."
        send_telegram_message(user_id_to_notify, message, parse_mode='Markdown'); log_event(f"Admin revoked key {key_string} for user {user_id_to_notify}.")
    flash(f'Successfully revoked key.', 'success'); return redirect(url_for('manage_keys'))

@app.route('/delete_subscription_key/<int:key_id>', methods=['POST'])
def delete_subscription_key(key_id):
    if not is_admin(): return redirect(url_for('login'))
    key = Key.query.get_or_404(key_id); db.session.delete(key); db.session.commit()
    flash(f'Subscription key {key.key_string} has been deleted.', 'success'); return redirect(url_for('manage_keys'))

@app.route('/delete_private_key/<int:key_id>', methods=['POST'])
def delete_private_key(key_id):
    if not is_admin(): return redirect(url_for('login'))
    key = PrivateKey.query.get_or_404(key_id); db.session.delete(key); db.session.commit()
    flash(f'Private key {key.key_string} has been deleted.', 'success'); return redirect(url_for('manage_private_keys'))

@app.route('/api/checker/validate_key', methods=['POST'])
def validate_checker_key():
    data = request.json; key_string = data.get('key'); hwid = data.get('hwid')
    if not key_string or not hwid: return jsonify({"success": False, "message": "Key and HWID are required."}), 400
    key = CheckerKey.query.filter_by(key_string=key_string).first()
    if not key or not key.is_active: return jsonify({"success": False, "message": "Invalid or inactive key."}), 403
    if key.expires_at and key.expires_at < datetime.now(timezone.utc):
        key.is_active = False; db.session.commit(); return jsonify({"success": False, "message": "Key has expired."}), 403
    if key.hwid and key.hwid != str(hwid): return jsonify({"success": False, "message": "Key is locked to another machine."}), 403
    if not key.hwid: key.hwid = str(hwid)
    key.last_used = datetime.now(timezone.utc); db.session.commit()
    return jsonify({"success": True, "message": "Access granted.", "expires_at": key.expires_at.isoformat() if key.expires_at else "Lifetime"})

@app.route('/api/panel/generate_checker_key', methods=['POST'])
def generate_checker_key():
    if not is_admin(): return jsonify({"error": "Unauthorized"}), 403
    try:
        quantity = int(request.form.get('quantity', '1')); duration_str = request.form.get('duration', '30d')
        if not (1 <= quantity <= 100): flash('Quantity must be between 1 and 100.', 'danger'); return redirect(url_for('manage_checker_keys'))
        delta = parse_duration_to_delta(duration_str)
        if delta is None and duration_str.lower() != 'lifetime':
            flash(f"Invalid duration format: '{duration_str}'. Use 'd', 'h', or 'm'.", 'danger'); return redirect(url_for('manage_checker_keys'))
        generated_keys = []
        for _ in range(quantity):
            new_key = CheckerKey(duration_str=duration_str, expires_at=(datetime.now(timezone.utc) + delta) if delta else None)
            db.session.add(new_key); generated_keys.append(new_key)
        db.session.commit()
        if quantity == 1: flash(f'Successfully generated key: {generated_keys[0].key_string}', 'success')
        else:
            keys_text = "\n".join([k.key_string for k in generated_keys]); buffer = io.BytesIO(keys_text.encode('utf-8')); buffer.seek(0)
            flash(f'Successfully generated {quantity} new keys.', 'success')
            return send_file(buffer, as_attachment=True, download_name=f'checker_keys_{datetime.now().strftime("%Y%m%d_%H%M")}.txt', mimetype='text/plain')
    except (ValueError, TypeError): flash('Invalid quantity.', 'danger')
    return redirect(url_for('manage_checker_keys'))

@app.route('/api/panel/delete_checker_key/<int:key_id>', methods=['POST'])
def delete_checker_key(key_id):
    if not is_admin(): return redirect(url_for('login'))
    key = CheckerKey.query.get_or_404(key_id); db.session.delete(key); db.session.commit()
    flash(f'Checker key {key.key_string} has been deleted.', 'success'); return redirect(url_for('manage_checker_keys'))

@app.route('/api/panel/reset_checker_hwid/<int:key_id>', methods=['POST'])
def reset_checker_hwid(key_id):
    if not is_admin(): return redirect(url_for('login'))
    key = CheckerKey.query.get_or_404(key_id); key_string_for_log = key.key_string
    key.hwid = None; db.session.commit()
    log_event(f"Admin reset HWID for checker key: {key_string_for_log}")
    flash(f'HWID for key {key_string_for_log} has been reset. It can now be registered on a new machine.', 'success')
    return redirect(url_for('manage_checker_keys'))

@app.route('/api/panel/generate_key', methods=['POST'])
def generate_key():
    if not is_admin(): return jsonify({"error": "Unauthorized"}), 403
    duration_str = request.form.get('duration', '30d')
    try: quantity = int(request.form.get('quantity', '1'));
    except (ValueError, TypeError): flash('Invalid quantity.', 'danger'); return redirect(url_for('manage_keys'))
    if not 1 <= quantity <= 100: flash('Quantity must be between 1 and 100.', 'danger'); return redirect(url_for('manage_keys'))
    delta = None
    if duration_str.lower() != "lifetime":
        try: value = int(duration_str[:-1]); unit = duration_str[-1].lower();
        except (ValueError, IndexError): flash('Invalid duration format.', 'danger'); return redirect(url_for('manage_keys'))
        if unit == 'd': delta = timedelta(days=value)
        elif unit == 'h': delta = timedelta(hours=value)
        else: flash('Invalid time unit.', 'danger'); return redirect(url_for('manage_keys'))
    generated_keys = []
    for _ in range(quantity):
        new_key = Key(duration_str=duration_str, expires_at=((datetime.now(timezone.utc) + delta) if delta else None))
        db.session.add(new_key); generated_keys.append(new_key)
    db.session.commit()
    if generated_keys:
        keys_text = "\n".join([f"`{k.key_string}` ({k.duration_str})" for k in generated_keys])
        send_telegram_message(ADMIN_TELEGRAM_ID, f"🔑 *New Subscription Keys Generated*\n\n{keys_text}", parse_mode='Markdown')
    flash(f'Successfully generated {quantity} new key(s).', 'success'); return redirect(url_for('manage_keys'))

@app.route('/api/panel/generate_private_key', methods=['POST'])
def generate_private_key():
    if not is_admin(): return jsonify({"error": "Unauthorized"}), 403
    try: quantity = int(request.form.get('quantity', '1'));
    except (ValueError, TypeError): flash('Invalid quantity.', 'danger'); return redirect(url_for('manage_private_keys'))
    if not 1 <= quantity <= 100: flash('Quantity must be between 1 and 100.', 'danger'); return redirect(url_for('manage_private_keys'))
    generated_keys = []
    for _ in range(quantity): new_key = PrivateKey(); db.session.add(new_key); generated_keys.append(new_key)
    db.session.commit()
    if generated_keys:
        keys_text = "\n".join([f"`{k.key_string}`" for k in generated_keys])
        send_telegram_message(ADMIN_TELEGRAM_ID, f"🔐 *New Private Keys Generated*\n\n{keys_text}", parse_mode='Markdown')
    flash(f'Successfully generated {len(generated_keys)} new private key(s).', 'success'); return redirect(url_for('manage_private_keys'))

@app.route('/api/bot_script/delete', methods=['POST'])
def delete_bot_script():
    if not is_admin(): return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    filename = request.form.get('filename')
    if not filename: return jsonify({'status': 'error', 'message': 'No filename provided.'}), 400
    if filename in [os.path.basename(__file__), 'bot_worker.py']: return jsonify({'status': 'error', 'message': f'Core file "{filename}" cannot be deleted.'}), 403
    safe_filename = secure_filename(filename)
    if safe_filename != filename: return jsonify({'status': 'error', 'message': f'Invalid filename: {filename}'}), 400
    bots = read_bots_state()
    if any(b.get('script_name') == safe_filename and b.get('pid') and psutil.pid_exists(b['pid']) for b in bots): return jsonify({'status': 'error', 'message': f'Cannot delete running script "{safe_filename}". Stop it first.'}), 409
    script_path = os.path.join(os.getcwd(), safe_filename)
    if os.path.exists(script_path):
        try: os.remove(script_path); log_event(f'Admin deleted bot script: {safe_filename}'); return jsonify({'status': 'success', 'message': f'Deleted script: {safe_filename}'})
        except Exception as e: return jsonify({'status': 'error', 'message': f'Error deleting script: {e}'}), 500
    else: return jsonify({'status': 'warning', 'message': f'Script "{safe_filename}" not found.'}), 404

@app.route('/api/bots/start', methods=['POST'])
def start_bot():
    if not is_admin(): return jsonify({"status": "error", "message": "Unauthorized"}), 403
    script_name = request.form.get('script_name');
    if not script_name: return jsonify({"status": "error", "message": "Script name is required."}), 400
    safe_script_name = secure_filename(script_name); script_path = os.path.join(os.getcwd(), safe_script_name)
    if not safe_script_name.endswith('.py') or not os.path.exists(script_path): return jsonify({"status": "error", "message": f"Invalid or non-existent script: {safe_script_name}"}), 400
    bots = read_bots_state(); active_bots = [b for b in bots if b.get('pid') and psutil.pid_exists(b['pid'])]
    if len(active_bots) != len(bots): write_bots_state(active_bots); bots = active_bots
    if any(b.get('script_name') == safe_script_name for b in bots): return jsonify({"status": "error", "message": f"Script '{safe_script_name}' is already running."}), 409
    try:
        process = subprocess.Popen([sys.executable, script_path])
        bots.append({'pid': process.pid, 'script_name': safe_script_name}); write_bots_state(bots); log_event(f"Bot script '{safe_script_name}' started (PID: {process.pid}).")
        return jsonify({"status": "success", "message": f"Bot '{safe_script_name}' started."})
    except Exception as e: return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/bots/stop', methods=['POST'])
def stop_bot():
    if not is_admin(): return jsonify({"status": "error", "message": "Unauthorized"}), 403
    script_to_stop = request.form.get('script_name')
    if not script_to_stop: return jsonify({"status": "error", "message": "No script name provided."}), 400
    bots = read_bots_state(); bot_found = None; remaining_bots = []
    for bot in bots:
        if bot.get('script_name') == script_to_stop: bot_found = bot
        else: remaining_bots.append(bot)
    if not bot_found: write_bots_state(remaining_bots); return jsonify({"status": "error", "message": f"Bot '{script_to_stop}' not found in running list."}), 404
    pid = bot_found.get('pid')
    try:
        if pid and psutil.pid_exists(pid): p = psutil.Process(pid); p.terminate(); log_event(f"Bot script '{script_to_stop}' stopped.")
    except psutil.NoSuchProcess: log_event(f"Bot script '{script_to_stop}' was already stopped (PID {pid} not found).")
    except Exception as e: write_bots_state(remaining_bots); return jsonify({"status": "error", "message": str(e)}), 500
    finally: write_bots_state(remaining_bots)
    return jsonify({"status": "success", "message": f"Bot '{script_to_stop}' stopped."})

@app.route('/api/bots/status', methods=['GET'])
def bots_status():
    if not is_admin(): return jsonify({"status": "error", "message": "Unauthorized"}), 403
    all_bots = read_bots_state(); running_bots = []; state_changed = False
    for bot in all_bots:
        pid = bot.get('pid')
        if pid and psutil.pid_exists(pid): running_bots.append(bot)
        else: state_changed = True
    if state_changed: write_bots_state(running_bots)
    return jsonify({"status": "success", "running_bots": running_bots})

@app.route('/api/system_stats')
def system_stats():
    if not is_admin(): return jsonify({"error": "Unauthorized"}), 403
    return jsonify(get_system_stats_dict())

@app.route('/api/events')
def events():
    def generate():
        if not os.path.exists(EVENT_LOG_FILE): open(EVENT_LOG_FILE, 'w').close()
        with open(EVENT_LOG_FILE, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line: time.sleep(0.1); continue
                yield line
    return Response(generate(), mimetype="text/event-stream")

@app.route('/api/panel/traffic_data')
@internal_api_or_admin_required
def traffic_data():
    try:
        time_threshold = datetime.now(timezone.utc) - timedelta(hours=24)
        traffic_counts = db.session.query(
            func.strftime('%Y-%m-%d %H:00:00', TrafficLog.timestamp).label('hour'),
            func.count(TrafficLog.id).label('count')
        ).filter(TrafficLog.timestamp >= time_threshold)\
         .group_by('hour')\
         .order_by('hour')\
         .all()

        labels = [datetime.strptime(row.hour, '%Y-%m-%d %H:%M:%S').strftime('%H:%M') for row in traffic_counts]
        data = [row.count for row in traffic_counts]

        return jsonify({"success": True, "labels": labels, "data": data})
    except Exception as e:
        app.logger.error(f"Error fetching traffic data: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/bot/announce', methods=['POST'])
def announce():
    if not is_admin(): return jsonify({'error': 'Unauthorized'}), 403
    message = request.form.get('message'); mention_all = request.form.get('mention_all') == 'true'
    if not message: flash('Announcement message cannot be empty.', 'danger'); return redirect(url_for('dashboard'))
    used_keys = Key.query.filter(Key.is_used == True, Key.telegram_user_id.isnot(None)).all()
    unique_users = {key.telegram_user_id: key for key in used_keys}
    if not unique_users: flash('No users to send announcement to.', 'warning'); return redirect(url_for('dashboard'))
    users_to_message = list(unique_users.values())
    if mention_all:
        mentions = [f'<a href="tg://user?id={user.telegram_user_id}">{user.telegram_username or f"User_{user.telegram_user_id}"}</a>' for user in users_to_message]
        mention_string = ", ".join(mentions)
        full_message = f"<b>📣 Announcement to All Users:</b>\n\n{message}\n\n<b>Mentioned Users:</b>\n{mention_string}"
        send_telegram_message(ADMIN_TELEGRAM_ID, full_message, parse_mode='HTML'); log_event("Admin sent an announcement with all user mentions to themselves."); flash('Announcement with all user mentions sent to admin.', 'success')
    else:
        sent_count = 0
        for user in users_to_message:
            user_mention = f'<a href="tg://user?id={user.telegram_user_id}">{user.telegram_username or f"User_{user.telegram_user_id}"}</a>'
            personalized_message = message.replace('{username}', user_mention).replace('{id}', str(user.telegram_user_id))
            send_telegram_message(user.telegram_user_id, personalized_message, parse_mode='HTML'); sent_count += 1; time.sleep(0.05)
        log_event(f"Admin sent an announcement to {sent_count} unique users."); flash(f'Announcement sent to {sent_count} unique users.', 'success')
    return redirect(url_for('dashboard'))

# --- API for the BOT WORKER ---
def _list_files_in_dir(folder):
    full_folder_path = os.path.join(DATA_DIR, folder)
    file_paths = []
    if os.path.exists(full_folder_path):
        for dirpath, _, filenames in os.walk(full_folder_path):
            for filename in filenames:
                if filename.endswith(".txt"):
                    full_path = os.path.join(dirpath, filename)
                    relative_path = os.path.relpath(full_path, full_folder_path)
                    file_paths.append(relative_path.replace('\\', '/'))
    return file_paths

def _check_user_access(user_id):
    if str(user_id) == str(ADMIN_TELEGRAM_ID): return True, "Admin access granted."
    key = Key.query.filter_by(telegram_user_id=str(user_id), is_used=True).order_by(Key.expires_at.desc().nullslast()).first()
    if not key: return False, "You do not have a registered key."
    if key.expires_at and key.expires_at < datetime.now(timezone.utc): return False, f"Your key expired on {key.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}."
    return True, "Access granted."

@app.route('/api/bot/log_traffic', methods=['POST'])
@internal_api_or_admin_required
def log_traffic():
    data = request.json
    user_id = data.get('telegram_user_id')
    if not user_id:
        return jsonify({"success": False, "message": "User ID is required."}), 400
    try:
        log_entry = TrafficLog(telegram_user_id=str(user_id))
        db.session.add(log_entry)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error logging traffic: {e}")
        return jsonify({"success": False, "message": "Internal server error."}), 500

@app.route('/api/bot/get_all_users', methods=['GET'])
@internal_api_or_admin_required
def get_all_users():
    users = Key.query.filter(Key.is_used == True, Key.telegram_user_id.isnot(None)).all()
    user_ids = list(set([user.telegram_user_id for user in users]))
    return jsonify({"success": True, "user_ids": user_ids})

@app.route('/api/bot/list_private_files', methods=['GET'])
@internal_api_or_admin_required
def list_private_files():
    return jsonify({"success": True, "files": sorted(_list_files_in_dir(PRIVATE_DATABASE_FOLDER))})

@app.route('/api/bot/list_info_files', methods=['GET'])
@internal_api_or_admin_required
def list_info_files():
    return jsonify({"success": True, "files": sorted(_list_files_in_dir(INFO_DATABASE_FOLDER))})

@app.route('/api/bot/get_info_line', methods=['POST'])
@internal_api_or_admin_required
def get_info_line():
    data = request.json; user_id = data.get('telegram_user_id')
    has_access, message = _check_user_access(user_id)
    if not has_access: return jsonify({"success": False, "message": message}), 403
    service_name = data.get('service_name')
    if not service_name: return jsonify({"success": False, "message": "Service name not provided."}), 400
    file_path = _secure_join(INFO_DATABASE_FOLDER, service_name)
    if not file_path or not os.path.isfile(file_path): app.logger.error(f"404 - Info file not found. Bot requested: {service_name}. Panel looked for: {file_path}"); return jsonify({"success": False, "message": "Service file not found on server."}), 404
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
        records = re.split(r'\n(?=Checking account)', content, flags=re.IGNORECASE); valid_records = [r.strip() for r in records if r.strip()]
        if not valid_records: return jsonify({"success": False, "message": "No valid account blocks found."}), 404
        chosen_record = random.choice(valid_records); log_event(f"✨ INFO-GEN: User {user_id} generated from '{service_name}'.")
        user = Key.query.filter_by(telegram_user_id=str(user_id)).first(); username = user.telegram_username if user else "Unknown"
        notif_message = f"<b>ℹ️ 'With Info' Generated</b>\n\n<b>User:</b> @{username} ({user_id})\n<b>Service:</b> <code>{service_name}</code>"
        send_telegram_message(ADMIN_TELEGRAM_ID, notif_message, parse_mode='HTML')
        return jsonify({"success": True, "line": chosen_record})
    except Exception as e: app.logger.error(f"Error getting info from {service_name}: {e}"); return jsonify({"success": False, "message": "An internal server error occurred."}), 500

@app.route('/api/bot/redeem_key', methods=['POST'])
@internal_api_or_admin_required
def bot_redeem_key():
    data = request.json; key = Key.query.filter_by(key_string=data.get('key')).first()
    if not key: return jsonify({"success": False, "message": "❌ Invalid Key"})
    if key.is_used: return jsonify({"success": False, "message": f"❌ Key already used by user `{key.telegram_user_id}`."})
    key.is_used = True; key.telegram_user_id = str(data.get('telegram_user_id')); key.telegram_username = data.get('telegram_username'); db.session.commit()
    log_event(f"User {data.get('telegram_username')} ({data.get('telegram_user_id')}) redeemed key {key.key_string}.")
    expiry_text = "Lifetime" if key.expires_at is None else key.expires_at.strftime('%Y-%m-%d')
    user_info = f"<b>User:</b> @{data.get('telegram_username', 'N/A')} ({data.get('telegram_user_id')})"
    key_info = f"<b>Key:</b> <code>{key.key_string}</code>\n<b>Duration:</b> {key.duration_str}"
    notif_message = f"<b>🔑 Key Redeemed</b>\n\n{user_info}\n{key_info}"
    send_telegram_message(ADMIN_TELEGRAM_ID, notif_message, parse_mode='HTML')
    return jsonify({"success": True, "message": f"🎉 Success! Your new expiry is: `{expiry_text}`"})

@app.route('/api/bot/check_access', methods=['POST'])
@internal_api_or_admin_required
def bot_check_access():
    tg_user_id = str(request.json.get('telegram_user_id'))
    key = Key.query.filter_by(telegram_user_id=tg_user_id, is_used=True).order_by(Key.expires_at.desc().nullslast()).first()
    user_points = UserPoints.query.filter_by(telegram_user_id=tg_user_id).first()
    points_balance = user_points.points if user_points else 0
    if not key: return jsonify({"has_access": False, "reason": "no_key", "message": "You do not have a registered key.", "points": points_balance})
    if key.expires_at and key.expires_at < datetime.now(timezone.utc):
        return jsonify({"has_access": False, "reason": "expired", "message": f"Your key expired on {key.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}.", "points": points_balance})
    return jsonify({"has_access": True, "is_lifetime": key.expires_at is None, "is_admin": False, "key_string": key.key_string, "key_type": key.duration_str, "expires_at": key.expires_at.isoformat() if key.expires_at else "Lifetime", "username": key.telegram_username, "is_from_points": key.is_from_points, "points": points_balance})

@app.route('/api/bot/submit_feedback', methods=['POST'])
@internal_api_or_admin_required
def submit_feedback():
    data = request.json
    user_id = str(data.get('telegram_user_id'))
    username = data.get('telegram_username')
    caption = data.get('caption')
    file_id = data.get('file_id')

    if not all([user_id, file_id]):
        return jsonify({"success": False, "message": "Missing required data."}), 400

    new_feedback = Feedback(
        telegram_user_id=user_id,
        telegram_username=username,
        caption=caption,
        file_id=file_id
    )
    db.session.add(new_feedback)

    user_points_entry = UserPoints.query.filter_by(telegram_user_id=user_id).first()
    if not user_points_entry:
        user_points_entry = UserPoints(telegram_user_id=user_id, points=0)
        db.session.add(user_points_entry)
    
    user_points_entry.points += FEEDBACK_POINTS
    db.session.commit()

    log_event(f"User {user_id} submitted feedback and earned {FEEDBACK_POINTS} points. New balance: {user_points_entry.points}.")
    return jsonify({"success": True, "message": "Feedback received and points awarded.", "new_balance": user_points_entry.points})

@app.route('/api/bot/get_my_feedback', methods=['POST'])
@internal_api_or_admin_required
def get_my_feedback():
    user_id = str(request.json.get('telegram_user_id'))
    if not user_id:
        return jsonify({"success": False, "message": "User ID is required."}), 400

    feedbacks = Feedback.query.filter_by(telegram_user_id=user_id).order_by(Feedback.timestamp.desc()).limit(25).all()
    
    results = [
        {
            "caption": fb.caption,
            "file_id": fb.file_id,
            "timestamp": fb.timestamp.isoformat()
        } for fb in feedbacks
    ]
    return jsonify({"success": True, "feedbacks": results})

@app.route('/api/bot/convert_points', methods=['POST'])
@internal_api_or_admin_required
def convert_points():
    data = request.json; user_id = str(data.get('telegram_user_id')); conversion_type = data.get('conversion_type')
    POINT_COSTS = {'1d': 100, '2d': 150, '3d': 200, 'private': 100}

    if not user_id or conversion_type not in POINT_COSTS:
        return jsonify({"success": False, "message": "Invalid request."}), 400
    
    cost = POINT_COSTS[conversion_type]
    user_points_entry = UserPoints.query.filter_by(telegram_user_id=user_id).first()

    if not user_points_entry or user_points_entry.points < cost:
        return jsonify({"success": False, "message": f"Not enough points. You need {cost}, but you have {getattr(user_points_entry, 'points', 0)}."}), 400
    
    user_points_entry.points -= cost
    
    if conversion_type == 'private':
        new_private_key = PrivateKey()
        db.session.add(new_private_key); db.session.commit()
        log_event(f"User {user_id} converted {cost} points for a PRIVATE ACCESS key. New key: {new_private_key.key_string}")
        send_telegram_message(ADMIN_TELEGRAM_ID, f"♻️ <b>Points Converted (PRIVATE)</b>\n\n<b>User:</b> {user_id}\n<b>Cost:</b> {cost} points\n<b>Reward:</b> Private Access Key\n<b>New Key:</b> <code>{new_private_key.key_string}</code>", parse_mode='HTML')
        return jsonify({"success": True, "message": "Private key conversion successful!", "key_string": new_private_key.key_string, "duration_str": "One-Time Private Access"})
    else:
        duration_map = {'1d': timedelta(days=1), '2d': timedelta(days=2), '3d': timedelta(days=3)}
        delta = duration_map.get(conversion_type)
        if not delta:
             return jsonify({"success": False, "message": "Invalid duration type."}), 400

        new_key = Key(duration_str=conversion_type, expires_at=datetime.now(timezone.utc) + delta, is_from_points=True)
        db.session.add(new_key); db.session.commit()
        log_event(f"User {user_id} converted {cost} points for a {conversion_type} key. New key: {new_key.key_string}")
        send_telegram_message(ADMIN_TELEGRAM_ID, f"♻️ <b>Points Converted (SUBSCRIPTION)</b>\n\n<b>User:</b> {user_id}\n<b>Cost:</b> {cost} points\n<b>Reward:</b> {conversion_type} key\n<b>New Key:</b> <code>{new_key.key_string}</code>", parse_mode='HTML')
        return jsonify({"success": True, "message": "Subscription key conversion successful!", "key_string": new_key.key_string, "duration_str": new_key.duration_str})

@app.route('/api/bot/redeem_private_key', methods=['POST'])
@internal_api_or_admin_required
def bot_redeem_private_key():
    data = request.json; key = PrivateKey.query.filter_by(key_string=data.get('key')).first()
    if not key: return jsonify({"success": False, "message": "❌ Invalid Private Access Key."})
    if key.is_used: return jsonify({"success": False, "message": "❌ This key has already been used."})
    key.is_used = True; key.used_by_id = str(data.get('telegram_user_id')); key.used_at = datetime.now(timezone.utc); db.session.commit()
    log_event(f"User {data.get('telegram_user_id')} used private key {key.key_string}.")
    return jsonify({"success": True, "message": "✅ Private Access Key accepted."})

@app.route('/api/bot/get_stock_batch', methods=['POST'])
@internal_api_or_admin_required
def get_stock_batch():
    data = request.json; requests_list = data.get('requests', [])
    if not isinstance(requests_list, list): return jsonify({"success": False, "message": "Invalid request format."}), 400
    stocks = {}
    
    all_checkable_folders = DATABASE_FOLDERS + [ADMIN_DATABASE_FOLDER]

    for req in requests_list:
        filename_req = req.get('service_name'); is_private = req.get('is_private', False); database_folder = req.get('database_folder')
        if not filename_req: continue
        
        folder_path_name = None
        unique_key = None

        if is_private:
            folder_path_name = PRIVATE_DATABASE_FOLDER
            unique_key = f"private:{filename_req}"
        elif database_folder in all_checkable_folders:
            folder_path_name = database_folder
            unique_key = f"{database_folder}:{filename_req}"
        else:
            unique_key = f"{database_folder or 'unknown'}:{filename_req}"
            stocks[unique_key] = -1 # Mark as error/unknown
            continue
        
        total_line_count = -1
        file_path = _secure_join(folder_path_name, filename_req)
        if file_path and os.path.isfile(file_path):
            file_lock = get_lock_for_file(file_path)
            with file_lock:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        total_line_count = sum(1 for line in f if line.strip())
                except Exception as e:
                    app.logger.error(f"Error reading file for stock count {file_path}: {e}")
                    total_line_count = -1
        else:
            total_line_count = 0 # File not found
        
        stocks[unique_key] = total_line_count
        
    return jsonify({"success": True, "stocks": stocks})

@app.route('/api/bot/get_service_lines_batch', methods=['POST'])
@internal_api_or_admin_required
def get_service_lines_batch():
    data = request.json; user_id = data.get('telegram_user_id')
    has_access, message = _check_user_access(user_id)
    if not has_access: return jsonify({"success": False, "message": message}), 403
    filename_req = data.get('service_name'); lines_to_generate = data.get('lines_to_generate'); is_private = data.get('is_private', False); database_folder = data.get('database_folder')
    folder_path_name = PRIVATE_DATABASE_FOLDER if is_private else (database_folder if database_folder in DATABASE_FOLDERS else None)
    if not folder_path_name: return jsonify({"success": False, "message": "Database source folder was not specified."}), 400
    file_path = _secure_join(folder_path_name, filename_req)
    if not (file_path and os.path.isfile(file_path)): return jsonify({"success": False, "message": f"No data found for {filename_req}."}), 404
    generated_lines = []; remaining_lines_count = 0
    file_lock = get_lock_for_file(file_path)
    with file_lock:
        try:
            with open(file_path, 'r+', encoding='utf-8', errors='ignore') as f:
                all_lines = list(set(line.strip() for line in f if line.strip()))
                if not all_lines: return jsonify({"success": False, "message": f"No data left for {filename_req}."}), 404
                try: lines_to_generate_int = int(lines_to_generate)
                except (ValueError, TypeError): return jsonify({"success": False, "message": "Invalid value for lines_to_generate."}), 400
                if len(all_lines) < lines_to_generate_int: lines_to_generate_int = len(all_lines)
                generated_lines = random.sample(all_lines, lines_to_generate_int)
                remaining_lines = [line for line in all_lines if line not in generated_lines]; remaining_lines_count = len(remaining_lines)
                f.seek(0); f.truncate(); f.write('\n'.join(remaining_lines));
                if remaining_lines: f.write('\n')
        except Exception as e: app.logger.error(f"Error processing file for batch generation {file_path}: {e}"); return jsonify({"success": False, "message": "An internal server error occurred."}), 500
    if not generated_lines: return jsonify({"success": False, "message": f"No data left for {filename_req}."}), 404
    try:
        log_entry = GenerationLog(telegram_user_id=str(user_id), service_name=filename_req, lines_generated=len(generated_lines)); db.session.add(log_entry); db.session.commit()
    except Exception as e: app.logger.error(f"Error logging generation event to DB: {e}"); db.session.rollback()
    log_event(f"User {user_id} generated {len(generated_lines)} lines for {filename_req}. Remaining: {remaining_lines_count}.")
    return jsonify({"success": True, "lines": "\n".join(generated_lines)})

@app.route('/api/admin/list_files', methods=['POST'])
@internal_api_or_admin_required
def list_files_for_admin_gen():
    folder = request.json.get('folder')
    allowed_folders = DATABASE_FOLDERS + [PRIVATE_DATABASE_FOLDER, ADMIN_DATABASE_FOLDER, INFO_DATABASE_FOLDER]
    if not folder or folder not in allowed_folders:
        return jsonify({"success": False, "error": "Invalid folder"}), 400
    base_path = os.path.join(DATA_DIR, folder)
    if not os.path.isdir(base_path):
        return jsonify({"success": True, "files": []})
    try:
        files = []
        for dirpath, _, filenames in os.walk(base_path):
            for f in filenames:
                if f.endswith('.txt'):
                    full_path = os.path.join(dirpath, f)
                    relative_path = os.path.relpath(full_path, base_path).replace('\\', '/')
                    line_count = 0
                    file_lock = get_lock_for_file(full_path)
                    with file_lock:
                        try:
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                                line_count = sum(1 for line in file_handle if line.strip())
                        except Exception as e:
                            app.logger.warning(f"Could not count lines in {full_path}: {e}")
                            line_count = -1
                    files.append({'path': relative_path, 'count': line_count})
        
        sorted_files = sorted(files, key=lambda x: x['path'])
        return jsonify({"success": True, "files": sorted_files})
    except Exception as e:
        app.logger.error(f"Error listing files in {folder}: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500

@app.route('/api/admin/generate', methods=['POST'])
@internal_api_or_admin_required
def admin_generate():
    folder = request.form.get('folder'); service_file = request.form.get('service_file')
    try: quantity = int(request.form.get('quantity', 1))
    except (ValueError, TypeError): return Response("Invalid quantity.", status=400)
    allowed_folders = DATABASE_FOLDERS + [PRIVATE_DATABASE_FOLDER, ADMIN_DATABASE_FOLDER, INFO_DATABASE_FOLDER]
    if not folder or folder not in allowed_folders or not service_file: return Response("Invalid folder or service file.", status=400)
    file_path = _secure_join(folder, service_file)
    if not file_path or not os.path.isfile(file_path): return Response(f"File not found: {service_file}", status=404)
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: lines = [line.strip() for line in f if line.strip()]
        if not lines: return Response("File is empty.", status=404)
        if quantity > len(lines): quantity = len(lines)
        generated_lines_raw = random.sample(lines, quantity)
        formatted_lines = [format_to_user_pass(line) for line in generated_lines_raw]
        log_event(f"Admin generated {len(formatted_lines)} lines from {folder}/{service_file}.")
        response_content = "\n".join(formatted_lines)
        clean_filename = secure_filename(service_file.replace('.txt', '')); download_filename = f"ADMIN_{clean_filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        return Response(response_content, mimetype="text/plain", headers={"Content-Disposition": f"attachment;filename={download_filename}"})
    except Exception as e: app.logger.error(f"Admin generation error from {file_path}: {e}"); return Response("An internal server error occurred.", status=500)

if __name__ == '__main__':
    all_dirs = [os.path.join(DATA_DIR, folder) for folder in DATABASE_FOLDERS + [PRIVATE_DATABASE_FOLDER, CHECKER_RESULTS_PATH, INFO_DATABASE_FOLDER, ADMIN_DATABASE_FOLDER]]
    for d in all_dirs:
        os.makedirs(d, exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=2004, threaded=True)

# --- END OF FILE app.py ---