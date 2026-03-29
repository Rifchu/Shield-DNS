import threading
import socket
import sqlite3
import time
import os
import re
import secrets
import base64
import logging
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, Response
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, RR, A
from waitress import serve
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger('shield-dns')

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Vercel deployment detection
IS_VERCEL = "VERCEL" in os.environ

DB_FILE = 'dns_blocker.db'
# In Vercel, the filesystem is read-only. We could use /tmp for a temporary DB,
# but it's better to warn the user that SQLite won't persist.
if IS_VERCEL:
    DB_FILE = os.path.join('/tmp', 'dns_blocker.db')
    # If the DB doesn't exist in /tmp, we could copy it if it exists in the repo
    if not os.path.exists(DB_FILE) and os.path.exists('dns_blocker.db'):
        import shutil
        shutil.copy('dns_blocker.db', DB_FILE)

SECRET_KEY_FILE = 'secret.key'
if IS_VERCEL:
    SECRET_KEY_FILE = os.path.join('/tmp', 'secret.key')

def load_or_create_secret_key():
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(key)
    return key

app.secret_key = load_or_create_secret_key()

# Domain validation regex
DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, doh_token):
        self.id = id
        self.username = username
        self.doh_token = doh_token

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, username, doh_token FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return User(row[0], row[1], row[2])
    return None

DEFAULT_CATEGORIES = {
    'Ads': ['doubleclick.net', 'adservice.google.com', 'pagead2.googlesyndication.com'],
    'Adult': ['example-adult.com', 'pornhub.com', 'xvideos.com'],
    'Malware & Phishing': ['quad9.net', 'malware.wicar.org'],
    'Cookies & Tracking': ['google-analytics.com', 'googletagmanager.com', 'scorecardresearch.com', 'quantserve.com', 'hotjar.com', 'outbrain.com', 'taboola.com', 'criteo.com'],
    'Meta / Facebook Tracker': ['graph.facebook.com', 'connect.facebook.net', 'pixel.facebook.com'],
    'TikTok / ByteDance Engine': ['byteoversea.com', 'tiktokv.com', 'ibytedtoy.com'],
    'Amazon Telemetry': ['fls-na.amazon.com', 'metrics.amazon.com']
}

def ensure_default_rules():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id FROM users")
    users = c.fetchall()
    
    for (uid,) in users:
        for cat, domains in DEFAULT_CATEGORIES.items():
            c.execute("SELECT 1 FROM rules WHERE user_id = ? AND category = ?", (uid, cat))
            if not c.fetchone():
                for dom in domains:
                    is_active = 0 if cat == 'Adult' else 1
                    c.execute("INSERT INTO rules (user_id, category, domain, is_active) VALUES (?, ?, ?, ?)", (uid, cat, dom, is_active))
    conn.commit()
    conn.close()

# In-memory rule cache mapping user_id -> rules
rules_cache = {}

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Check if this is the first migration to Multi-User by checking if 'users' table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not c.fetchone():
        c.execute("DROP TABLE IF EXISTS logs")
        c.execute("DROP TABLE IF EXISTS rules")
        
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, doh_token TEXT UNIQUE)''')
                 
    try:
        c.execute("ALTER TABLE users ADD COLUMN logging_enabled INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass
        
    try:
        c.execute("ALTER TABLE users ADD COLUMN total_blocked INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
                 
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY, user_id INTEGER, domain TEXT, action TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
                 
    c.execute('''CREATE TABLE IF NOT EXISTS rules
                 (id INTEGER PRIMARY KEY, user_id INTEGER, category TEXT, domain TEXT, is_active INTEGER)''')
    
    # Privacy-safe daily blocked aggregate (no domain info — works in stealth mode)
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_daily
                 (id INTEGER PRIMARY KEY, user_id INTEGER, day TEXT, count INTEGER DEFAULT 0,
                  UNIQUE(user_id, day))''')
    
    # DB indexes for query performance
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_user_action ON logs(user_id, action, timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_rules_user ON rules(user_id, category)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_blocked_daily ON blocked_daily(user_id, day)")

    # One-time sync: Initialize the counter from historical logs for existing users if it is empty
    c.execute("UPDATE users SET total_blocked = (SELECT COUNT(*) FROM logs WHERE logs.user_id = users.id AND logs.action = 'BLOCKED') WHERE total_blocked = 0")
    
    c.execute("SELECT count(*) FROM users")
    if c.fetchone()[0] == 0:
        token = secrets.token_urlsafe(8)
        pw_hash = generate_password_hash("admin") # Default password is admin
        c.execute("INSERT INTO users (username, password_hash, doh_token) VALUES (?, ?, ?)", ("admin", pw_hash, token))
        conn.commit()
        
    conn.close()
    ensure_default_rules()
    reload_rules_cache()

def reload_rules_cache():
    global rules_cache
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id FROM users")
    users = c.fetchall()
    
    new_cache = {}
    for (uid,) in users:
        new_cache[uid] = {'categories': {}, 'domains': set(), 'logging_enabled': True}
        
        c.execute("SELECT logging_enabled FROM users WHERE id = ?", (uid,))
        logging_row = c.fetchone()
        if logging_row: new_cache[uid]['logging_enabled'] = bool(logging_row[0])
        
        c.execute("SELECT category, MAX(is_active) FROM rules WHERE user_id = ? AND category != 'Specific Website' GROUP BY category", (uid,))
        new_cache[uid]['categories'] = {row[0]: bool(row[1]) for row in c.fetchall()}
        
        c.execute("SELECT domain FROM rules WHERE user_id = ? AND is_active = 1", (uid,))
        new_cache[uid]['domains'] = {row[0] for row in c.fetchall()}
        
    rules_cache = new_cache
    conn.close()

init_db()

# --- DNS Logic ---
last_logged = {}

def _evict_stale_dedup():
    """Remove dedup entries older than 3 seconds to prevent unbounded growth."""
    now = time.time()
    stale = [k for k, t in last_logged.items() if now - t > 3.0]
    for k in stale:
        del last_logged[k]

def log_request_async(domain, action, user_id):
    if domain.endswith('.arpa') or domain.endswith('.arpa.'):
        return

    now = time.time()
    key = f"{user_id}_{domain}_{action}"
    if key in last_logged and (now - last_logged[key]) < 2.0:
        return

    # TTL-based eviction instead of full clear
    if len(last_logged) > 500:
        _evict_stale_dedup()

    last_logged[key] = now

    # Increment the persistent aggregate counter (always, even in stealth mode)
    if action == "BLOCKED":
        def _increment():
            conn = None
            try:
                conn = sqlite3.connect(DB_FILE, timeout=5)
                c = conn.cursor()
                c.execute("UPDATE users SET total_blocked = total_blocked + 1 WHERE id = ?", (user_id,))
                # Also update daily aggregate (privacy-safe — no domain info)
                c.execute("INSERT INTO blocked_daily (user_id, day, count) VALUES (?, date('now', 'localtime'), 1) ON CONFLICT(user_id, day) DO UPDATE SET count = count + 1", (user_id,))
                conn.commit()
            except Exception as e:
                logger.warning(f"Failed to increment blocked count: {e}")
            finally:
                if conn: conn.close()
        threading.Thread(target=_increment, daemon=True).start()

    user_cache = rules_cache.get(user_id, {})
    if not user_cache.get('logging_enabled', True):
        return

    def _log():
        conn = None
        try:
            conn = sqlite3.connect(DB_FILE, timeout=5)
            c = conn.cursor()
            c.execute("INSERT INTO logs (user_id, domain, action) VALUES (?, ?, ?)", (user_id, domain, action))
            conn.commit()
        except Exception as e:
            logger.warning(f"Failed to write log entry: {e}")
        finally:
            if conn: conn.close()
    threading.Thread(target=_log, daemon=True).start()

def process_dns_query(data, addr, sock, user_id=1, is_doh=False):
    try:
        request_data = DNSRecord.parse(data)
        qname = str(request_data.q.qname).rstrip('.')
        reply = DNSRecord(DNSHeader(id=request_data.header.id, qr=1, aa=1, ra=1), q=request_data.q)
        
        user_cache = rules_cache.get(user_id, {'categories': {}, 'domains': set()})
        is_blocked = any(bd in qname for bd in user_cache['domains'])
        
        if is_blocked:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0")))
            log_request_async(qname, "BLOCKED", user_id)
            res_packed = reply.pack()
            if not is_doh: sock.sendto(res_packed, addr)
            return res_packed
        else:
            try:
                is_adult = user_cache['categories'].get('Adult', False)
                is_malware = user_cache['categories'].get('Malware & Phishing', False)
                
                upstream_dns = "8.8.8.8"
                if is_adult: upstream_dns = "185.228.168.10"
                elif is_malware: upstream_dns = "9.9.9.9"
                
                real_dns_response = request_data.send(upstream_dns, 53, timeout=3)
                
                action = "ALLOWED"
                try:
                    resp_obj = DNSRecord.parse(real_dns_response)
                    if resp_obj.header.rcode == 3:
                        action = "BLOCKED"
                    else:
                        is_cname_blocked = False
                        for answer in resp_obj.rr:
                            if getattr(answer, 'rtype', None) == 1 and str(answer.rdata) in ['0.0.0.0', '185.228.168.10']:
                                action = "BLOCKED"
                            elif getattr(answer, 'rtype', None) == 5:
                                cname_trg = str(answer.rdata).rstrip('.')
                                if any(bd in cname_trg for bd in user_cache['domains']):
                                    is_cname_blocked = True
                                    action = "BLOCKED"
                                    break
                                    
                        if is_cname_blocked:
                            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0")))
                            log_request_async(qname, "BLOCKED", user_id)
                            res_packed = reply.pack()
                            if not is_doh: sock.sendto(res_packed, addr)
                            return res_packed
                except Exception as e:
                    logger.debug(f"CNAME parse error for {qname}: {e}")
                    
                log_request_async(qname, action, user_id)
                if not is_doh: sock.sendto(real_dns_response, addr)
                return real_dns_response
            except Exception as e:
                logger.warning(f"Upstream DNS failure for {qname}: {e}")
                reply.header.rcode = 2
                res_packed = reply.pack()
                if not is_doh: sock.sendto(res_packed, addr)
                return res_packed
    except Exception as e:
        logger.error(f"DNS query processing error: {e}")
        return b''

def dns_handler():
    try:
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.bind(('0.0.0.0', 53))
        print("Legacy Local UDP DNS Server listening on port 53...")
    except Exception:
        return

    while True:
        try:
            data, addr = udps.recvfrom(1024)
            # Default to User 1 for legacy LAN traffic
            threading.Thread(target=process_dns_query, args=(data, addr, udps, 1, False), daemon=True).start()
        except Exception as e:
            logger.error(f"DNS handler error: {e}")

if not IS_VERCEL:
    dns_thread = threading.Thread(target=dns_handler, daemon=True)
    dns_thread.start()
else:
    logger.info("Running on Vercel: Skipping local UDP DNS server (port 53).")

# --- DNS over HTTPS Endpoints ---

def get_user_by_token(token):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE doh_token = ?", (token,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

@app.route('/dns-query/<token>', methods=['GET'])
def doh_get(token):
    user_id = get_user_by_token(token)
    if not user_id: return "Unauthorized", 401
    
    dns_b64 = request.args.get('dns')
    if not dns_b64: return "Bad Request", 400
    
    try:
        dns_b64 += '=' * (-len(dns_b64) % 4)
        dns_query = base64.urlsafe_b64decode(dns_b64)
        res = process_dns_query(dns_query, None, None, user_id, True)
        return Response(res, mimetype='application/dns-message')
    except:
        return "Bad Request", 400

@app.route('/dns-query/<token>', methods=['POST'])
def doh_post(token):
    user_id = get_user_by_token(token)
    if not user_id: return "Unauthorized", 401
    
    if request.headers.get('Content-Type') != 'application/dns-message':
        return "Unsupported Media Type", 415
        
    dns_query = request.get_data()
    res = process_dns_query(dns_query, None, None, user_id, True)
    return Response(res, mimetype='application/dns-message')

# --- Secure Web Dashboard ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, username, doh_token, password_hash FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        
        if row and check_password_hash(row[3], password):
            user = User(row[0], row[1], row[2])
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        if c.fetchone():
            conn.close()
            return render_template('register.html', error="Username is already taken.")
            
        token = secrets.token_urlsafe(8)
        pw_hash = generate_password_hash(password)
        
        try:
            c.execute("INSERT INTO users (username, password_hash, doh_token) VALUES (?, ?, ?)", (username, pw_hash, token))
            conn.commit()
            
            user_id = c.lastrowid
            
            for cat, domains in DEFAULT_CATEGORIES.items():
                for dom in domains:
                    is_active = 0 if cat == 'Adult' else 1
                    c.execute("INSERT INTO rules (user_id, category, domain, is_active) VALUES (?, ?, ?, ?)", (user_id, cat, dom, is_active))
            conn.commit()
            
            user = User(user_id, username, token)
            login_user(user)
            conn.close()
            
            reload_rules_cache()
            return redirect(url_for('index'))
        except Exception as e:
            conn.close()
            return render_template('register.html', error="An error occurred creating your account.")
            
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # Pass DoH token, username, and admin status to the dashboard
    return render_template('index.html', doh_token=current_user.doh_token, username=current_user.username, is_admin=(current_user.id == 1))

@app.route('/api/admin/users', methods=['GET'])
@login_required
def admin_get_users():
    if current_user.id != 1: return "Forbidden", 403
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, username, doh_token FROM users")
    users = [{"id": r[0], "username": r[1], "doh_token": r[2]} for r in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/api/admin/users/<int:uid>', methods=['DELETE'])
@login_required
def admin_delete_user(uid):
    if current_user.id != 1 or uid == 1: return "Forbidden", 403
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (uid,))
    c.execute("DELETE FROM rules WHERE user_id=?", (uid,))
    c.execute("DELETE FROM logs WHERE user_id=?", (uid,))
    conn.commit()
    conn.close()
    reload_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/stats')
@login_required
def get_stats():
    period = request.args.get('period', 'all')
    time_filter = ""
    uid = current_user.id
    
    if period == 'today': time_filter = "AND date(timestamp, 'localtime') = date('now', 'localtime')"
    elif period == 'yesterday': time_filter = "AND date(timestamp, 'localtime') = date('now', 'localtime', '-1 day')"
    elif period == '7days': time_filter = "AND date(timestamp, 'localtime') >= date('now', 'localtime', '-7 days')"
    elif period == 'this_month': time_filter = "AND strftime('%Y-%m', timestamp, 'localtime') = strftime('%Y-%m', 'now', 'localtime')"
    elif period == 'last_month': time_filter = "AND strftime('%Y-%m', timestamp, 'localtime') = strftime('%Y-%m', 'now', 'localtime', '-1 month')"
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Check stealth mode — never return logs if disabled
    c.execute("SELECT logging_enabled FROM users WHERE id = ?", (uid,))
    stealth_row = c.fetchone()
    is_stealth = stealth_row and not stealth_row[0]

    if period == 'all':
        c.execute("SELECT total_blocked FROM users WHERE id = ?", (uid,))
        total = c.fetchone()[0]
    elif is_stealth:
        # Stealth mode: use privacy-safe daily aggregates instead of logs
        day_filter = ""
        if period == 'today': day_filter = "AND day = date('now', 'localtime')"
        elif period == 'yesterday': day_filter = "AND day = date('now', 'localtime', '-1 day')"
        elif period == '7days': day_filter = "AND day >= date('now', 'localtime', '-7 days')"
        elif period == 'this_month': day_filter = "AND strftime('%Y-%m', day) = strftime('%Y-%m', 'now', 'localtime')"
        elif period == 'last_month': day_filter = "AND strftime('%Y-%m', day) = strftime('%Y-%m', 'now', 'localtime', '-1 month')"
        c.execute(f"SELECT COALESCE(SUM(count), 0) FROM blocked_daily WHERE user_id=? {day_filter}", (uid,))
        total = c.fetchone()[0]
    else:
        c.execute(f"SELECT count(*) FROM logs WHERE action='BLOCKED' AND user_id=? {time_filter}", (uid,))
        total = c.fetchone()[0]

    if is_stealth:
        recent = []
    else:
        c.execute(f"SELECT domain, MAX(timestamp) FROM logs WHERE action='BLOCKED' AND user_id=? {time_filter} GROUP BY domain ORDER BY MAX(timestamp) DESC LIMIT 15", (uid,))
        recent = [{"domain": r[0], "time": r[1]} for r in c.fetchall()]

    conn.close()
    return jsonify({"total_blocked": total, "recent_blocks": recent, "stealth": is_stealth})

@app.route('/api/activity')
@login_required
def get_activity():
    uid = current_user.id
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT logging_enabled FROM users WHERE id = ?", (uid,))
    logging_row = c.fetchone()
    if logging_row and not logging_row[0]:
        conn.close()
        return jsonify([])
    c.execute("SELECT domain, action, timestamp FROM logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 200", (uid,))
    acts = [{"domain": r[0], "action": r[1], "time": r[2]} for r in c.fetchall()]
    conn.close()
    return jsonify(acts)

@app.route('/api/rules', methods=['GET'])
@login_required
def get_rules():
    uid = current_user.id
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT domain, is_active FROM rules WHERE category = 'Specific Website' AND user_id=?", (uid,))
    custom = [{"domain": r[0], "is_active": bool(r[1])} for r in c.fetchall()]
    
    c.execute("SELECT category, domain FROM rules WHERE category != 'Specific Website' AND user_id=?", (uid,))
    cat_domains = {}
    for row in c.fetchall():
        cat_domains.setdefault(row[0], []).append(row[1])
    conn.close()

    cat_list = []
    user_cache = rules_cache.get(uid, {'categories': {}})
    for k, v in user_cache['categories'].items():
        cat_list.append({"category": k, "is_active": v, "domains": cat_domains.get(k, [])})

    return jsonify({"categories": cat_list, "custom_domains": custom})

@app.route('/api/rules/category', methods=['POST'])
@login_required
def manage_category_rule():
    data = request.json
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE rules SET is_active = ? WHERE category = ? AND user_id=?", (data['is_active'], data['category'], current_user.id))
    conn.commit()
    conn.close()
    reload_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/rules/domain', methods=['POST'])
@login_required
def add_domain_rule():
    domain = request.json.get('domain', '').strip().lower()
    if not domain or not DOMAIN_RE.match(domain):
        return jsonify({"status": "error", "message": "Invalid domain format"}), 400
        
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    uid = current_user.id
    c.execute("SELECT id FROM rules WHERE domain = ? AND category = 'Specific Website' AND user_id=?", (domain, uid))
    if c.fetchone():
        c.execute("UPDATE rules SET is_active = 1 WHERE domain = ? AND category = 'Specific Website' AND user_id=?", (domain, uid))
    else:
        c.execute("INSERT INTO rules (user_id, category, domain, is_active) VALUES (?, 'Specific Website', ?, 1)", (uid, domain))
    conn.commit()
    conn.close()
    reload_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/rules/domain', methods=['DELETE'])
@login_required
def delete_domain_rule():
    domain = request.json.get('domain', '').strip().lower()
    if not domain: return jsonify({"status": "error"}), 400
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM rules WHERE domain = ? AND category = 'Specific Website' AND user_id=?", (domain, current_user.id))
    conn.commit()
    conn.close()
    reload_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/rules/domain_toggle', methods=['POST'])
@login_required
def toggle_domain_rule():
    data = request.json
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE rules SET is_active = ? WHERE domain = ? AND category = 'Specific Website' AND user_id=?", (data['is_active'], data['domain'].strip(), current_user.id))
    conn.commit()
    conn.close()
    reload_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/user/logging', methods=['GET', 'POST'])
@login_required
def manage_logging():
    uid = current_user.id
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if request.method == 'POST':
        enabled = 1 if request.json.get('enabled') else 0
        c.execute("UPDATE users SET logging_enabled = ? WHERE id = ?", (enabled, uid))
        conn.commit()
        conn.close()
        reload_rules_cache()
        return jsonify({"status": "success"})
    else:
        c.execute("SELECT logging_enabled FROM users WHERE id = ?", (uid,))
        row = c.fetchone()
        conn.close()
        return jsonify({"enabled": bool(row[0]) if row else True})

if __name__ == '__main__':
    print("\n================================================")
    print("   SHIELD DNS IS NOW RUNNING IN MULTI-TENANT    ")
    print("   Dashboard: http://localhost:8080             ")
    print("================================================\n")
    serve(app, host='0.0.0.0', port=8080, threads=6)
