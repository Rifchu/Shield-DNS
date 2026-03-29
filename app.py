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

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

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
    # Priority 1: Environment Variable (Perfect for Vercel)
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
        
    # Priority 2: Local File (For local dev persistence)
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            return f.read().strip()
            
    # Priority 3: Generate New (Last resort)
    key = secrets.token_hex(32)
    try:
        with open(SECRET_KEY_FILE, 'w') as f:
            f.write(key)
    except:
        pass # Might fail on read-only fs
    return key

app.secret_key = load_or_create_secret_key()
# Make sessions last longer and survive browser restarts
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=2592000 # 30 days
)

# Domain validation regex
DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

def get_db_connection():
    postgres_url = os.environ.get('POSTGRES_URL')
    if postgres_url and HAS_POSTGRES:
        conn = psycopg2.connect(postgres_url)
        return conn
    else:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn

def get_cursor(conn):
    if hasattr(conn, 'cursor_factory'): # Postgres
        return conn.cursor(cursor_factory=RealDictCursor)
    return conn.cursor()

def fetch_one(cursor):
    row = cursor.fetchone()
    if row and not isinstance(row, dict) and hasattr(row, 'keys'):
        return dict(row)
    return row

def fetch_all(cursor):
    rows = cursor.fetchall()
    return [dict(r) if not isinstance(r, dict) and hasattr(r, 'keys') else r for r in rows]

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
    conn = get_db_connection()
    c = get_cursor(conn)
    c.execute("SELECT id, username, doh_token FROM users WHERE id = %s" if 'POSTGRES_URL' in os.environ else "SELECT id, username, doh_token FROM users WHERE id = ?", (int(user_id),))
    row = fetch_one(c)
    conn.close()
    if row:
        return User(row['id'], row['username'], row['doh_token'])
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
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    
    c.execute("SELECT id FROM users")
    users = fetch_all(c)
    
    for row in users:
        uid = row['id']
        for cat, domains in DEFAULT_CATEGORIES.items():
            c.execute(f"SELECT 1 FROM rules WHERE user_id = {p_mark} AND category = {p_mark}", (uid, cat))
            if not fetch_one(c):
                for dom in domains:
                    is_active = 0 if cat == 'Adult' else 1
                    c.execute(f"INSERT INTO rules (user_id, category, domain, is_active) VALUES ({p_mark}, {p_mark}, {p_mark}, {p_mark})", (uid, cat, dom, is_active))
    conn.commit()
    conn.close()

# In-memory rule cache mapping user_id -> rules
rules_cache = {}

def init_db():
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    
    # Table creation with cross-DB compatibility
    id_type = "SERIAL PRIMARY KEY" if is_postgres else "INTEGER PRIMARY KEY"
    p_mark = "%s" if is_postgres else "?"
    
    c.execute(f'''CREATE TABLE IF NOT EXISTS users
                 (id {id_type}, username TEXT UNIQUE, password_hash TEXT, doh_token TEXT UNIQUE)''')
                 
    try:
        c.execute("ALTER TABLE users ADD COLUMN logging_enabled INTEGER DEFAULT 1")
    except (sqlite3.OperationalError, Exception):
        pass
        
    try:
        c.execute("ALTER TABLE users ADD COLUMN total_blocked INTEGER DEFAULT 0")
    except (sqlite3.OperationalError, Exception):
        pass
                 
    c.execute(f'''CREATE TABLE IF NOT EXISTS logs
                 (id {id_type}, user_id INTEGER, domain TEXT, action TEXT, "timestamp" TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
                 
    c.execute(f'''CREATE TABLE IF NOT EXISTS rules
                 (id {id_type}, user_id INTEGER, category TEXT, domain TEXT, is_active INTEGER)''')
    
    c.execute(f'''CREATE TABLE IF NOT EXISTS blocked_daily
                 (id {id_type}, user_id INTEGER, day TEXT, count INTEGER DEFAULT 0,
                  UNIQUE(user_id, day))''')
    conn.commit()
    conn.close()
    
    # Ensure all existing users have the default categories populated
    ensure_default_rules()
    
    # DB indexes
    if not is_postgres:
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_user_action ON logs(user_id, action, timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_rules_user ON rules(user_id, category)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_blocked_daily ON blocked_daily(user_id, day)")

    # Legacy cleanup
    if not is_postgres:
        c.execute("UPDATE users SET total_blocked = (SELECT COUNT(*) FROM logs WHERE logs.user_id = users.id AND logs.action = 'BLOCKED') WHERE total_blocked = 0")
    
    c.execute("SELECT count(*) as total FROM users")
    row = fetch_one(c)
    if not row or row['total'] == 0:
        token = secrets.token_urlsafe(8)
        pw_hash = generate_password_hash("admin123")
        c.execute(f"INSERT INTO users (username, password_hash, doh_token) VALUES ({p_mark}, {p_mark}, {p_mark})", ("admin", pw_hash, token))
        conn.commit()
        
    conn.close()
    ensure_default_rules()
    reload_rules_cache()

def reload_rules_cache():
    global rules_cache
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    
    c.execute("SELECT id FROM users")
    users = fetch_all(c)
    
    new_cache = {}
    for user_row in users:
        uid = user_row['id']
        new_cache[uid] = {'categories': {}, 'domains': set(), 'logging_enabled': True}
        
        c.execute(f"SELECT logging_enabled FROM users WHERE id = {p_mark}", (uid,))
        logging_row = fetch_one(c)
        if logging_row: new_cache[uid]['logging_enabled'] = bool(logging_row['logging_enabled'])
        
        # Postgres requires explicit column names in GROUP BY or aggregation
        c.execute(f"SELECT category, MAX(is_active) as max_active FROM rules WHERE user_id = {p_mark} AND category != 'Specific Website' GROUP BY category", (uid,))
        for row in fetch_all(c):
            new_cache[uid]['categories'][row['category']] = bool(row['max_active'])
        
        c.execute(f"SELECT domain FROM rules WHERE user_id = {p_mark} AND is_active = 1", (uid,))
        new_cache[uid]['domains'] = {row['domain'] for row in fetch_all(c)}
        
    rules_cache = new_cache
    conn.close()

try:
    init_db()
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")

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

    # Internal logging logic
    def _do_log(domain, action, uid):
        conn = None
        try:
            conn = get_db_connection()
            c = get_cursor(conn)
            is_postgres = 'POSTGRES_URL' in os.environ
            p_mark = "%s" if is_postgres else "?"
            
            # 1. Update counters
            if action == "BLOCKED":
                c.execute(f"UPDATE users SET total_blocked = total_blocked + 1 WHERE id = {p_mark}", (uid,))
                date_func = "CURRENT_DATE" if is_postgres else "date('now', 'localtime')"
                if is_postgres:
                    c.execute(f"INSERT INTO blocked_daily (user_id, day, count) VALUES (%s, {date_func}, 1) ON CONFLICT(user_id, day) DO UPDATE SET count = blocked_daily.count + 1", (uid,))
                else:
                    c.execute(f"INSERT INTO blocked_daily (user_id, day, count) VALUES (?, {date_func}, 1) ON CONFLICT(user_id, day) DO UPDATE SET count = count + 1", (uid,))
            
            # 2. Write log entry (if enabled)
            c.execute(f"SELECT logging_enabled FROM users WHERE id = {p_mark}", (uid,))
            logging_row = fetch_one(c)
            if logging_row and logging_row['logging_enabled']:
                c.execute(f'INSERT INTO logs (user_id, domain, action) VALUES ({p_mark}, {p_mark}, {p_mark})', (uid, domain, action))
            
            conn.commit()
        except Exception as e:
            logger.warning(f"Logging failed for {domain}: {e}")
        finally:
            if conn: conn.close()

    if IS_VERCEL:
        _do_log(domain, action, user_id)
    else:
        threading.Thread(target=_do_log, args=(domain, action, user_id), daemon=True).start()

def process_dns_query(data, addr, sock, user_id=1, is_doh=False):
    try:
        request_data = DNSRecord.parse(data)
        qname = str(request_data.q.qname).rstrip('.').lower()
        reply = DNSRecord(DNSHeader(id=request_data.header.id, qr=1, aa=1, ra=1), q=request_data.q)
        
        # On Vercel (Serverless), we must check the DB directly for reliability
        is_blocked = False
        is_adult = False
        is_malware = False
        
        conn = None
        try:
            conn = get_db_connection()
            c = get_cursor(conn)
            is_postgres = 'POSTGRES_URL' in os.environ
            p_mark = "%s" if is_postgres else "?"
            
            # 1. Check all active categories to set upstream DNS flags
            c.execute(f"SELECT DISTINCT category FROM rules WHERE user_id={p_mark} AND is_active=1 AND category != 'Specific Website'", (user_id,))
            for r in fetch_all(c):
                if r['category'] == 'Adult': is_adult = True
                if r['category'] == 'Malware & Phishing': is_malware = True
            
            # 2. Hard-block list (Specific domains + All domains in active categories)
            c.execute(f"SELECT domain FROM rules WHERE user_id={p_mark} AND is_active=1", (user_id,))
            blocked_list = {r['domain'].lower() for r in fetch_all(c)}
            
            # Match qname against blocked domains (exact or as a parent domain)
            for bd in blocked_list:
                if bd == qname or qname.endswith('.' + bd):
                    is_blocked = True
                    logger.info(f"BLOCKED: {qname} caught by rule {bd} for user {user_id}")
                    break
                
        except Exception as db_e:
            logger.error(f"DB lookup during DNS query failed: {db_e}")
        finally:
            if conn: conn.close()
        
        if is_blocked:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0")))
            log_request_async(qname, "BLOCKED", user_id)
            res_packed = reply.pack()
            if not is_doh: sock.sendto(res_packed, addr)
            return res_packed
        else:
            try:
                # Use DoH Upstreams for better reliability on Vercel
                upstream_url = "https://dns.google/dns-query"
                if is_adult: upstream_url = "https://doh.cleanbrowsing.org/doh/adult-filter/"
                elif is_malware: upstream_url = "https://dns.quad9.net/dns-query"
                
                # Fetch via HTTPS
                import urllib.request
                req = urllib.request.Request(
                    upstream_url, 
                    data=data, 
                    headers={'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message'}
                )
                with urllib.request.urlopen(req, timeout=3) as response:
                    real_dns_response = response.read()
                
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
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    c.execute(f"SELECT id FROM users WHERE doh_token = {p_mark}", (token,))
    row = fetch_one(c)
    conn.close()
    return row['id'] if row else None

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
        conn = get_db_connection()
        c = get_cursor(conn)
        is_postgres = 'POSTGRES_URL' in os.environ
        p_mark = "%s" if is_postgres else "?"
        c.execute(f"SELECT id, username, doh_token, password_hash FROM users WHERE username = {p_mark}", (username,))
        row = fetch_one(c)
        conn.close()
        
        if row and check_password_hash(row['password_hash'], password):
            user = User(row['id'], row['username'], row['doh_token'])
            login_user(user, remember=True) # Enable "Remember Me"
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        c = get_cursor(conn)
        is_postgres = 'POSTGRES_URL' in os.environ
        p_mark = "%s" if is_postgres else "?"
        
        c.execute(f"SELECT id FROM users WHERE username = {p_mark}", (username,))
        if fetch_one(c):
            conn.close()
            return render_template('register.html', error="Username is already taken.")
            
        token = secrets.token_urlsafe(8)
        pw_hash = generate_password_hash(password)
        
        try:
            c.execute(f"INSERT INTO users (username, password_hash, doh_token) VALUES ({p_mark}, {p_mark}, {p_mark})", (username, pw_hash, token))
            conn.commit()
            
            # Need to get user_id correctly for both
            if is_postgres:
                c.execute("SELECT id FROM users WHERE username = %s", (username,))
                user_id = fetch_one(c)['id']
            else:
                user_id = c.lastrowid
            
            for cat, domains in DEFAULT_CATEGORIES.items():
                for dom in domains:
                    is_active = 0 if cat == 'Adult' else 1
                    c.execute(f"INSERT INTO rules (user_id, category, domain, is_active) VALUES ({p_mark}, {p_mark}, {p_mark}, {p_mark})", (user_id, cat, dom, is_active))
            conn.commit()
            
            user = User(user_id, username, token)
            login_user(user)
            conn.close()
            
            reload_rules_cache()
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Registration error: {e}")
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
    conn = get_db_connection()
    c = get_cursor(conn)
    c.execute("SELECT id, username, doh_token FROM users")
    users = fetch_all(c)
    conn.close()
    return jsonify(users)

@app.route('/api/admin/users/<int:uid>', methods=['DELETE'])
@login_required
def admin_delete_user(uid):
    if current_user.id != 1 or uid == 1: return "Forbidden", 403
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    c.execute(f"DELETE FROM users WHERE id={p_mark}", (uid,))
    c.execute(f"DELETE FROM rules WHERE user_id={p_mark}", (uid,))
    c.execute(f"DELETE FROM logs WHERE user_id={p_mark}", (uid,))
    conn.commit()
    conn.close()
    reload_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/stats')
@login_required
def get_stats():
    period = request.args.get('period', 'all')
    uid = current_user.id
    
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    
    # Check stealth mode
    c.execute(f"SELECT logging_enabled FROM users WHERE id = {p_mark}", (uid,))
    stealth_row = fetch_one(c)
    is_stealth = stealth_row and not stealth_row['logging_enabled']

    # Date filters
    if is_postgres:
        time_filters = {
            'today': "AND \"timestamp\"::date = CURRENT_DATE",
            'yesterday': "AND \"timestamp\"::date = CURRENT_DATE - INTERVAL '1 day'",
            '7days': "AND \"timestamp\"::date >= CURRENT_DATE - INTERVAL '7 days'",
            'this_month': "AND to_char(\"timestamp\", 'YYYY-MM') = to_char(CURRENT_DATE, 'YYYY-MM')",
            'last_month': "AND to_char(\"timestamp\", 'YYYY-MM') = to_char(CURRENT_DATE - INTERVAL '1 month', 'YYYY-MM')"
        }
    else:
        time_filters = {
            'today': "AND date(timestamp, 'localtime') = date('now', 'localtime')",
            'yesterday': "AND date(timestamp, 'localtime') = date('now', 'localtime', '-1 day')",
            '7days': "AND date(timestamp, 'localtime') >= date('now', 'localtime', '-7 days')",
            'this_month': "AND strftime('%Y-%m', timestamp, 'localtime') = strftime('%Y-%m', 'now', 'localtime')",
            'last_month': "AND strftime('%Y-%m', timestamp, 'localtime') = strftime('%Y-%m', 'now', 'localtime', '-1 month')"
        }
    
    time_filter = time_filters.get(period, "")

    if period == 'all':
        c.execute(f"SELECT total_blocked FROM users WHERE id = {p_mark}", (uid,))
        total_row = fetch_one(c)
        total = total_row['total_blocked'] if total_row else 0
    elif is_stealth:
        day_filter = ""
        if is_postgres:
            filters = {
                'today': "AND day = CURRENT_DATE::text",
                'yesterday': "AND day = (CURRENT_DATE - INTERVAL '1 day')::text",
                '7days': "AND day::date >= CURRENT_DATE - INTERVAL '7 days'",
                'this_month': "AND left(day, 7) = to_char(CURRENT_DATE, 'YYYY-MM')",
                'last_month': "AND left(day, 7) = to_char(CURRENT_DATE - INTERVAL '1 month', 'YYYY-MM')"
            }
        else:
            filters = {
                'today': "AND day = date('now', 'localtime')",
                'yesterday': "AND day = date('now', 'localtime', '-1 day')",
                '7days': "AND day >= date('now', 'localtime', '-7 days')",
                'this_month': "AND strftime('%Y-%m', day) = strftime('%Y-%m', 'now', 'localtime')",
                'last_month': "AND strftime('%Y-%m', day) = strftime('%Y-%m', 'now', 'localtime', '-1 month')"
            }
        day_filter = filters.get(period, "")
        c.execute(f"SELECT COALESCE(SUM(count), 0) as total FROM blocked_daily WHERE user_id={p_mark} {day_filter}", (uid,))
        total_row = fetch_one(c)
        total = total_row['total'] if total_row else 0
    else:
        c.execute(f"SELECT count(*) as total FROM logs WHERE action='BLOCKED' AND user_id={p_mark} {time_filter}", (uid,))
        total_row = fetch_one(c)
        total = total_row['total'] if total_row else 0

    if is_stealth:
        recent = []
    else:
        # Complex GROUP BY for Postgres
        if is_postgres:
            c.execute(f"SELECT domain, MAX(\"timestamp\") as time FROM logs WHERE action='BLOCKED' AND user_id=%s {time_filter} GROUP BY domain ORDER BY time DESC LIMIT 15", (uid,))
        else:
            c.execute(f"SELECT domain, MAX(timestamp) as time FROM logs WHERE action='BLOCKED' AND user_id=? {time_filter} GROUP BY domain ORDER BY time DESC LIMIT 15", (uid,))
        recent = [{"domain": r['domain'], "time": str(r['time'])} for r in fetch_all(c)]

    conn.close()
    return jsonify({"total_blocked": total, "recent_blocks": recent, "stealth": is_stealth})

@app.route('/api/debug')
@login_required
def get_debug_info():
    uid = current_user.id
    conn = get_db_connection()
    c = get_cursor(conn)
    
    c.execute("SELECT count(*) as total FROM rules WHERE user_id = %s" if 'POSTGRES_URL' in os.environ else "SELECT count(*) FROM rules WHERE user_id = ?", (uid,))
    rules_row = fetch_one(c)
    
    c.execute("SELECT count(*) as total FROM logs WHERE user_id = %s" if 'POSTGRES_URL' in os.environ else "SELECT count(*) FROM logs WHERE user_id = ?", (uid,))
    logs_row = fetch_one(c)
    
    conn.close()
    return jsonify({
        "user_id": uid,
        "is_vercel": IS_VERCEL,
        "database": "Postgres" if 'POSTGRES_URL' in os.environ else "SQLite",
        "rules_count": rules_row['total'] if rules_row else 0,
        "logs_count": logs_row['total'] if logs_row else 0,
        "doh_url": f"https://{request.host}/dns-query/{current_user.doh_token}"
    })

@app.route('/api/activity')
@login_required
def get_activity():
    uid = current_user.id
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    
    c.execute(f"SELECT logging_enabled FROM users WHERE id = {p_mark}", (uid,))
    logging_row = fetch_one(c)
    if logging_row and not logging_row['logging_enabled']:
        conn.close()
        return jsonify([])
    c.execute(f"SELECT domain, action, \"timestamp\" FROM logs WHERE user_id={p_mark} ORDER BY \"timestamp\" DESC LIMIT 200", (uid,))
    acts = [{"domain": r['domain'], "action": r['action'], "time": str(r['timestamp'])} for r in fetch_all(c)]
    conn.close()
    return jsonify(acts)

@app.route('/api/rules', methods=['GET'])
@login_required
def get_rules():
    uid = current_user.id
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    
    c.execute(f"SELECT domain, is_active FROM rules WHERE category = 'Specific Website' AND user_id={p_mark}", (uid,))
    custom = [{"domain": r['domain'], "is_active": bool(r['is_active'])} for r in fetch_all(c)]
    
    c.execute(f"SELECT category, domain FROM rules WHERE category != 'Specific Website' AND user_id={p_mark}", (uid,))
    cat_domains = {}
    for row in fetch_all(c):
        cat_domains.setdefault(row['category'], []).append(row['domain'])
    conn.close()
 
    user_cache = rules_cache.get(uid)
    
    # If cache is missing or empty, try one-time emergency reload
    if not user_cache or not user_cache.get('categories'):
        logger.info(f"Rules cache empty for user {uid}. Triggering emergency reload...")
        ensure_default_rules()
        reload_rules_cache()
        user_cache = rules_cache.get(uid, {'categories': {}, 'domains': set()})

    cat_list = []
    for k, v in user_cache['categories'].items():
        cat_list.append({"category": k, "is_active": v, "domains": cat_domains.get(k, [])})
 
    return jsonify({"categories": cat_list, "custom_domains": custom})

@app.route('/api/rules/category', methods=['POST'])
@login_required
def manage_category_rule():
    data = request.json
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    c.execute(f"UPDATE rules SET is_active = {p_mark} WHERE category = {p_mark} AND user_id={p_mark}", (int(data['is_active']), data['category'], current_user.id))
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
        
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    uid = current_user.id
    
    c.execute(f"SELECT id FROM rules WHERE domain = {p_mark} AND category = 'Specific Website' AND user_id={p_mark}", (domain, uid))
    if fetch_one(c):
        c.execute(f"UPDATE rules SET is_active = 1 WHERE domain = {p_mark} AND category = 'Specific Website' AND user_id={p_mark}", (domain, uid))
    else:
        c.execute(f"INSERT INTO rules (user_id, category, domain, is_active) VALUES ({p_mark}, 'Specific Website', {p_mark}, 1)", (uid, domain))
    conn.commit()
    conn.close()
    reload_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/rules/domain', methods=['DELETE'])
@login_required
def delete_domain_rule():
    domain = request.json.get('domain', '').strip().lower()
    if not domain: return jsonify({"status": "error"}), 400
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    c.execute(f"DELETE FROM rules WHERE domain = {p_mark} AND category = 'Specific Website' AND user_id={p_mark}", (domain.strip(), current_user.id))
    conn.commit()
    conn.close()
    reload_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/rules/domain_toggle', methods=['POST'])
@login_required
def toggle_domain_rule():
    data = request.json
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    c.execute(f"UPDATE rules SET is_active = {p_mark} WHERE domain = {p_mark} AND category = 'Specific Website' AND user_id={p_mark}", (int(data['is_active']), data['domain'].strip(), current_user.id))
    conn.commit()
    conn.close()
    reload_rules_cache()
    return jsonify({"status": "success"})

@app.route('/api/user/logging', methods=['GET', 'POST'])
@login_required
def manage_logging():
    uid = current_user.id
    conn = get_db_connection()
    c = get_cursor(conn)
    is_postgres = 'POSTGRES_URL' in os.environ
    p_mark = "%s" if is_postgres else "?"
    
    if request.method == 'POST':
        enabled = 1 if request.json.get('enabled') else 0
        c.execute(f"UPDATE users SET logging_enabled = {p_mark} WHERE id = {p_mark}", (enabled, uid))
        conn.commit()
        conn.close()
        reload_rules_cache()
        return jsonify({"status": "success"})
    else:
        c.execute(f"SELECT logging_enabled FROM users WHERE id = {p_mark}", (uid,))
        row = fetch_one(c)
        conn.close()
        return jsonify({"enabled": bool(row['logging_enabled']) if row else True})

if __name__ == '__main__':
    print("\n================================================")
    print("   SHIELD DNS IS NOW RUNNING IN MULTI-TENANT    ")
    print("   Dashboard: http://localhost:8080             ")
    print("================================================\n")
    serve(app, host='0.0.0.0', port=8080, threads=6)
