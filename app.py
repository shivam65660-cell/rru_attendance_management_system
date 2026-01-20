from os import getcwdb
from flask import Flask, app, render_template, request, redirect, url_for, session, flash, jsonify
from flask_session import Session
import sqlite3
from flask import Flask
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from calendar import month_name
from flask import send_file, jsonify, request
import csv, io, sqlite3
import os
import smtplib
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import send_from_directory
import secrets, hashlib, smtplib, datetime
from email.message import EmailMessage
import random, datetime
from flask import jsonify
from flask_mail import Mail, Message
import requests
from dotenv import load_dotenv          
from flask_talisman import Talisman     
from flask_wtf import CSRFProtect       
from flask_limiter import Limiter      
from flask_limiter.util import get_remote_address
from flask import abort, request
import re
from functools import wraps
from flask import session, redirect, url_for, flash
import psycopg2
from psycopg2.extras import RealDictCursor
# from flask_limiter.util import exempt
 # CSP configure करें production में
#from flask_socketio import SocketIO, emit
#socketio = SocketIO(app, cors_allowed_origins="*")

# ✅ 1. ENVIRONMENT VARIABLES LOAD (SABSE PEHLE)
load_dotenv() 

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ✅ Step (Session Config)
os.environ.get('FLASK_SECRET_KEY') or 'dev-fallback-secret-5f2a1d9b8a37c47c2d9e47b173f1a8af' 
app.secret_key = '5f2a1d9b8a37c47c2d9e47b173f1a8af'
#app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True 
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
#app.config['SESSION_FILE_DIR'] = './.flask_session/'
#Session(app)

app.config.update(
    SESSION_COOKIE_SECURE=True,     # only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY=True,   # not accessible from JS
    SESSION_COOKIE_SAMESITE='Lax' ,  # prevents cross-site cookie leakage #Lax tha pahle
    PERMANENT_SESSION_LIFETIME=600  # 10 minutes
)
# ✅ Step (Rate Limiting Config)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"], # global limit
)

# email config (example using SMTP)
app.config.update({
    "MAIL_SERVER": "smtp.gmail.com",
    "MAIL_PORT": 587,
   "MAIL_USERNAME": os.environ.get('MAIL_USERNAME', '25mscup022@student.rru.ac.in'),
    "MAIL_PASSWORD": os.environ.get('MAIL_PASSWORD', 'YOUR_EMAIL_APP_PASSWORD'),
    "MAIL_USE_TLS": True,
    "MAIL_USE_SSL": False,
    "OTP_EXPIRY_MINUTES": 10,
    "MAX_OTP_SENDS_PER_HOUR": 3,
    "MAX_OTP_VERIFY_ATTEMPTS": 5,
    "RECAPTCHA_SECRET_KEY": os.environ.get("RECAPTCHA_SECRET_KEY", "6Ldeof4rAAAAAFWYXaGiW78kvOF90At6bb0k_p22"),
})

# Talisman(app, content_security_policy=None, force_https=False) # Development के लिए False, Production में True करें

# ✅ A: CSRF Protection
CSRFProtect(app)

# ✅ A/C: Rate Limiting
#limiter = Limiter(
    #key_func=get_remote_address,
    #app=app,
    #default_limits=["50 per minute"], # Default limit for all routes
    #storage_uri="memory://" # Production में Redis या Memcached उपयोग करें
#)

# ---------- Block Bad Bots ----------
BAD_AGENTS = ["sqlmap", "curl", "bot", "crawler", "dirbuster", "nmap"]

@app.before_request
def block_bad_bots():
    ua = request.headers.get("User-Agent", "").lower()
    for bad in BAD_AGENTS:
        if bad in ua:
            abort(403)


@limiter.limit("3 per minute")
@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json() or request.form
    email = (data.get('email') or '').strip().lower()
    role = (data.get('role') or 'student').strip().lower()

     # 🚨 RESTRICTION: Sirf Student hi reset kar payein
    if role != 'student':
            return jsonify({'status':'error', 'message':'Keval students hi password reset kar sakte hain.'}), 403

    table = table_for_role(role)
    if not table:
        return jsonify({'status':'error', 'message':'Invalid role'}), 400

    if not email:
        return jsonify({'status':'error', 'message':'Email required'}), 400
# database check
    conn = get_db_connection()
    cur = conn.cursor()
    # parameterized query -> SQL injection safe
    cur.execute(f"SELECT id, email FROM {table} WHERE email = %s", (email,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'status':'error', 'message':'Email not found for this role'}), 404

    # Rate-limit: agar already active OTP hai (expiry in future), deny short requests
    cur.execute(f"SELECT otp_expiry FROM {table} WHERE email = %s", (email,))
    r = cur.fetchone()
    if r and r.get('otp_expiry'):
        try:
            expiry = datetime.fromisoformat(r['otp_expiry'])
            if expiry > datetime.utcnow():
                conn.close()
                return jsonify({'status':'error','message':'OTP already sent. Please wait until it expires.'}), 429
        except Exception:
            pass

    otp = generate_otp()
    otp_hash = generate_password_hash(otp)   # store hashed OTP
    expiry_time = (datetime.utcnow() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

    # Save to DB
    cur.execute(f"UPDATE {table} SET otp_hash = %s, otp_expiry = %s WHERE email = %s", (otp_hash, expiry_time, email))
    conn.commit()
    conn.close()

    # Send email (best-effort)
    subject = "RRU Attendance — OTP for password reset"
    body = f"आपका OTP है: {otp}\nयह OTP 5 मिनट के लिए वैध है.\n\nअगर आपने request नहीं किया, तो कृपया ignore करें."
    try:
        send_email_via_gmail(email, subject, body)
    except Exception as e:
        # बेहतर UX: DB में OTP छोड़े, पर user को बताओ
        return jsonify({'status':'error', 'message':f'Failed to send email: {str(e)}'}), 500

    return jsonify({'status':'success', 'message':'OTP sent to your email (check inbox/spam).'})
# 2) Verify OTP
@limiter.limit("5 per minute")
@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    email = request.form.get("email")
    role = request.form.get("role")
    otp = request.form.get("otp")

    conn = get_db_connection()
    user = conn.execute(f"SELECT * FROM {role}s WHERE email=%s", (email,)).fetchone()

    if not user or not user["otp_hash"]:
        return jsonify({"status": "error", "message": "Invalid request"})

    if datetime.now() > datetime.fromisoformat(user["otp_expiry"]):
        return jsonify({"status": "error", "message": "OTP expired"})

    if not check_password_hash(user["otp_hash"], otp):
        return jsonify({"status": "error", "message": "Invalid OTP"})

    return jsonify({"status": "success"})

# 3) Reset Password
@limiter.limit("3 per minute")
@app.route("/reset_password", methods=["POST"])
def reset_password():
    email = request.form.get("email")
    role = request.form.get("role")
    new_password = request.form.get("password")

    conn = get_db_connection()
    hashed_pw = generate_password_hash(new_password)

    conn.execute(f"UPDATE {role}s SET password=%s, otp_hash=NULL, otp_expiry=NULL WHERE email=%s", (hashed_pw, email))
    conn.commit()
    conn.close()

    return jsonify({"status": "success"})

# Helper: generate 6-digit numeric OTP (string)
def generate_otp():
    return f"{secrets.randbelow(10**6):06d}"  # e.g. '034521'

# Helper: send email via Gmail SMTP (TLS)
def send_email_via_gmail(to_email, subject, body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = to_email
    msg.set_content(body)

    server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
    server.starttls()
    server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
    server.send_message(msg)
    server.quit()

# Helper: map role -> table name (validate)
def table_for_role(role):
    mapping = {
        'student': 'students',
        'teacher': 'teachers',
        'admin': 'admins',
    }
    return mapping.get(role)

# Security Headers
#@app.after_request
#def add_security_headers(response):
   # response.headers["X-Frame-Options"] = "SAMEORIGIN"
   # response.headers["X-XSS-Protection"] = "1; mode=block"
   # response.headers["X-Content-Type-Options"] = "nosniff"
   # response.headers["Referrer-Policy"] = "strict-origin"
   # response.headers["Content-Security-Policy"] = "default-src 'self' https://www.google.com https://www.gstatic.com"
   # return response

# ---------- DB helper ----------
#def get_db_connection():
    #conn = sqlite3.connect("rru.db")
    #conn.row_factory = sqlite3.Row
    #return conn
    
def get_db_connection():
    db_url = os.environ.get('DATABASE_URL') # Vercel variable
    
    if db_url:
        # 🟢 Cloud PostgreSQL (Production)
        conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
        return conn
    else:
        # 🟡 Local SQLite (Development)
        import sqlite3
        conn = sqlite3.connect("rru.db")
        conn.row_factory = sqlite3.Row
        return conn

# ---------- Basic Security Middleware ----------
SQL_PATTERN = re.compile(r"\b(union|drop|delete|insert|update)\b", re.IGNORECASE)

@app.before_request
def block_sql_injection():
    data = str(request.values)
    if SQL_PATTERN.search(data):
        abort(403)
# ---------- Utility Functions ----------
def _hash_otp(otp: str, salt: str):
    return hashlib.sha256((otp + salt).encode('utf-8')).hexdigest()

def send_email(to_email, subject, body, smtp_config=None):
    # सरल smtp send — production में Flask-Mail या transactional provider use करें
    cfg = smtp_config or {
        "host": app.config["MAIL_SERVER"],
        "port": app.config["MAIL_PORT"],
        "username": app.config["MAIL_USERNAME"],
        "password": app.config["MAIL_PASSWORD"],
        "use_tls": app.config.get("MAIL_USE_TLS", True)
    }
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["username"]
    msg["To"] = to_email
    msg.set_content(body)

    try:
        s = smtplib.SMTP(cfg["host"], cfg["port"])
        if cfg.get("use_tls"):
            s.starttls()
        s.login(cfg["username"], cfg["password"])
        s.send_message(msg)
        s.quit()
        return True
    except Exception as e:
        app.logger.error("Email send failed: %s", e)
        return False

# ✅ Step (Debug: Show Session)
@app.before_request
def show_session():
    print("\n Current Session Data:", dict(session))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def save_uploaded_file(fileobj):
    """Save file securely, return (rel_path, original_name, mime)"""
    if fileobj and fileobj.filename:
        filename = secure_filename(fileobj.filename)
        ext = filename.rsplit('.',1)[1].lower() if '.' in filename else ''
        # unique suffix
        suffix = datetime.now().strftime('%Y%m%d%H%M%S%f')
        stored_name = f"{suffix}_{filename}"
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
        fileobj.save(full_path)
        rel_path = os.path.relpath(full_path, start=os.getcwd())  # store relative path
        return rel_path, filename, fileobj.mimetype
    return None, None, None

# Allowed upload extensions
ALLOWED_EXT = {'png','jpg','jpeg','gif','pdf','ppt','pptx','doc','docx','zip'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024   # 16 MB max per upload

app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads', 'notifications')
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# ensure folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# -------------------------------
# ADMIN DECORATOR
# -------------------------------
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Unauthorized access! Admin only.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# -------------------------------
# TEACHER DECORATOR
# -------------------------------
def teacher_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "teacher":
            flash("Please login as teacher!", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# -------------------------------
# STUDENT DECORATOR
# -------------------------------
def student_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "student":
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# -------------------------------
# STAFF DECORATOR
# -------------------------------
def staff_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "staff":
            flash("Please login as staff!", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ---------- Home ----------
@app.route("/")
def home():
    return render_template("index.html")


# ---------- About ----------
@app.route("/about")
def about():
    return render_template("about.html")


MAX_FAILED = 5
LOCK_MINUTES = 15
# record on failed login
def record_failed_login(conn, email, role):
    from datetime import datetime
    now = datetime.utcnow().isoformat()

    # पहले check करें कि entry पहले से है या नहीं
    row = conn.execute("SELECT attempts FROM failed_logins WHERE user_email=%s AND role=%s", (email, role)).fetchone()

    if row:
        # अगर पहले से मौजूद है तो attempts बढ़ाओ और last_attempt अपडेट करो
        conn.execute(
            "UPDATE failed_logins SET attempts = attempts + 1, last_attempt=%s WHERE user_email=%s AND role=%s",
            (now, email, role)
        )
    else:
        # पहली बार असफल प्रयास
        conn.execute(
            "INSERT INTO failed_logins (user_email, role, attempts, last_attempt) VALUES (%s, %s, %s, %s)",
            (email, role, 1, now)
        )

    conn.commit()

# reset on successful login
def reset_failed_login(conn, email, role):
    conn.execute("DELETE FROM failed_logins WHERE user_email=%s AND role=%s", (email, role))
    conn.commit()
# check if account is locked

from datetime import datetime, timedelta, timezone

# check if account is locked
def check_account_lock(conn, email, role):
    row = conn.execute(
        "SELECT attempts, last_attempt, locked_until FROM failed_logins WHERE user_email=%s AND role=%s",
        (email, role)
    ).fetchone()

    if not row:
        return False, None

    # 🔒 Check if locked
    if row["locked_until"]:
        locked_until_dt = datetime.fromisoformat(row["locked_until"])
        if locked_until_dt > datetime.now(timezone.utc):
            return True, row["locked_until"]
        else:
            # ⏱ Lock expired → reset
            conn.execute(
                "UPDATE failed_logins SET attempts=0, locked_until=NULL WHERE user_email=%s AND role=%s",
                (email, role),
            )
            conn.commit()
            return False, None

    # 🚫 If attempts exceeded → lock
    if row["attempts"] >= MAX_FAILED:
        locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCK_MINUTES)).isoformat()
        conn.execute(
            "UPDATE failed_logins SET locked_until=%s WHERE user_email=%s AND role=%s",
            (locked_until, email, role),
        )
        conn.commit()
        return True, locked_until

    return False, None

# check if admin account is locked
def check_lockout(username, role):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT attempts, locked_until FROM failed_logins WHERE user_email=%s AND role=%s",
        (username, role)
    ).fetchone()
    conn.close()

    if not row:
        return False, None

    # 🔒 Check if locked
    if row["locked_until"]:
        locked_until_dt = datetime.fromisoformat(row["locked_until"])
        if locked_until_dt > datetime.now(timezone.utc):
            return True, locked_until_dt
        else:
            # ⏱ Lock expired → reset
            conn = get_db_connection()
            conn.execute(
                "UPDATE failed_logins SET attempts=0, locked_until=NULL WHERE user_email=%s AND role=%s",
                (username, role),
            )
            conn.commit()
            conn.close()
            return False, None

    # 🚫 If attempts exceeded → lock
    if row["attempts"] >= MAX_FAILED:
        locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCK_MINUTES)
        conn = get_db_connection()
        conn.execute(
            "UPDATE failed_logins SET locked_until=%s WHERE user_email=%s AND role=%s",
            (locked_until.isoformat(), username, role),
        )
        conn.commit()
        conn.close()
        return True, locked_until

    return False, None

# ================ Login Route ============================
@limiter.limit("5 per minute")  # 5 login attempts / min
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        role = request.form.get("role", "")

# ✅ Get the recaptcha response from form
        recaptcha_response = request.form.get("g-recaptcha-response")
 # ✅ Verify reCAPTCHA
        secret_key = "6Ldeof4rAAAAAFWYXaGiW78kvOF90At6bb0k_p22"  
        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        payload = {"secret": secret_key, "response": recaptcha_response}
        response = requests.post(verify_url, data=payload)
        result = response.json()
        
        # basic validation
        if not email or not password or role not in ("student","teacher","staff"):
            flash("Please fill all fields correctly.", "danger")
            return render_template("login.html")
       
        elif not result.get("success"):
             flash("Please verify the reCAPTCHA before logging in.", "danger")
             return render_template("login.html")

        conn = get_db_connection()

        # check lock first
        is_locked, locked_until = check_account_lock(conn, email, role)
        if is_locked:
            flash(f"Too many failed attempts. Try again after {locked_until}.", "danger")
            conn.close()
            return render_template("login.html")

        # Parameterized queries (no string interpolation)
        if role == "student":
            user = conn.execute("SELECT * FROM students WHERE email = %s", (email,)).fetchone()
        elif role == "teacher":
            user = conn.execute("SELECT * FROM teachers WHERE email = %s", (email,)).fetchone()
        elif role == "staff":
            user = conn.execute("SELECT * FROM staff WHERE email = %s", (email,)).fetchone()
        else:
            user = None

        # authenticate
        if user and check_password_hash(user["password"], password):
            # success: reset failed login tracker
            reset_failed_login(conn, email, role)

            # session hardening
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = role
            session["user_name"] = user["name"]
            session["school_id"] = user["school_id"]
            session.permanent = True  # if you want persistent session, set PERMANENT_SESSION_LIFETIME in config

            # regenerate session id (Flask will create a new cookie on session.clear + set)
            # optional: use Flask-Login for robust session management

            flash("Login successful!", "success")
            conn.close()

            if role == "student":
                return redirect(url_for("student_dashboard"))
            elif role == "teacher":
                return redirect(url_for("teacher_dashboard"))
            elif role == "staff":
                return redirect(url_for("staff_dashboard"))

        else:
            # failure: record attempt
            record_failed_login(conn, email, role)
            flash("Invalid email or password.", "danger")
            conn.close()

    # GET or failed POST
    return render_template("login.html")

# ======================== Forgot Password ============================

# 1) Show forgot password form
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "student")  # choose role on UI

        # find user by role
        conn = get_db_connection()
        if role == "student":
            user = conn.execute("SELECT id, email, name FROM students WHERE email = %s", (email,)).fetchone()
        elif role == "teacher":
            user = conn.execute("SELECT id, email, name FROM teachers WHERE email = %s", (email,)).fetchone()
        elif role == "staff":
            user = conn.execute("SELECT id, email, name FROM staff WHERE email = %s", (email,)).fetchone()
        elif role == "admin":
            user = conn.execute("SELECT id, email, name FROM admin WHERE email = %s", (email,)).fetchone()
        else:
            user = None

        if not user:
            flash("अगर यह ईमेल हमारे रिकॉर्ड में नहीं है तो भी सुरक्षा के कारण कोई सूचना नहीं दी जा रही है। कृपया अपना ईमेल चेक करें।", "info")
            conn.close()
            return redirect(url_for("forgot_password"))

        user_id = user["id"]

        # rate limit: OTP sends per hour
        one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        recent_sends = conn.execute("""
            SELECT count(*) as cnt FROM password_resets
            WHERE user_id=%s AND role=%s AND created_at >= %s
        """, (user_id, role, one_hour_ago)).fetchone()["cnt"]
        if recent_sends >= app.config.get("MAX_OTP_SENDS_PER_HOUR", 3):
            flash("आप बहुत जल्दी OTP माँग रहे हैं — कृपया थोड़ी देर बाद प्रयास करें।", "warning")
            conn.close()
            return redirect(url_for("forgot_password"))

        # generate OTP
        otp = f"{secrets.randbelow(10**6):06d}"   # 6 digit
        otp_hash = _hash_otp(otp, app.config["SECRET_KEY"])
        expires_at = (datetime.utcnow() + timedelta(minutes=app.config.get("OTP_EXPIRY_MINUTES", 10))).isoformat()

        # upsert: existing row replace
        conn.execute("DELETE FROM password_resets WHERE user_id=%s AND role=%s", (user_id, role))
        conn.execute("""
            INSERT INTO password_resets (user_id, role, otp_hash, expires_at, attempts, created_at)
            VALUES (%s, %s, %s, %s, 0, %s)
        """, (user_id, role, otp_hash, expires_at, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        # send email
        subject = "RRU - OTP for password reset"
        body = f"नमस्ते {user['name']},\n\nआपका पासवर्ड रीसैट OTP है: {otp}\nयह OTP {app.config.get('OTP_EXPIRY_MINUTES',10)} मिनट में समाप्त हो जाएगा।\n\nयदि आपने अनुरोध नहीं किया है तो इसे नज़रअंदाज़ करें।"
        sent = send_email(user["email"], subject, body)
        if sent:
            flash("OTP आपके ईमेल पर भेज दिया गया है। कृपया चेक करें।", "success")
        else:
            flash("OTP भेजने में समस्या हुई — बाद में पुन: प्रयास करें।", "danger")

        return redirect(url_for("verify_otp_page", role=role, user_id=user_id))
    return render_template("forgot_password.html")

# 2) Verify OTP and reset password
# show page to enter otp + new password
@limiter.limit("5 per minute")
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp_page():
    role = request.args.get("role")
    user_id = request.args.get("user_id")
    if request.method == "POST":
        user_id = request.form.get("user_id")
        role = request.form.get("role")
        otp = request.form.get("otp", "").strip()
        new_password = request.form.get("new_password", "")
        if not otp or not new_password:
            flash("OTP और नया पासवर्ड दोनों भरें।", "warning")
            return redirect(url_for("verify_otp_page", role=role, user_id=user_id))

        conn = get_db_connection()
        row = conn.execute("SELECT * FROM password_resets WHERE user_id=%s AND role=%s", (user_id, role)).fetchone()
        if not row:
            flash("कोई OTP अनुरोध रिकॉर्ड नहीं मिला या पहले ही उपयोग हो चुका है।", "danger")
            conn.close()
            return redirect(url_for("forgot_password"))

        # check expiry
        if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            conn.execute("DELETE FROM password_resets WHERE id=%s", (row["id"],))
            conn.commit()
            conn.close()
            flash("OTP की समय सीमा समाप्त हो चुकी है। फिर से अनुरोध करें।", "danger")
            return redirect(url_for("forgot_password"))

        # attempts limit
        if row["attempts"] >= app.config.get("MAX_OTP_VERIFY_ATTEMPTS", 5):
            conn.execute("DELETE FROM password_resets WHERE id=%s", (row["id"],))
            conn.commit()
            conn.close()
            flash("आपने अधिकतम बार OTP डाल दिया है। फिर से प्रयास करें।", "danger")
            return redirect(url_for("forgot_password"))

        # verify hash
        if _hash_otp(otp, app.config["SECRET_KEY"]) != row["otp_hash"]:
            conn.execute("UPDATE password_resets SET attempts = attempts + 1 WHERE id = %s", (row["id"],))
            conn.commit()
            conn.close()
            flash("गलत OTP। कृपया फिर प्रयास करें।", "danger")
            return redirect(url_for("verify_otp_page", role=role, user_id=user_id))

        # success -> update password in correct table
        hashed_pw = generate_password_hash(new_password)
        if role == "student":
            conn.execute("UPDATE students SET password = %s WHERE id = %s", (hashed_pw, user_id))
        elif role == "teacher":
            conn.execute("UPDATE teachers SET password = %s WHERE id = %s", (hashed_pw, user_id))
        elif role == "staff":
            conn.execute("UPDATE staff SET password = %s WHERE id = %s", (hashed_pw, user_id))
        elif role == "admin":
            conn.execute("UPDATE admin SET password = %s WHERE id = %s", (hashed_pw, user_id))
        else:
            conn.close()
            flash("Unknown role", "danger")
            return redirect(url_for("forgot_password"))

        # remove reset record
        conn.execute("DELETE FROM password_resets WHERE id = %s", (row["id"],))
        conn.commit()
        conn.close()

        flash("पासवर्ड सफलतापूर्वक अपडेट हो गया है। कृपया लॉगिन करें।", "success")
        return redirect(url_for("login"))

    # GET -> render form
    return render_template("verify_otp.html", role=role, user_id=user_id)


# ---------- Logout ---------- 
@app.route("/logout")
def logout():
    role = session.get("role", None)
    user_name = session.get("user_name", "User")

    # Session clear
    session.clear()

    # Optional flash message
    flash(f"{user_name}, you have been logged out successfully!", "info")

    # Redirect according to role
    if role == "teacher":
        return redirect(url_for("login"))
    elif role == "student":
        return redirect(url_for("login"))
    else:
        # Admin ke liye alag login page ho to yahan redirect kar sakte ho:
        return redirect(url_for("admin_login"))

# ============================================================
#                         ADMIN LOGIN
# ============================================================

# ✅ Admin Login Route
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        # Yeh saari lines 'if' ke andar honi chahiye (4 spaces aage)
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        recaptcha_response = request.form.get("g-recaptcha-response")
        
        # ✅ Verify reCAPTCHA
        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        res = requests.post(verify_url, data={
            'secret': '6Ldeof4rAAAAAFWYXaGiW78kvOF90At6bb0k_p22', 
            'response': recaptcha_response
        }).json()

        if not res.get("success"):
            flash("Please verify the reCAPTCHA.", "warning")
            return render_template("admin_login.html")

        # 2. Check Lockout
        is_locked, unlock_time = check_lockout(username, 'admin')
        if is_locked:
            flash(f"Account locked. Try again later.", "danger")
            return render_template("admin_login.html") 

        conn = sqlite3.connect("rru.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM admins WHERE username=%s", (username,))
        admin = cur.fetchone() 
        conn.close()

        # admin structure: (id, username, password)
        if admin and check_password_hash(admin[2], password):
            session["admin_id"] = admin[0]
            session["admin_username"] = admin[1]
            session["user_id"] = admin[0]
            session["role"] = "admin" 
            flash("Login successful!", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid admin credentials", "danger")

    # Yeh line 'if' se bahar hogi, taaki GET request par page dikhe
    return render_template("admin_login.html")

# ✅ Admin Logout
@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for("admin_login"))

# ============================================================
#                         ADMIN PANEL
# ============================================================

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    return render_template("admin_dashboard.html")


# --- Manage Schools ---
@app.route("/admin/schools")
def manage_schools():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    conn = get_db_connection()
    schools = conn.execute("SELECT * FROM schools").fetchall()
    conn.close()
    return render_template("manage_schools.html", schools=schools)

#--- add school ---
@app.route("/admin/add_school", methods=["POST"])
def add_school():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    school_name = request.form["school_name"]
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO schools (school_name) VALUES (%s)", (school_name,))
        conn.commit()
        flash("School added!", "success")
    except sqlite3.IntegrityError:
        flash("School already exists!", "danger")
    conn.close()
    return redirect(url_for("manage_schools"))

#--- delete school ---
@app.route("/admin/delete_school/<int:id>")
def delete_school(id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    conn = get_db_connection()
    conn.execute("DELETE FROM schools WHERE id=%s", (id,))
    conn.commit()
    conn.close()
    flash("Student deleted successfully", "info")
    return redirect(url_for("manage_schools"))

# --- Manage Courses ---
@app.route('/admin/manage_courses', methods=['GET', 'POST'])
def manage_courses():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    schools = conn.execute("SELECT * FROM schools").fetchall()

    if request.method == 'POST':
        school_id = request.form['school_id']
        course_name = request.form['course_name'].strip()

        # पहले से exist check
        existing = conn.execute(
            "SELECT * FROM courses WHERE course_name=%s AND school_id=%s",
            (course_name, school_id)
        ).fetchone()

        if existing:
            flash("⚠️ This course already exists for this school!", "danger")
            conn.close()
            return redirect(url_for('manage_courses'))
        else:
            conn.execute(
                "INSERT INTO courses (course_name, school_id) VALUES (%s, %s)",
                (course_name, school_id)
            )
            conn.commit()
            conn.close()
            flash("✅ Course added successfully!", "success")
            return redirect(url_for('manage_courses'))  # 💡 Redirect 

    courses = conn.execute("""
        SELECT c.id, c.course_name, s.school_name 
        FROM courses c
        JOIN schools s ON c.school_id = s.id
    """).fetchall()

    conn.close()
    return render_template("manage_courses.html", schools=schools, courses=courses)


# --- Manage Subjects ---
@app.route('/admin/manage_subjects', methods=['GET', 'POST'])
def manage_subjects():
    conn = get_db_connection()

    if request.method == 'POST':
        school_id = request.form['school_id']
        course_id = request.form['course_id']
        semester = request.form['semester']
        subject_name = request.form['subject_name']

        # Duplicate check (same course, semester, subject)
        existing = conn.execute("""
            SELECT * FROM subjects WHERE course_id = %s AND semester = %s AND subject_name = %s
        """, (course_id, semester, subject_name)).fetchone()

        if existing:
            flash('This subject already exists for the selected course and semester!', 'warning')
        else:
            conn.execute("""
                INSERT INTO subjects (subject_name, course_id, semester)
                VALUES (%s, %s, %s)
            """, (subject_name, course_id, semester))
            conn.commit()
            flash('Operation successful!', 'success')

    subjects = conn.execute("""
        SELECT sub.id, sub.subject_name, sub.semester, c.course_name, s.school_name
        FROM subjects sub
        JOIN courses c ON sub.course_id = c.id
        JOIN schools s ON c.school_id = s.id
        ORDER BY s.school_name, c.course_name, sub.semester
    """).fetchall()

    schools = conn.execute("SELECT * FROM schools").fetchall()
    conn.close()
    return render_template("manage_subjects.html", subjects=subjects, schools=schools)

#--- delete subject ---
@app.route('/admin/delete_subject/<int:id>')
def delete_subject(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM subjects WHERE id = %s', (id,))
    conn.commit()
    conn.close()
    flash('Subject deleted successfully!', 'success')
    return redirect(url_for('manage_subjects'))

#---- add Courses ---
@app.route("/admin/add_course", methods=["POST"])
def add_course():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    course_name = request.form["course_name"]
    school_id = request.form["school_id"]
    conn = get_db_connection()
    conn.execute("INSERT INTO courses (course_name, school_id) VALUES (%s, %s)",
                 (course_name, school_id))
    conn.commit()
    conn.close()
    flash("Course added!", "success")
    return redirect(url_for("manage_courses"))

#--- delete course ---
@app.route("/admin/delete_course/<int:id>")
def delete_course(id):
    if session.get("role") != "admin":
        return redirect(url_for("admin_login"))
    conn = get_db_connection()
    conn.execute("DELETE FROM courses WHERE id=%s", (id,))
    conn.commit()
    conn.close()
    flash("Course deleted!", "info")
    return redirect(url_for("view_students"))

#---- register student
@app.route("/admin/register_student", methods=["GET", "POST"])
def register_student():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    conn = get_db_connection()
    schools = conn.execute("SELECT * FROM schools").fetchall()  # ✅ पहले schools लेंगे

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"].lower()
        password = generate_password_hash(request.form["password"])
        school_id = request.form["school_id"]  # ✅ नया field
        course_id = request.form["course_id"]
        semester = request.form["semester"]
        roll_number = request.form["roll_number"]

        try:
            conn.execute("""
                INSERT INTO students (name, email, password, course_id, semester, roll_number)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, email, password, course_id, semester, roll_number))
            conn.commit()
            flash("Student registered!", "success")
            return redirect(url_for("view_students"))
        except sqlite3.IntegrityError:
            flash("Email or Roll Number already exists!", "danger")

    conn.close()
    return render_template("register_student.html", schools=schools)

# --- Register Teacher ---
@app.route("/admin/register_teacher", methods=["GET", "POST"])
def register_teacher():
    if session.get("role") != "admin":
        flash("Not authorized", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        school_id = request.form["school_id"]

        hashed_password = generate_password_hash(password)

        cur.execute(
            "INSERT INTO teachers (name, email, password, school_id) VALUES (%s, %s, %s, %s)",
            (name, email, hashed_password, school_id),
        )
        conn.commit()
        conn.close()
        flash("Teacher registered successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    cur.execute("SELECT * FROM schools")
    schools = cur.fetchall()
    conn.close()
    return render_template("register_teacher.html", schools=schools)

# --- View Students --- 
@app.route("/admin/students")
def view_students():
    if session.get("role") != "admin": 
        return redirect(url_for("login")) 

    conn = get_db_connection()  

    students = conn.execute("""
        SELECT s.*, c.course_name, sc.school_name, c.id as course_id, sc.id as school_id
        FROM students s
        LEFT JOIN courses c ON s.course_id = c.id
        LEFT JOIN schools sc ON c.school_id = sc.id
    """).fetchall()

    courses = conn.execute("SELECT * FROM courses").fetchall()
    schools = conn.execute("SELECT * FROM schools").fetchall()

    conn.close()  

    return render_template(
        "view_students.html",
        students=students,
        courses=courses,
        schools=schools
    )


# ------------------ VIEW TEACHERS ------------------
@app.route("/admin/teachers")
def view_teachers():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    conn = get_db_connection()
    
    teachers = conn.execute("""
         SELECT t.*, sc.school_name
        FROM teachers t 
        LEFT JOIN schools sc ON t.school_id = sc.id
    """).fetchall()

    schools = conn.execute("SELECT * FROM schools").fetchall()

    # Teacher-wise school specific courses fetch करेंगे
    teacher_courses_map = {}
    for t in teachers:
        courses = conn.execute("""
            SELECT id, course_name 
            FROM courses 
            WHERE school_id=%s
        """, (t["school_id"],)).fetchall()
        teacher_courses_map[t["id"]] = courses

    # अब पहले से assigned courses निकालेंगे
    assigned_courses = {} 
    assignments = conn.execute("""
    SELECT tc.id, tc.teacher_id, tc.semester,
           sc.school_name, c.course_name, s.subject_name
    FROM teacher_courses tc
    JOIN schools sc ON tc.school_id = sc.id
    JOIN courses c ON tc.course_id = c.id
    JOIN subjects s ON tc.subject_id = s.id
""").fetchall()
    for a in assignments: assigned_courses.setdefault(a["teacher_id"], []).append({
        "id": a["id"],                # assignment id (delete में काम आएगा)
        "school": a["school_name"],
        "course": a["course_name"],
        "subject": a["subject_name"],
        "semester": a["semester"]
    })
    return render_template(
        "view_teachers.html",
        teachers=teachers,
        schools=schools,
        teacher_courses=assigned_courses,
        teacher_courses_map=teacher_courses_map
    )
    
# --- Update Teacher ---
@app.route("/admin/teachers/update/<int:teacher_id>", methods=["POST"])
def update_teacher(teacher_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    name = request.form.get("name")
    email = request.form.get("email")
    department = request.form.get("department")
    conn = get_db_connection()
    conn.execute("""
        UPDATE teachers SET name=%s, email=%s, department=%s WHERE id=%s
    """, (name, email, department, teacher_id))
    conn.commit()
    conn.close()
    flash("Teacher updated successfully!", "success")
    return redirect(url_for("view_teachers"))

# ---------------- Students Management (Admin Control) ----------------
@app.route("/students")
def manage_students():
    conn = get_db_connection()
    students = conn.execute("""
        SELECT t.*, s.school_name,
           GROUP_CONCAT(c.course_name, ', ') AS courses
    FROM teachers t
    LEFT JOIN schools s ON t.school_id = s.id
    LEFT JOIN teacher_courses tc ON t.id = tc.teacher_id
    LEFT JOIN courses c ON tc.course_id = c.id
    GROUP BY t.id
    """).fetchall()
    conn.close()
    return render_template("view_students.html", students=students)

# --- Edit Student -----#

@app.route("/edit_student/<int:student_id>", methods=["POST"])
def edit_student(student_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    name = request.form.get("name")
    roll_number = request.form.get("roll_number")
    email = request.form.get("email")
    school_id = request.form.get("school_id")
    course_id = request.form.get("course_id")
    semester = request.form.get("semester")
    password = request.form.get("password")

    conn = get_db_connection()
    cur = conn.cursor()

    if password:  # अगर नया password दिया है तो update होगा
        cur.execute("""
            UPDATE students 
            SET name = %s, roll_number = %s, email = %s, school_id = %s, course_id = %s, semester = %s, password = %s
            WHERE id = %s
        """, (name, roll_number, email, school_id, course_id, semester, password, student_id))
    else:  # password खाली है तो पुराना ही रहेगा
        cur.execute("""
            UPDATE students 
            SET name = %s, roll_number = %s, email = %s, school_id = %s, course_id = %s, semester = %s
            WHERE id = %s
        """, (name, roll_number, email, school_id, course_id, semester, student_id))

    conn.commit()
    conn.close()
    flash("Student updated successfully!", "success")
    return redirect(url_for("view_students"))

#---student delete----#

@app.route("/admin/delete_student/<int:id>")
def delete_student(id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    conn = get_db_connection()
    conn.execute("DELETE FROM students WHERE id=%s", (id,))
    conn.commit()
    conn.close()
    flash("Student deleted successfully!", "info")
    return redirect(url_for("view_students"))

# Helper to get teacher courses mapping
def get_teacher_courses():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT tc.id as id, tc.teacher_id, s.school_name, c.course_name, sub.subject_name, tc.semester
        FROM teacher_courses tc
        LEFT JOIN schools s ON tc.school_id = s.id
        LEFT JOIN courses c ON tc.course_id = c.id
        LEFT JOIN subjects sub ON tc.subject_id = sub.id
        ORDER BY tc.teacher_id, s.school_name, c.course_name, sub.subject_name, tc.semester
    """)
    rows = cur.fetchall()
    conn.close()

    teacher_courses = {}
    for r in rows:
        teacher_courses.setdefault(r["teacher_id"], []).append({
            "id": r["id"],
            "school": r["school_name"] or "—",
            "course": r["course_name"] or "—",
            "subject": r["subject_name"] or "—",
            "semester": r["semester"] or ""
        })
    return teacher_courses


# ------------------ MANAGE TEACHERS ------------------

# ✅ Manage Teachers (Edit/Delete)

@app.route("/admin/manage_teachers")
def manage_teachers():
    if session.get("role") != "admin":
        return redirect(url_for("admin_login"))

    conn = get_db_connection()
    # fetch teachers with their primary school (if any)
    teachers = conn.execute("""
        SELECT t.id, t.name, t.email, t.school_id, s.school_name
        FROM teachers t
        LEFT JOIN schools s ON t.school_id = s.id
        ORDER BY t.name
    """).fetchall()

    # fetch all schools (for select boxes)
    schools = conn.execute("SELECT * FROM schools ORDER BY school_name").fetchall()

    # fetch all courses & subjects (useful for initial mapping or debug)
    # Note: for dynamic dropdowns we use AJAX endpoints already present.
    # courses = conn.execute("SELECT * FROM courses").fetchall()
    # subjects = conn.execute("SELECT * FROM subjects").fetchall()

    conn.close()

    teacher_courses = get_teacher_courses()   # helper above

    return render_template("manage_teachers.html",
                           teachers=teachers,
                           schools=schools,
                           teacher_courses=teacher_courses)



#---delete assign course teacher--#

@app.route("/admin/delete_assignment/<int:assignment_id>", methods=["POST"])
def delete_assignment(assignment_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM teacher_courses WHERE id = %s", (assignment_id,))
    conn.commit()
    conn.close()
    flash("Assignment removed successfully!", "success")
    return redirect(url_for("manage_teachers"))

# ✅ Edit Teacher
@app.route("/admin/edit_teacher/<int:id>", methods=["GET", "POST"])
def edit_teacher(id):
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")

        cur.execute("UPDATE teachers SET name=%s, email=%s WHERE id=%s", (name, email, id))
        conn.commit()
        conn.close()

        flash("Teacher updated successfully!", "success")
        return redirect(url_for("manage_teachers"))

    teacher = cur.execute("SELECT * FROM teachers WHERE id=%s", (id,)).fetchone()
    conn.close()
    return render_template("edit_teacher.html", teacher=teacher)

# ✅ Delete Teacher
@app.route("/admin/delete_teacher/<int:id>")
def delete_teacher(id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM teachers WHERE id=%s", (id,))
    conn.commit()
    conn.close()
    flash("Teacher deleted successfully!", "success")
    return redirect(url_for("manage_teachers"))


# ------------------ ASSIGN SCHOOL TO TEACHER ------------------
@app.route("/admin/update_teacher_school/<int:teacher_id>", methods=["POST"])
def update_teacher_school(teacher_id):
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    school_id = request.form.get("school_id")

    if school_id:
        conn = get_db_connection()
        try:
            conn.execute("UPDATE teachers SET school_id=%s WHERE id=%s", (school_id, teacher_id))
            conn.commit()
        finally:
            conn.close()
    return redirect(url_for("view_teachers"))


# ------------------ ASSIGN COURSE TO TEACHER ------------------
@app.route("/admin/assign_course/<int:teacher_id>", methods=["POST"])
def assign_course(teacher_id):
    if session.get("role") != "admin":
        flash("Not authorized", "danger")
        return redirect(url_for("admin_login"))

    school_id = request.form.get("school_id")
    course_id = request.form.get("course_id")
    subject_id = request.form.get("subject_id")
    semester = request.form.get("semester")

    if not (school_id and course_id and subject_id and semester):
        flash("Please select school, course, subject and semester!", "danger")
        return redirect(url_for("manage_teachers"))

    conn = get_db_connection()
    cur = conn.cursor()

    # prevent duplicate
    cur.execute("""
        SELECT id FROM teacher_courses
        WHERE teacher_id=%s AND school_id=%s AND course_id=%s AND subject_id=%s AND semester=%s
    """, (teacher_id, school_id, course_id, subject_id, semester))
    if cur.fetchone():
        flash("This assignment already exists!", "warning")
    else:
        cur.execute("""
            INSERT INTO teacher_courses (teacher_id, school_id, course_id, subject_id, semester)
            VALUES (%s, %s, %s, %s, %s)
        """, (teacher_id, school_id, course_id, subject_id, semester))
        conn.commit()
        flash("Assignment saved.", "success")

    conn.close()
    return redirect(url_for("manage_teachers"))

#------------------ AJAX Routes for Dynamic Dropdowns ------------------
@app.route('/get_courses/<int:school_id>')
def get_courses(school_id):
    conn = get_db_connection()
    courses = conn.execute("SELECT id, course_name FROM courses WHERE school_id = %s", (school_id,)).fetchall()
    conn.close()
    return jsonify([dict(c) for c in courses])

# ✅ Get Subjects by Course + Semester

@app.route('/get_subjects/<int:course_id>/<int:semester>/<int:teacher_id>')
def get_subjects(course_id, semester, teacher_id):
    conn = get_db_connection()
    # उन subjects को exclude करें जो पहले से assign हो चुके हैं
    query = """
        SELECT s.id, s.subject_name
        FROM subjects s
        WHERE s.course_id = %s AND s.semester = %s
        AND s.id NOT IN (
            SELECT subject_id FROM teacher_courses WHERE teacher_id = %s
        )
    """
    subjects = conn.execute(query, (course_id, semester, teacher_id)).fetchall()
    conn.close()
    return jsonify([{'id': s['id'], 'subject_name': s['subject_name']} for s in subjects])

#✅ Get Subjects assigned to a Teacher for given Course + Semester
@app.route("/get_subjects_for_teacher/<int:teacher_id>/<int:course_id>/<int:semester>")
def get_subjects_for_teacher(teacher_id, course_id, semester):
    conn = get_db_connection()
    subjects = conn.execute("""
        SELECT s.id, s.subject_name
        FROM teacher_courses tc
        JOIN subjects s ON tc.subject_id = s.id
        WHERE tc.teacher_id = %s AND tc.course_id = %s AND tc.semester = %s
    """, (teacher_id, course_id, semester)).fetchall()
    conn.close()
    return jsonify([{"id": s["id"], "subject_name": s["subject_name"]} for s in subjects])

# ================= Staff Management (Admin Control) =================

@app.route("/admin/manage_staff", methods=["GET", "POST"])
def manage_staff():
    # Access control
    if "role" not in session or session["role"] != "admin":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()

    # Fetch all schools (for dropdown)
    schools = conn.execute("SELECT id, school_name AS name FROM schools ORDER BY school_name ASC").fetchall()

    # Handle form submission
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = generate_password_hash(request.form["password"])  # secure password hashing
        school_id = request.form["school_id"]

        # Check duplicate email
        existing = conn.execute("SELECT * FROM staff WHERE email = %s", (email,)).fetchone()
        if existing:
            flash("⚠️ Staff with this email already exists.", "danger")
        else:
            conn.execute(
                "INSERT INTO staff (name, email, password, school_id) VALUES (%s, %s, %s, %s)",
                (name, email, password, school_id)
            )
            conn.commit()
            flash("✅ Staff added successfully!", "success")

    # Fetch staff list with school names
    staff = conn.execute("""
        SELECT staff.id, staff.name, staff.email, staff.school_id, schools.school_name AS school_name
        FROM staff
        LEFT JOIN schools ON staff.school_id = schools.id
        ORDER BY staff.id DESC
    """).fetchall()

    conn.close()

    return render_template("manage_staff.html", staff=staff, schools=schools)

# --- Edit Staff ---

@app.route("/edit_staff/<int:staff_id>", methods=["GET", "POST"])
def edit_staff(staff_id):
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        school_id = request.form["school_id"]
        cur.execute("UPDATE staff SET name=%s, email=%s, school_id=%s WHERE id=%s",
                    (name, email, school_id, staff_id))
        conn.commit()
        conn.close()
        flash("Staff updated successfully!", "success")
        return redirect(url_for("manage_staff"))

    cur.execute("SELECT * FROM staff WHERE id=%s", (staff_id,))
    staff = cur.fetchone()
    cur.execute("SELECT * FROM schools")
    schools = cur.fetchall()
    conn.close()
    return render_template("edit_staff.html", staff=staff, schools=schools)

# --- Delete Staff ---

@app.route("/delete_staff/<int:staff_id>")
def delete_staff(staff_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM staff WHERE id=%s", (staff_id,))
    conn.commit()
    conn.close()
    flash("Staff deleted successfully!", "success")
    return redirect(url_for("manage_staff"))

# --- Update Staff Details ---

# --- Update Staff Details ---
@app.route("/update_staff", methods=["POST"])
def update_staff():
    if "role" not in session or session["role"] != "admin":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("login"))

    staff_id = request.form["staff_id"]
    name = request.form["name"].strip()
    email = request.form["email"].strip().lower()
    school_id = request.form["school_id"]
    new_password = request.form.get("password", "").strip()   # 🔑 new line

    conn = get_db_connection()
    cur = conn.cursor()

    # 🔐 agar password dala hai to update + hash karo
    if new_password:
        hashed = generate_password_hash(new_password)
        cur.execute("""
            UPDATE staff
            SET name = %s, email = %s, school_id = %s, password = %s
            WHERE id = %s
        """, (name, email, school_id, hashed, staff_id))
    else:
        # 🔐 password blank chhoda to sirf basic details update
        cur.execute("""
            UPDATE staff
            SET name = %s, email = %s, school_id = %s
            WHERE id = %s
        """, (name, email, school_id, staff_id))

    conn.commit()
    conn.close()

    flash("Staff details updated successfully!", "success")
    return redirect(url_for("manage_staff"))

# ================= Staff Dashboard ============================================

@app.route("/staff/dashboard")
@staff_required
@limiter.exempt
def staff_dashboard():

    school_id = session.get("school_id")
    conn = get_db_connection()
    staff = conn.execute("SELECT * FROM staff WHERE id = %s", (session["user_id"],)).fetchone()
    school = conn.execute("SELECT school_name AS name FROM schools WHERE id=%s", (school_id,)).fetchone()
    conn.close()

# ✅ Defensive check
    if not school:
        flash("School details not found for this staff!", "warning")
        return redirect(url_for("login"))
    
    return render_template("staff_dashboard.html", school=school)

# ============================= STAFF: Register Student =============================
@app.route("/staff/register_student", methods=["GET", "POST"])
def staff_register_student():
    if "user_id" not in session or session.get("role") != "staff":
        flash("Please login as staff first!", "danger")
        return redirect(url_for("login"))  

    conn = get_db_connection()
    school_id = session["school_id"]

    # Load courses of this staff's school
    courses = conn.execute("SELECT id, course_name FROM courses WHERE school_id = %s", (school_id,)).fetchall()

    # Get school info
    school = conn.execute("SELECT school_name AS name FROM schools WHERE id=%s", (school_id,)).fetchone()

    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        roll_number = request.form["roll_number"].strip()
        course_id = request.form["course_id"]
        semester = request.form["semester"]
        password = generate_password_hash(request.form["password"])

        exists = conn.execute(
            "SELECT 1 FROM students WHERE email = %s OR roll_number = %s", (email, roll_number)
        ).fetchone()

        if exists:
            flash("⚠️ Student with this email or roll number already exists!", "warning")
        else:
            conn.execute("""
                INSERT INTO students (name, email, roll_number, password, course_id, semester, school_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (name, email, roll_number, password, course_id, semester, school_id))
            conn.commit()
            flash(f"✅ Student '{name}' registered successfully!", "success")
            conn.close()
            return redirect(url_for("staff_view_students"))

    conn.close()
    return render_template("staff_register_student.html", school=school, courses=courses)

# ============================= STAFF: View Students =============================
@app.route("/staff/students", methods=["GET", "POST"])
@staff_required
def staff_view_students():
    school_id = session.get("school_id")
    conn = get_db_connection()

    # Get all courses for dropdown
    courses = conn.execute("""
        SELECT id, course_name FROM courses WHERE school_id=%s
    """, (school_id,)).fetchall()

    # FORM VALUES
    search = request.form.get("search", "").strip().lower()
    course_id = request.form.get("course_id", "")
    semester = request.form.get("semester", "")

    query = """
        SELECT s.id, s.name, s.email, s.roll_number, s.semester, c.course_name
        FROM students s
        LEFT JOIN courses c ON s.course_id = c.id
        WHERE s.school_id=%s
    """
    params = [school_id]

    # Add filters dynamically
    if search:
        query += " AND (LOWER(s.name) LIKE %s OR LOWER(s.email) LIKE %s OR s.roll_number LIKE %s)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    if course_id:
        query += " AND s.course_id=%s"
        params.append(course_id)

    if semester:
        query += " AND s.semester=%s"
        params.append(semester)

    students = conn.execute(query, params).fetchall()

    school = conn.execute("SELECT school_name AS name FROM schools WHERE id=%s", (school_id,)).fetchone()
    conn.close()

    return render_template(
        "staff_view_students.html",
        students=students,
        school=school,
        courses=courses,
        selected_course=course_id,
        selected_semester=semester,
        search=search
    )

# ============================= STAFF: Edit Student (AJAX Modal) =============================
@app.route("/staff/students/edit/<int:student_id>", methods=["GET", "POST"])
def staff_edit_student(student_id):
    """Handles GET (fetch student JSON) and POST (update student via AJAX)"""
    if "user_id" not in session or session.get("role") != "staff":
        return jsonify({"error": "Unauthorized access"}), 403

    school_id = session.get("school_id")
    conn = get_db_connection()

    # 🟢 Get student record
    student = conn.execute("""
        SELECT id, name, email, roll_number, semester, course_id
        FROM students
        WHERE id = %s AND school_id = %s
    """, (student_id, school_id)).fetchone()

    if not student:
        conn.close()
        return jsonify({"error": "Student not found"}), 404

    # 🟢 Handle POST request (AJAX update)
    if request.method == "POST":
        data = request.get_json()

        # Defensive validation
        if not all(k in data for k in ("name", "email", "roll_number", "semester")):
            conn.close()
            return jsonify({"error": "Missing fields"}), 400

        conn.execute("""
            UPDATE students
            SET name=%s, email=%s, roll_number=%s, semester=%s
            WHERE id=%s AND school_id=%s
        """, (
            data["name"].strip(),
            data["email"].strip(),
            data["roll_number"].strip(),
            data["semester"].strip(),
            student_id,
            school_id
        ))
        conn.commit()
        conn.close()

        return jsonify({"message": "✅ Student updated successfully!"})

    # 🟢 Handle GET request (AJAX fetch)
    conn.close()
    # Convert Row to dict
    return jsonify({
        "id": student["id"],
        "name": student["name"],
        "email": student["email"],
        "roll_number": student["roll_number"],
        "semester": student["semester"],
        "course_id": student["course_id"]
    })

# ============================= STAFF: Delete Student =============================
@app.route("/staff/students/delete/<int:student_id>")
def staff_delete_student(student_id):
    if "user_id" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    school_id = session["school_id"]
    conn = get_db_connection()

    # Delete only if belongs to this staff's school
    conn.execute("DELETE FROM students WHERE id=%s AND school_id=%s", (student_id, school_id))
    conn.commit()
    conn.close()

    flash("🗑 Student deleted successfully!", "success")
    return redirect(url_for("staff_view_students"))

# ========================== STAFF: View Attendance Records (Advanced Filters) ==========================
@app.route("/staff/attendance", methods=["GET", "POST"])
@staff_required
def staff_attendance_records():

    school_id = session.get("school_id")
    conn = get_db_connection()

    # Dropdown data
    courses = conn.execute(
        "SELECT id, course_name FROM courses WHERE school_id=%s",
        (school_id,)
    ).fetchall()

    # Subjects table agar hai
    subjects = conn.execute("""
    SELECT DISTINCT sub.subject_name, sub.id
    FROM subjects sub
    JOIN attendance a ON a.subject_id = sub.id
    WHERE sub.subject_name IS NOT NULL
    ORDER BY sub.subject_name
""").fetchall()

    # FORM VALUES
    course_id = request.form.get("course_id", "")
    semester = request.form.get("semester", "")
    subject_id = request.form.get("subject_id", "")
    year = request.form.get("year", "")
    month = request.form.get("month", "")

    query = """
        SELECT a.id, a.date, a.status, a.remark,
               s.roll_number, s.name AS student_name,
               c.course_name, a.semester
        FROM attendance a
        JOIN students s ON a.student_id = s.id
        JOIN courses c ON a.course_id = c.id
        WHERE s.school_id=%s
    """
    params = [school_id]

    if course_id:
        query += " AND a.course_id=%s"
        params.append(course_id)

    if semester:
        query += " AND a.semester=%s"
        params.append(semester)

    if subject_id:
        query += " AND a.subject_id=%s"
        params.append(subject_id)

    if year:
        query += " AND strftime('%Y', a.date)=%s"
        params.append(year)

    if month:
        query += " AND strftime('%m', a.date)=%s"
        params.append(f"{int(month):02d}")

    query += " ORDER BY a.date DESC"

    records = conn.execute(query, params).fetchall()
    conn.close()

    return render_template(
        "staff_attendance_records.html",
        records=records,
        courses=courses,
        subjects=subjects,
        selected_course=course_id,
        selected_semester=semester,
        selected_subject=subject_id,
        selected_year=year,
        selected_month=month
    )
# ========================== STAFF: Edit Attendance Record ==========================
@app.route("/staff/attendance/edit/<int:attendance_id>", methods=["GET", "POST"])
def staff_edit_attendance(attendance_id):
    if "user_id" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    school_id = session["school_id"]
    conn = get_db_connection()

    record = conn.execute("""
        SELECT a.id, a.status, a.remark, s.name AS student_name, s.roll_number, c.course_name
        FROM attendance a
        JOIN students s ON a.student_id = s.id
        JOIN courses c ON a.course_id = c.id
        WHERE a.id=%s AND s.school_id=%s
    """, (attendance_id, school_id)).fetchone()

    if not record:
        conn.close()
        return jsonify({"error": "Record not found"}), 404

    if request.method == "POST":
        data = request.get_json()
        conn.execute("UPDATE attendance SET status=%s, remark=%s WHERE id=%s", (data["status"], data["remark"], attendance_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "Attendance updated successfully!"})

    conn.close()
    return jsonify(dict(record))

# ========================== STAFF: Delete Attendance Record ==========================

@app.route("/staff/attendance/delete/<int:attendance_id>")
def staff_delete_attendance(attendance_id):
    if "user_id" not in session or session.get("role") != "staff":
        return redirect(url_for("login"))

    school_id = session["school_id"]
    conn = get_db_connection()
    conn.execute("""
        DELETE FROM attendance
        WHERE id=%s AND student_id IN (SELECT id FROM students WHERE school_id=%s)
    """, (attendance_id, school_id))
    conn.commit()
    conn.close() 

    flash("🗑 Record deleted successfully!", "success")
    return redirect(url_for("staff_attendance_records"))

# ========================== STAFF: Download Attendance CSV ==========================
@app.route("/staff/attendance/download")
@staff_required
def staff_download_attendance():
    school_id = session.get("school_id")
    conn = get_db_connection()

    # Correct JOIN query (NO attendance_view)
    data = conn.execute("""
        SELECT 
            a.date,
            s.roll_number,
            s.name,
            c.course_name,
            a.semester,
            a.status,
            a.remark
        FROM attendance a
        JOIN students s ON a.student_id = s.id
        JOIN courses c ON a.course_id = c.id
        WHERE s.school_id=%s
        ORDER BY a.date DESC
    """, (school_id,)).fetchall()

    conn.close()

    # CSV generate
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Roll No", "Name", "Course", "Semester", "Status", "Remark"])

    for r in data:
        writer.writerow([
            r["date"],
            r["roll_number"],
            r["name"],
            r["course_name"],
            r["semester"],
            r["status"],
            r["remark"]
        ])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="attendance.csv"
    )

# ============================================================
#                         STUDENT PANEL
# ============================================================

@app.route("/student/dashboard")
@student_required
@limiter.exempt
def student_dashboard():
    conn = get_db_connection()
    
    # 🔹 Detailed attendance (for table)
    attendance = conn.execute("""
        SELECT 
            a.date,
            a.status,
            a.remark,
            s.roll_number,
            sub.subject_name,
            t.name AS teacher_name,
            a.semester
        FROM attendance a
        JOIN students s ON a.student_id = s.id
        JOIN subjects sub ON a.subject_id = sub.id
        JOIN teachers t ON a.marked_by = t.id
        WHERE a.student_id = %s
        ORDER BY a.date DESC
    """, (session["user_id"],)).fetchall()

    # 🔹 Subject-wise attendance summary
    summary = conn.execute("""
        SELECT 
            sub.subject_name,
            a.semester,
            COUNT(*) AS total_classes,
            SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) AS present_count,
            ROUND(SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS percentage
        FROM attendance a
        JOIN subjects sub ON a.subject_id = sub.id
        WHERE a.student_id = %s
        GROUP BY sub.subject_name, a.semester
        ORDER BY a.semester, sub.subject_name
    """, (session["user_id"],)).fetchall()
    
    notifications = get_notifications_for_student(session["user_id"])

    conn.close()
    return render_template("student_dashboard.html", attendance=attendance, summary=summary,notifications=notifications)

# ============================= Notifications for Student =============================
@app.route('/student/notifications')
def student_notifications():
    if "user_id" not in session or session.get("role") != "student":
        return redirect(url_for('login'))
    sid = session['user_id']

    conn = get_db_connection()
    # fetch student's course & semester
    stu = conn.execute("SELECT course_id, semester FROM students WHERE id=%s", (sid,)).fetchone()
    course_id = stu['course_id']
    semester = stu['semester']

    rows = conn.execute("""
      SELECT n.*, t.name AS teacher_name
      FROM notifications n
      JOIN teachers t ON n.teacher_id = t.id
      WHERE (n.student_id = %s)
         OR (n.student_id IS NULL AND n.course_id = %s AND n.semester = %s)
      ORDER BY n.created_at DESC
    """, (sid, course_id, semester)).fetchall()
    conn.close()
    return render_template('student_notifications.html', notifications=rows)


def get_notifications_for_student(student_id):
    conn = get_db_connection()
    cur = conn.cursor()

    # Find student's course, semester, and school
    cur.execute("""
        SELECT course_id, semester, school_id
        FROM students
        WHERE id = %s
    """, (student_id,))
    student = cur.fetchone()
    if not student:
        conn.close()
        return []

    course_id, semester, school_id = student

    # Fetch notifications for:
    #   - entire course + semester
    #   - OR specific student
    cur.execute("""
        SELECT n.id, n.title, n.message, n.created_at,
               t.name AS teacher_name,
               n.file_path, n.file_name
        FROM notifications n
        LEFT JOIN teachers t ON n.teacher_id = t.id
        WHERE 
            (n.course_id = %s AND n.semester = %s AND n.student_id IS NULL)
            OR n.student_id = %s
        ORDER BY n.created_at DESC
    """, (course_id, semester, student_id))

    rows = cur.fetchall()
    conn.close()

    # Convert to list of dicts
    notifications = []
    for r in rows:
        notifications.append({
            'title': r['title'],
            'message': r['message'],
            'created_at': r['created_at'],
            'teacher_name': r['teacher_name'] or 'Unknown',
            'file_path': r['file_path'],
            'file_name': r['file_name']
        })
    return notifications
# ============================================================
#               AJAX Route for Dynamic Courses
# ============================================================

@app.route("/get_courses/<int:school_id>")
def get_courses_by_school(school_id):
    conn = get_db_connection()
    courses = conn.execute(
        "SELECT id, course_name FROM courses WHERE school_id=%s", (school_id,)
    ).fetchall()
    conn.close()
    
    courses_list = [{'id': row['id'], 'course_name': row['course_name']} for row in courses]
    return jsonify(courses_list)

# ============================================================
#                 TEACHER PANEL
# ============================================================


# teacher_dashboard को अपडेट करें ताकि courses और schools दोनों लोड हों
@app.route("/teacher/dashboard")
@teacher_required
@limiter.exempt
def teacher_dashboard():
    
    teacher_id = session["user_id"]

    conn = get_db_connection()
    teacher = conn.execute("SELECT * FROM teachers WHERE id = %s", (session['user_id'],)).fetchone()
    schools = conn.execute("SELECT * FROM schools").fetchall()
    conn.close()

    return render_template("teacher_dashboard.html", teacher=teacher, schools=schools)

# load_students को अपडेट करें ताकि यह सही स्टूडेंट्स को लोड करे
@app.route("/teacher/load_students", methods=["POST"])
def load_students():
    if "user_id" not in session or session["role"] != "teacher":
        return redirect(url_for("login"))
    
    school_id = request.form.get("school_id")
    course_id = request.form.get("course_id")
    semester = request.form.get("semester")
    
    conn = get_db_connection()
    # अब सिर्फ़ वही स्टूडेंट्स दिखेंगे जो selected course और semester में हैं
    students = conn.execute("""
        SELECT id, name, email, roll_number
        FROM students 
        WHERE course_id=%s AND semester=%s
        ORDER BY name
    """, (course_id, semester)).fetchall()

    schools = conn.execute("SELECT * FROM schools").fetchall()
    courses = conn.execute("SELECT id, course_name FROM courses WHERE school_id=%s ORDER BY course_name", (school_id,)).fetchall()
    conn.close()
    
    return render_template("teacher_dashboard.html",
                           students=students, 
                           schools=schools, 
                           courses=courses,
                           selected_school=school_id,
                           selected_course=course_id, 
                           selected_semester=semester)


# ✅ Load Students for given Teacher + Course + Semester + Subject
@app.route("/teacher/load_students/<int:teacher_id>/<int:course_id>/<int:semester>/<int:subject_id>")
def load_students_for_teacher(teacher_id, course_id, semester, subject_id):
    conn = get_db_connection()

    # Verify that this teacher is actually assigned to this subject
    assigned = conn.execute("""
        SELECT 1 FROM teacher_courses
        WHERE teacher_id = %s AND course_id = %s AND semester = %s AND subject_id = %s
    """, (teacher_id, course_id, semester, subject_id)).fetchone()

    if not assigned:
        conn.close()
        return jsonify([])  # not authorized for this subject

    # ✅ Load all students in that course + semester
    students = conn.execute("""
        SELECT id, name, roll_number
        FROM students
        WHERE course_id = %s AND semester = %s
        ORDER BY roll_number
    """, (course_id, semester)).fetchall()

    conn.close()

    # Convert to JSON serializable format
    student_list = [dict(s) for s in students]
    return jsonify(student_list)

# ✅ Mark Attendance
@app.route("/mark_attendance", methods=["POST"])
def mark_attendance():
    if "user_id" not in session or session.get("role") != "teacher":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("login"))

    teacher_id = session["user_id"]
    course_id = request.form.get("course_id")
    semester = request.form.get("semester")
    subject_id = request.form.get("subject_id")
    date_today = datetime.now().strftime("%Y-%m-%d")

    conn = get_db_connection()

    # ✅ सभी छात्रों के लिए attendance mark करें
    students = conn.execute(
        "SELECT id FROM students WHERE course_id = %s AND semester = %s",
        (course_id, semester),
    ).fetchall()

    for s in students:
        student_id = s["id"]
        status = request.form.get(f"status_{student_id}")
        remark = request.form.get(f"remark_{student_id}", "")

        # ✅ Duplicate check (एक दिन में एक ही बार attendance mark)
        existing = conn.execute("""
            SELECT * FROM attendance 
            WHERE student_id = %s AND subject_id = %s AND date = %s
        """, (student_id, subject_id, date_today)).fetchone()

        if not existing:
            conn.execute("""
                INSERT INTO attendance 
                (student_id, course_id, semester, subject_id, date, status, remark, marked_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                student_id,
                course_id,
                semester,
                subject_id,
                date_today,
                status,
                remark,
                teacher_id,
            ))
        else:
            # ✅ अगर पहले से attendance है, तो update कर दो
            conn.execute("""
                UPDATE attendance
                SET status = %s, remark = %s, marked_by = %s
                WHERE student_id = %s AND subject_id = %s AND date = %s
            """, (
                status,
                remark,
                teacher_id,
                student_id,
                subject_id,
                date_today,
            ))

    conn.commit()
    conn.close()

    flash("Attendance marked successfully!", "success")
    return redirect(url_for("teacher_dashboard"))

# ✅ Get Subjects assigned to the logged-in Teacher
@app.route("/teacher/ajax/get_my_subjects")
def teacher_get_subjects():
    if "user_id" not in session or session.get("role") != "teacher":
        return jsonify([]), 403

    teacher_id = session["user_id"]
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT tcs.subject_id, s.subject_name, tcs.course_id, tcs.semester
        FROM teacher_courses tcs
        JOIN subjects s ON tcs.subject_id = s.id
        WHERE tcs.teacher_id = %s
        ORDER BY s.subject_name
    """, (teacher_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ✅ Fetch Attendance Records for the logged-in Teacher with filters
@app.route("/teacher/ajax/get_my_attendance")
def teacher_get_attendance():
    if "user_id" not in session or session.get("role") != "teacher":
        return jsonify({"error":"Unauthorized"}), 403

    teacher_id = session["user_id"]
    course_id = request.args.get("course_id", type=int)
    semester = request.args.get("semester", type=int)
    subject_id = request.args.get("subject_id", type=int)
    year = request.args.get("year", type=int) or None

    where = ["a.marked_by = %s"]
    params = [teacher_id]

    if course_id:
        where.append("a.course_id = %s"); params.append(course_id)
    if semester:
        where.append("a.semester = %s"); params.append(semester)
    if subject_id:
        where.append("a.subject_id = %s"); params.append(subject_id)
    if year:
        where.append("strftime('%Y', a.date) = %s"); params.append(str(year))

    query = f"""
        SELECT a.id AS attendance_id, a.date, a.status, a.remark,
               s.id AS student_id, s.name AS student_name, s.roll_number,
               sub.id AS subject_id, sub.subject_name
        FROM attendance a
        JOIN students s ON a.student_id = s.id
        LEFT JOIN subjects sub ON a.subject_id = sub.id
        WHERE {' AND '.join(where)}
        ORDER BY a.date DESC, s.roll_number
    """

    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

#  Update Attendance Record (only by the teacher who marked it)

@app.route("/teacher/ajax/update_attendance/<int:attendance_id>", methods=["POST"])
def teacher_update_attendance(attendance_id):
    if "user_id" not in session or session.get("role") != "teacher":
        return jsonify({"error":"Unauthorized"}), 403

    teacher_id = session["user_id"]
    status = request.form.get("status")
    remark = request.form.get("remark", "")

    if status not in ("Present","Absent","present","absent"):
        return jsonify({"error":"Invalid status"}), 400

    conn = get_db_connection()
    # verify ownership: only the teacher who marked can edit
    row = conn.execute("SELECT marked_by FROM attendance WHERE id = %s", (attendance_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error":"Attendance row not found"}), 404
    if row["marked_by"] != teacher_id:
        conn.close()
        return jsonify({"error":"Not allowed to edit this attendance"}), 403

    conn.execute("UPDATE attendance SET status = %s, remark = %s WHERE id = %s", (status, remark, attendance_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})
# ============================= Teacher Notifications =============================
@app.route('/teacher/send_notification', methods=['POST'])
def teacher_send_notification():
    if "user_id" not in session or session.get("role") != "teacher":
        flash("Unauthorized", "danger")
        return redirect(url_for("login"))

    teacher_id = session['user_id']
    school_id = request.form.get('school_id') or None
    course_id = request.form.get('course_id') or None
    semester = request.form.get('semester') or None
    subject_id = request.form.get('subject_id') or None
    target = request.form.get('target')  # 'all' or 'student'
    student_id = request.form.get('student_id') if target == 'student' else None
    title = request.form.get('title', '').strip()
    message = request.form.get('message', '').strip()
    fileobj = request.files.get('file')

    if not title:
        flash("Please provide a title", "danger")
        return redirect(url_for('teacher_dashboard'))

    file_path = file_name = mime_type = None
    if fileobj and fileobj.filename:
        if not allowed_file(fileobj.filename):
            flash("File type not allowed", "danger")
            return redirect(url_for('teacher_dashboard'))
        file_path, file_name, mime_type = save_uploaded_file(fileobj)

    conn = get_db_connection()
    conn.execute("""
        INSERT INTO notifications
        (teacher_id, school_id, course_id, semester, subject_id, student_id, title, message, file_path, file_name, mime_type)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (teacher_id, school_id, course_id, semester, subject_id, student_id, title, message, file_path, file_name, mime_type))
    conn.commit()
    conn.close()

    flash("Notification sent.", "success")
    return redirect(url_for('teacher_dashboard'))

# Teacher Notifications List
@app.route('/teacher/notifications')
def teacher_notifications():
    if "user_id" not in session or session.get("role") != "teacher":
        return redirect(url_for('login'))
    tid = session['user_id']
    conn = get_db_connection()
    rows = conn.execute("""
       SELECT n.*, 
         (SELECT COUNT(*) FROM students st WHERE (n.student_id IS NULL AND st.course_id = n.course_id AND st.semester = n.semester) OR st.id = n.student_id) AS recipient_count
       FROM notifications n
       WHERE n.teacher_id = %s
       ORDER BY n.created_at DESC
    """, (tid,)).fetchall()
    conn.close()
    return render_template('teacher_notifications.html', notifications=rows)

# Ajax: get students for course + semester
@app.route('/teacher/ajax/get_students/<int:course_id>/<int:semester>')
def ajax_get_students(course_id, semester):
    teacher_id = session.get('user_id')
    conn = get_db_connection()

    # Verify teacher has access to this course+semester
    check = conn.execute("""
        SELECT 1 FROM teacher_courses 
        WHERE teacher_id=%s AND course_id=%s AND semester=%s 
        LIMIT 1
    """, (teacher_id, course_id, semester)).fetchone()

    if not check:
        conn.close()
        return jsonify([])  # unauthorized or no assignment

    students = conn.execute("""
        SELECT id, name, roll_number 
        FROM students 
        WHERE course_id=%s AND semester=%s
        ORDER BY roll_number
    """, (course_id, semester)).fetchall()

    conn.close()
    return jsonify([dict(s) for s in students])

@app.route('/get_courses/<int:school_id>')
def get_courses_for_teacher(school_id):
    teacher_id = session.get('user_id')
    conn = get_db_connection()

    # केवल उस teacher के assigned courses (उस school के अंदर)
    query = """
        SELECT DISTINCT c.id, c.course_name
        FROM courses c
        JOIN teacher_courses tc ON tc.course_id = c.id
        WHERE tc.teacher_id = %s AND tc.school_id = %s
    """
    courses = conn.execute(query, (teacher_id, school_id)).fetchall()
    conn.close()
    return jsonify([dict(c) for c in courses])

# ---------- Admin Attendance Management ----------#

# Admin page (UI)
@app.route("/admin/attendance")
def admin_attendance():
    if session.get("role") != "admin":
        flash("Unauthorized. Please login as admin.", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    schools = conn.execute("SELECT id, school_name FROM schools ORDER BY school_name").fetchall()
    conn.close()
    # Render the page; table will be loaded via Ajax
    return render_template("admin_attendance.html", schools=schools)


# Ajax: get courses for a school
@app.route("/admin/ajax/get_courses/<int:school_id>")
def admin_get_courses(school_id):
    conn = get_db_connection()
    rows = conn.execute("SELECT id, course_name FROM courses WHERE school_id = %s ORDER BY course_name", (school_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# Ajax: get semesters available for a course (optional) or return 1..8
@app.route("/admin/ajax/get_semesters/<int:course_id>")
def admin_get_semesters(course_id):
    # if you store semester per subject, you can fetch distinct semesters:
    conn = get_db_connection()
    rows = conn.execute("SELECT DISTINCT semester FROM subjects WHERE course_id = %s ORDER BY semester", (course_id,)).fetchall()
    conn.close()
    result = [r['semester'] for r in rows]
    if not result:
        result = list(range(1, 9))
    return jsonify(result)


# Ajax: get subjects for course + semester
@app.route("/admin/ajax/get_subjects/<int:course_id>/<int:semester>")
def admin_get_subjects(course_id, semester):
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, subject_name FROM subjects WHERE course_id = %s AND semester = %s ORDER BY subject_name",
         (course_id, semester)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# Ajax: get students for course + semester
@app.route("/admin/ajax/get_students/<int:course_id>/<int:semester>")
def admin_get_students(course_id, semester):
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, name, roll_number FROM students WHERE course_id = %s AND semester = %s ORDER BY roll_number",
        (course_id, semester)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# Ajax: fetch attendance table (filter). returns a structured object to render table:
# Accepts query params: school_id, course_id, semester, subject_id (optional), student_id (optional), year (optional)
@app.route("/admin/ajax/get_attendance")
def admin_get_attendance():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    school_id = request.args.get("school_id", type=int)
    course_id = request.args.get("course_id", type=int)
    semester = request.args.get("semester", type=int)
    subject_id = request.args.get("subject_id", type=int)  # optional
    student_id = request.args.get("student_id", type=int)  # optional
    roll_number = request.args.get("roll_number", type=str)  # ✅ New
    year = request.args.get("year", type=int)  # optional, e.g. 2025

    # Build base WHERE clause
    where = ["a.course_id = %s","a.semester = %s"]
    params = [course_id, semester]

    if subject_id:
        where.append("a.subject_id = %s"); params.append(subject_id)
    if student_id:
        where.append("a.student_id = %s"); params.append(student_id)
        
    if roll_number:
        where.append("s.roll_number = %s")  # ✅ New filter
        params.append(roll_number)
    # optionally filter by school_id (via course -> school). Not strictly needed if course selected.
    # We'll limit rows by course+semester(+subject) which is enough.

    # We'll compute month-wise percentages for the given year (default current year)
    if not year:
        year = datetime.now().year

    # Query: fetch raw attendance rows joined to students, subjects, teachers
    query = f"""
    SELECT a.id, a.date, a.status, a.remark,
           a.student_id, s.name AS student_name, s.roll_number,
           sub.id AS subject_id, sub.subject_name,
           t.id AS teacher_id, t.name AS teacher_name
    FROM attendance a
    JOIN students s ON a.student_id = s.id
    LEFT JOIN subjects sub ON a.subject_id = sub.id
    LEFT JOIN teachers t ON a.marked_by = t.id
    WHERE {' AND '.join(where)} AND strftime('%Y', a.date) = %s
    ORDER BY s.roll_number, a.date
    """
    params.append(str(year))

    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    # Transform rows into grouped structure: student -> subject -> monthly counts
    from collections import defaultdict
    data = defaultdict(lambda: defaultdict(lambda: {"present":0, "total":0, "rows":[]}))
    # rows is sqlite3.Row, access like dict
    for r in rows:
        dt = r["date"]  # string in YYYY-MM-DD
        # extract month number
        try:
            m = int(dt.split("-")[1])
        except Exception:
            continue
        key_student = (r["student_id"], r["student_name"], r["roll_number"])
        subject_key = (r["subject_id"], r["subject_name"])
        # record
        cell = data[key_student][subject_key]
        cell["total"] += 1
        if r["status"] and r["status"].lower().startswith("p"):
            cell["present"] += 1
        # store row meta for editing
        cell["rows"].append({
            "attendance_id": r["id"],
            "date": r["date"],
            "status": r["status"],
            "remark": r["remark"],
            "teacher_id": r["teacher_id"],
            "teacher_name": r["teacher_name"]
        })

    # Now build a JSON-friendly array
    out = []
    for (sid, sname, sroll), subjects in data.items():
        for (subid, subname), stats in subjects.items():
            percent = round((stats["present"] / stats["total"] * 100), 2) if stats["total"] else 0
            out.append({
                "student_id": sid,
                "student_name": sname,
                "roll_number": sroll,
                "subject_id": subid,
                "subject_name": subname,
                "present": stats["present"],
                "total": stats["total"],
                "percent": percent,
                "rows": stats["rows"]  # details for the edit modal
            })

    return jsonify({"year": year, "data": out})

# Ajax: fetch detailed attendance for a student (date-wise)
# ✅ 1. Student Attendance Detail (Date-wise)
@app.route("/admin/ajax/student_attendance_detail/<int:student_id>")
def student_attendance_detail(student_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                a.id AS attendance_id,
                a.date,
                a.status,
                a.remark,
                t.name AS teacher_name
            FROM attendance a
            LEFT JOIN teachers t ON a.marked_by = t.id
            WHERE a.student_id = %s
            ORDER BY a.date DESC
        """, (student_id,))
        rows = [dict(row) for row in cur.fetchall()]
        conn.close()
        return jsonify(rows)
    except Exception as e:
        print("Error:", e)
        return jsonify([])


# ✅ 2. Download Month-wise Attendance CSV
@app.route("/admin/download_month_csv")
def download_month_csv():
    month = request.args.get("month")
    year = request.args.get("year")
    
    if not month or not year:
        return "Month and Year required", 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT 
    s.roll_number,
    s.name AS student_name,
    c.course_name,
    su.subject_name,
    COUNT(a.id) AS total_classes,
    SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) AS total_present,
    ROUND(SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) * 100.0 / COUNT(a.id), 2) AS percentage
FROM attendance a
LEFT JOIN students s ON a.student_id = s.id
LEFT JOIN teachers t ON a.marked_by = t.id
LEFT JOIN subjects su ON a.subject_id = su.id
LEFT JOIN courses c ON a.course_id = c.id
WHERE strftime('%m', a.date) = :month
  AND strftime('%Y', a.date) = :year
GROUP BY s.roll_number, su.subject_name
ORDER BY s.roll_number
        """, {"month": f"{int(month):02d}", "year": str(year)})

        rows = cur.fetchall()
        conn.close()

        # अगर कोई attendance नहीं है
        if not rows:
            return "No attendance found for selected month.", 404

        # CSV बनाना
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Roll No", "Student Name", "Course", "Subject", "Total Classes", "Present", "Percentage"])
        for r in rows:
            writer.writerow([r["roll_number"], r["student_name"], r["course_name"],
                             r["subject_name"], r["total_classes"], r["total_present"], r["percentage"]])

        output.seek(0)
        filename = f"attendance_{year}_{month}.csv"
        return send_file(io.BytesIO(output.getvalue().encode("utf-8")),
                         mimetype="text/csv",
                         as_attachment=True,
                         download_name=filename)

    except Exception as e:
        print("Error in download_month_csv:", e)
        return f"Error: {str(e)}", 500
    

# Ajax: update an attendance row (admin)
@app.route("/admin/ajax/update_attendance/<int:attendance_id>", methods=["POST"])
def admin_update_attendance(attendance_id):
    if session.get("role") != "admin":
        return jsonify({"error":"Unauthorized"}), 403

    status = request.form.get("status")
    remark = request.form.get("remark", "")

    # basic validation
    if status not in ("Present","Absent","present","absent"):
        return jsonify({"error":"Invalid status"}), 400

    conn = get_db_connection()
    conn.execute("UPDATE attendance SET status = %s, remark = %s WHERE id = %s", (status, remark, attendance_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

# Ajax: fetch attendance with month-wise percentages (for filters)
@app.route('/admin/ajax/get_attendance', methods=['POST'])
def get_attendance_ajax():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403

    data = request.get_json()
    school_id = data.get('school_id')
    course_id = data.get('course_id')
    semester = data.get('semester')
    subject_id = data.get('subject_id')
    student_id = data.get('student_id')

    conn = get_db_connection()
    cur = conn.cursor()

    query = """
        SELECT s.id AS student_id, s.roll_number, s.name AS student_name,
               sub.name AS subject_name, a.date, a.status, a.remark,
               t.name AS marked_by
        FROM attendance a
        JOIN students s ON a.student_id = s.id
        JOIN subjects sub ON a.subject_id = sub.id
        JOIN teachers t ON a.marked_by = t.id
        WHERE 1=1
    """
    params = []

    if school_id:
        query += " AND s.school_id = %s"
        params.append(school_id)
    if course_id:
        query += " AND s.course_id = %s"
        params.append(course_id)
    if semester:
        query += " AND a.semester = %s"
        params.append(semester)
    if subject_id:
        query += " AND a.subject_id = %s"
        params.append(subject_id)
    if student_id:
        query += " AND s.id = %s"
        params.append(student_id)
    records = cur.execute(query, params).fetchall()

    # ✅ Month-wise attendance calculation
    from collections import defaultdict
    import datetime

    month_stats = defaultdict(lambda: {'present': 0, 'total': 0})
    for r in records:
        if not r['date']:
            continue
        month = datetime.datetime.strptime(r['date'], "%Y-%m-%d").strftime("%B")
        month_stats[month]['total'] += 1
        if r['status'] == 'Present':
            month_stats[month]['present'] += 1

    # Calculate percentages
    month_percentages = {}
    for month, stats in month_stats.items():
        if stats['total'] > 0:
            month_percentages[month] = round((stats['present'] / stats['total']) * 100, 2)
        else:
            month_percentages[month] = 0.0

    overall_total = sum(v['total'] for v in month_stats.values())
    overall_present = sum(v['present'] for v in month_stats.values())
    overall_percent = round((overall_present / overall_total) * 100, 2) if overall_total else 0

    conn.close()

    return jsonify({
        'records': [dict(r) for r in records],
        'month_percentages': month_percentages,
        'overall_percent': overall_percent
    })


# ============================================================
#                  CHANGE PASSWORD (Student/Teacher)
# ============================================================

@app.route("/change_password", methods=["POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))

    old = request.form["old_password"]
    new = request.form["new_password"]

    conn = get_db_connection()
    cur = conn.cursor()

    table = "students" if session["role"] == "student" else "teachers"
    cur.execute(f"SELECT * FROM {table} WHERE id=%s", (session["user_id"],))
    user = cur.fetchone()

    if user and check_password_hash(user["password"], old):
        cur.execute(f"UPDATE {table} SET password=%s WHERE id=%s",
                    (generate_password_hash(new), session["user_id"]))
        conn.commit()
        flash("Password updated successfully!", "success")
    else:
        flash("Old password incorrect!", "danger")

    conn.close()
    # 👇 Return to same dashboard
    if session["role"] == "student":
        return redirect(url_for("student_dashboard"))
    else:
        return redirect(url_for("teacher_dashboard"))

# 🔍 Admin: Search Attendance by Roll Number
@app.route("/admin/ajax/search_by_roll", methods=["POST"])
def admin_search_by_roll():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    roll_number = data.get("roll_number")

    if not roll_number:
        return jsonify({"error": "Roll number required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    query = """
        SELECT 
            s.id AS student_id,
            s.roll_number,
            s.name AS student_name,
            sub.subject_name,
            a.date,
            a.status,
            a.remark,
            t.name AS teacher_name
        FROM attendance a
        JOIN students s ON a.student_id = s.id
        LEFT JOIN subjects sub ON a.subject_id = sub.id
        LEFT JOIN teachers t ON a.marked_by = t.id
        WHERE s.roll_number = %s
        ORDER BY a.date DESC
    """
    records = cur.execute(query, (roll_number,)).fetchall()
    conn.close()

    if not records:
        return jsonify({"records": []})

    return jsonify({"records": [dict(r) for r in records]})


# ============================================================
#                        Dashboard Redirect
# ============================================================

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    if session["role"] == "student":
        return redirect(url_for("student_dashboard"))
    elif session["role"] == "teacher":
        return redirect(url_for("teacher_dashboard"))
    elif session["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    else:
        flash("Unknown role!", "danger")
        return redirect(url_for("login"))

#  Serve uploaded notification files
@app.route('/uploads/notifications/<path:filename>')
def uploaded_notification(filename):
    # NOTE: You may add permission checks here if needed
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

mail = Mail(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "YOUR_EMAIL@gmail.com"
app.config['MAIL_PASSWORD'] = "YOUR_EMAIL_APP_PASSWORD"

#app.config['MAIL_DEFAULT_SENDER'] = "

@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://www.google.com https://www.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "img-src 'self' data: blob: https://*; "
        # ✅ fonts.gstatic + jsdelivr allow for bootstrap icons
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
        "frame-src https://www.google.com https://www.gstatic.com;"
    )
    return response


# ---------- Run ----------
if __name__ == "__main__":
    # ⚠️ Debug mode को False सेट करें
    app.run(host='0.0.0.0', port=5000, debug=True)
    # या, केवल होस्ट सेट करें; डिबग डिफ़ॉल्ट रूप से False होता है जब host 127.0.0.1 नहीं होता है
    # app.run(host='0.0.0.0', port=5000)
# ---------- Run ----------
#if __name__ == "__main__":
#    app.run(debug=True)
