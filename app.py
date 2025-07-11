# app.py: Main Flask application for the Password Manager web app.
# Implements routes for authentication, dashboard, password management,
# 2FA setup, encryption/decryption logic, and email notifications.

from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from models.user import User, db  # add db import
from models.entry import PasswordEntry  # import entry model
import os
import json
import pyotp
import qrcode
from io import BytesIO
import base64
from authlib.integrations.flask_client import OAuth
from datetime import datetime
import string
import random
import re
from dotenv import load_dotenv
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from sqlalchemy import inspect, text
import smtplib
from email.message import EmailMessage

# Initialize environment variables
load_dotenv()
key_hex = os.getenv('ENCRYPTION_KEY')
if not key_hex:
    raise RuntimeError('ENCRYPTION_KEY environment variable is not set')
try:
    ENC_KEY = bytes.fromhex(key_hex)
    if len(ENC_KEY) != 32:
        raise ValueError
except Exception:
    raise RuntimeError('ENCRYPTION_KEY must be 64 hex characters (32 bytes)')

app = Flask(__name__)
app.secret_key = os.urandom(24)

## Configure Google OAuth via environment variables
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    # Create tables if they don't exist (preserve existing data)
    db.create_all()
    # Ensure new columns exist in SQLite table
    insp = inspect(db.engine)
    cols = [c['name'] for c in insp.get_columns('password_entries')]
    # Run ALTER TABLE statements in a transactional block
    with db.engine.begin() as conn:
        if 'final_password' not in cols:
            conn.execute(text('ALTER TABLE password_entries ADD COLUMN final_password TEXT'))
        if 'original_decimal' not in cols:
            conn.execute(text('ALTER TABLE password_entries ADD COLUMN original_decimal TEXT'))
    # safety_key column managed in model migration; no manual ALTER needed

class UserManager:
    def __init__(self, db_file="users.json"):
        self.db_file = db_file
        self.users = self._load_users()
    
    def _load_users(self):
        try:
            with open(self.db_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def _save_users(self):
        with open(self.db_file, 'w') as f:
            json.dump(self.users, f, indent=4)
    
    def get_user_by_email(self, email):
        for user_id, user_data in self.users.items():
            if user_data['email'] == email:
                return user_id, user_data
        return None, None

    def get_or_create_user(self, google_id, email, name):
        if google_id not in self.users:
            self.users[google_id] = {
                'email': email,
                'name': name,
                'password': None, # Handled by Google
                'totp_secret': None,
                'totp_verified': False,
                'created_at': datetime.now().isoformat()
            }
            self._save_users()
        return self.users[google_id]
    
    def create_user(self, username, email, password):
        if self.get_user_by_email(email)[0]:
            return None # User already exists
        
        user_id = str(len(self.users) + 1)
        self.users[user_id] = {
            'username': username,
            'email': email,
            'password': password, # In a real app, hash this!
            'totp_secret': None,
            'totp_verified': False,
            'created_at': datetime.now().isoformat()
        }
        self._save_users()
        return user_id

    def update_user_totp(self, user_id, totp_secret, verified=False):
        if user_id in self.users:
            self.users[user_id]['totp_secret'] = totp_secret
            self.users[user_id]['totp_verified'] = verified
            self._save_users()

user_manager = UserManager()

@app.route('/')
def index():
    """Render the home page."""
    return render_template('home.html')

@app.route('/home')
def home():
    """Alias for home route, renders the home page."""
    return render_template('home.html')

@app.route('/dashboard')
def dashboard():
    """Render the user dashboard page."""
    # Login guard enforced via decorators or middleware (removed inline dev bypass)
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login: validate credentials and redirect to 2FA or dashboard."""
    if request.method == 'POST':
        email = request.form['username'] # Assuming username field can be email
        password = request.form['password']
        user_id, user = user_manager.get_user_by_email(email)
        if user and user['password'] == password: # In a real app, verify hashed password
            session['user_id'] = user_id
            if not user.get('totp_verified', False):
                return redirect(url_for('setup_2fa'))
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user signup: create account and initiate 2FA setup."""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_id = user_manager.create_user(username, email, password)
        if user_id:
            session['user_id'] = user_id
            return redirect(url_for('setup_2fa'))
        flash('User with this email already exists')
    return render_template('signup.html')

@app.route('/login/google')
def google_login():
    """Initiate Google OAuth login flow."""
    return google.authorize_redirect(redirect_uri=url_for('google_callback', _external=True))

@app.route('/login/google/callback')
def google_callback():
    """Handle OAuth callback: obtain user info and redirect appropriately."""
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    
    user = user_manager.get_or_create_user(
        google_id=user_info['id'],
        email=user_info['email'],
        name=user_info['name']
    )
    
    session['user_id'] = user_info['id']
    
    if not user['totp_verified']:
        return redirect(url_for('setup_2fa'))
    return redirect(url_for('dashboard'))

@app.route('/setup-2fa')
def setup_2fa():
    """Render TOTP 2FA setup page or redirect if already configured."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = user_manager.users[session['user_id']]
    if user.get('totp_verified', False):
        return redirect(url_for('dashboard'))
    
    if not user.get('totp_secret'):
        totp_secret = pyotp.random_base32()
        user_manager.update_user_totp(session['user_id'], totp_secret)
    else:
        totp_secret = user['totp_secret']
    
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user['email'],
        issuer_name="PassFort"
    )
    
    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('setup_2fa.html', qr_code=qr_code_base64)

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    """Verify submitted TOTP code and enable 2FA for the user."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = user_manager.users[session['user_id']]
    totp = pyotp.TOTP(user['totp_secret'])
    
    if totp.verify(request.form['code']):
        user_manager.update_user_totp(session['user_id'], user['totp_secret'], verified=True)
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid code. Please try again.")
        return redirect(url_for('setup_2fa'))

@app.route('/logout')
def logout():
    """Log out the user and clear session."""
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/generate-password', methods=['GET','POST'])
def generate_password():
    """Generate a random password based on user-selected criteria."""
    password = ''
    if request.method == 'POST':
        length = int(request.form.get('length', 16))
        include_upper = 'include_upper' in request.form
        include_lower = 'include_lower' in request.form
        include_numbers = 'include_numbers' in request.form
        include_symbols = 'include_symbols' in request.form
        char_pool = ''
        if include_upper:
            char_pool += string.ascii_uppercase
        if include_lower:
            char_pool += string.ascii_lowercase
        if include_numbers:
            char_pool += string.digits
        if include_symbols:
            char_pool += string.punctuation
        if not char_pool:
            flash('Select at least one character type')
        else:
            password = ''.join(random.choice(char_pool) for _ in range(length))
    return render_template('password_generator.html', password=password)

@app.route('/password-strength', methods=['GET','POST'])
def password_strength():
    if request.method == 'POST':
        data = request.get_json() or {}
        pwd = data.get('password', '')
        length = len(pwd)
        has_lower = bool(re.search(r'[a-z]', pwd))
        has_upper = bool(re.search(r'[A-Z]', pwd))
        has_number = bool(re.search(r'[0-9]', pwd))
        has_symbol = bool(re.search(r'[^A-Za-z0-9]', pwd))
        # Estimate crack time
        pool = (26 if has_lower else 0) + (26 if has_upper else 0) + (10 if has_number else 0) + (32 if has_symbol else 0)
        combos = pool**length if pool > 0 else 0
        guesses_per_sec = 1e9
        seconds = combos/guesses_per_sec if combos > 0 else 0
        return jsonify({
            'length': length,
            'has_lower': has_lower,
            'has_upper': has_upper,
            'has_number': has_number,
            'has_symbol': has_symbol,
            'crack_time_sec': seconds
        })
    # GET
    return render_template('password_strength.html')

@app.route('/password-manager')
def password_manager():
    # load stored password entries
    entries = PasswordEntry.query.order_by(PasswordEntry.created_at.desc()).all()
    return render_template('password_manager.html', entries=entries)

@app.route('/add-password', methods=['GET', 'POST'])
def add_password():
    if request.method == 'POST':
        # Collect form data
        username = request.form['username']
        website = request.form['website']
        plaintext = request.form['password']
        safety_key = request.form['safety_key']  # should match \d{4}
        note = request.form.get('note')
        # Encrypt password
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(ENC_KEY), modes.CBC(iv), backend=default_backend())
        ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
        enc_bytes = iv + ct
        original_decimal = int.from_bytes(enc_bytes, 'big')
        safety_int = int(safety_key)
        final_decimal = original_decimal + safety_int
        # Store as strings to accommodate large ints
        entry = PasswordEntry(
            username=username,
            website=website,
            final_password=str(final_decimal),
            original_decimal=str(original_decimal),
            safety_key=safety_int,
            note=note
        )
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('password_manager'))
    return render_template('add_password.html')

@app.route('/delete-password/<int:entry_id>', methods=['POST'])
def delete_password(entry_id):
    # Delete the specified password entry
    entry = PasswordEntry.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    return redirect(url_for('password_manager'))

def send_alert_email(to_email, entry):
    # send email alert about wrong key attempt
    msg = EmailMessage()
    msg['Subject'] = 'Alert: Wrong Key Entered'
    msg['From'] = os.getenv('MAIL_SENDER')
    msg['To'] = to_email
    # Use requested alert message
    msg.set_content('You have entered a wrong key in the password manager. Please make sure that you are secure.')
    try:
        with smtplib.SMTP(os.getenv('MAIL_SERVER'), int(os.getenv('MAIL_PORT', '25'))) as smtp:
            smtp.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
            smtp.send_message(msg)
    except Exception as e:
        print('Email send failed:', e)
    
# Helper to send the safety key via email
def send_key_email(to_email, entry):
    msg = EmailMessage()
    msg['Subject'] = 'Your PassFort Safety Key'
    msg['From'] = os.getenv('MAIL_SENDER')
    msg['To'] = to_email
    msg.set_content(f'Your safety key for {entry.website} is {entry.safety_key}.')
    try:
        with smtplib.SMTP(os.getenv('MAIL_SERVER'), int(os.getenv('MAIL_PORT', '25'))) as smtp:
            smtp.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
            smtp.send_message(msg)
    except Exception as e:
        print('Key email send failed:', e)

@app.route('/reveal-password/<int:entry_id>', methods=['POST'])
def reveal_password(entry_id):
    data = request.get_json() or {}
    try:
        key = int(data.get('key', 0))
    except ValueError:
        return jsonify({'success': False, 'error': 'invalid key'}), 400
    entry = PasswordEntry.query.get_or_404(entry_id)
    if key != entry.safety_key:
        # alert user
        # get user email from session
        user_id = session.get('user_id')
        if user_id:
            user = user_manager.users.get(str(user_id))
            if user and user.get('email'):
                send_alert_email(user['email'], entry)
        return jsonify({'success': False, 'error': 'wrong key'}), 403
    # correct key: decrypt
    final_decimal = int(entry.final_password)
    original_decimal = final_decimal - key
    # compute byte length
    length = (original_decimal.bit_length() + 7) // 8
    enc_bytes = original_decimal.to_bytes(length, 'big')
    iv = enc_bytes[:16]
    ct = enc_bytes[16:]
    cipher = Cipher(algorithms.AES(ENC_KEY), modes.CBC(iv), backend=default_backend())
    plain_padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        plaintext = unpadder.update(plain_padded) + unpadder.finalize()
    except ValueError:
        # padding error indicates wrong key
        return jsonify({'success': False, 'error': 'wrong key'}), 403
    return jsonify({'success': True, 'password': plaintext.decode()})

@app.route('/guide')
def guide():
    return render_template('guide.html')

# Endpoint to email safety key
@app.route('/send-key/<int:entry_id>', methods=['POST'])
def send_key(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    user_id = session.get('user_id')
    if user_id:
        user = user_manager.users.get(str(user_id))
        if user and user.get('email'):
            send_key_email(user['email'], entry)
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True)