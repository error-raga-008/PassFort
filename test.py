import streamlit as st
import pandas as pd
import json
import os
import pyotp
import qrcode
from io import BytesIO
import base64
import string
import random
import re
from datetime import datetime
import smtplib
from email.message import EmailMessage
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sqlite3
import hashlib
import time
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Page config
st.set_page_config(
    page_title="PassFort - Password Manager",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    
    .main-header {
        background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
    }
    
    .feature-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        margin: 1rem 0;
        border-left: 4px solid #4facfe;
    }
    
    .password-strength-bar {
        height: 10px;
        border-radius: 5px;
        margin: 10px 0;
    }
    
    .strength-very-weak { background-color: #ff4444; }
    .strength-weak { background-color: #ff8800; }
    .strength-medium { background-color: #ffbb33; }
    .strength-strong { background-color: #00C851; }
    .strength-very-strong { background-color: #007E33; }
    
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #2196F3 0%, #1976D2 100%);
    }
    
    .metric-card {
        background: linear-gradient(45deg, #FF6B6B, #4ECDC4);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'user_data' not in st.session_state:
    st.session_state.user_data = None
if 'passwords' not in st.session_state:
    st.session_state.passwords = []

# Configuration
class Config:
    def __init__(self):
        self.encryption_key = self.get_encryption_key()
        self.db_file = "password_manager.db"
        self.users_file = "users.json"
        
    def get_encryption_key(self):
        # For demo purposes, using a hardcoded key
        # In production, use environment variables
        key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        return bytes.fromhex(key_hex)

config = Config()

# Database functions
def init_database():
    conn = sqlite3.connect(config.db_file)
    cursor = conn.cursor()
    
    # Create password entries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            website TEXT NOT NULL,
            final_password TEXT NOT NULL,
            original_decimal TEXT NOT NULL,
            safety_key INTEGER NOT NULL,
            note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# User management
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
    
    def create_user(self, username, email, password):
        if self.get_user_by_email(email)[0]:
            return None
        
        user_id = str(len(self.users) + 1)
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        self.users[user_id] = {
            'username': username,
            'email': email,
            'password': password_hash,
            'totp_secret': None,
            'totp_verified': False,
            'created_at': datetime.now().isoformat()
        }
        self._save_users()
        return user_id
    
    def verify_user(self, email, password):
        user_id, user = self.get_user_by_email(email)
        if user:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if user['password'] == password_hash:
                return user_id, user
        return None, None
    
    def update_user_totp(self, user_id, totp_secret, verified=False):
        if user_id in self.users:
            self.users[user_id]['totp_secret'] = totp_secret
            self.users[user_id]['totp_verified'] = verified
            self._save_users()

# Password functions
def encrypt_password(plaintext, safety_key):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(config.encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    enc_bytes = iv + ct
    original_decimal = int.from_bytes(enc_bytes, 'big')
    final_decimal = original_decimal + safety_key
    return str(final_decimal), str(original_decimal)

def decrypt_password(final_password, safety_key):
    try:
        final_decimal = int(final_password)
        original_decimal = final_decimal - safety_key
        length = (original_decimal.bit_length() + 7) // 8
        enc_bytes = original_decimal.to_bytes(length, 'big')
        iv = enc_bytes[:16]
        ct = enc_bytes[16:]
        cipher = Cipher(algorithms.AES(config.encryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plain_padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plain_padded) + unpadder.finalize()
        return plaintext.decode()
    except Exception as e:
        return None

def calculate_password_strength(password):
    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_number = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))
    
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if has_lower: score += 1
    if has_upper: score += 1
    if has_number: score += 1
    if has_symbol: score += 1
    
    strength_levels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
    colors = ["#ff4444", "#ff8800", "#ffbb33", "#00C851", "#007E33"]
    
    if score <= 1:
        return strength_levels[0], colors[0], score
    elif score <= 2:
        return strength_levels[1], colors[1], score
    elif score <= 3:
        return strength_levels[2], colors[2], score
    elif score <= 4:
        return strength_levels[3], colors[3], score
    else:
        return strength_levels[4], colors[4], score

def generate_password(length, include_upper, include_lower, include_numbers, include_symbols):
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
        return None
    
    return ''.join(random.choice(char_pool) for _ in range(length))

# Database operations
def save_password_entry(user_id, username, website, password, safety_key, note=""):
    final_password, original_decimal = encrypt_password(password, safety_key)
    
    conn = sqlite3.connect(config.db_file)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO password_entries (user_id, username, website, final_password, original_decimal, safety_key, note)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, username, website, final_password, original_decimal, safety_key, note))
    conn.commit()
    conn.close()

def get_password_entries(user_id):
    conn = sqlite3.connect(config.db_file)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, username, website, final_password, safety_key, note, created_at
        FROM password_entries WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (user_id,))
    entries = cursor.fetchall()
    conn.close()
    return entries

def delete_password_entry(entry_id):
    conn = sqlite3.connect(config.db_file)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM password_entries WHERE id = ?', (entry_id,))
    conn.commit()
    conn.close()

# Initialize everything
init_database()
user_manager = UserManager()

# Main app
def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1 style="color: white; margin: 0;">🔐 PassFort</h1>
        <p style="color: white; margin: 0;">Your Ultimate Password Manager</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar navigation
    with st.sidebar:
        st.title("🔐 PassFort")
        
        if st.session_state.authenticated:
            st.success(f"Welcome, {st.session_state.user_data['username']}!")
            
            menu_options = [
                "📊 Dashboard",
                "🔑 Password Manager", 
                "🎲 Password Generator",
                "💪 Password Strength",
                "🔧 2FA Setup",
                "📖 Guide",
                "🚪 Logout"
            ]
            
            selected = st.selectbox("Navigate", menu_options)
            
            if selected == "🚪 Logout":
                st.session_state.authenticated = False
                st.session_state.user_id = None
                st.session_state.user_data = None
                st.rerun()
        else:
            st.info("Please login to continue")
            auth_option = st.selectbox("Choose an option", ["Login", "Sign Up"])
            
            if auth_option == "Login":
                show_login()
            else:
                show_signup()
            return
    
    # Main content based on selection
    if st.session_state.authenticated:
        if selected == "📊 Dashboard":
            show_dashboard()
        elif selected == "🔑 Password Manager":
            show_password_manager()
        elif selected == "🎲 Password Generator":
            show_password_generator()
        elif selected == "💪 Password Strength":
            show_password_strength()
        elif selected == "🔧 2FA Setup":
            show_2fa_setup()
        elif selected == "📖 Guide":
            show_guide()

def show_login():
    st.subheader("🔐 Login")
    
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            user_id, user_data = user_manager.verify_user(email, password)
            if user_id:
                st.session_state.authenticated = True
                st.session_state.user_id = user_id
                st.session_state.user_data = user_data
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid credentials")

def show_signup():
    st.subheader("📝 Sign Up")
    
    with st.form("signup_form"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Sign Up")
        
        if submitted:
            if password != confirm_password:
                st.error("Passwords don't match")
            elif len(password) < 6:
                st.error("Password must be at least 6 characters")
            else:
                user_id = user_manager.create_user(username, email, password)
                if user_id:
                    st.success("Account created successfully! Please login.")
                else:
                    st.error("User with this email already exists")

def show_dashboard():
    st.title("📊 Dashboard")
    
    # Get user's password entries
    entries = get_password_entries(st.session_state.user_id)
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h3>Total Passwords</h3>
            <h1>{}</h1>
        </div>
        """.format(len(entries)), unsafe_allow_html=True)
    
    with col2:
        websites = len(set([entry[2] for entry in entries]))
        st.markdown("""
        <div class="metric-card">
            <h3>Websites</h3>
            <h1>{}</h1>
        </div>
        """.format(websites), unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h3>2FA Status</h3>
            <h1>{}</h1>
        </div>
        """.format("✅" if st.session_state.user_data.get('totp_verified') else "❌"), unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="metric-card">
            <h3>Account Age</h3>
            <h1>{} days</h1>
        </div>
        """.format((datetime.now() - datetime.fromisoformat(st.session_state.user_data['created_at'])).days), unsafe_allow_html=True)
    
    # Recent activity
    st.subheader("📝 Recent Password Entries")
    if entries:
        df = pd.DataFrame(entries[:5], columns=['ID', 'Username', 'Website', 'Final Password', 'Safety Key', 'Note', 'Created'])
        df = df[['Website', 'Username', 'Created']]
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No password entries yet. Add some passwords to get started!")
    
    # Password strength analysis
    if entries:
        st.subheader("🔍 Password Analysis")
        
        # For demo purposes, we'll show a simple chart
        fig = go.Figure(data=[
            go.Bar(name='Websites', x=['Strong', 'Medium', 'Weak'], y=[3, 2, 1])
        ])
        fig.update_layout(title="Password Strength Distribution", xaxis_title="Strength", yaxis_title="Count")
        st.plotly_chart(fig, use_container_width=True)

def show_password_manager():
    st.title("🔑 Password Manager")
    
    # Add new password section
    with st.expander("➕ Add New Password", expanded=False):
        with st.form("add_password_form"):
            col1, col2 = st.columns(2)
            with col1:
                website = st.text_input("Website/Service")
                username = st.text_input("Username/Email")
            with col2:
                password = st.text_input("Password", type="password")
                safety_key = st.number_input("Safety Key (4-digit)", min_value=1000, max_value=9999, value=1234)
            
            note = st.text_area("Note (optional)")
            submitted = st.form_submit_button("Add Password")
            
            if submitted:
                if website and username and password:
                    save_password_entry(st.session_state.user_id, username, website, password, safety_key, note)
                    st.success("Password added successfully!")
                    st.rerun()
                else:
                    st.error("Please fill in all required fields")
    
    # Display existing passwords
    st.subheader("💾 Your Passwords")
    entries = get_password_entries(st.session_state.user_id)
    
    if entries:
        for entry in entries:
            entry_id, username, website, final_password, safety_key, note, created_at = entry
            
            with st.container():
                st.markdown("""
                <div class="feature-card">
                    <h4>🌐 {}</h4>
                    <p><strong>Username:</strong> {}</p>
                    <p><strong>Note:</strong> {}</p>
                    <p><strong>Added:</strong> {}</p>
                </div>
                """.format(website, username, note or "No note", created_at), unsafe_allow_html=True)
                
                col1, col2, col3 = st.columns([1, 1, 1])
                
                with col1:
                    reveal_key = st.number_input(f"Safety Key for {website}", min_value=1000, max_value=9999, key=f"key_{entry_id}")
                
                with col2:
                    if st.button(f"🔍 Reveal", key=f"reveal_{entry_id}"):
                        decrypted = decrypt_password(final_password, reveal_key)
                        if decrypted:
                            st.success(f"Password: {decrypted}")
                        else:
                            st.error("Wrong safety key!")
                
                with col3:
                    if st.button(f"🗑️ Delete", key=f"delete_{entry_id}"):
                        delete_password_entry(entry_id)
                        st.success("Password deleted!")
                        st.rerun()
                
                st.divider()
    else:
        st.info("No passwords stored yet. Add your first password above!")

def show_password_generator():
    st.title("🎲 Password Generator")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("⚙️ Settings")
        length = st.slider("Password Length", 8, 50, 16)
        include_upper = st.checkbox("Include Uppercase Letters", value=True)
        include_lower = st.checkbox("Include Lowercase Letters", value=True)
        include_numbers = st.checkbox("Include Numbers", value=True)
        include_symbols = st.checkbox("Include Symbols", value=True)
        
        if st.button("🎲 Generate Password"):
            password = generate_password(length, include_upper, include_lower, include_numbers, include_symbols)
            if password:
                st.session_state.generated_password = password
                st.success("Password generated!")
            else:
                st.error("Please select at least one character type")
    
    with col2:
        st.subheader("🔑 Generated Password")
        if 'generated_password' in st.session_state:
            st.code(st.session_state.generated_password, language=None)
            
            # Show password strength
            strength, color, score = calculate_password_strength(st.session_state.generated_password)
            st.markdown(f"""
            <div style="background-color: {color}; padding: 10px; border-radius: 5px; color: white; text-align: center;">
                <strong>Strength: {strength}</strong>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("📋 Copy to Clipboard"):
                st.info("Password copied! (Note: Clipboard functionality requires additional setup)")
        else:
            st.info("Click 'Generate Password' to create a new password")

def show_password_strength():
    st.title("💪 Password Strength Checker")
    
    password = st.text_input("Enter password to check", type="password")
    
    if password:
        strength, color, score = calculate_password_strength(password)
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.subheader("🔍 Analysis")
            st.markdown(f"""
            <div style="background-color: {color}; padding: 15px; border-radius: 10px; color: white; text-align: center;">
                <h3>Strength: {strength}</h3>
                <p>Score: {score}/6</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.subheader("📊 Details")
            st.write(f"Length: {len(password)} characters")
            st.write(f"Has lowercase: {'✅' if re.search(r'[a-z]', password) else '❌'}")
            st.write(f"Has uppercase: {'✅' if re.search(r'[A-Z]', password) else '❌'}")
            st.write(f"Has numbers: {'✅' if re.search(r'[0-9]', password) else '❌'}")
            st.write(f"Has symbols: {'✅' if re.search(r'[^A-Za-z0-9]', password) else '❌'}")
        
        # Recommendations
        st.subheader("💡 Recommendations")
        recommendations = []
        if len(password) < 12:
            recommendations.append("Use at least 12 characters")
        if not re.search(r'[a-z]', password):
            recommendations.append("Include lowercase letters")
        if not re.search(r'[A-Z]', password):
            recommendations.append("Include uppercase letters")
        if not re.search(r'[0-9]', password):
            recommendations.append("Include numbers")
        if not re.search(r'[^A-Za-z0-9]', password):
            recommendations.append("Include special characters")
        
        if recommendations:
            for rec in recommendations:
                st.write(f"• {rec}")
        else:
            st.success("Your password looks strong! 🎉")

def show_2fa_setup():
    st.title("🔧 Two-Factor Authentication Setup")
    
    user_data = st.session_state.user_data
    
    if user_data.get('totp_verified'):
        st.success("✅ 2FA is already enabled for your account!")
        st.info("Your account is protected with Two-Factor Authentication.")
    else:
        st.info("Enable 2FA for additional security")
        
        if not user_data.get('totp_secret'):
            if st.button("🔐 Generate 2FA Secret"):
                totp_secret = pyotp.random_base32()
                user_manager.update_user_totp(st.session_state.user_id, totp_secret)
                st.session_state.user_data['totp_secret'] = totp_secret
                st.success("2FA secret generated!")
                st.rerun()
        else:
            totp_secret = user_data['totp_secret']
            totp = pyotp.TOTP(totp_secret)
            
            # Generate QR code
            provisioning_uri = totp.provisioning_uri(
                name=user_data['email'],
                issuer_name="PassFort"
            )
            
            qr = qrcode.make(provisioning_uri)
            buffered = BytesIO()
            qr.save(buffered, format="PNG")
            qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
            
            st.subheader("📱 Scan QR Code")
            st.markdown(f'<img src="data:image/png;base64,{qr_code_base64}" width="200">', unsafe_allow_html=True)
            
            st.subheader("🔑 Manual Entry")
            st.code(totp_secret)
            
            # Verify 2FA
            st.subheader("✅ Verify Setup")
            with st.form("verify_2fa"):
                code = st.text_input("Enter 6-digit code from your authenticator app")
                submitted = st.form_submit_button("Verify")
                
                if submitted:
                    if totp.verify(code):
                        user_manager.update_user_totp(st.session_state.user_id, totp_secret, verified=True)
                        st.session_state.user_data['totp_verified'] = True
                        st.success("2FA enabled successfully!")
                        st.rerun()
                    else:
                        st.error("Invalid code. Please try again.")

def show_guide():
    st.title("📖 User Guide")
    
    st.markdown("""
    ## Welcome to PassFort! 🔐
    
    PassFort is your secure password manager that helps you store and manage your passwords safely.
    
    ### 🔑 Key Features
    
    **Password Storage**: Store your passwords securely with advanced encryption.
    
    **Password Generation**: Create strong, random passwords with customizable criteria.
    
    **Password Strength Analysis**: Check how strong your passwords are and get recommendations.
    
    **Two-Factor Authentication**: Add an extra layer of security to your account.
    
    **Safety Keys**: Use 4-digit safety keys for additional protection when accessing your passwords.
    
    ### 🛡️ Security Features
    
    - **AES Encryption**: All passwords are encrypted using AES-256 encryption
    - **Safety Keys**: Additional 4-digit keys required to decrypt passwords
    - **Email Alerts**: Get notified when someone tries to access your passwords with wrong keys
    - **No Plain Text Storage**: Passwords are never stored in plain text
    
    ### 🚀 Getting Started
    
    1. **Sign Up**: Create your account with a strong password
    2. **Enable 2FA**: Set up two-factor authentication for extra security
    3. **Add Passwords**: Start adding your existing passwords to the manager
    4. **Generate New Passwords**: Use the password generator for new accounts
    5. **Stay Secure**: Regularly check your password strength and update weak passwords
    
    ### 💡 Tips for Better Security
    
    - Use unique passwords for each account
    - Enable 2FA wherever possible
    - Regularly update your passwords
    - Use the password generator for new accounts
    - Keep your safety keys secure and memorable
    - Don't share your account credentials with anyone
    
    ### 🔒 Safety Key System
    
    PassFort uses a unique safety key system:
    - Each password is protected by a 4-digit safety key
    - You need this key to decrypt and view your passwords
    - If someone enters the wrong key, you'll receive an email alert
    - Choose memorable but secure safety keys
    
    ### 📧 Need Help?
    
    If you have any questions or need assistance, please contact our support team.
    
    **Stay Safe, Stay Secure! 🛡️**
    """)

if __name__ == "__main__":
    main()
