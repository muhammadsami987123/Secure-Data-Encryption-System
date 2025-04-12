import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from datetime import datetime

# Set page config must be the first Streamlit command
st.set_page_config(
    page_title="Secure Data Encryption System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Constants
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
DATA_FILE = "encrypted_data.json"
USERS_FILE = "users.json"

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0
if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'home'

# Load users data
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

# Save users data
def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

# Initialize users data
users_data = load_users()

# Generate or load encryption key
def get_encryption_key():
    if 'encryption_key' not in st.session_state:
        key = Fernet.generate_key()
        st.session_state.encryption_key = key
    return st.session_state.encryption_key

# Initialize cipher
cipher = Fernet(get_encryption_key())

# Load stored data from file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

# Save data to file
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# Initialize stored data
stored_data = load_data()

# Enhanced password hashing using PBKDF2
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key, salt

# Encrypt data
def encrypt_data(text, passkey):
    salt = os.urandom(16)
    key, salt = hash_passkey(passkey, salt)
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode()).decode()
    return encrypted_text, salt

# Decrypt data
def decrypt_data(encrypted_text, passkey, salt):
    try:
        key, _ = hash_passkey(passkey, salt)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Check if user is locked out
def is_locked_out():
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        if time.time() - st.session_state.lockout_time < LOCKOUT_TIME:
            return True
        else:
            st.session_state.failed_attempts = 0
    return False

# Custom CSS
st.markdown("""
    <style>
    .main {
        background-color: #f5f5f5;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
        background-color: #4CAF50;
        color: white;
        font-weight: bold;
    }
    .stTextInput>div>div>input {
        border-radius: 5px;
    }
    .stTextArea>div>div>textarea {
        border-radius: 5px;
    }
    .css-1d391kg {
        padding: 1rem;
        border-radius: 5px;
        background-color: white;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    /* Navbar Styles */
    .sidebar .sidebar-content {
        background-color: #2c3e50;
        color: white;
    }
    .sidebar .sidebar-content .stSelectbox > div {
        background-color: #34495e;
        color: white;
    }
    .sidebar .sidebar-content .stSelectbox > div > div > div {
        color: white;
    }
    .sidebar .sidebar-content .stSelectbox > div > div > div:hover {
        background-color: #3498db;
    }
    .sidebar .sidebar-content .stButton > button {
        background-color: #3498db;
        color: white;
        border: none;
        transition: all 0.3s ease;
    }
    .sidebar .sidebar-content .stButton > button:hover {
        background-color: #2980b9;
    }
    .sidebar .sidebar-content .stMarkdown {
        color: white;
    }
    .sidebar .sidebar-content .stSuccess {
        background-color: #27ae60;
        color: white;
    }
    .sidebar .sidebar-content .stWarning {
        background-color: #f39c12;
        color: white;
    }
    /* Simple Title Styles */
    .app-title {
        text-align: center;
        padding: 1.5rem;
        background: linear-gradient(45deg, #2c3e50, #3498db);
        border-radius: 10px;
        margin-bottom: 1rem;
    }
    .app-title h1 {
        color: white;
        margin: 0;
        font-size: 1.8rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
    }
    .app-title p {
        color: #ecf0f1;
        margin: 0.5rem 0 0 0;
        font-size: 0.9rem;
    }
    /* Simple Footer Styles */
    .app-footer {
        background: linear-gradient(to bottom, #2c3e50, #34495e);
        border-radius: 10px;
        padding: 20px;
        margin-top: 20px;
    }
    .footer-title {
        color: white;
        font-size: 1.2em;
        text-align: center;
        margin-bottom: 10px;
    }
    .footer-subtitle {
        color: #95a5a6;
        font-size: 0.9em;
        text-align: center;
        margin-bottom: 15px;
    }
    .footer-social {
        display: flex;
        justify-content: center;
        gap: 15px;
        margin: 15px 0;
        padding: 10px 0;
        border-top: 1px solid rgba(255,255,255,0.1);
        border-bottom: 1px solid rgba(255,255,255,0.1);
    }
    .social-link {
        color: #ecf0f1;
        text-decoration: none;
        padding: 8px 15px;
        border-radius: 20px;
        font-size: 0.9em;
        transition: all 0.3s ease;
        background: rgba(52, 152, 219, 0.1);
    }
    .social-link:hover {
        background: #3498db;
        transform: translateY(-2px);
    }
    .footer-contact {
        text-align: center;
        color: #bdc3c7;
        margin: 15px 0;
    }
    .footer-copyright {
        color: #95a5a6;
        font-size: 0.8em;
        text-align: center;
        margin-top: 15px;
    }
    </style>
    """, unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("""
    <div style='
        text-align: center;
        padding: 25px;
        background: linear-gradient(135deg, #2c3e50, #3498db);
        border-radius: 10px;
        margin-bottom: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    '>
        <h1 style='
            color: white;
            margin: 0;
            font-size: 24px;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        '>🔒 Secure Data System</h1>
        <p style='
            color: #ecf0f1;
            margin: 8px 0 0 0;
            font-size: 14px;
            opacity: 0.9;
        '>Advanced Data Protection</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Navigation Menu
    menu = {
        "Home": "🏠",
        "Create Account": "👤",
        "Login": "🔑",
        "Store Data": "📂",
        "Retrieve Data": "🔍"
    }
    
    # Create styled menu items
    selected = st.selectbox(
        "Navigation",
        list(menu.keys()),
        format_func=lambda x: f"{menu[x]} {x}"
    )
    
    st.markdown("---")
    
    # User Status Section
    if st.session_state.is_authenticated:
        st.markdown("""
        <div style='background-color: #27ae60; padding: 10px; border-radius: 5px; text-align: center;'>
            <p style='color: white; margin: 0;'>✅ Logged in as</p>
            <p style='color: white; margin: 0; font-weight: bold;'>{}</p>
        </div>
        """.format(st.session_state.current_user), unsafe_allow_html=True)
        
        if st.button("Logout", key="sidebar_logout"):
            st.session_state.is_authenticated = False
            st.session_state.current_user = None
            st.rerun()
    else:
        st.markdown("""
        <div style='background-color: #f39c12; padding: 10px; border-radius: 5px; text-align: center;'>
            <p style='color: white; margin: 0;'>⚠️ Not logged in</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")

    # Footer
    st.markdown("""
    <div style='
        background: linear-gradient(to bottom, #2c3e50, #1a2634);
        border-radius: 10px;
        padding: 20px;
        margin-top: auto;
        box-shadow: 0 -2px 10px rgba(0,0,0,0.1);
    '>
        <div style='
            text-align: center;
            color: #ecf0f1;
            font-size: 14px;
            margin-bottom: 10px;
        '>
            <p style='margin: 0;'>Created by</p>
            <p style='margin: 5px 0; font-weight: bold;'>Muhammad Sami</p>
        </div>
        <div style='
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-bottom: 15px;
        '>
            <a href="https://github.com/muhammadsami987123" target="_blank" style='
                color: #ecf0f1;
                text-decoration: none;
                padding: 8px 15px;
                border-radius: 20px;
                background: rgba(255,255,255,0.1);
                transition: all 0.3s ease;
            '>🐙 GitHub</a>
            <a href="https://www.linkedin.com/in/muhammad-sami-3aa6102b8/" target="_blank" style='
                color: #ecf0f1;
                text-decoration: none;
                padding: 8px 15px;
                border-radius: 20px;
                background: rgba(255,255,255,0.1);
                transition: all 0.3s ease;
            '>🔗 LinkedIn</a>
            <a href="https://x.com/MSAMIWASEEM1" target="_blank" style='
                color: #ecf0f1;
                text-decoration: none;
                padding: 8px 15px;
                border-radius: 20px;
                background: rgba(255,255,255,0.1);
                transition: all 0.3s ease;
            '>𝕏 Twitter</a>
        </div>
        <div style='
            text-align: center;
            color: #95a5a6;
            font-size: 12px;
            padding-top: 10px;
            border-top: 1px solid rgba(255,255,255,0.1);
        '>
            <p style='margin: 5px 0;'>© 2024 Secure Data System</p>
            <p style='margin: 5px 0;'>Version 1.0.0</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

# Update the choice variable to use the selected menu item
choice = selected

# Main content
if choice == "Home":
    st.title("🏠 Welcome to the Secure Data System")
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🔐 About This System
        
        This application provides a secure way to store and retrieve sensitive data using:
        - Advanced encryption (Fernet)
        - PBKDF2 password hashing
        - Account protection
        - Persistent storage
        - Multi-user support
        """)
    
    with col2:
        st.markdown("""
        ### 📝 Quick Guide
        
        1. **Create Account**: Register for a new account
        2. **Login**: Access your secure space
        3. **Store Data**: Encrypt and save your sensitive information
        4. **Retrieve Data**: Access your encrypted data with your passkey
        5. **Security**: System locks after 3 failed attempts
        """)
    
    st.markdown("---")
    st.info("ℹ️ Please use the sidebar to navigate through different sections")

# Create Account Page
elif choice == "Create Account":
    st.title("👤 Create New Account")
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        new_username = st.text_input("Choose Username")
        st.info("ℹ️ Choose a unique username")
    
    with col2:
        new_password = st.text_input("Choose Password", type="password")
        st.info("ℹ️ Choose a strong password")
    
    if st.button("Create Account", key="create_account_button"):
        if not new_username or not new_password:
            st.error("⚠️ Please enter both username and password!")
        elif new_username in users_data:
            st.error("⚠️ Username already exists!")
        else:
            # Hash the password
            salt = os.urandom(16)
            hashed_password, salt = hash_passkey(new_password, salt)
            
            # Create new user
            users_data[new_username] = {
                "password": hashed_password.decode(),
                "salt": base64.b64encode(salt).decode(),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_login": None
            }
            
            # Save users data
            save_users(users_data)
            st.success("✅ Account created successfully!")
            st.info("ℹ️ Please login with your new credentials")

# Login Page
elif choice == "Login":
    st.title("🔑 Login")
    st.markdown("---")
    
    if st.session_state.is_authenticated:
        st.success("✅ You are already logged in!")
        if st.button("Logout", key="login_page_logout"):
            st.session_state.is_authenticated = False
            st.session_state.current_user = None
            st.rerun()
    else:
        col1, col2 = st.columns(2)
        
        with col1:
            username = st.text_input("Username")
            st.info("ℹ️ Enter your username")
        
        with col2:
            password = st.text_input("Password", type="password")
            st.info("ℹ️ Enter your password")
        
        if st.button("Login", key="login_button"):
            if username in users_data:
                user = users_data[username]
                salt = base64.b64decode(user["salt"])
                hashed_password, _ = hash_passkey(password, salt)
                
                if hashed_password.decode() == user["password"]:
                    st.session_state.is_authenticated = True
                    st.session_state.current_user = username
                    st.session_state.failed_attempts = 0
                    
                    # Update last login
                    users_data[username]["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    save_users(users_data)
                    
                    st.success("✅ Login successful!")
                    st.rerun()
                else:
                    st.error("❌ Invalid password!")
            else:
                st.error("❌ User not found!")

# Store Data Page
elif choice == "Store Data":
    st.title("📂 Store Data Securely")
    st.markdown("---")
    
    if not st.session_state.is_authenticated:
        st.error("⚠️ Please login first!")
        st.stop()
    
    if is_locked_out():
        st.error(f"🔒 Account locked! Please wait {int((LOCKOUT_TIME - (time.time() - st.session_state.lockout_time)) / 60)} minutes.")
        st.stop()
    
    col1, col2 = st.columns(2)
    
    with col1:
        user_data = st.text_area("Enter Data to Encrypt:", height=200)
        st.info("ℹ️ Enter the sensitive data you want to encrypt")
    
    with col2:
        passkey = st.text_input("Enter Passkey:", type="password")
        confirm_passkey = st.text_input("Confirm Passkey:", type="password")
        st.info("ℹ️ Choose a strong passkey and keep it safe")
    
    if st.button("Encrypt & Save", key="encrypt_button"):
        if not user_data or not passkey:
            st.error("⚠️ Please enter both data and passkey!")
        elif passkey != confirm_passkey:
            st.error("⚠️ Passkeys do not match!")
        else:
            with st.spinner("Encrypting and saving your data..."):
                encrypted_text, salt = encrypt_data(user_data, passkey)
                if st.session_state.current_user not in stored_data:
                    stored_data[st.session_state.current_user] = {}
                
                stored_data[st.session_state.current_user][encrypted_text] = {
                    "encrypted_text": encrypted_text,
                    "salt": base64.b64encode(salt).decode(),
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                save_data(stored_data)
                st.success("✅ Data stored securely!")
                st.info("🔑 Please save your passkey securely. You'll need it to retrieve the data.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    st.title("🔍 Retrieve Your Data")
    st.markdown("---")
    
    if not st.session_state.is_authenticated:
        st.error("⚠️ Please login first!")
        st.stop()
    
    if is_locked_out():
        st.error(f"🔒 Account locked! Please wait {int((LOCKOUT_TIME - (time.time() - st.session_state.lockout_time)) / 60)} minutes.")
        st.stop()
    
    if st.session_state.current_user not in stored_data or not stored_data[st.session_state.current_user]:
        st.warning("⚠️ No data available to retrieve.")
        st.stop()
    
    col1, col2 = st.columns(2)
    
    with col1:
        user_data = stored_data[st.session_state.current_user]
        data_choice = st.selectbox("Select Data to Retrieve:", list(user_data.keys()))
        st.info("ℹ️ Select the encrypted data you want to decrypt")
    
    with col2:
        passkey = st.text_input("Enter Passkey:", type="password")
        st.info("ℹ️ Enter the passkey you used to encrypt this data")
    
    if st.button("Decrypt", key="decrypt_button"):
        if not passkey:
            st.error("⚠️ Please enter your passkey!")
        else:
            with st.spinner("Decrypting your data..."):
                data = user_data[data_choice]
                salt = base64.b64decode(data["salt"])
                decrypted_text = decrypt_data(data["encrypted_text"], passkey, salt)
                
                if decrypted_text:
                    st.session_state.failed_attempts = 0
                    st.success("✅ Data decrypted successfully!")
                    st.text_area("Decrypted Data:", decrypted_text, height=200)
                else:
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                        st.session_state.lockout_time = time.time()
                        st.error("🔒 Too many failed attempts! Account locked.")
                    else:
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {MAX_ATTEMPTS - st.session_state.failed_attempts}") 