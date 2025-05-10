import streamlit as st
import hashlib
import json
import time
import os
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timedelta

# Initialize session state variables if they don't exist
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_until' not in st.session_state:
    st.session_state.lockout_until = None
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'master_password_hash' not in st.session_state:
    # Default master password is "admin123" - you would change this in production
    st.session_state.master_password_hash = hashlib.sha256("admin123".encode()).hexdigest()

# Constants
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 30  # seconds
DATA_FILE = "encrypted_data.json"

# Custom styling
st.markdown("""
<style>
    .main {
        background-color: #f5f7ff;
    }
    .stButton>button {
        background-color: #4c66af;
        color: white;
        border-radius: 5px;
        padding: 0.5rem 1rem;
        border: none;
    }
    .stButton>button:hover {
        background-color: #3a508c;
    }
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 10px;
        border-radius: 5px;
        border-left: 5px solid #28a745;
    }
    .error-box {
        background-color: #f8d7da;
        color: #721c24;
        padding: 10px;
        border-radius: 5px;
        border-left: 5px solid #dc3545;
    }
    .warning-box {
        background-color: #fff3cd;
        color: #856404;
        padding: 10px;
        border-radius: 5px;
        border-left: 5px solid #ffc107;
    }
</style>
""", unsafe_allow_html=True)

# Function to derive encryption key from passkey
def derive_key(passkey, salt=None):
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

# Function to hash passkey with salt (more secure than plain SHA-256)
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    # Combine passkey with salt and hash
    salted_passkey = passkey.encode() + salt
    hashed = hashlib.pbkdf2_hmac('sha256', salted_passkey, salt, 100000)
    
    # Convert to storable format
    hashed_passkey = base64.b64encode(hashed).decode('ascii')
    salt_str = base64.b64encode(salt).decode('ascii')
    
    return hashed_passkey, salt_str

# Function to verify passkey
def verify_passkey(passkey, stored_hash, stored_salt):
    salt = base64.b64decode(stored_salt)
    salted_passkey = passkey.encode() + salt
    hashed = hashlib.pbkdf2_hmac('sha256', salted_passkey, salt, 100000)
    
    # Convert to comparable format
    hashed_passkey = base64.b64encode(hashed).decode('ascii')
    
    return hashed_passkey == stored_hash

# Function to encrypt data
def encrypt_data(text, passkey):
    key, salt = derive_key(passkey)
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode())
    
    return {
        "encrypted_text": base64.b64encode(encrypted_text).decode('ascii'),
        "salt": base64.b64encode(salt).decode('ascii')
    }

# Function to decrypt data
def decrypt_data(encrypted_data, passkey):
    try:
        encrypted_text = base64.b64decode(encrypted_data["encrypted_text"])
        salt = base64.b64decode(encrypted_data["salt"])
        
        key, _ = derive_key(passkey, salt)
        cipher = Fernet(key)
        
        decrypted_text = cipher.decrypt(encrypted_text).decode()
        return decrypted_text
    except Exception:
        return None

# Function to save data to file
def save_data_to_file():
    with open(DATA_FILE, "w") as f:
        json.dump(st.session_state.stored_data, f)

# Function to load data from file
def load_data_from_file():
    try:
        if Path(DATA_FILE).exists():
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        return {}
    except Exception:
        st.error("Error loading data file. Starting with empty data store.")
        return {}

# Load data on startup
st.session_state.stored_data = load_data_from_file()

# Check if user is locked out
def is_locked_out():
    if st.session_state.lockout_until is not None:
        if datetime.now() < st.session_state.lockout_until:
            remaining = (st.session_state.lockout_until - datetime.now()).seconds
            st.error(f"🔒 Account locked. Try again in {remaining} seconds.")
            return True
        else:
            st.session_state.lockout_until = None
    return False

# Custom success message with icon
def show_success(message):
    st.markdown(f"""
    <div class="success-box">
        ✅ {message}
    </div>
    """, unsafe_allow_html=True)

# Custom error message with icon
def show_error(message):
    st.markdown(f"""
    <div class="error-box">
        ❌ {message}
    </div>
    """, unsafe_allow_html=True)

# Custom warning message with icon
def show_warning(message):
    st.markdown(f"""
    <div class="warning-box">
        ⚠️ {message}
    </div>
    """, unsafe_allow_html=True)

# Generate a unique ID for new data
def generate_data_id():
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/data-encryption.png", width=80)
    st.subheader("Navigation")
    
    menu = ["Home", "Store Data", "Retrieve Data", "View Data IDs", "Login"]
    choice = st.selectbox("Choose an option", menu)
    
    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    This application provides secure data storage with encryption.
    - Store data using unique passkeys
    - Retrieve data with the correct passkey
    - Security measures prevent unauthorized access
    """)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ### Features
        
        - **End-to-End Encryption**: Your data is encrypted using industry-standard algorithms
        - **Passkey Protection**: Access your data with unique passkeys known only to you
        - **In-Memory Processing**: Sensitive operations happen securely in memory
        - **Data Persistence**: Your encrypted data is saved between sessions
        - **Brute Force Protection**: Multiple failed attempts trigger account lockout
        
        ### How to Use
        
        1. Go to **Store Data** to encrypt and save your information
        2. Use **Retrieve Data** to access your encrypted content
        3. If you forget your passkey, you'll need the master password to reset
        """)
    
    with col2:
        st.image("https://img.icons8.com/color/240/000000/cyber-security.png", width=180)

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    
    user_data = st.text_area("Enter Data to Encrypt:", height=150)
    data_name = st.text_input("Data Label (optional):")
    passkey = st.text_input("Create Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")
    
    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("Encrypt & Save"):
            if user_data and passkey:
                if passkey != confirm_passkey:
                    show_error("Passkeys don't match!")
                else:
                    # Generate a unique ID for this data
                    data_id = generate_data_id()
                    
                    # Hash the passkey
                    hashed_passkey, salt = hash_passkey(passkey)
                    
                    # Encrypt the data
                    encryption_result = encrypt_data(user_data, passkey)
                    
                    # Store everything
                    data_entry = {
                        "encrypted_text": encryption_result["encrypted_text"],
                        "salt": encryption_result["salt"],
                        "passkey_hash": hashed_passkey,
                        "passkey_salt": salt,
                        "name": data_name if data_name else f"Data_{data_id}",
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    st.session_state.stored_data[data_id] = data_entry
                    save_data_to_file()
                    
                    # Show success message with the data ID
                    show_success(f"Data stored securely with ID: {data_id}")
            else:
                show_error("Both data and passkey are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    if is_locked_out():
        st.stop()
    
    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")
    
    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("Decrypt"):
            if data_id and passkey:
                if data_id in st.session_state.stored_data:
                    data_entry = st.session_state.stored_data[data_id]
                    
                    # Verify passkey
                    if verify_passkey(passkey, data_entry["passkey_hash"], data_entry["passkey_salt"]):
                        # Decrypt data
                        decryption_data = {
                            "encrypted_text": data_entry["encrypted_text"],
                            "salt": data_entry["salt"]
                        }
                        decrypted_text = decrypt_data(decryption_data, passkey)
                        
                        if decrypted_text:
                            # Reset failed attempts on success
                            st.session_state.failed_attempts = 0
                            
                            # Display decrypted data
                            st.markdown("### Decrypted Data")
                            st.markdown(f"**{data_entry['name']}**")
                            st.text_area("Content:", value=decrypted_text, height=200, disabled=True)
                            show_success("Data decrypted successfully!")
                        else:
                            # Increment failed attempts
                            st.session_state.failed_attempts += 1
                            remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                            
                            if remaining > 0:
                                show_error(f"Decryption failed! Attempts remaining: {remaining}")
                            else:
                                # Lock account after max attempts
                                st.session_state.lockout_until = datetime.now() + timedelta(seconds=LOCKOUT_DURATION)
                                show_warning("Too many failed attempts! Account locked temporarily.")
                                st.rerun()
                    else:
                        # Increment failed attempts
                        st.session_state.failed_attempts += 1
                        remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                        
                        if remaining > 0:
                            show_error(f"Incorrect passkey! Attempts remaining: {remaining}")
                        else:
                            # Lock account after max attempts
                            st.session_state.lockout_until = datetime.now() + timedelta(seconds=LOCKOUT_DURATION)
                            show_warning("Too many failed attempts! Account locked temporarily.")
                            st.experimental_rerun()
                else:
                    show_error("Data ID not found!")
            else:
                show_error("Both Data ID and passkey are required!")

elif choice == "View Data IDs":
    st.subheader("📋 Your Stored Data IDs")
    
    if not st.session_state.stored_data:
        st.info("No data stored yet. Go to 'Store Data' to encrypt and save your information.")
    else:
        st.write("These are your stored data entries. You'll need the corresponding ID to retrieve each item.")
        
        # Create a table of data IDs and names
        data_table = []
        for data_id, data_info in st.session_state.stored_data.items():
            data_table.append({
                "ID": data_id,
                "Label": data_info["name"],
                "Created": data_info["created_at"]
            })
        
        st.table(data_table)

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    
    if is_locked_out():
        st.stop()
    
    st.markdown("Enter the master password to reset your failed attempts and regain access.")
    
    master_pass = st.text_input("Enter Master Password:", type="password")
    
    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("Login"):
            if hashlib.sha256(master_pass.encode()).hexdigest() == st.session_state.master_password_hash:
                # Reset lockout and failed attempts
                st.session_state.failed_attempts = 0
                st.session_state.lockout_until = None
                st.session_state.authenticated = True
                
                show_success("Reauthorized successfully! You can now access the system.")
                time.sleep(1)
                st.experimental_rerun()
            else:
                show_error("Incorrect master password!")

# Footer
st.markdown("---")
st.markdown(
    "#### Secure Data Encryption System | Developed with ❤️ using Python & Streamlit"
)