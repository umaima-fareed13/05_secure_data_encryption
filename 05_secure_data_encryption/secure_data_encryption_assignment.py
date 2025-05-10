import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# Generate or use a consistent Fernet key (for demo, hardcoded for stability)
FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)

# Global in-memory store
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

# Track failed attempts
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# Track login status
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = True


# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


# Insert data page
def insert_data_page():
    st.header("🔐 Insert New Secure Data")
    data_key = st.text_input("Enter a key/name for your data (e.g., note1)")
    text = st.text_area("Enter the text you want to encrypt")
    passkey = st.text_input("Enter a passkey (keep this safe!)", type="password")

    if st.button("Store Securely"):
        if data_key and text and passkey:
            encrypted = cipher.encrypt(text.encode())
            hashed = hash_passkey(passkey)
            st.session_state.stored_data[data_key] = {
                "encrypted_text": encrypted.decode(),
                "passkey": hashed
            }
            st.success("✅ Data stored securely!")
        else:
            st.error("❗Please fill all fields")


# Retrieve data page
def retrieve_data_page():
    if not st.session_state.logged_in:
        st.warning("🚫 Please log in again to continue.")
        login_page()
        return

    st.header("🔓 Retrieve Secure Data")
    data_key = st.text_input("Enter the key/name of your data")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt"):
        data = st.session_state.stored_data.get(data_key)
        if data:
            hashed_input = hash_passkey(passkey)
            if hashed_input == data["passkey"]:
                decrypted = cipher.decrypt(data["encrypted_text"].encode()).decode()
                st.success("✅ Decryption successful!")
                st.text_area("Your decrypted text:", decrypted, height=150)
                st.session_state.failed_attempts = 0  # Reset attempts
            else:
                st.session_state.failed_attempts += 1
                st.error(f"❌ Wrong passkey! Attempt {st.session_state.failed_attempts}/3")
        else:
            st.error("⚠️ No data found with that key!")

        if st.session_state.failed_attempts >= 3:
            st.warning("🔁 Too many failed attempts. Redirecting to login.")
            st.session_state.logged_in = False
            st.experimental_rerun()


# Login Page (Reauthorization)
def login_page():
    st.header("🔐 Re-Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.success("✅ Login successful!")
            st.session_state.failed_attempts = 0
            st.session_state.logged_in = True
            st.experimental_rerun()
        else:
            st.error("❌ Invalid login")


# Main navigation
def main():
    st.title("🛡️ Secure Data Encryption System")

    menu = ["Home", "Insert Data", "Retrieve Data", "Login Page"]
    choice = st.sidebar.selectbox("Navigate", menu)

    if choice == "Home":
        st.subheader("Welcome to Secure Storage App")
        st.markdown("""
        - 🗝️ Store encrypted data with a passkey.
        - 🔓 Decrypt it only with the correct passkey.
        - 🛡️ 3 wrong attempts? Login again.
        """)

    elif choice == "Insert Data":
        insert_data_page()

    elif choice == "Retrieve Data":
        retrieve_data_page()

    elif choice == "Login Page":
        login_page()


if __name__ == "__main__":
    main()
