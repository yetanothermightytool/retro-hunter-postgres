#!/usr/bin/python3
from cryptography.fernet import Fernet
import getpass

# Function - Generate Encryption Key
def generate_key():
    key = Fernet.generate_key()
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)
    return key

# Function - Get Password From Prompt
def encrypt_password(password):
    try:
        with open("encryption_key.key", "rb") as key_file:
            key = key_file.read()
    except FileNotFoundError:
        print("❗ Encryption key not found. Generating a new key...")
        key = generate_key()

    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())

    with open("encrypted_password.bin", "wb") as encrypted_file:
        encrypted_file.write(encrypted_password)
    print("🔒 Password encrypted and stored securely.")

# Main
if __name__ == "__main__":
    user_password = getpass.getpass("🔑 Enter the Veeam REST API user password to be stored securely: ")
    encrypt_password(user_password)
