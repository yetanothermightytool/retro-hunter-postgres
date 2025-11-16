#!/usr/bin/python3
from cryptography.fernet import Fernet
import getpass

def generate_key():
   key = Fernet.generate_key()
   with open("encryption_key.key", "wb") as key_file:
       key_file.write(key)
   return key

def load_key():
   try:
       with open("encryption_key.key", "rb") as key_file:
           key = key_file.read()
   except FileNotFoundError:
       print("❗ Encryption key not found. Generating a new key...")
       key = generate_key()
   return key

def encrypt_password(password, output_file, key):
   fernet = Fernet(key)
   encrypted_password = fernet.encrypt(password.encode())
   with open(output_file, "wb") as encrypted_file:
       encrypted_file.write(encrypted_password)
   print(f"🔒 Password encrypted and stored securely in {output_file}.")

if __name__ == "__main__":
   key = load_key()

   rest_password = getpass.getpass("🔑 Enter the Veeam REST API user password to be stored securely: ")
   encrypt_password(rest_password, "encrypted_password.bin", key)
   # Only used for the NAS AV Scanner. File can be deleted if not used!
   smb_password = getpass.getpass("🔑 Enter the SMB user password to be stored securely: ")
   encrypt_password(smb_password, "encrypted_smb_password.bin", key)

