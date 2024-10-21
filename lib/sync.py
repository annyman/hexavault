import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.low_level import Type, hash_secret_raw

# Function to generate both a random salt (16 bytes) and IV (16 bytes)
def generate_salt_and_iv():
    salt = os.urandom(16)
    iv = os.urandom(16)
    return salt, iv

# Function to derive a key from the master password and salt using Argon2
def derive_key_argon2(master_password, salt):
    key = hash_secret_raw(
        secret=master_password.encode(),  # The master password
        salt=salt,  # The generated salt
        time_cost=3,  # Number of iterations
        memory_cost=2**16,  # Memory usage (64MB)
        parallelism=1,  # Parallel threads
        hash_len=32,  # AES-256 key length (32 bytes)
        type=Type.I  # Use Argon2i (memory-hard)
    )
    return key

# Function to encrypt a password with a given key and IV
def encrypt_passwd(key, plain_password, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(plain_password.encode()) + encryptor.finalize()
    
    # Return the encrypted password (Base64-encoded)
    return base64.b64encode(encrypted_password).decode()

# Function to decrypt a password with a given key and IV
def decrypt_passwd(key, encrypted_password, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(base64.b64decode(encrypted_password)) + decryptor.finalize()
    return decrypted_password.decode()

# Example usage:
master_password = "my_master_password"

# 1. Generate both a salt and IV
salt, iv = generate_salt_and_iv()

# 2. Derive a key using Argon2 and the master password + salt
key = derive_key_argon2(master_password, salt)

# 3. Encrypt the password
encrypted_password = encrypt_passwd(key, "my_secret_password", iv)

print(f"Encrypted Password: {encrypted_password}")
print(f"Salt (Base64): {base64.b64encode(salt).decode()}")
print(f"IV (Base64): {base64.b64encode(iv).decode()}")

# 4. Decrypt the password
decrypted_password = decrypt_passwd(key, encrypted_password, iv)
print(f"Decrypted Password: {decrypted_password}")