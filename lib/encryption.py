from cryptography.fernet import Fernet

def encrypt_passwd(cipher, passwd):
    return cipher.encrypt(passwd.encode()).decode() # Encrypt using given cipher key

def decrypt_passwd(cipher, passwd):
    return cipher.decrypt(passwd).decode() # Decrypt using given cipher key
