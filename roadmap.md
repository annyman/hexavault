# Roadmap

## Phase 1: Planning & Basic Setup

- ~~Research password encryption and hashing (AES, bcrypt, argon2).~~
- ~~Define how you’ll store the data (SQLite for simplicity or a plain text JSON file).~~
- Set up your basic Tkinter GUI skeleton (login form, buttons for adding passwords).

## Phase 2: Implement Core Features

- ~~Master Password: Implement a master password system (with bcrypt/argon2 for hashing).~~
- ~~Encryption: Use cryptography to encrypt and decrypt passwords before storage and retrieval.~~
- ~~Storage: Use a local file or SQLite database to store the encrypted passwords.~~
- Password Generator: Implement the generator using secrets for random password generation.

## Phase 3: Security Enhancements

- ~~Add salt to password hashing to prevent rainbow table attacks.~~
- Implement PBKDF2 for securely deriving encryption keys from the master password.
- Ensure that the encrypted file or database has proper access permissions (e.g., not world-readable).

## Phase 4: Refine the GUI

- Improve the user interface to include password viewing, editing, and deletion features.
- Add clipboard functionality to easily copy passwords to the clipboard.

## Phase 5: Testing & Packaging

- Testing: Test encryption, decryption, and password generation features.
- Packaging: Package the entire program using PyInstaller into an executable.