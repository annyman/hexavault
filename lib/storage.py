from lib.encryption import *
import json

def add_passwd(table, user, passwd, cipher):
    table[user] = encrypt_passwd(cipher, passwd)

# Write encrypted passwords to JSON file
def write_passwd(path, table):
    try:
        # Step 1: Read the existing data from the JSON file
        with open(path, 'r') as file:
            existing_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        # If file doesn't exist or is empty, start with an empty dict
        existing_data = {}

    # Step 2: Update the dictionary with the new data (this merges the dictionaries)    existing_data.update(table)
    existing_data.update(table)

    # Step 3: Write the updated data back to the JSON file
    with open(path, 'w') as file:
        json.dump({k: v for k, v in existing_data.items()}, file)


# To retrieve and decrypt the password:
def read_passwd(path, cipher):
    with open(path, 'r') as json_file:
        stored_passwords = json.load(json_file)
        for user, encrypted_password in stored_passwords.items():
            print(f"{user}: {decrypt_passwd(cipher, encrypted_password)}")
