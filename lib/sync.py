from cryptography.fernet import Fernet
import json
import os

def generate_key():
    # Generate a new Fernet symmetric key
    return Fernet.generate_key()

def export_encrypted_json(input_file, output_file, key_file):
    # Read the JSON data from passwords.json
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Convert the JSON data to a string and encode it to bytes
    json_data = json.dumps(data).encode('utf-8')
    
    # Generate a new key if not provided, then encrypt
    key = generate_key()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(json_data)

    # Write the encrypted data to export.json
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

    # Write the key to key.key
    with open(key_file, 'wb') as f:
        f.write(key)
    
    print(f"Data encrypted and saved to {output_file}. Key saved to {key_file}.")

def import_encrypted_json(encrypted_file, key_file, output_file):
    # Read the encryption key
    with open(key_file, 'rb') as f:
        key = f.read()

    # Read the encrypted data from export.json
    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt the data
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    # Load JSON from decrypted data and write to passwords.json
    json_data = json.loads(decrypted_data.decode('utf-8'))
    with open(output_file, 'w') as f:
        json.dump(json_data, f, indent=4)
    
    print(f"Data decrypted and saved to {output_file}.")

    os.remove(encrypted_file)
    os.remove(key_file)