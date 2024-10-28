from cryptography.fernet import Fernet
import json
import os

import lib.hashing as hashe

def generate_key():
    # Generate a new Fernet symmetric key
    return Fernet.generate_key()

def export_encrypted_json(input_file, output_file, key_file, snapshot):
    # Read the JSON data from passwords.json
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Convert the JSON data to a string and encode it to bytes
    json_data = json.dumps(data).encode('utf-8')
    
    # Generate a new key if not provided, then encrypt
    key = generate_key()
    snapshot.append(key)
    snapshot[0] = snapshot[0].encode()
    snapshot[1] = snapshot[1].encode()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(json_data)

    # Write the encrypted data to export.json
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

    # Write the key to key.key
    with open(key_file, 'wb') as f:
        f.writelines(snapshot)
    
    print(f"Data encrypted and saved to {output_file}. Key saved to {key_file}.")

def import_encrypted_json(encrypted_file, key_file, output_file, snapshot):
    # Read the encryption key
    with open(key_file, 'rb') as f:
        lines = f.readlines()
    masterp = lines[0].decode()
    email = lines[1].decode()
    print(masterp, email)
    key = lines[2]

    if hashe.check_passwd(masterp, hashe.hash_passwd(snapshot[0])) and hashe.check_passwd(email, hashe.hash_passwd(snapshot[1])):
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
        alert = False
    else:
        alert = True
    os.remove(encrypted_file)
    os.remove(key_file)

    return alert