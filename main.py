from cryptography.fernet import Fernet
import os
from tinydb import TinyDB

import lib.hashing as hash
import lib.generator as gen
import lib.dbms as dbms
    
key = b'IqLHbWPMEN-IR_J3wynIIxwKa7l46ylJ63gzB7Hl0BQ='
master = "mypass123"
# CIPHER = Fernet(Fernet.generate_key())
CIPHER = Fernet(key)
pass_db = TinyDB('passwords.json')

while True:
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Linux and macOS
        os.system('clear')

    print("Enter master password:")
    given = input()
    hashed = hash.hash_passwd(given)

    if hash.check_passwd(master, hashed):
        print("\nMaster password is correct!, letting you in.\n")
        break
    else:
        print("\nIncorrect Master password! booooo.\n")

while True:
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Linux and macOS
        os.system('clear')

    print('1> Enter username and password')
    print('2> Display')
    print('3> Reset')
    print('4> Exit')
    inp = int(input("\n"))

    if inp == 1:
        entry = dbms.ask_passwd(CIPHER)
        alert, strength, feedback = gen.check_strength(entry.password)

        if alert == True:
            print(f"\nPassword is {strength}")
            print("Do you want to generate a stronger password?")
            yes = str(input())
            if yes == "y" or yes == "yes":
                print("Generating a stronger password...")
                entry.password = gen.gen_random_passwd(14, True, True, True)
                print(f"New password: {entry.password}")
                input()

        print("Saving password...")
        input()

        dbms.add_passwd(pass_db, entry, CIPHER)

    elif inp == 2:
        print("")
        dbms.read_passwd(pass_db, CIPHER)
        input()
    elif inp == 3:
        print("\nRemoving stored passwords...")
        input()
        pass_db.truncate()
    elif inp == 4:
        break
    else:
        print('Invalid input!')