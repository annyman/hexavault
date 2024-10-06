from cryptography.fernet import Fernet
import os

import lib.hashing as hash
import lib.storage as storage
import lib.generator as gen
    
key = b'IqLHbWPMEN-IR_J3wynIIxwKa7l46ylJ63gzB7Hl0BQ='
master = "mypass123"
# CIPHER = Fernet(Fernet.generate_key())
CIPHER = Fernet(key)
pass_db = {}

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
        print('\nUsername: ')
        user = input()
        print('Password: ')
        passwd = input()
        alert, strength, feedback = gen.check_strength(passwd)

        if alert == True:
            print(f"\nPassword is {strength}")
            print("Do you want to generate a stronger password?")
            yes = str(input())
            if yes == "y" or yes == "yes":
                print("Generating a stronger password...")
                passwd = gen.gen_random_passwd(14, True, True, True)
                print(f"New password: {passwd}. Saving it...")
                input()
                storage.add_passwd(pass_db, user, passwd, CIPHER)
                storage.write_passwd('passwords.json', pass_db)

        print("Saving password...")
        input()
        storage.add_passwd(pass_db, user, passwd, CIPHER)
        storage.write_passwd('passwords.json', pass_db)

    elif inp == 2:
        print("")
        storage.read_passwd('passwords.json', CIPHER)
        input()
    elif inp == 3:
        pass_db = {}
        print("\nRemoving stored passwords...")
        input()
        os.remove('passwords.json')
    elif inp == 4:
        break
    else:
        print('Invalid input!')