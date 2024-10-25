from cryptography.fernet import Fernet
import os
from tinydb import TinyDB

import lib.hashing as hashe
import lib.generator as gen
import lib.dbms as dbms
import gui.gui as gui
# ✔

master = "mypass123" # ✔
pass_db = TinyDB('passwords.json') # ✔

def cls():
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Linux and macOS
        os.system('clear')

while True:
    cls()

    print("Enter master password:")
    given = input()
    hashed = hashe.hash_passwd(given)

    if hashe.check_passwd(master, hashed):
        print("\nMaster password is correct!, letting you in.\n")
        break
    else:
        print("\nIncorrect Master password! booooo.\n")

while True:
    gui.mainloop_tk()

    cls()

    print('1> Enter username and password')
    print('2> Display')
    print('3> Reset')
    print('4> Search')
    print('5> Exit')

    try:
        inp = int(input("\n"))
    except ValueError:
        print("Invalid input!")
        input()
        continue

    if inp == 1:
        cls()
        entry = dbms.ask_passwd()
        alert, strength, feedback = gen.check_strength(entry.password)

        if alert == True:
            print(f"\nPassword is {strength}")
            print("Do you want to generate a stronger password?")
            yes = str(input())
            if yes == "y" or yes == "yes":
                print("Generating a stronger password...")
                entry.password = gen.gen_random_passwd(14, True, True, True)
                entry.strength = 'STRONG'
                print(f"New password: {entry.password}")
                input()

        entry.strength = strength
        print("Saving password...")
        input()

        dbms.add_passwd(pass_db, entry, master)

    elif inp == 2:
        cls()
        print("")
        dbms.read_passwd(pass_db, master)
        input()
    elif inp == 3:
        cls()
        print("\nRemoving stored passwords...")
        input()
        pass_db.truncate()
    elif inp == 4:
        cls()
        print("\nGive the name and tags to search: ")
        text = input()
        names, tags = dbms.parse_input(text)

        dbms.read_passwd(dbms.search_name_tag(names, tags, pass_db), master)
        input()
        pass_db.drop_table('search')
    elif inp == 5:
        quit()
    elif type(inp) != int:
        print('Invalid input!')