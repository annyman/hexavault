import dataclasses as dc
from lib.encryption import *
from tinydb import TinyDB, Query, where
from typing import List
from enum import Enum

@dc.dataclass
class Passwd:
    name: str
    url: str
    username: str
    password: str
    tags: List[str]
    strength: str
    salt: str
    iv: str

def print_passwd(pwd: Passwd):
    for k, v in dc.asdict(pwd).items():
            if k == 'salt':
                break
            else:
                print(f"{k}: {v}")

def ask_passwd() -> Passwd:
    print("Enter Name:")
    name = input()
    print("Enter URL:")
    url = input()
    print("Enter Username:")
    username = input()
    print("Enter Password:")
    password = input()
    print("Enter Tags:")
    txt = input()
    tags = []
    words = txt.split()  # Split input by spaces
    for word in words:
        if word.startswith('#'):
            tags.append(word[1:])  # Remove '#' from tag
    
    strength = 'default'
    salt, iv = generate_salt_iv()

    return Passwd(name, url, username, password, tags, strength, salt, iv)

def load_passwd(entry: dict): # not needed
    return Passwd(**entry)

def add_passwd(db: TinyDB, entry: Passwd, master_password: str): # encrypt and add password to db
    key = derive_key_argon2(master_password, entry.salt)
    entry.password = encrypt_passwd(key, entry.password, entry.iv)
    db.insert(dc.asdict(entry))

def read_passwd(db: TinyDB, master_password: str): # retrieve and decrypt the password:
    for item in db:
        key = derive_key_argon2(master_password, item['salt'])
        item['password'] = decrypt_passwd(key, item['password'], item['iv'])
        for k, v in item.items():
            if k == 'salt':
                break
            else:
                print(f"{k}: {v}") # print the key value pairs
        print(f"\n")

def parse_input(input_text):
    names = []
    tags = []

    words = input_text.split()  # Split input by spaces
    
    for word in words:
        if word.startswith('#'):
            tags.append(word[1:])  # Remove '#' from tag
        else:
            names.append(word)  # It's a name
    
    return names, tags

def search_name_tag(names: List[str], tags: List[str], db: TinyDB) -> TinyDB.table:
    table = db.table('search')
    Entry = Query()

    if len(names) == 0:
        result = db.search(Entry.tags.all(tags))
        for entry in result:
            if entry not in table:
                table.insert(entry)
    if len(tags) == 0:
        for name in names:
            result = db.search(Entry.name == name)
            for entry in result:
                if entry not in table:
                    table.insert(entry)
    else: 
        for name in names:
            for tag in tags:
                result = db.search(Entry.name == name and Entry.tags.all(tags))
                for entry in result:
                    if entry not in result:
                        table.insert(entry)

    return table
