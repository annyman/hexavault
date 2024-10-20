import dataclasses as dc
from lib.encryption import *
from tinydb import TinyDB, Query, where
from typing import List

@dc.dataclass
class Passwd:
    name: str
    url: str
    username: str
    password: str
    tags: List[str] = dc.field(default_factory=list)
    #strength: enum
    #salt: int

def print_passwd(pwd: Passwd):
    for k, v in dc.asdict(pwd).items():
            if k == 'salt':
                break
            else:
                print(f"{k}: {v}")

def ask_passwd(cipher) -> Passwd:
    print("Enter Name:")
    name = input()
    print("Enter URL:")
    url = input()
    print("Enter Username:")
    username = input()
    print("Enter Password:")
    password = input()
    print("Enter Tags:")
    input()
    tags = []

    return Passwd(name, url, username, password, tags)

def load_passwd(entry: dict): # not needed
    return Passwd(**entry)

def add_passwd(db: TinyDB, entry, cipher): # encrypt and add password to db
    entry.password = encrypt_passwd(cipher, entry.password)
    db.insert(dc.asdict(entry))

def read_passwd(db, cipher): # retrieve and decrypt the password:
    for item in db:
        item['password'] = decrypt_passwd(cipher, item['password'])
        for k, v in item.items():
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
