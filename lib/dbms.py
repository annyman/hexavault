import dataclasses as dc
from lib.encryption import *
from tinydb import TinyDB, Query
from typing import List

@dc.dataclass
class Passwd:
    name: str
    url: str
    username: str
    password: str
    tags: List[str]

def print_passwd(pwd: Passwd):
    for k, v in dc.asdict(pwd).items():
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

# Upcoming: query searches (name, username), input parsing for #tags, maybe a token system??
