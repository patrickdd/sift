import hashlib
import subprocess

import yaml


def find_user(cursor, name):
    cursor.execute(f"select * from users where name = '{name}'")
    return cursor.fetchall()


def load(text):
    return yaml.load(text)


def run(cmd):
    return subprocess.call(cmd, shell=True)


def digest(data):
    return hashlib.md5(data).hexdigest()
