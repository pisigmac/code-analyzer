"""Test fixture with security issues."""

import hashlib
import pickle
import subprocess
import random


# Hardcoded secret
API_KEY = "sk-1234567890abcdef"

# Debug mode enabled
DEBUG = True


def sql_injection(user_id):
    query = "SELECT * FROM users WHERE id = %s" % user_id
    return query


def dangerous_eval():
    user_input = input("Enter code: ")
    return eval(user_input)


def unsafe_pickle():
    data = pickle.loads(b"some data")
    return data


def weak_hash():
    return hashlib.md5(b"password").hexdigest()


def insecure_temp_file():
    with open("/tmp/myfile.txt", "w") as f:
        f.write("data")


def shell_injection(cmd):
    subprocess.run(cmd, shell=True)


def assert_auth(user):
    assert user.is_authenticated, "Not logged in"


def random_token():
    return random.token_hex(32)


BASE_URL = "http://example.com/api"


def broad_except():
    try:
        pass
    except Exception:
        pass
