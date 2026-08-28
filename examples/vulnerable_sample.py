"""
Intentionally insecure Python file used to demo aisecscan.

DO NOT use any of these patterns in real code. Each one is a classic
security anti-pattern that Bandit (and therefore aisecscan) should flag.
"""

import hashlib
import os
import pickle
import subprocess

#  Hardcoded secrets 
DB_PASSWORD = "SuperSecret123!"  # noqa: hardcoded password
API_KEY = "sk-live-1234567890abcdef"


def connect_to_db(password=DB_PASSWORD):
    print(f"Connecting with password: {password}")


# Command injection via shell=True 
def list_directory(user_supplied_path):
    # user_supplied_path could contain shell metacharacters (e.g. "; rm -rf /")
    subprocess.call(f"ls {user_supplied_path}", shell=True)


def run_os_command(cmd):
    os.system(cmd)


#eval() on untrusted input 
def calculate(expression):
    # Never eval() user input - arbitrary code execution risk.
    return eval(expression)


# Insecure deserialization
def load_user_object(serialized_bytes):
    # pickle.loads on untrusted data can execute arbitrary code.
    return pickle.loads(serialized_bytes)


# Weak cryptography 
def hash_password(password):
    # MD5 is not suitable for password hashing (fast + broken).
    return hashlib.md5(password.encode()).hexdigest()


#  SQL injection via string formatting 
def get_user(conn, username):
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()


#  Insecure temp file 
def make_temp_file():
    import tempfile

    path = tempfile.mktemp()
    with open(path, "w") as f:
        f.write("temp data")
    return path


#  Bare except swallowing errors 
def risky_operation():
    try:
        1 / 0
    except:  # noqa: E722
        pass


if __name__ == "__main__":
    connect_to_db()
    hash_password("hunter2")
