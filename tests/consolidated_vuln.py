import os
import sqlite3
import pickle
import hashlib
import subprocess
import yaml
from flask import Flask, request

app = Flask(__name__)

class VulnerableApp:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name)

    def get_user_unsafe(self, username):
        # VULN: SQL Injection
        query = "SELECT * FROM users WHERE username = '" + username + "'"
        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()

    def ping_host(self, host):
        # VULN: Command Injection
        os.system("ping -c 1 " + host)

    def load_user_data(self, data):
        # VULN: Pickle Deserialization
        return pickle.loads(data)

    def load_config(self, config_str):
        # VULN: YAML Deserialization
        return yaml.load(config_str)

    def store_password(self, password):
        # VULN: Weak Hash
        return hashlib.md5(password.encode()).hexdigest()

    def run_script(self, script_name):
        # VULN: Command Injection
        subprocess.call("./scripts/" + script_name, shell=True)

@app.route('/hello')
def hello():
    # VULN: Reflected XSS
    name = request.args.get('name', 'World')
    return "<h1>Hello " + name + "</h1>"

if __name__ == "__main__":
    v = VulnerableApp("test.db")
    v.ping_host("127.0.0.1; ls")