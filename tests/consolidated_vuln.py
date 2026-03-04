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
        # sql injection
        query = "SELECT * FROM users WHERE username = '" + username + "'"
        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()

    def ping_host(self, host):
        # command injection
        os.system("ping -c 1 " + host)

    def load_user_data(self, data):
        # unsafe pickle
        return pickle.loads(data)

    def load_config(self, config_str):
        # unsafe yaml load
        return yaml.load(config_str)

    def store_password(self, password):
        # weak hash
        return hashlib.md5(password.encode()).hexdigest()

    def run_script(self, script_name):
        # command injection via shell
        subprocess.call("./scripts/" + script_name, shell=True)

@app.route('/hello')
def hello():
    # reflected xss
    name = request.args.get('name', 'World')
    return "<h1>Hello " + name + "</h1>"

if __name__ == "__main__":
    v = VulnerableApp("test.db")
    v.ping_host("127.0.0.1; ls")