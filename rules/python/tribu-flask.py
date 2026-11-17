# Fixtures de prueba para rules/python/tribu-flask.yml
# `ruleid:` = la regla DEBE disparar en la linea siguiente. `ok:` = NO debe disparar.
import os
import pickle
import sqlite3
import subprocess
import urllib.request

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ruleid: tribu.python.hardcoded-credential
SECRET_KEY = "super_secret_key_12345"
# ruleid: tribu.python.hardcoded-credential
API_KEY = "sk-ant-api03-FAKE_KEY_FOR_DEMO_ONLY"
# ok: tribu.python.hardcoded-credential
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "")
# ok: tribu.python.hardcoded-credential
TOKEN_HEADER = ""


def sqli(username):
    cur = sqlite3.connect("x.db").cursor()
    # ruleid: tribu.flask.sqli-string-built-query
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    # ruleid: tribu.flask.sqli-string-built-query
    cur.execute(query)
    # ok: tribu.flask.sqli-string-built-query
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))


def cmdi():
    host = request.args.get("host")
    # ruleid: tribu.flask.command-injection-shell-true
    subprocess.run(f"ping -c 1 {host}", shell=True)
    # ok: tribu.flask.command-injection-shell-true
    subprocess.run(["ping", "-c", "1", host])
    # ok: tribu.flask.command-injection-shell-true
    subprocess.run("uptime", shell=True)


def sinks():
    data = request.get_data()
    # ruleid: tribu.flask.untrusted-input-to-dangerous-sink
    pickle.loads(data)

    name = request.args.get("name")
    # ruleid: tribu.flask.untrusted-input-to-dangerous-sink
    open(f"/app/data/{name}")
    # ok: tribu.flask.untrusted-input-to-dangerous-sink
    open(f"/app/data/{secure_filename(name)}")

    url = request.args.get("url")
    # ruleid: tribu.flask.untrusted-input-to-dangerous-sink
    urllib.request.urlopen(url)


if __name__ == "__main__":
    # ruleid: tribu.flask.debug-enabled
    app.run(host="0.0.0.0", port=5000, debug=True)
    # ok: tribu.flask.debug-enabled
    app.run(host="127.0.0.1", port=5000)
