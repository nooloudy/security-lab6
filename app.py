# app_vulnerable_api.py
# Учебный уязвимый REST API (НЕ использовать в проде)
from flask import Flask, request, jsonify
import sqlite3
import subprocess

app = Flask(__name__)

# Hardcoded credentials (плохо)
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

def get_db():
    conn = sqlite3.connect("users.db")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, secret TEXT)")
    return conn

@app.route('/api/login', methods=['POST'])
def api_login():
    """
    POST JSON: {"username":"...", "password":"..."}
    ❌ Vulnerable: compares plaintext credentials and uses hardcoded password
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if username == ADMIN_USER and password == ADMIN_PASS:
        return jsonify({"status":"ok","message":"Logged in as admin"}), 200
    return jsonify({"status":"error","message":"Wrong credentials"}), 401

@app.route('/api/user', methods=['GET'])
def api_user():
    """
    GET /api/user?username=...
    ❌ Vulnerable: SQL injection via string formatting
    """
    username = request.args.get("username", "")
    conn = get_db()
    try:
        # ❌ уязвимый SQL (конкатенация)
        query = "SELECT username, secret FROM users WHERE username = '%s'" % username
        cur = conn.execute(query)
        row = cur.fetchone()
        if row:
            return jsonify({"found": True, "username": row[0], "secret": row[1]})
        return jsonify({"found": False}), 404
    finally:
        conn.close()

@app.route('/api/exec', methods=['POST'])
def api_exec():
    """
    POST JSON: {"cmd": "ls -la"} — ❌ Vulnerable: executes arbitrary shell commands
    """
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd", "")
    # ❌ опасно: выполняем команду без проверки
    output = subprocess.getoutput(cmd)
    return jsonify({"cmd": cmd, "output": output})

@app.route('/api/calc', methods=['POST'])
def api_calc():
    """
    POST JSON: {"expr": "2+2"} — ❌ Vulnerable: eval on user input
    """
    data = request.get_json(silent=True) or {}
    expr = data.get("expr", "")
    try:
        # ❌ eval — исполнение произвольного кода
        result = eval(expr)
        return jsonify({"expr": expr, "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8888, debug=True)
