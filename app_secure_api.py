# app_secure_api.py
from flask import Flask, request, jsonify, abort
import sqlite3
import hashlib
import subprocess
import shlex
import os

app = Flask(__name__)

# Храним хэш (для демонстрации); в реале — bcrypt/argon2 + БД
STORED_USER = "admin"
STORED_PASS_HASH = hashlib.sha256("admin123".encode()).hexdigest()

def get_db():
    conn = sqlite3.connect("users.db", check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, secret TEXT)")
    return conn

def json_required(fields):
    """Валидатор простого JSON тела — возвращает dict или abort(400)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(jsonify({"error":"Request must be JSON"}), 400)
    for f in fields:
        if f not in data:
            abort(jsonify({"error":f"Missing field: {f}"}), 400)
    return data

@app.route('/api/login', methods=['POST'])
def api_login():
    """
    Secure login example: compare password hashes (demo).
    POST JSON: {"username":"...", "password":"..."}
    """
    data = json_required(["username","password"])
    username = data["username"]
    password = data["password"]
    hashed = hashlib.sha256(password.encode()).hexdigest()
    if username == STORED_USER and hashed == STORED_PASS_HASH:
        return jsonify({"status":"ok","message":"Logged in as admin"}), 200
    return jsonify({"status":"error","message":"Wrong credentials"}), 401

@app.route('/api/user', methods=['GET'])
def api_user():
    """
    Safe: use parameterized queries to prevent SQL injection.
    GET /api/user?username=...
    """
    username = request.args.get("username","")
    conn = get_db()
    try:
        cur = conn.execute("SELECT username, secret FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row:
            return jsonify({"found": True, "username": row[0], "secret": row[1]})
        return jsonify({"found": False}), 404
    finally:
        conn.close()

# Белый список разрешённых команд (без аргументов) — безопаснее
ALLOWED_CMDS = {
    "date": ["date"],
    "uptime": ["uptime"]
}

@app.route('/api/exec', methods=['POST'])
def api_exec():
    """
    Safe exec: only allow specific commands by name (whitelist),
    no shell=True, and no user args passed to shell.
    POST JSON: {"cmd":"date"}
    """
    data = json_required(["cmd"])
    cmd = data["cmd"].strip()
    if cmd not in ALLOWED_CMDS:
        return jsonify({"error":"Command not allowed"}), 403
    args = ALLOWED_CMDS[cmd]
    try:
        out = subprocess.check_output(args, stderr=subprocess.STDOUT, shell=False, timeout=5)
        return jsonify({"cmd": cmd, "output": out.decode()})
    except subprocess.SubprocessError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/calc', methods=['POST'])
def api_calc():
    """
    Safe calculator: allow only digits and basic operators.
    POST JSON: {"expr":"2 + 2 * (3 - 1)"}
    """
    data = json_required(["expr"])
    expr = data["expr"]
    allowed_chars = set("0123456789+-*/(). ")
    if not set(expr).issubset(allowed_chars):
        return jsonify({"error":"Invalid characters in expression"}), 400
    try:
        # eval с пустыми builtins и пустым globals — минимальная защита
        result = eval(expr, {"__builtins__": None}, {})
        return jsonify({"expr": expr, "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    # debug=False для безопасного поведения (не показывать stacktrace)
    app.run(host='127.0.0.1', port=5001, debug=False)
