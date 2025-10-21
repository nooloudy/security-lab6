# safe_app.py
import os

def login(username, password):
    # ✅ Используем безопасное сравнение и хэширование (пример)
    import hashlib
    hashed = hashlib.sha256(password.encode()).hexdigest()
    stored = hashlib.sha256("admin123".encode()).hexdigest()
    if username == "admin" and hashed == stored:
        print("Access granted")
    else:
        print("Access denied")

def read_file(filename):
    # ✅ Добавляем проверку имени файла
    if ".." in filename or "/" in filename:
        print("Access denied!")
        return
    with open(filename, "r") as f:
        print(f.read())

