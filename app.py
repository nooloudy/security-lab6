# app.py
import os

def login(username, password):
    # ❌ Пример плохого кода (уязвимость)
    if username == "admin" and password == "admin123":
        print("Access granted")
    else:
        print("Access denied")

def read_file(filename):
    # ❌ Потенциальная уязвимость: можно читать системные файлы
    with open(filename, "r") as f:
        print(f.read())

user = input("Enter username: ")
pwd = input("Enter password: ")
login(user, pwd)

file = input("Enter file name: ")
read_file(file)
