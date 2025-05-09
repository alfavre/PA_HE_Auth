from flask import Flask, request, render_template, redirect, url_for, session
import hashlib
import json
import os

app = Flask(__name__)
app.secret_key = os.urandom(16)  # Required for sessions

PEPPER = "my_secret_pepper"  # move this in own file

USER_DB = "db/users.json"


def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f)


def hash_password(password, salt):
    return hashlib.sha256((salt + password + PEPPER).encode()).hexdigest()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()

        if username in users:
            return "User already exists"
        
        #Add the passport field here

        #Add the call to passport encryption here

        salt = os.urandom(8).hex()
        hashed = hash_password(password, salt)

        users[username] = {"salt": salt, "hash": hashed}
        save_users(users)
        return "User registered!"
    return render_template("login.html", action="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()

        if username not in users:
            return "Invalid credentials"

        salt = users[username]["salt"]
        expected_hash = users[username]["hash"]
        if hash_password(password, salt) == expected_hash:
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            return "Invalid credentials"
    return render_template("login.html", action="login")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return f"Welcome, {session['user']}! <a href='/logout'>Logout</a>"


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def root():
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
