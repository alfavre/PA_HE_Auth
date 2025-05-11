from flask import Flask, request, render_template, redirect, url_for, session
import hashlib
import json
import os

app = Flask(__name__)
app.secret_key = os.urandom(16)  # Required for sessions

PEPPER = "my_secret_pepper"  # move this in own file

USER_DB = "db_auth_app/users.json"


# these will be replaced with the c++ functions
def placeholder_call(*args: str):
    final_str: str = "<"
    is_first: bool = True
    i: int = 0

    for arg in args:

        if is_first:
            final_str += "FUNCTION_"
        else:
            final_str += f"ARG{i}_"
        final_str += f"{arg}_"
        i += 1

    final_str = final_str[:-1] + ">"
    print(final_str)
    return final_str


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
        username: str = request.form["username"]
        password: str = request.form["password"]
        passport: str = request.form["passport"]
        users = load_users()

        if username in users:
            return "User already exists"

        # Add the call to passport encryption here
        encrypted_passport = placeholder_call(
            "encrypt_passport()", "passport", "HE_encryption_key"
        )

        salt = os.urandom(8).hex()
        hashed = hash_password(password, salt)

        users[username] = {
            "salt": salt,
            "hash": hashed,
            "HE_passport": encrypted_passport,
        }
        save_users(users)
        return "User registered!"
    return render_template("register.html")


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
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=session["user"])


@app.route("/verify_age")
def verify_age():
    if "user" not in session:
        return redirect(url_for("login"))

    result = "FOO"
    return f"<h1>{result}</h1><br><a href='/dashboard'>Back to Dashboard</a>"


@app.route("/verify_passport")
def verify_passport():
    if "user" not in session:
        return redirect(url_for("login"))

    result = placeholder_call('verify_passport_signature()',"HE_passport")
    return f"<h1>{result}</h1><br><a href='/dashboard'>Back to Dashboard</a>"


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def root():
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
