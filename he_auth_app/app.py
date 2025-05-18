from flask import Flask, request, render_template, redirect, url_for, session
import hashlib
import json
import os
import subprocess

from models import UserData
import constants
import utils

app = Flask(__name__)
app.secret_key = os.urandom(16)  # Required for sessions


# cpp wrapper
# it may look slow, but it will never be as slow as HE
def call_c_age_main(a: int, b: int) -> int:
    result = subprocess.run(
        [".cbin/age_verification_main", str(a), str(b)],
        capture_output=True,
        text=True,
        check=True,
    )
    return int(result.stdout.strip())


def encrypt_passport(passport_str: str) -> tuple[str, str, str, str, str]:
    passport_json = json.loads(passport_str)
    # we will call call_c_age_encrypt here
    # we will load the pub key here
    a = call_c_age_encrypt(passport_json["first_name"], 0)
    b = call_c_age_encrypt(passport_json["last_name"], 0)
    c = call_c_age_encrypt(passport_json["birthdate"], 0)
    return (a, b, c, passport_json["hash"], passport_json["signature"])


# with public key
# cpp wrapper
def call_c_age_encrypt(my_str: str, pub_key_age) -> str:
    return my_str + "ct"


# with private key
# cpp wrapper
def call_c_age_decrypt(my_str_ct, priv_key_age) -> str:
    return my_str_ct + "pt"


def load_users():
    if os.path.exists(constants.USER_DB):
        with open(constants.USER_DB, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def load_user(username):
    if os.path.exists(constants.USER_DB):
        with open(constants.USER_DB, "r") as f:
            try:
                users = json.load(f)
                return users.get(username, None)
            except json.JSONDecodeError:
                return None
    return None


def save_users(users):
    with open(constants.USER_DB, "w") as f:
        json.dump(users, f)


def hash_password(password, salt):
    return hashlib.sha256((salt + password + constants.PEPPER).encode()).hexdigest()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username: str = request.form["username"]
        password: str = request.form["password"]
        passport_clear: str = request.form["passport"]

        users = load_users()

        if username in users:
            return "User already exists"

        # Add the call to encryption here
        f_name_ct, l_name_ct, birthdate_ct, passport_hash, passport_signature = (
            encrypt_passport(passport_clear)
        )

        salt = os.urandom(8).hex()
        hashed_password = hash_password(password, salt)

        user = UserData(
            username=username,
            password=hashed_password,
            passport_first_name=f_name_ct,
            passport_last_name=l_name_ct,
            passport_birthdate=birthdate_ct,
            passport_hash=passport_hash,
            passport_signature=passport_signature,
        )
        user_json = json.dumps(user.__dict__)
        users[username] = user_json
        save_users(users)
        return "User registered!"
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()

        # vulberable to timing attacks
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

    my_user_data = load_user(session["user"])
    user = UserData.from_json(my_user_data)


    today_pt:int = utils.get_today_in_days()
    today_ct:str = call_c_age_encrypt(today_pt,0)


    delta_ct: str = call_c_age_main(today_ct,user.passport_birthdate)
    delta_pt: int = call_c_age_decrypt(delta_ct,0)
    result: bool = delta_pt > 4745

    return f"<h1>{result}</h1><br><a href='/dashboard'>Back to Dashboard</a>"


@app.route("/verify_passport")
def verify_passport():
    if "user" not in session:
        return redirect(url_for("login"))

    result = 'foobar' #placeholder_call("verify_passport_signature()", "HE_passport")
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
