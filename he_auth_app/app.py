from flask import Flask, request, render_template, redirect, url_for, session
import hashlib
import json
import os
import subprocess
import time

from models import UserData
import constants
import utils

PRIV_KEY_NAME: str = "privkey_av.bin"

app = Flask(__name__)
app.secret_key = os.urandom(16)  # Required for sessions


# cpp wrapper
# it may look slow, but it will never be as slow as HE
def call_c_age_main(a: str, b: str, ct_result_path:str):
    result = subprocess.run(
        ["cbin/age_verification_main", a+".bin", b+".bin"],
        capture_output=True,
        text=True,
        check=True,
    )
    subprocess.run(
        ["mv", "ct_av_result.bin", ct_result_path + ".bin"],
        capture_output=False,
        text=True,
        check=True,
    )


def encrypt_passport(passport_str: str, username :str) -> tuple[str,str,str]:
    filename: str = "ct_" + username + "_birthdate"
    passport_json = json.loads(passport_str)
    # we will call call_c_age_encrypt here
    # we will load the pub key here
    #a = call_c_age_encrypt(passport_json["first_name"], 0)
    #b = call_c_age_encrypt(passport_json["last_name"], 0)
    call_c_age_encrypt(passport_json["birthdate"], filename)
    return (filename, passport_json["hash"], passport_json["signature"])


# with public key
# cpp wrapper
def call_c_age_encrypt(my_int: int, ct_file_name: str):
    result = subprocess.run(
        ["cbin/age_verification_encrypt", str(my_int)],
        capture_output=False,
        text=True,
        check=True,
    )
    subprocess.run(
        ["mv", "ct_av.bin", ct_file_name + ".bin"],
        capture_output=False,
        text=True,
        check=True,
    )


# with private key
# cpp wrapper
def call_c_age_decrypt(ct_file_name) -> int:
    result = subprocess.run(
        ["cbin/age_verification_decrypt", PRIV_KEY_NAME, ct_file_name + ".bin"],
        capture_output=True,
        text=True,
        check=True,
    )
    return int(result.stdout.strip().splitlines()[-1])


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
                print("in load: " + str(type(users)))
                print("in load: " + str(type(users.get(username))))
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
        birthdate_ct_file_name, passport_hash, passport_signature = (
            encrypt_passport(passport_clear, username)
        )

        salt = os.urandom(8).hex()
        hashed_password = hash_password(password, salt)

        user = UserData(
            username=username,
            password_hash=hashed_password,
            salt=salt,
            #passport_first_name=f_name_ct,
            #passport_last_name=l_name_ct,
            passport_birthdate_path=birthdate_ct_file_name,
            passport_hash=passport_hash,
            passport_signature=passport_signature,
        )
        users[username] = user.__dict__
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
        
        user_data = users[username]

        salt = user_data["salt"]
        expected_hash = user_data["password_hash"]
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

    result = subprocess.run(
        ["pwd"],
        capture_output=True,
        text=True,
        check=True,
    )

    today_ct_path = "ct_" + user.username + "_today"
    today_pt: int = utils.get_today_in_days() - 4745 # minus 4745
    start_time = time.time()
    call_c_age_encrypt(today_pt, today_ct_path)


    result_ct_path:str= "ct_result_" + user.username
    call_c_age_main(today_ct_path, user.passport_birthdate_path, result_ct_path)
    delta_pt: int = call_c_age_decrypt(result_ct_path)
    end_time = time.time()
    result: bool = delta_pt > 0 # thirteen
    print(f"execution time is: {end_time - start_time} second")

    return f"<h1>{result}</h1><br><a href='/dashboard'>Back to Dashboard</a>"


@app.route("/verify_passport")
def verify_passport():
    if "user" not in session:
        return redirect(url_for("login"))

    result = "foobar"  # placeholder_call("verify_passport_signature()", "HE_passport")
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
