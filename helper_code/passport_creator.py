import json
import os
import hashlib
import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

PRIV_KEY_FILE = "../db_general/passport_auth_priv_key_rsa.pem"
PUB_KEY_FILE = "../db_general/passport_auth_pub_key_rsa.pem"
DATA_FILE = "../db_general/passports_clear.json"


# Generate or load the RSA key
# Pub key is not loaded
def get_rsa_private_key():
    if not os.path.exists(PRIV_KEY_FILE):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(PRIV_KEY_FILE, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    else:
        with open(PRIV_KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )
    return private_key


def save_rsa_public_key(private_key, public_key_path):
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


# Get user data
def get_user_data():
    first_name = input("Enter your first name: ")
    last_name = input("Enter your last name: ")
    birthdate_str = input("Enter your birthdate (YYYY-MM-DD): ")

    # Convert to timestamp
    try:
        birthdate_obj = datetime.datetime.strptime(birthdate_str, "%Y-%m-%d")
        birthdate_ts = int(birthdate_obj.timestamp())
        birthdate_days = birthdate_ts // 86400
    except ValueError:
        print("Invalid date format. Please use YYYY-MM-DD.")
        exit(1)

    return first_name, last_name, birthdate_days


# Create hash of user fields
def create_hash(first_name, last_name, birthdate_ts):
    hash_input = f"{first_name}|{last_name}|{birthdate_ts}".encode("utf-8")
    entry_hash = hashlib.sha256(hash_input).hexdigest()
    return entry_hash


# Sign the hash
def sign_hash(entry_hash):
    private_key = get_rsa_private_key()
    signature = private_key.sign(
        entry_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return signature


# Create the entry for the JSON
def create_entry(first_name, last_name, birthdate_ts, entry_hash, signature):
    entry = {
        "first_name": first_name,
        "last_name": last_name,
        "birthdate": birthdate_ts,
        "hash": entry_hash,
        "signature": signature.hex(),
    }
    return entry


# Load existing data and append
def append_to_data(entry):
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            data = json.load(file)
    else:
        data = []

    data.append(entry)

    # Save back to file
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)


# Main function to control the flow of the program
def main():
    save_keys_to_disk: bool = False

    if save_keys_to_disk:
        private_key = get_rsa_private_key()
        save_rsa_public_key(private_key, PUB_KEY_FILE)
        print("Keys written in file.")
    else:
        first_name, last_name, birthdate_days = get_user_data()
        entry_hash = create_hash(first_name, last_name, birthdate_days)
        signature = sign_hash(entry_hash)
        entry = create_entry(first_name, last_name, birthdate_days, entry_hash, signature)
        append_to_data(entry)
        print("Entry saved to passports_clear.json")


if __name__ == "__main__":
    main()
