from dataclasses import dataclass


@dataclass
class UserData:
    username: str
    password: str
    #the 3 personal data are encrypted
    passport_first_name: str
    passport_last_name: str
    passport_birthdate: str
    passport_hash: str
    passport_signature: str

    @classmethod
    def from_json(cls, json_data):
        return cls(
            username=json_data.get("username", ""),
            password=json_data.get("password_hash", ""),
            passport_first_name=json_data.get("passport_first_name", ""),
            passport_last_name=json_data.get("passport_last_name", ""),
            passport_birthdate=json_data.get("passport_birthdate", ""),
            passport_hash=json_data.get("passport_hash", ""),
            passport_signature=json_data.get("passport_signature", ""),
        )
