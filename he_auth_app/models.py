from dataclasses import dataclass


@dataclass
class UserData:
    username: str
    password_hash: str
    salt: str
    #the 3 personal data are encrypted
    #passport_first_name: str
    #passport_last_name: str
    passport_birthdate_path: str
    passport_hash: str
    passport_signature: str

    @classmethod
    def from_json(cls, json_data):
        return cls(
            username=json_data.get("username", ""),
            password_hash=json_data.get("password_hash", ""),
            salt=json_data.get("salt", ""),
            #passport_first_name=json_data.get("passport_first_name", ""),
            #passport_last_name=json_data.get("passport_last_name", ""),
            passport_birthdate_path=json_data.get("passport_birthdate_path", ""),
            passport_hash=json_data.get("passport_hash", ""),
            passport_signature=json_data.get("passport_signature", ""),
        )
    def to_string(self):
        return f"{self.username} {self.password_hash} {self.salt} {self.passport_birthdate_path} {self.passport_hash} {self.passport_signature}"