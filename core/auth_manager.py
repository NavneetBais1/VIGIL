import os
import json
import hashlib
import hmac

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")

class AuthManager:
    """Handles master password, security questions, and system state resets."""
    def __init__(self):
        self.config = self._load_config()

    def _load_config(self):
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "initialized": False,
            "password_hash": "",
            "salt": "",
            "security_question": "What is your secret backup recovery key?",
            "security_answer_hash": ""
        }

    def save_config(self):
        with open(CONFIG_PATH, "w") as f:
            json.dump(self.config, f, indent=4)

    def is_initialized(self):
        return self.config.get("initialized", False)

    @staticmethod
    def _normalize_answer(ans: str) -> str:
        return "".join(ans.strip().lower().split())

    def set_credentials(self, password: str, question: str, answer: str):
        salt = os.urandom(16).hex()
        pw_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        
        norm_ans = self._normalize_answer(answer)
        ans_hash = hashlib.sha256((norm_ans + salt).encode()).hexdigest()

        self.config["initialized"] = True
        self.config["salt"] = salt
        self.config["password_hash"] = pw_hash
        self.config["security_question"] = question
        self.config["security_answer_hash"] = ans_hash
        self.save_config()

    def update_password_only(self, new_password: str):
        salt = os.urandom(16).hex()
        pw_hash = hashlib.sha256((new_password + salt).encode()).hexdigest()
        self.config["salt"] = salt
        self.config["password_hash"] = pw_hash
        self.save_config()

    def reset_all_data(self):
        """Wipes config file entirely to force a clean re-initialization."""
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
        self.config = self._load_config()

    def verify_password(self, password: str) -> bool:
        if not self.is_initialized():
            return True
        salt = self.config.get("salt", "")
        calc_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return hmac.compare_digest(calc_hash, self.config.get("password_hash", ""))

    def verify_security_answer(self, answer: str) -> bool:
        if not self.is_initialized():
            return True
        salt = self.config.get("salt", "")
        norm_ans = self._normalize_answer(answer)
        calc_hash = hashlib.sha256((norm_ans + salt).encode()).hexdigest()
        return hmac.compare_digest(calc_hash, self.config.get("security_answer_hash", ""))

    def get_security_question(self) -> str:
        return self.config.get("security_question", "What is your secret backup recovery key?")