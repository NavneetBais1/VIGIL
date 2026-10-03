import hashlib
import hmac
import json
import os
import sys
import tempfile
import winreg
from pathlib import Path
from typing import Any


APP_NAME = "Vigil"
LOCAL_APP_DATA = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/.local/share")

# Each copy/install of Vigil gets its own namespace. This prevents a second
# copy of the suite from inheriting the first copy's authentication profile.
# The path is stable as long as that copy remains in the same directory.
APP_ROOT = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent
if getattr(sys, "frozen", False):
    APP_ROOT = APP_ROOT
else:
    # core/auth_manager.py -> project root
    APP_ROOT = APP_ROOT.parent

INSTANCE_ID = hashlib.sha256(str(APP_ROOT).lower().encode("utf-8")).hexdigest()[:16]
VIGIL_DATA_DIR = Path(LOCAL_APP_DATA) / APP_NAME / "instances" / INSTANCE_ID
CONFIG_PATH = VIGIL_DATA_DIR / "config.json"
REGISTRY_PATH = rf"Software\Vigil\Instances\{INSTANCE_ID}"

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32


class AuthManager:
    """Manages one Vigil installation's local authentication state."""

    def __init__(self):
        VIGIL_DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.config = self._load_config()

    @staticmethod
    def _default_config() -> dict[str, Any]:
        return {
            "version": 3,
            "instance_id": INSTANCE_ID,
            "initialized": False,
            "password_hash": "",
            "password_salt": "",
            "security_question": "",
            "security_answer_hash": "",
            "security_answer_salt": "",
            "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "dklen": SCRYPT_DKLEN},
        }

    @staticmethod
    def _registry_is_initialized() -> bool:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "Initialized")
                return value == 1
        except (FileNotFoundError, OSError):
            return False

    @staticmethod
    def _set_registry_initialized() -> None:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH) as key:
            winreg.SetValueEx(key, "Initialized", 0, winreg.REG_DWORD, 1)

    @staticmethod
    def _clear_registry_initialized() -> None:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "Initialized")
        except (FileNotFoundError, OSError):
            pass

    def _load_config(self) -> dict[str, Any]:
        if not CONFIG_PATH.exists():
            if self._registry_is_initialized():
                cfg = self._default_config()
                cfg["initialized"] = True
                cfg["damaged"] = True
                return cfg
            return self._default_config()

        try:
            with CONFIG_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Invalid configuration format")
            if data.get("instance_id") not in (None, INSTANCE_ID):
                raise ValueError("Configuration belongs to another Vigil instance")

            # Existing v2 installs already use scrypt and can be upgraded in-place.
            if data.get("version") == 2:
                data["version"] = 3
                data["instance_id"] = INSTANCE_ID
                self._atomic_save(data)
            return data
        except (OSError, json.JSONDecodeError, ValueError):
            return {"version": 3, "initialized": True, "damaged": True, "instance_id": INSTANCE_ID}

    @staticmethod
    def _atomic_save(data: dict[str, Any]) -> None:
        VIGIL_DATA_DIR.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix="config_", suffix=".tmp", dir=VIGIL_DATA_DIR)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_name, CONFIG_PATH)
        finally:
            if os.path.exists(temp_name):
                try:
                    os.remove(temp_name)
                except OSError:
                    pass

    def save_config(self) -> None:
        self._atomic_save(self.config)

    def is_initialized(self) -> bool:
        return self._registry_is_initialized() and bool(self.config.get("initialized"))

    @staticmethod
    def _normalize_answer(answer: str) -> str:
        return "".join(answer.strip().lower().split())

    @staticmethod
    def _derive_scrypt(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)

    @staticmethod
    def _legacy_sha256(password: str, salt_text: str) -> str:
        return hashlib.sha256((password + salt_text).encode("utf-8")).hexdigest()

    def _hash_answer(self, answer: str, salt: bytes) -> bytes:
        return self._derive_scrypt(self._normalize_answer(answer), salt)

    def set_credentials(self, password: str, question: str, answer: str) -> None:
        if self._registry_is_initialized():
            raise RuntimeError("This Vigil instance is already initialized. Use Factory Reset first.")
        if len(password) < 12:
            raise ValueError("Master password must be at least 12 characters long.")
        if len(question.strip()) < 3:
            raise ValueError("Security question is too short.")
        if len(self._normalize_answer(answer)) < 3:
            raise ValueError("Security answer is too short.")

        password_salt = os.urandom(16)
        answer_salt = os.urandom(16)
        self.config = self._default_config()
        self.config.update({
            "initialized": True,
            "password_hash": self._derive_scrypt(password, password_salt).hex(),
            "password_salt": password_salt.hex(),
            "security_question": question.strip(),
            "security_answer_hash": self._hash_answer(answer, answer_salt).hex(),
            "security_answer_salt": answer_salt.hex(),
        })
        self.save_config()
        try:
            self._set_registry_initialized()
        except OSError:
            CONFIG_PATH.unlink(missing_ok=True)
            self.config = self._default_config()
            raise RuntimeError("Could not create the Windows initialization marker.")

    def update_password_only(self, new_password: str) -> None:
        if not self.is_initialized():
            raise RuntimeError("Vigil has not been initialized.")
        if len(new_password) < 12:
            raise ValueError("Master password must be at least 12 characters long.")
        salt = os.urandom(16)
        self.config["password_hash"] = self._derive_scrypt(new_password, salt).hex()
        self.config["password_salt"] = salt.hex()
        self.save_config()

    def update_security_credentials(self, question: str, answer: str) -> None:
        if not self.is_initialized():
            raise RuntimeError("Vigil has not been initialized.")
        if len(question.strip()) < 3 or len(self._normalize_answer(answer)) < 3:
            raise ValueError("Security question and answer are too short.")
        salt = os.urandom(16)
        self.config["security_question"] = question.strip()
        self.config["security_answer_salt"] = salt.hex()
        self.config["security_answer_hash"] = self._hash_answer(answer, salt).hex()
        self.save_config()

    def reset_all_data(self) -> None:
        CONFIG_PATH.unlink(missing_ok=True)
        self._clear_registry_initialized()
        self.config = self._default_config()

    def verify_password(self, password: str) -> bool:
        if not self.is_initialized():
            return False
        try:
            stored_hex = self.config.get("password_hash", "")
            salt_hex = self.config.get("password_salt", "")

            # Compatibility with the previous Vigil GitHub-ready build.
            if stored_hex and salt_hex:
                stored = bytes.fromhex(stored_hex)
                salt = bytes.fromhex(salt_hex)
                if len(stored) == SCRYPT_DKLEN and len(salt) == 16:
                    return hmac.compare_digest(self._derive_scrypt(password, salt), stored)

            # Compatibility with the original Vigil config format. On a
            # successful login, immediately upgrade the stored credential to scrypt.
            legacy_salt = self.config.get("salt", "")
            legacy_hash = self.config.get("password_hash", "")
            if legacy_salt and legacy_hash and hmac.compare_digest(self._legacy_sha256(password, legacy_salt), legacy_hash):
                new_salt = os.urandom(16)
                self.config["version"] = 3
                self.config["instance_id"] = INSTANCE_ID
                self.config["password_hash"] = self._derive_scrypt(password, new_salt).hex()
                self.config["password_salt"] = new_salt.hex()
                self.config["_legacy_salt"] = legacy_salt
                self.config.pop("salt", None)
                self.save_config()
                return True
        except (ValueError, TypeError, OSError):
            return False
        return False

    def verify_security_answer(self, answer: str) -> bool:
        if not self.is_initialized():
            return False
        try:
            stored = bytes.fromhex(self.config.get("security_answer_hash", ""))
            salt = bytes.fromhex(self.config.get("security_answer_salt", ""))
            if len(stored) == SCRYPT_DKLEN and len(salt) == 16:
                return hmac.compare_digest(self._hash_answer(answer, salt), stored)

            # Legacy answer format upgrade.
            legacy_salt = self.config.get("salt", self.config.get("_legacy_salt", ""))
            legacy_hash = self.config.get("security_answer_hash", "")
            if legacy_salt and legacy_hash:
                candidate = self._legacy_sha256(self._normalize_answer(answer), legacy_salt)
                if hmac.compare_digest(candidate, legacy_hash):
                    new_salt = os.urandom(16)
                    self.config["security_answer_hash"] = self._hash_answer(answer, new_salt).hex()
                    self.config["security_answer_salt"] = new_salt.hex()
                    self.config.pop("salt", None)
                    self.config.pop("_legacy_salt", None)
                    self.save_config()
                    return True
        except (ValueError, TypeError, OSError):
            return False
        return False

    def get_security_question(self) -> str:
        return self.config.get("security_question", "")

    @staticmethod
    def instance_location() -> str:
        return str(VIGIL_DATA_DIR)
