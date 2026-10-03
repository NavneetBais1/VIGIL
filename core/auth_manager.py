import os
import json
import hashlib
import hmac
import winreg


# =========================================================
# Vigil application data location
# =========================================================

LOCAL_APP_DATA = os.environ.get("LOCALAPPDATA")

if not LOCAL_APP_DATA:
    raise RuntimeError(
        "Vigil requires the Windows LOCALAPPDATA environment variable."
    )


VIGIL_DATA_DIR = os.path.join(
    LOCAL_APP_DATA,
    "Vigil"
)


# New location for Vigil's security configuration
CONFIG_PATH = os.path.join(
    VIGIL_DATA_DIR,
    "config.json"
)


# Old development location.
# This is used only once to migrate the existing config.
LEGACY_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "config.json"
)


# Windows Registry location used to remember that
# this Vigil installation has already been initialized.
REGISTRY_PATH = r"Software\Vigil"


class AuthManager:

    # =====================================================
    # Startup
    # =====================================================

    def __init__(self):

        # Create:
        # C:\Users\<username>\AppData\Local\Vigil
        os.makedirs(
            VIGIL_DATA_DIR,
            exist_ok=True
        )

        # Move the old development config into AppData
        # if this is an existing installation.
        self._migrate_legacy_config()

        # Load Vigil configuration.
        self.config = self._load_config()


    # =====================================================
    # Migrate old config.json
    # =====================================================

    def _migrate_legacy_config(self):

        # If the new config already exists,
        # there is nothing to migrate.
        if os.path.exists(CONFIG_PATH):
            return

        # If there is no old config,
        # this is probably a genuinely new installation.
        if not os.path.exists(LEGACY_CONFIG_PATH):
            return

        try:

            # -------------------------------------------------
            # IMPORTANT:
            #
            # os.replace() cannot move files between drives.
            #
            # Your project is on F:
            # F:\coding\VIGILinstaller\
            #
            # AppData is on C:
            # C:\Users\ASUS\AppData\Local\
            #
            # Therefore we copy the file first.
            # -------------------------------------------------

            with open(
                LEGACY_CONFIG_PATH,
                "rb"
            ) as source:

                with open(
                    CONFIG_PATH,
                    "wb"
                ) as destination:

                    destination.write(
                        source.read()
                    )


            # Only remove the old file AFTER the
            # new file was successfully created.
            os.remove(
                LEGACY_CONFIG_PATH
            )


        except OSError as exc:

            raise RuntimeError(
                "Unable to migrate Vigil security "
                f"configuration: {exc}"
            )


    # =====================================================
    # Windows initialization state
    # =====================================================

    def _registry_is_initialized(self):

        try:

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                REGISTRY_PATH,
                0,
                winreg.KEY_READ
            ) as key:

                value, _ = winreg.QueryValueEx(
                    key,
                    "Initialized"
                )

                return value == 1


        except FileNotFoundError:

            return False


        except OSError:

            return False


    def _set_registry_initialized(self):

        with winreg.CreateKey(
            winreg.HKEY_CURRENT_USER,
            REGISTRY_PATH
        ) as key:

            winreg.SetValueEx(
                key,
                "Initialized",
                0,
                winreg.REG_DWORD,
                1
            )


    def _clear_registry_initialized(self):

        try:

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                REGISTRY_PATH,
                0,
                winreg.KEY_SET_VALUE
            ) as key:

                winreg.DeleteValue(
                    key,
                    "Initialized"
                )


        except FileNotFoundError:

            pass


        except OSError:

            pass


    # =====================================================
    # Load configuration
    # =====================================================

    def _load_config(self):

        registry_initialized = (
            self._registry_is_initialized()
        )


        # -------------------------------------------------
        # Configuration exists
        # -------------------------------------------------

        if os.path.exists(CONFIG_PATH):

            try:

                with open(
                    CONFIG_PATH,
                    "r",
                    encoding="utf-8"
                ) as f:

                    return json.load(f)


            except (
                OSError,
                json.JSONDecodeError
            ):

                # The file exists but is damaged.
                #
                # DO NOT treat this as a new installation.
                return {
                    "initialized": registry_initialized,
                    "password_hash": "",
                    "salt": "",
                    "security_question": "",
                    "security_answer_hash": ""
                }


        # -------------------------------------------------
        # Configuration is missing
        # -------------------------------------------------
        #
        # If Windows says Vigil was already initialized,
        # this is a damaged/missing installation.
        #
        # DO NOT allow a new profile to be created.
        # -------------------------------------------------

        if registry_initialized:

            return {
                "initialized": True,
                "password_hash": "",
                "salt": "",
                "security_question": "",
                "security_answer_hash": ""
            }


        # -------------------------------------------------
        # Genuine first launch
        # -------------------------------------------------

        return {
            "initialized": False,
            "password_hash": "",
            "salt": "",
            "security_question": (
                "What is your secret backup recovery key?"
            ),
            "security_answer_hash": ""
        }


    # =====================================================
    # Save configuration
    # =====================================================

    def save_config(self):

        with open(
            CONFIG_PATH,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                self.config,
                f,
                indent=4
            )


    # =====================================================
    # Check initialization
    # =====================================================

    def is_initialized(self):

        return self._registry_is_initialized()


    # =====================================================
    # Normalize security answer
    # =====================================================

    @staticmethod
    def _normalize_answer(ans: str):

        return "".join(
            ans.strip().lower().split()
        )


    # =====================================================
    # Create master credentials
    # =====================================================

    def set_credentials(
        self,
        password: str,
        question: str,
        answer: str
    ):

        # Generate random salt.
        salt = os.urandom(16).hex()


        # Temporary password hashing implementation.
        #
        # We will replace this with Argon2id later.
        pw_hash = hashlib.sha256(
            (password + salt).encode()
        ).hexdigest()


        # Normalize security answer.
        norm_ans = self._normalize_answer(
            answer
        )


        # Temporary security-answer hashing.
        ans_hash = hashlib.sha256(
            (norm_ans + salt).encode()
        ).hexdigest()


        # Store configuration.
        self.config["initialized"] = True
        self.config["salt"] = salt
        self.config["password_hash"] = pw_hash
        self.config["security_question"] = question
        self.config["security_answer_hash"] = ans_hash


        # Save configuration FIRST.
        self.save_config()


        # Only after successful save do we mark
        # the Windows installation as initialized.
        self._set_registry_initialized()


    # =====================================================
    # Change master password
    # =====================================================

    def update_password_only(
        self,
        new_password: str
    ):

        if not self.is_initialized():

            raise RuntimeError(
                "Vigil has not been initialized."
            )


        salt = os.urandom(16).hex()


        pw_hash = hashlib.sha256(
            (new_password + salt).encode()
        ).hexdigest()


        self.config["salt"] = salt
        self.config["password_hash"] = pw_hash


        self.save_config()


    # =====================================================
    # Factory reset
    # =====================================================

    def reset_all_data(self):

        # Delete the configuration file.
        if os.path.exists(CONFIG_PATH):

            os.remove(
                CONFIG_PATH
            )


        # Remove the Windows initialization marker.
        self._clear_registry_initialized()


        # Reload fresh state.
        self.config = self._load_config()


    # =====================================================
    # Verify master password
    # =====================================================

    def verify_password(
        self,
        password: str
    ):

        # Never authenticate an uninitialized
        # installation automatically.
        if not self.is_initialized():

            return False


        stored_hash = self.config.get(
            "password_hash",
            ""
        )


        salt = self.config.get(
            "salt",
            ""
        )


        # Missing authentication data means that
        # the installation is damaged or incomplete.
        if not stored_hash or not salt:

            return False


        calc_hash = hashlib.sha256(
            (password + salt).encode()
        ).hexdigest()


        return hmac.compare_digest(
            calc_hash,
            stored_hash
        )


    # =====================================================
    # Verify security answer
    # =====================================================

    def verify_security_answer(
        self,
        answer: str
    ):

        if not self.is_initialized():

            return False


        stored_hash = self.config.get(
            "security_answer_hash",
            ""
        )


        salt = self.config.get(
            "salt",
            ""
        )


        if not stored_hash or not salt:

            return False


        norm_ans = self._normalize_answer(
            answer
        )


        calc_hash = hashlib.sha256(
            (norm_ans + salt).encode()
        ).hexdigest()


        return hmac.compare_digest(
            calc_hash,
            stored_hash
        )


    # =====================================================
    # Get security question
    # =====================================================

    def get_security_question(self):

        return self.config.get(
            "security_question",
            "What is your secret backup recovery key?"
        )